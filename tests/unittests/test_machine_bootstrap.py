"""Unit tests for named singleton-machine bootstrap.

Cover OpenTofu planning, saved-plan validation, credential-bound preflight,
Tailscale registration retirement, machine replacement, and SSH verification.
External services and commands are mocked; tests never change the estate.
"""

import hashlib
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock

import pytest

from mxm.control.credentials import CredentialError
from mxm.control.machine_bootstrap import (
    MachineBootstrapError,
    _await_bootstrap_device,
    _bootstrap_ssh_ready,
    _credential_preflight_worker,
    _key_to_replace,
    _retire_bootstrap_devices,
    _worker_main,
    apply_machine_bootstrap,
    apply_machine_bootstrap_inherited,
    inspect_machine_bootstrap_plan,
    machine_bootstrap_plan_sha256,
    preflight_machine_bootstrap_credentials,
    validate_machine_bootstrap_apply_plan,
)
from mxm.control.opentofu import OpenTofuError
from mxm.control.tailscale import TailscaleClient, TailscaleDevice, TailscaleError

KEY_ADDRESS = "tailscale_tailnet_key.security"
SERVICE_TAG = "tag:mxm-security"


# ---------------------------------------------------------------------------
# Fixtures and representative plans
# ---------------------------------------------------------------------------


@pytest.fixture
def bootstrap_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Provide an existing root, policy path, and owner-only saved plan."""
    root = tmp_path / "root"
    root.mkdir()
    policy = tmp_path / "environment.toml"
    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)
    return root, policy, plan


def _bootstrap_plan_document(
    *,
    server_actions: tuple[str, ...] = ("delete", "create"),
    key_actions: tuple[str, ...] = ("delete", "create"),
    tag: str = SERVICE_TAG,
) -> dict[str, object]:
    """Build a saved-plan JSON fixture with no secret material."""
    return {
        "resource_changes": [
            {
                "mode": "managed",
                "type": "hcloud_firewall",
                "address": "hcloud_firewall.security",
                "change": {"actions": ["no-op"]},
            },
            {
                "mode": "managed",
                "type": "hcloud_server",
                "address": "hcloud_server.security",
                "change": {"actions": list(server_actions)},
            },
            {
                "mode": "managed",
                "type": "hcloud_ssh_key",
                "address": "hcloud_ssh_key.forge_primary",
                "change": {"actions": ["no-op"]},
            },
            {
                "mode": "managed",
                "type": "tailscale_tailnet_key",
                "address": KEY_ADDRESS,
                "change": {
                    "actions": list(key_actions),
                    "after": {"tags": [tag]},
                },
            },
        ]
    }


def fake_show_bootstrap_plan(
    root: Path,
    plan: Path,
    environment_policy: Path,
) -> dict[str, object]:
    """Return valid plan JSON without running OpenTofu."""
    return _bootstrap_plan_document()


def _change(
    resource_type: str,
    actions: list[str],
    *,
    address: str | None = None,
    mode: str = "managed",
) -> dict[str, object]:
    """Build an OpenTofu resource-change record."""
    result: dict[str, object] = {
        "mode": mode,
        "type": resource_type,
        "change": {"actions": actions},
    }
    if address is not None:
        result["address"] = address
    return result


def _server(*actions: str) -> dict[str, object]:
    """Build a Hetzner server change record."""
    return _change("hcloud_server", list(actions))


def _key(*actions: str, address: str = KEY_ADDRESS) -> dict[str, object]:
    """Build a Tailscale enrollment-key change record."""
    return _change("tailscale_tailnet_key", list(actions), address=address)


def _device(
    device_id: str,
    *,
    tag: str = SERVICE_TAG,
    connected: bool | None = True,
) -> TailscaleDevice:
    """Build a Tailscale registration with a distinct device ID."""
    return TailscaleDevice(
        id=device_id,
        name=f"mxm-security-{device_id}.tailnet.ts.net",
        tags=(tag,),
        connected_to_control=connected,
    )


def _client_with_devices(*devices: TailscaleDevice) -> MagicMock:
    """Provide a context-managed Tailscale client with a fixed inventory."""
    client = MagicMock()
    client.__enter__.return_value = client
    client.list_devices.return_value = list(devices)
    return client


def _patch_client(monkeypatch: pytest.MonkeyPatch, client: MagicMock) -> None:
    """Inject a Tailscale client without an OAuth API request."""

    def fake_client() -> TailscaleClient:
        """Return the configured test client."""
        return cast("TailscaleClient", client)

    monkeypatch.setattr(TailscaleClient, "from_environment", fake_client)


def _patch_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use representative plan JSON instead of executing OpenTofu show."""
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._show_plan",
        fake_show_bootstrap_plan,
    )


def _patch_ssh_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide an empty filtered environment for enrollment tests."""
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.load_environment_policy",
        MagicMock(return_value={}),
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.filter_environment",
        MagicMock(return_value={}),
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.load_credentials",
        MagicMock(return_value={}),
    )


# ---------------------------------------------------------------------------
# Planning decisions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        pytest.param([], None, id="empty-plan"),
        pytest.param(
            [_change("hcloud_firewall", ["update"])],
            None,
            id="unrelated-change",
        ),
        pytest.param(
            [_server("create"), _key("create")],
            None,
            id="new-server-and-new-key",
        ),
        pytest.param(
            [_server("create"), _key("no-op")],
            KEY_ADDRESS,
            id="new-server-requires-new-key",
        ),
        pytest.param(
            [_server("delete", "create"), _key("no-op")],
            KEY_ADDRESS,
            id="replace-server-delete-first",
        ),
        pytest.param(
            [_server("create", "delete"), _key("no-op")],
            KEY_ADDRESS,
            id="replace-server-create-first",
        ),
        pytest.param(
            [_server("delete"), _key("no-op")],
            None,
            id="delete-server-only",
        ),
        pytest.param(
            [_server("create"), _key("delete", "create")],
            None,
            id="key-already-replaced",
        ),
        pytest.param(
            [_server("no-op"), _key("no-op")],
            None,
            id="no-change",
        ),
        pytest.param(
            [
                _server("create"),
                _key("no-op"),
                _key("create", address="tailscale_tailnet_key.other"),
            ],
            None,
            id="other-key-created",
        ),
        pytest.param(
            [_change("hcloud_server", ["create"], mode="data"), _key("no-op")],
            None,
            id="ignore-data-source",
        ),
    ],
)
def test_key_replacement_decision(
    changes: list[object],
    expected: str | None,
) -> None:
    """Renew enrollment authority only when server creation requires it."""
    assert _key_to_replace({"resource_changes": changes}) == expected


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        pytest.param(
            [_server("create")],
            "exactly one tailscale_tailnet_key",
            id="missing-key",
        ),
        pytest.param(
            [
                _server("create"),
                _key("no-op"),
                _key("no-op", address="tailscale_tailnet_key.other"),
            ],
            "exactly one tailscale_tailnet_key",
            id="ambiguous-keys",
        ),
        pytest.param([None], "malformed resource change", id="invalid-record"),
        pytest.param(
            [{"mode": "managed", "type": "hcloud_server"}],
            "malformed change details",
            id="missing-change",
        ),
        pytest.param(
            [
                {
                    "mode": "managed",
                    "type": "hcloud_server",
                    "change": {"actions": ["create", 42]},
                }
            ],
            "malformed resource actions",
            id="non-string-action",
        ),
        pytest.param(
            [_server("create"), _change("tailscale_tailnet_key", ["no-op"])],
            "no valid resource address",
            id="missing-key-address",
        ),
    ],
)
def test_invalid_resource_changes_fail_closed(
    changes: list[object],
    message: str,
) -> None:
    """Reject malformed or ambiguous planning inputs."""
    with pytest.raises(MachineBootstrapError, match=message):
        _key_to_replace({"resource_changes": changes})


@pytest.mark.parametrize("invalid", [None, "unexpected", {"not": "a list"}])
def test_invalid_resource_changes_collection(invalid: object) -> None:
    """Require resource_changes to be a list when explicitly supplied."""
    with pytest.raises(MachineBootstrapError, match="invalid resource_changes"):
        _key_to_replace({"resource_changes": invalid})


def test_missing_resource_changes_is_empty_plan() -> None:
    """Treat absent resource_changes as an empty planning change set."""
    assert _key_to_replace({}) is None


# ---------------------------------------------------------------------------
# Saved-plan validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server_actions", "key_actions"),
    [
        (("create",), ("create",)),
        (("delete", "create"), ("delete", "create")),
        (("create", "delete"), ("create", "delete")),
    ],
)
def test_inspect_bootstrap_plan(
    server_actions: tuple[str, ...],
    key_actions: tuple[str, ...],
) -> None:
    """Identify the single machine, enrollment key, and exact service tag."""
    result = inspect_machine_bootstrap_plan(
        _bootstrap_plan_document(
            server_actions=server_actions,
            key_actions=key_actions,
        )
    )
    assert result.server_address == "hcloud_server.security"
    assert result.server_actions == server_actions
    assert result.key_address == KEY_ADDRESS
    assert result.key_actions == key_actions
    assert result.service_tag == SERVICE_TAG


@pytest.mark.parametrize(
    ("server_actions", "key_actions"),
    [
        (("no-op",), ("no-op",)),
        (("delete",), ("delete", "create")),
        (("delete", "create"), ("no-op",)),
        (("create",), ("delete",)),
        (("update",), ("create",)),
    ],
)
def test_inspect_rejects_unsupported_lifecycle(
    server_actions: tuple[str, ...],
    key_actions: tuple[str, ...],
) -> None:
    """Require server and enrollment-key creation or replacement."""
    with pytest.raises(MachineBootstrapError, match="requires"):
        inspect_machine_bootstrap_plan(
            _bootstrap_plan_document(
                server_actions=server_actions,
                key_actions=key_actions,
            )
        )


@pytest.mark.parametrize(
    "tag",
    ["", "mxm-security", "tag:", "tag:mxm security", "tag:mxm-security/other"],
)
def test_inspect_rejects_invalid_service_tag(tag: str) -> None:
    """Reject malformed Tailscale identity declarations."""
    with pytest.raises(MachineBootstrapError, match="invalid service tag"):
        inspect_machine_bootstrap_plan(_bootstrap_plan_document(tag=tag))


def test_inspect_rejects_missing_server() -> None:
    """Require exactly one managed Hetzner server."""
    document = _bootstrap_plan_document()
    changes = cast("list[object]", document["resource_changes"])
    changes[:] = [
        item
        for item in changes
        if cast("dict[str, object]", item).get("type") != "hcloud_server"
    ]
    with pytest.raises(MachineBootstrapError, match="exactly one hcloud_server"):
        inspect_machine_bootstrap_plan(document)


@pytest.mark.parametrize("resource_type", ["hcloud_server", "tailscale_tailnet_key"])
def test_inspect_rejects_ambiguous_resources(resource_type: str) -> None:
    """Reject plans with multiple servers or multiple enrollment keys."""
    document = _bootstrap_plan_document()
    changes = cast("list[object]", document["resource_changes"])
    if resource_type == "hcloud_server":
        changes.append(
            {
                "mode": "managed",
                "type": "hcloud_server",
                "address": "hcloud_server.other",
                "change": {"actions": ["create"]},
            }
        )
        message = "exactly one hcloud_server"
    else:
        changes.append(
            {
                "mode": "managed",
                "type": "tailscale_tailnet_key",
                "address": "tailscale_tailnet_key.other",
                "change": {"actions": ["create"], "after": {"tags": ["tag:other"]}},
            }
        )
        message = "exactly one tailscale_tailnet_key"
    with pytest.raises(MachineBootstrapError, match=message):
        inspect_machine_bootstrap_plan(document)


def test_inspect_rejects_missing_resource_changes() -> None:
    """Require a resource-change collection for saved-plan inspection."""
    with pytest.raises(MachineBootstrapError, match="invalid resource changes"):
        inspect_machine_bootstrap_plan({})


def test_apply_plan_accepts_unrelated_no_ops() -> None:
    """Allow no-op firewall and SSH-key records beside the machine changes."""
    result = validate_machine_bootstrap_apply_plan(_bootstrap_plan_document())
    assert result.service_tag == SERVICE_TAG


def test_apply_plan_rejects_unrelated_mutations() -> None:
    """Reject a replacement plan that also modifies an unrelated resource."""
    document = _bootstrap_plan_document()
    changes = cast("list[object]", document["resource_changes"])
    changes.append(
        {
            "mode": "managed",
            "type": "hcloud_network",
            "address": "hcloud_network.other",
            "change": {"actions": ["delete"]},
        }
    )
    with pytest.raises(MachineBootstrapError, match="unrelated resource"):
        validate_machine_bootstrap_apply_plan(document)


def test_plan_digest_matches_saved_bytes(
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Hash the saved plan without reading or disclosing its JSON contents."""
    _, _, plan = bootstrap_paths
    expected = hashlib.sha256(b"saved plan").hexdigest()
    assert machine_bootstrap_plan_sha256(plan) == expected


# ---------------------------------------------------------------------------
# Credential-bound preflight
# ---------------------------------------------------------------------------


def test_preflight_launches_credential_bound_worker(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Pass the validated singleton tag to the credential-bound worker."""
    root, policy, plan = bootstrap_paths
    _patch_plan(monkeypatch)
    observed: dict[str, object] = {}

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        """Capture worker arguments without resolving credentials."""
        observed.update(
            command=command,
            stack=stack,
            policy=environment_policy,
            restrictive_umask=restrictive_umask,
        )
        return 0

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fake_run_with_credentials,
    )
    assert preflight_machine_bootstrap_credentials(root, policy, plan) == plan
    assert observed == {
        "command": [
            sys.executable,
            "-m",
            "mxm.control.machine_bootstrap",
            "preflight",
            "--root",
            str(root),
            "--plan",
            str(plan),
            "--service-tag",
            SERVICE_TAG,
        ],
        "stack": root,
        "policy": policy,
        "restrictive_umask": True,
    }


@pytest.mark.parametrize("returncode", [1, 2, 127])
def test_preflight_reports_worker_failure(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
    returncode: int,
) -> None:
    """Reject an unsuccessful credential-bound preflight process."""
    root, policy, plan = bootstrap_paths
    _patch_plan(monkeypatch)

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        """Return the simulated worker exit status."""
        return returncode

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fake_run_with_credentials,
    )
    with pytest.raises(
        MachineBootstrapError,
        match=f"worker failed with exit status {returncode}",
    ):
        preflight_machine_bootstrap_credentials(root, policy, plan)


def test_preflight_reports_credential_failure(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Translate a credential-runner error into a bootstrap error."""
    root, policy, plan = bootstrap_paths
    _patch_plan(monkeypatch)

    def fail_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        """Simulate unavailable bootstrap credentials."""
        raise CredentialError("Operator credentials unavailable")

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fail_credentials,
    )
    with pytest.raises(MachineBootstrapError, match="Operator credentials unavailable"):
        preflight_machine_bootstrap_credentials(root, policy, plan)


def test_preflight_rejects_insecure_plan_before_worker(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Reject a world-readable saved plan before requesting credentials."""
    root, policy, plan = bootstrap_paths
    plan.chmod(0o644)
    unexpected_worker = MagicMock()
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials", unexpected_worker
    )
    with pytest.raises(MachineBootstrapError, match="permissions must be owner-only"):
        preflight_machine_bootstrap_credentials(root, policy, plan)
    unexpected_worker.assert_not_called()


def test_credential_worker_reports_only_exact_tag_matches(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Report tagged registrations without deleting any device."""
    root, _, plan = bootstrap_paths
    client = _client_with_devices(
        _device("1001"),
        _device("1002", connected=False),
        _device("1003", tag="tag:mxm-factory-agent"),
    )
    _patch_client(monkeypatch, client)
    _credential_preflight_worker(root, plan, service_tag=SERVICE_TAG)
    output = capsys.readouterr().out
    assert "DEVICES   3 registered" in output
    assert f"MATCHES   2 for {SERVICE_TAG}" in output
    assert "1001" in output
    assert "1002" in output
    assert "1003" not in output
    assert "connected" in output
    assert "disconnected" in output
    client.list_devices.assert_called_once_with()
    client.delete_device.assert_not_called()
    client.__exit__.assert_called_once()


def test_credential_worker_reports_empty_inventory(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Allow a new singleton without a previous device registration."""
    root, _, plan = bootstrap_paths
    client = _client_with_devices()
    _patch_client(monkeypatch, client)
    _credential_preflight_worker(root, plan, service_tag=SERVICE_TAG)
    assert "MATCHES   0" in capsys.readouterr().out
    client.delete_device.assert_not_called()


def test_credential_worker_propagates_tailscale_failure(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Preserve Tailscale authentication and API failures in preflight."""
    root, _, plan = bootstrap_paths
    client = _client_with_devices()
    client.list_devices.side_effect = TailscaleError("Device discovery failed")
    _patch_client(monkeypatch, client)
    with pytest.raises(TailscaleError, match="Device discovery failed"):
        _credential_preflight_worker(root, plan, service_tag=SERVICE_TAG)
    client.delete_device.assert_not_called()
    client.__exit__.assert_called_once()


# ---------------------------------------------------------------------------
# Credential-bound worker dispatch
# ---------------------------------------------------------------------------


def test_worker_dispatches_preflight(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Dispatch preflight with the root, plan, and planned service tag."""
    root, _, plan = bootstrap_paths
    observed: dict[str, object] = {}

    def fake_preflight(root: Path, plan: Path, *, service_tag: str) -> None:
        """Capture the preflight worker arguments."""
        observed.update(root=root, plan=plan, tag=service_tag)

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._credential_preflight_worker", fake_preflight
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mxm.control.machine_bootstrap",
            "preflight",
            "--root",
            str(root),
            "--plan",
            str(plan),
            "--service-tag",
            SERVICE_TAG,
        ],
    )
    assert _worker_main() == 0
    assert observed == {"root": root, "plan": plan, "tag": SERVICE_TAG}
    assert "OK" in capsys.readouterr().out


def test_worker_dispatches_apply(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Forward only plan identity and environment inputs to apply."""
    root, policy, plan = bootstrap_paths
    observed: dict[str, object] = {}

    def fake_apply(
        root: Path,
        environment_policy: Path,
        plan: Path,
        *,
        expected_plan_sha256: str,
        expected_service_tag: str,
    ) -> TailscaleDevice:
        """Record dispatch without changing any external resource."""
        observed.update(
            root=root,
            policy=environment_policy,
            plan=plan,
            digest=expected_plan_sha256,
            tag=expected_service_tag,
        )
        return _device("new-device")

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.apply_machine_bootstrap_inherited",
        fake_apply,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mxm.control.machine_bootstrap",
            "apply",
            "--root",
            str(root),
            "--plan",
            str(plan),
            "--service-tag",
            SERVICE_TAG,
            "--environment-policy",
            str(policy),
            "--expected-plan-sha256",
            "abc123",
        ],
    )
    assert _worker_main() == 0
    assert observed == {
        "root": root,
        "policy": policy,
        "plan": plan,
        "digest": "abc123",
        "tag": SERVICE_TAG,
    }
    assert "OK" in capsys.readouterr().out


def test_worker_main_reports_tailscale_failure(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Return failure without reporting a successful preflight."""
    root, _, plan = bootstrap_paths

    def fail_preflight(root: Path, plan: Path, *, service_tag: str) -> None:
        """Simulate failed Tailscale discovery."""
        raise TailscaleError("Device discovery failed")

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._credential_preflight_worker", fail_preflight
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mxm.control.machine_bootstrap",
            "preflight",
            "--root",
            str(root),
            "--plan",
            str(plan),
            "--service-tag",
            SERVICE_TAG,
        ],
    )
    assert _worker_main() == 1
    assert "Device discovery failed" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Application and device retirement
# ---------------------------------------------------------------------------


def test_apply_launches_credential_bound_worker(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Pass the validated plan digest and tag into the apply worker."""
    root, policy, plan = bootstrap_paths
    observed: dict[str, object] = {}
    _patch_plan(monkeypatch)

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        """Capture the invocation without resolving provider credentials."""
        observed.update(
            command=command,
            stack=stack,
            policy=environment_policy,
            umask=restrictive_umask,
        )
        return 0

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fake_run_with_credentials,
    )
    assert apply_machine_bootstrap(root, policy, plan) == plan
    assert observed == {
        "command": [
            sys.executable,
            "-m",
            "mxm.control.machine_bootstrap",
            "apply",
            "--root",
            str(root),
            "--environment-policy",
            str(policy),
            "--plan",
            str(plan),
            "--service-tag",
            SERVICE_TAG,
            "--expected-plan-sha256",
            hashlib.sha256(b"saved plan").hexdigest(),
        ],
        "stack": root,
        "policy": policy,
        "umask": True,
    }


def test_apply_reports_failed_credential_worker(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Return a bootstrap failure when the apply worker exits unsuccessfully."""
    root, policy, plan = bootstrap_paths
    _patch_plan(monkeypatch)

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        """Simulate an unsuccessful worker process."""
        return 1

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fake_run_with_credentials,
    )
    with pytest.raises(MachineBootstrapError, match="worker failed with exit status 1"):
        apply_machine_bootstrap(root, policy, plan)


def test_apply_inherited_rejects_modified_plan(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Reject a changed plan before contacting Tailscale or OpenTofu."""
    root, policy, plan = bootstrap_paths
    client_factory = MagicMock()
    monkeypatch.setattr(TailscaleClient, "from_environment", client_factory)
    with pytest.raises(MachineBootstrapError, match="differs from the approved digest"):
        apply_machine_bootstrap_inherited(
            root,
            policy,
            plan,
            expected_plan_sha256="wrong-digest",
            expected_service_tag=SERVICE_TAG,
        )
    client_factory.assert_not_called()


def test_retirement_rejects_changed_device_inventory() -> None:
    """Abort deletion if the discovered singleton set has changed."""
    client = _client_with_devices(_device("unexpected"))
    with pytest.raises(MachineBootstrapError, match="candidates changed"):
        _retire_bootstrap_devices(
            cast("TailscaleClient", client), SERVICE_TAG, ["old-device"]
        )
    client.delete_device.assert_not_called()


def test_retirement_rejects_duplicate_ids() -> None:
    """Reject ambiguous, duplicate discovery results before deletion."""
    client = _client_with_devices(_device("old-device"))
    with pytest.raises(MachineBootstrapError, match="unique and non-empty"):
        _retire_bootstrap_devices(
            cast("TailscaleClient", client), SERVICE_TAG, ["old-device", "old-device"]
        )
    client.list_devices.assert_not_called()
    client.delete_device.assert_not_called()


def test_retirement_deletes_exact_tagged_devices() -> None:
    """Delete all matching singleton registrations, not unrelated devices."""
    client = _client_with_devices()
    client.list_devices.side_effect = [
        [_device("old-1"), _device("old-2"), _device("other", tag="tag:other")],
        [_device("other", tag="tag:other")],
    ]
    _retire_bootstrap_devices(
        cast("TailscaleClient", client), SERVICE_TAG, ["old-1", "old-2"]
    )
    assert client.delete_device.call_count == 2
    assert {call.args[0] for call in client.delete_device.call_args_list} == {
        "old-1",
        "old-2",
    }
    assert client.list_devices.call_count == 2


def test_retirement_allows_empty_registration_set() -> None:
    """Allow initial provisioning when no previous singleton exists."""
    client = _client_with_devices()
    _retire_bootstrap_devices(cast("TailscaleClient", client), SERVICE_TAG, [])
    client.delete_device.assert_not_called()
    assert client.list_devices.call_count == 2


def test_retirement_aborts_when_device_deletion_fails() -> None:
    """Propagate a Tailscale API deletion failure."""
    client = _client_with_devices(_device("old-device"))
    client.delete_device.side_effect = TailscaleError("Device deletion denied")
    with pytest.raises(TailscaleError, match="Device deletion denied"):
        _retire_bootstrap_devices(
            cast("TailscaleClient", client), SERVICE_TAG, ["old-device"]
        )
    client.delete_device.assert_called_once_with("old-device")
    client.list_devices.assert_called_once()


def test_retirement_times_out_when_registration_remains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop when removal cannot be confirmed after a successful DELETE."""
    client = _client_with_devices(_device("old-device"))
    calls = 0

    def fake_monotonic() -> float:
        """Move the verification clock past the deadline."""
        nonlocal calls
        calls += 1
        return 0.0 if calls == 1 else 61.0

    monkeypatch.setattr("mxm.control.machine_bootstrap.time.monotonic", fake_monotonic)
    with pytest.raises(MachineBootstrapError, match="Timed out verifying"):
        _retire_bootstrap_devices(
            cast("TailscaleClient", client), SERVICE_TAG, ["old-device"]
        )
    client.delete_device.assert_called_once_with("old-device")
    assert client.list_devices.call_count == 2


@pytest.mark.parametrize("old_ids", [(), ("old-device",), ("old-1", "old-2")])
def test_apply_inherited_discovers_singleton_devices_and_orders_steps(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
    old_ids: tuple[str, ...],
) -> None:
    """Discover retired IDs before OpenTofu apply and new-device verification."""
    root, policy, plan = bootstrap_paths
    _patch_plan(monkeypatch)
    client = _client_with_devices(*(_device(device_id) for device_id in old_ids))
    _patch_client(monkeypatch, client)
    observed: list[str] = []

    def fake_retirement(
        tailscale: TailscaleClient,
        service_tag: str,
        expected_device_ids: Sequence[str],
    ) -> None:
        """Verify the exact registration set derived from live discovery."""
        assert service_tag == SERVICE_TAG
        assert tuple(expected_device_ids) == old_ids
        observed.append("retire")

    def fake_apply(root: Path, plan: Path) -> Path:
        """Record the saved-plan application stage."""
        observed.append("apply")
        return plan

    def fake_enrollment(
        tailscale: TailscaleClient,
        *,
        service_tag: str,
        retired_device_ids: Sequence[str],
        root: Path,
        environment_policy: Path,
        timeout_seconds: float = 600.0,
    ) -> TailscaleDevice:
        """Verify new-device enrollment inputs and return a healthy machine."""
        assert service_tag == SERVICE_TAG
        assert tuple(retired_device_ids) == old_ids
        assert root == bootstrap_paths[0]
        assert environment_policy == bootstrap_paths[1]
        observed.append("verify")
        return _device("new-device")

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._retire_bootstrap_devices", fake_retirement
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.apply_opentofu_inherited", fake_apply
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._await_bootstrap_device", fake_enrollment
    )
    result = apply_machine_bootstrap_inherited(
        root,
        policy,
        plan,
        expected_plan_sha256=machine_bootstrap_plan_sha256(plan),
        expected_service_tag=SERVICE_TAG,
    )
    assert observed == ["retire", "apply", "verify"]
    assert result.id == "new-device"
    client.list_devices.assert_called_once()


def test_apply_aborts_before_opentofu_when_retirement_fails(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Prevent OpenTofu apply after an unsuccessful Tailscale retirement."""
    root, policy, plan = bootstrap_paths
    _patch_plan(monkeypatch)
    client = _client_with_devices(_device("old-device"))
    _patch_client(monkeypatch, client)
    failed_retirement = MagicMock(side_effect=TailscaleError("Retirement failed"))
    fake_apply = MagicMock()
    fake_enrollment = MagicMock()
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._retire_bootstrap_devices", failed_retirement
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.apply_opentofu_inherited", fake_apply
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._await_bootstrap_device", fake_enrollment
    )
    with pytest.raises(TailscaleError, match="Retirement failed"):
        apply_machine_bootstrap_inherited(
            root,
            policy,
            plan,
            expected_plan_sha256=machine_bootstrap_plan_sha256(plan),
            expected_service_tag=SERVICE_TAG,
        )
    failed_retirement.assert_called_once()
    fake_apply.assert_not_called()
    fake_enrollment.assert_not_called()


def test_apply_does_not_verify_enrollment_after_opentofu_failure(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Stop after failed OpenTofu apply without claiming a new machine."""
    root, policy, plan = bootstrap_paths
    _patch_plan(monkeypatch)
    client = _client_with_devices(_device("old-device"))
    _patch_client(monkeypatch, client)
    fake_retirement = MagicMock()
    failed_apply = MagicMock(side_effect=OpenTofuError("OpenTofu apply failed"))
    fake_enrollment = MagicMock()
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._retire_bootstrap_devices", fake_retirement
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.apply_opentofu_inherited", failed_apply
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._await_bootstrap_device", fake_enrollment
    )
    with pytest.raises(OpenTofuError, match="OpenTofu apply failed"):
        apply_machine_bootstrap_inherited(
            root,
            policy,
            plan,
            expected_plan_sha256=machine_bootstrap_plan_sha256(plan),
            expected_service_tag=SERVICE_TAG,
        )
    fake_retirement.assert_called_once()
    failed_apply.assert_called_once_with(root, plan)
    fake_enrollment.assert_not_called()


# ---------------------------------------------------------------------------
# Enrollment and SSH verification
# ---------------------------------------------------------------------------


def test_enrollment_times_out_when_new_device_never_appears(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Require a fresh registration after retirement or provisioning."""
    root, policy, _ = bootstrap_paths
    client = _client_with_devices()
    _patch_ssh_environment(monkeypatch)
    fake_ssh = MagicMock()
    monkeypatch.setattr("mxm.control.machine_bootstrap._bootstrap_ssh_ready", fake_ssh)
    with pytest.raises(MachineBootstrapError, match="Timed out waiting"):
        _await_bootstrap_device(
            cast("TailscaleClient", client),
            service_tag=SERVICE_TAG,
            retired_device_ids=["old-device"],
            root=root,
            environment_policy=policy,
            timeout_seconds=0.0,
        )
    client.list_devices.assert_called_once()
    fake_ssh.assert_not_called()


def test_enrollment_excludes_retired_ids(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Never accept a previous registration as proof of replacement."""
    root, policy, _ = bootstrap_paths
    client = _client_with_devices(_device("old-device"))
    _patch_ssh_environment(monkeypatch)
    fake_ssh = MagicMock()
    monkeypatch.setattr("mxm.control.machine_bootstrap._bootstrap_ssh_ready", fake_ssh)
    with pytest.raises(MachineBootstrapError, match="Timed out waiting"):
        _await_bootstrap_device(
            cast("TailscaleClient", client),
            service_tag=SERVICE_TAG,
            retired_device_ids=["old-device"],
            root=root,
            environment_policy=policy,
            timeout_seconds=0.0,
        )
    fake_ssh.assert_not_called()


def test_enrollment_rejects_multiple_new_devices(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Reject ambiguous singleton enrollment before attempting SSH."""
    root, policy, _ = bootstrap_paths
    client = _client_with_devices(_device("new-1"), _device("new-2"))
    _patch_ssh_environment(monkeypatch)
    fake_ssh = MagicMock()
    monkeypatch.setattr("mxm.control.machine_bootstrap._bootstrap_ssh_ready", fake_ssh)
    with pytest.raises(MachineBootstrapError, match="Multiple new Tailscale"):
        _await_bootstrap_device(
            cast("TailscaleClient", client),
            service_tag=SERVICE_TAG,
            retired_device_ids=[],
            root=root,
            environment_policy=policy,
        )
    fake_ssh.assert_not_called()


def test_enrollment_rejects_machine_without_ssh(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """A connected registration alone does not satisfy the L1 postcondition."""
    root, policy, _ = bootstrap_paths
    client = _client_with_devices(_device("new-device"))
    _patch_ssh_environment(monkeypatch)
    fake_ssh = MagicMock(return_value=False)
    monkeypatch.setattr("mxm.control.machine_bootstrap._bootstrap_ssh_ready", fake_ssh)
    with pytest.raises(MachineBootstrapError, match="Timed out waiting"):
        _await_bootstrap_device(
            cast("TailscaleClient", client),
            service_tag=SERVICE_TAG,
            retired_device_ids=[],
            root=root,
            environment_policy=policy,
            timeout_seconds=0.0,
        )
    fake_ssh.assert_called_once()


def test_enrollment_requires_control_plane_connection(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Do not attempt SSH while a new device remains disconnected."""
    root, policy, _ = bootstrap_paths
    client = _client_with_devices(_device("new-device", connected=False))
    _patch_ssh_environment(monkeypatch)
    fake_ssh = MagicMock()
    monkeypatch.setattr("mxm.control.machine_bootstrap._bootstrap_ssh_ready", fake_ssh)
    with pytest.raises(MachineBootstrapError, match="Timed out waiting"):
        _await_bootstrap_device(
            cast("TailscaleClient", client),
            service_tag=SERVICE_TAG,
            retired_device_ids=[],
            root=root,
            environment_policy=policy,
            timeout_seconds=0.0,
        )
    fake_ssh.assert_not_called()


def test_enrollment_succeeds_for_new_connected_ssh_device(
    monkeypatch: pytest.MonkeyPatch,
    bootstrap_paths: tuple[Path, Path, Path],
) -> None:
    """Accept a new exact-tag registration after successful Tailscale SSH."""
    root, policy, _ = bootstrap_paths
    device = _device("new-device")
    client = _client_with_devices(device)
    _patch_ssh_environment(monkeypatch)
    fake_ssh = MagicMock(return_value=True)
    monkeypatch.setattr("mxm.control.machine_bootstrap._bootstrap_ssh_ready", fake_ssh)
    result = _await_bootstrap_device(
        cast("TailscaleClient", client),
        service_tag=SERVICE_TAG,
        retired_device_ids=["old-device"],
        root=root,
        environment_policy=policy,
        timeout_seconds=0.0,
    )
    assert result == device
    fake_ssh.assert_called_once_with(device.name, {})


def test_ssh_ready_executes_tailscale_ssh_as_mxm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the enrolled Tailscale device name and the mxm SSH account."""
    fake_run = MagicMock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr("mxm.control.machine_bootstrap.subprocess.run", fake_run)
    assert _bootstrap_ssh_ready("new-device.tailnet.ts.net", {}) is True
    args = fake_run.call_args
    assert args.args[0] == ["tailscale", "ssh", "mxm@new-device.tailnet.ts.net", "true"]
    assert args.kwargs["timeout"] == 20
    assert args.kwargs["env"] == {}


def test_ssh_ready_reports_command_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Treat a nonzero Tailscale SSH exit status as not yet reachable."""
    fake_run = MagicMock(return_value=subprocess.CompletedProcess([], 255))
    monkeypatch.setattr("mxm.control.machine_bootstrap.subprocess.run", fake_run)
    assert _bootstrap_ssh_ready("new-device.tailnet.ts.net", {}) is False
