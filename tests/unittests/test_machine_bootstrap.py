"""Unit tests for MXM machine-bootstrap planning decisions.

Machine bootstrap coordinates Hetzner VM creation with the availability
of fresh Tailscale enrollment authority.

These tests verify resource-change interpretation, enrollment-key
replacement decisions, and validation of OpenTofu plan structures.

All tests operate on representative plan data without invoking OpenTofu,
Proton Pass, Hetzner, or Tailscale.
"""

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


def fake_show_bootstrap_plan(
    root: Path,
    plan: Path,
    environment_policy: Path,
) -> dict[str, object]:
    """Return a valid saved bootstrap plan without invoking OpenTofu."""
    return _bootstrap_plan_document()


def _bootstrap_plan_document(
    *,
    server_actions: tuple[str, ...] = ("delete", "create"),
    key_actions: tuple[str, ...] = ("delete", "create"),
    tag: str = "tag:mxm-security",
) -> dict[str, object]:
    """Construct a saved-plan JSON fixture without sensitive values."""
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
                "address": "tailscale_tailnet_key.security",
                "change": {
                    "actions": list(key_actions),
                    "after": {"tags": [tag]},
                },
            },
        ]
    }


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
    """Identify machine, enrollment key, and exact service tag."""
    result = inspect_machine_bootstrap_plan(
        _bootstrap_plan_document(
            server_actions=server_actions,
            key_actions=key_actions,
        )
    )

    assert result.server_address == "hcloud_server.security"
    assert result.server_actions == server_actions
    assert result.key_address == "tailscale_tailnet_key.security"
    assert result.key_actions == key_actions
    assert result.service_tag == "tag:mxm-security"


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
    """Require fresh machine and enrollment-key creation."""
    with pytest.raises(MachineBootstrapError, match="requires"):
        inspect_machine_bootstrap_plan(
            _bootstrap_plan_document(
                server_actions=server_actions,
                key_actions=key_actions,
            )
        )


@pytest.mark.parametrize(
    "tag",
    [
        "",
        "mxm-security",
        "tag:",
        "tag:mxm security",
        "tag:mxm-security/other",
    ],
)
def test_inspect_rejects_invalid_service_tag(tag: str) -> None:
    """Reject malformed service identity declarations."""
    with pytest.raises(
        MachineBootstrapError,
        match="invalid service tag",
    ):
        inspect_machine_bootstrap_plan(_bootstrap_plan_document(tag=tag))


def test_inspect_rejects_missing_server() -> None:
    """Require a managed machine in the reviewed plan."""
    document: dict[str, object] = {
        "resource_changes": [
            {
                "mode": "managed",
                "type": "tailscale_tailnet_key",
                "address": "tailscale_tailnet_key.security",
                "change": {
                    "actions": ["create"],
                    "after": {"tags": ["tag:mxm-security"]},
                },
            }
        ]
    }

    with pytest.raises(
        MachineBootstrapError,
        match="exactly one hcloud_server",
    ):
        inspect_machine_bootstrap_plan(document)


def test_inspect_rejects_ambiguous_servers() -> None:
    """Never infer which machine is being bootstrapped."""
    document = _bootstrap_plan_document()
    changes = cast("list[object]", document["resource_changes"])

    changes.append(
        {
            "mode": "managed",
            "type": "hcloud_server",
            "address": "hcloud_server.other",
            "change": {"actions": ["create"]},
        }
    )

    with pytest.raises(
        MachineBootstrapError,
        match="exactly one hcloud_server",
    ):
        inspect_machine_bootstrap_plan(document)


def test_inspect_rejects_ambiguous_keys() -> None:
    """Require one authoritative Tailscale enrollment-key resource."""
    document = _bootstrap_plan_document()
    changes = cast("list[object]", document["resource_changes"])

    changes.append(
        {
            "mode": "managed",
            "type": "tailscale_tailnet_key",
            "address": "tailscale_tailnet_key.other",
            "change": {
                "actions": ["create"],
                "after": {"tags": ["tag:other"]},
            },
        }
    )

    with pytest.raises(
        MachineBootstrapError,
        match="exactly one tailscale_tailnet_key",
    ):
        inspect_machine_bootstrap_plan(document)


def test_inspect_rejects_missing_resource_changes() -> None:
    """Require an inspectable resource-change collection."""
    with pytest.raises(
        MachineBootstrapError,
        match="invalid resource changes",
    ):
        inspect_machine_bootstrap_plan({})


def test_credential_worker_reports_exact_tagged_devices(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Report matching registrations without deleting devices."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    client = MagicMock()
    client.__enter__.return_value = client
    client.list_devices.return_value = [
        TailscaleDevice(
            id="1001",
            name="mxm-security.tailnet.ts.net",
            tags=("tag:mxm-security",),
            connected_to_control=True,
        ),
        TailscaleDevice(
            id="1002",
            name="mxm-security-1.tailnet.ts.net",
            tags=("tag:mxm-security",),
            connected_to_control=False,
        ),
        TailscaleDevice(
            id="1003",
            name="mxm-factory-agent.tailnet.ts.net",
            tags=("tag:mxm-factory-agent",),
            connected_to_control=True,
        ),
    ]

    monkeypatch.setattr(
        TailscaleClient,
        "from_environment",
        lambda: client,
    )

    _credential_preflight_worker(
        root,
        plan,
        service_tag="tag:mxm-security",
    )

    output = capsys.readouterr().out

    assert "MATCHES   2 for tag:mxm-security" in output
    assert "1001" in output
    assert "1002" in output
    assert "connected" in output
    assert "disconnected" in output
    assert "1003" not in output

    client.list_devices.assert_called_once_with()
    client.delete_device.assert_not_called()


def _change(
    resource_type: str,
    actions: list[str],
    *,
    address: str | None = None,
    mode: str = "managed",
) -> dict[str, object]:
    """Build a representative OpenTofu resource-change record."""
    result: dict[str, object] = {
        "mode": mode,
        "type": resource_type,
        "change": {"actions": actions},
    }

    if address is not None:
        result["address"] = address

    return result


def _server(*actions: str) -> dict[str, object]:
    """Build a Hetzner server resource-change record."""
    return _change("hcloud_server", list(actions))


def _key(*actions: str, address: str = KEY_ADDRESS) -> dict[str, object]:
    """Build a Tailscale enrollment-key resource-change record."""
    return _change(
        "tailscale_tailnet_key",
        list(actions),
        address=address,
    )


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        pytest.param(
            [],
            None,
            id="empty-plan",
        ),
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
            id="new-server-requires-fresh-key",
        ),
        pytest.param(
            [_server("delete", "create"), _key("no-op")],
            KEY_ADDRESS,
            id="server-replacement-delete-first",
        ),
        pytest.param(
            [_server("create", "delete"), _key("no-op")],
            KEY_ADDRESS,
            id="server-replacement-create-first",
        ),
        pytest.param(
            [_server("delete"), _key("no-op")],
            None,
            id="server-deletion-only",
        ),
        pytest.param(
            [_server("create"), _key("delete", "create")],
            None,
            id="key-already-being-replaced",
        ),
        pytest.param(
            [_server("no-op"), _key("no-op")],
            None,
            id="no-change-reconciliation",
        ),
        pytest.param(
            [
                _server("create"),
                _key("no-op"),
                _key(
                    "create",
                    address="tailscale_tailnet_key.other",
                ),
            ],
            None,
            id="planned-key-creation-satisfies-enrollment-requirement",
        ),
        pytest.param(
            [
                _change(
                    "hcloud_server",
                    ["create"],
                    mode="data",
                ),
                _key("no-op"),
            ],
            None,
            id="ignore-unmanaged-server",
        ),
    ],
)
def test_key_replacement_decision(
    changes: list[object],
    expected: str | None,
) -> None:
    """Select key renewal only when VM creation requires it."""
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
                _key(
                    "no-op",
                    address="tailscale_tailnet_key.extra",
                ),
            ],
            "exactly one tailscale_tailnet_key",
            id="ambiguous-keys",
        ),
        pytest.param(
            [None],
            "malformed resource change",
            id="non-object-record",
        ),
        pytest.param(
            [
                {
                    "mode": "managed",
                    "type": "hcloud_server",
                },
            ],
            "malformed change details",
            id="missing-change-details",
        ),
        pytest.param(
            [
                {
                    "mode": "managed",
                    "type": "hcloud_server",
                    "change": {
                        "actions": ["create", 42],
                    },
                },
            ],
            "malformed resource actions",
            id="non-string-action",
        ),
        pytest.param(
            [
                _server("create"),
                _change(
                    "tailscale_tailnet_key",
                    ["no-op"],
                ),
            ],
            "no valid resource address",
            id="missing-key-address",
        ),
    ],
)
def test_invalid_resource_changes_fail_closed(
    changes: list[object],
    message: str,
) -> None:
    """Reject invalid or ambiguous resource changes."""
    with pytest.raises(MachineBootstrapError, match=message):
        _key_to_replace({"resource_changes": changes})


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "unexpected",
        {"not": "a list"},
    ],
)
def test_invalid_resource_changes_collection(
    invalid: object,
) -> None:
    """Require a list when resource_changes is explicitly provided."""
    with pytest.raises(
        MachineBootstrapError,
        match="invalid resource_changes",
    ):
        _key_to_replace({"resource_changes": invalid})


def test_missing_resource_changes_is_empty_plan() -> None:
    """Treat an absent resource_changes field as an empty change set."""
    assert _key_to_replace({}) is None


def test_preflight_launches_credential_bound_worker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Launch the Python worker through the shared credential runner."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._show_plan",
        fake_show_bootstrap_plan,
    )
    environment_policy = tmp_path / "environment.toml"
    observed: dict[str, object] = {}

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        observed["command"] = command
        observed["stack"] = stack
        observed["environment_policy"] = environment_policy
        observed["restrictive_umask"] = restrictive_umask
        return 0

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fake_run_with_credentials,
    )

    result = preflight_machine_bootstrap_credentials(
        root,
        environment_policy,
        plan,
    )

    assert result == plan
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
            "tag:mxm-security",
        ],
        "stack": root,
        "environment_policy": environment_policy,
        "restrictive_umask": True,
    }


@pytest.mark.parametrize("returncode", [1, 2, 127])
def test_preflight_reports_worker_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    returncode: int,
) -> None:
    """Reject unsuccessful credential-bound worker execution."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._show_plan",
        fake_show_bootstrap_plan,
    )

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        return returncode

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fake_run_with_credentials,
    )

    with pytest.raises(
        MachineBootstrapError,
        match=f"worker failed with exit status {returncode}",
    ):
        preflight_machine_bootstrap_credentials(
            root,
            tmp_path / "environment.toml",
            plan,
        )


def test_preflight_reports_credential_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Translate credential-runner failures into bootstrap failures."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._show_plan",
        fake_show_bootstrap_plan,
    )

    def fail_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        raise CredentialError("Operator credentials unavailable")

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fail_credentials,
    )

    with pytest.raises(
        MachineBootstrapError,
        match="Operator credentials unavailable",
    ):
        preflight_machine_bootstrap_credentials(
            root,
            tmp_path / "environment.toml",
            plan,
        )


def test_preflight_rejects_insecure_plan_before_worker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Validate saved-plan permissions before establishing authority."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o644)

    def unexpected_worker(*args: object, **kwargs: object) -> None:
        pytest.fail("Credential worker must not be launched")

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        unexpected_worker,
    )

    with pytest.raises(
        MachineBootstrapError,
        match="permissions must be owner-only",
    ):
        preflight_machine_bootstrap_credentials(
            root,
            tmp_path / "environment.toml",
            plan,
        )


def test_credential_worker_discovers_tailscale_devices(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify that the inner worker uses resolved OAuth authority."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    client = MagicMock()
    client.__enter__.return_value = client
    client.list_devices.return_value = []

    monkeypatch.setattr(
        TailscaleClient,
        "from_environment",
        lambda: client,
    )

    _credential_preflight_worker(
        root,
        plan,
        service_tag="tag:mxm-security",
    )

    client.list_devices.assert_called_once_with()
    client.delete_device.assert_not_called()
    client.__exit__.assert_called_once()


def test_credential_worker_propagates_tailscale_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Preserve Tailscale authentication and API failures."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    client = MagicMock()
    client.__enter__.return_value = client
    client.list_devices.side_effect = TailscaleError("Device discovery failed")

    monkeypatch.setattr(
        TailscaleClient,
        "from_environment",
        lambda: client,
    )

    with pytest.raises(
        TailscaleError,
        match="Device discovery failed",
    ):
        _credential_preflight_worker(
            root,
            plan,
            service_tag="tag:mxm-security",
        )

    client.delete_device.assert_not_called()
    client.__exit__.assert_called_once()


def test_worker_main_dispatches_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Dispatch the requested worker operation to the Python mechanism."""
    root = tmp_path / "root"
    plan = tmp_path / "reviewed.plan"
    observed: dict[str, object] = {}

    def fake_preflight(
        root: Path,
        plan: Path,
        *,
        service_tag: str,
    ) -> None:
        observed["root"] = root
        observed["plan"] = plan
        observed["service_tag"] = service_tag

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._credential_preflight_worker",
        fake_preflight,
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
            "tag:mxm-security",
        ],
    )

    assert _worker_main() == 0
    assert observed == {
        "root": root,
        "plan": plan,
        "service_tag": "tag:mxm-security",
    }
    assert "OK" in capsys.readouterr().out


def test_worker_main_reports_tailscale_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Return failure without disguising an unsuccessful preflight."""

    def fail_preflight(
        root: Path,
        plan: Path,
        *,
        service_tag: str,
    ) -> None:
        raise TailscaleError("Device discovery failed")

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._credential_preflight_worker",
        fail_preflight,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mxm.control.machine_bootstrap",
            "preflight",
            "--root",
            str(tmp_path / "root"),
            "--plan",
            str(tmp_path / "reviewed.plan"),
            "--service-tag",
            "tag:mxm-security",
        ],
    )

    assert _worker_main() == 1
    assert "Device discovery failed" in capsys.readouterr().err


def test_apply_plan_rejects_unrelated_mutations() -> None:
    """Machine replacement must not change unrelated estate resources."""
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

    with pytest.raises(
        MachineBootstrapError,
        match="unrelated resource",
    ):
        validate_machine_bootstrap_apply_plan(document)


def test_apply_requires_recovery_approval(
    tmp_path: Path,
) -> None:
    """Do not start an apply without an explicit recovery acknowledgement."""
    with pytest.raises(
        MachineBootstrapError,
        match="recovery material",
    ):
        apply_machine_bootstrap(
            tmp_path,
            tmp_path / "environment.toml",
            tmp_path / "plan.tfplan",
            expected_hostname="mxm-security",
            recovery_verified=False,
            confirmation="REBUILD hcloud_server.security",
        )


def test_apply_launches_credential_bound_worker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Pass exact approved machine identity into the credential-bound worker."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    policy = tmp_path / "environment.toml"
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._show_plan",
        fake_show_bootstrap_plan,
    )

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        observed["command"] = command
        observed["stack"] = stack
        observed["policy"] = environment_policy
        observed["umask"] = restrictive_umask
        return 0

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.run_with_credentials",
        fake_run_with_credentials,
    )

    result = apply_machine_bootstrap(
        root,
        policy,
        plan,
        expected_hostname="mxm-security",
        recovery_verified=True,
        confirmation="REBUILD hcloud_server.security",
    )

    assert result == plan

    command = observed["command"]
    assert isinstance(command, list)
    assert command[:4] == [
        sys.executable,
        "-m",
        "mxm.control.machine_bootstrap",
        "apply",
    ]
    assert "--expected-device-id" not in command
    assert "--expected-plan-sha256" in command
    assert machine_bootstrap_plan_sha256(plan) in command
    assert "--recovery-verified" in command
    assert observed["stack"] == root
    assert observed["policy"] == policy
    assert observed["umask"] is True


def test_retirement_rejects_changed_device_inventory() -> None:
    """A newly discovered retirement set requires fresh approval."""
    client = MagicMock()
    client.list_devices.return_value = [
        TailscaleDevice(
            id="unexpected-device",
            name="mxm-security.tailnet.ts.net",
            tags=("tag:mxm-security",),
        )
    ]

    with pytest.raises(
        MachineBootstrapError,
        match="candidates changed",
    ):
        _retire_bootstrap_devices(
            cast("TailscaleClient", client),
            "tag:mxm-security",
            ["approved-device"],
        )

    client.delete_device.assert_not_called()


def test_retirement_deletes_and_verifies_exact_device() -> None:
    """Delete only approved IDs, then verify their disappearance."""
    client = MagicMock()
    client.list_devices.side_effect = [
        [
            TailscaleDevice(
                id="approved-device",
                name="mxm-security.tailnet.ts.net",
                tags=("tag:mxm-security",),
            )
        ],
        [],
    ]

    _retire_bootstrap_devices(
        cast("TailscaleClient", client),
        "tag:mxm-security",
        ["approved-device"],
    )

    client.delete_device.assert_called_once_with("approved-device")
    assert client.list_devices.call_count == 2


def test_apply_inherited_executes_ordered_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Retire registrations before applying, then verify the new machine."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    policy = tmp_path / "environment.toml"
    observed: list[str] = []

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._show_plan",
        fake_show_bootstrap_plan,
    )

    client = MagicMock()
    client.__enter__.return_value = client
    client.list_devices.return_value = [
        TailscaleDevice(
            id="old-device",
            name="mxm-security.tailnet.ts.net",
            tags=("tag:mxm-security",),
            connected_to_control=True,
        ),
    ]

    def fake_client() -> TailscaleClient:
        return cast("TailscaleClient", client)

    def fake_retirement(
        tailscale: TailscaleClient,
        service_tag: str,
        expected_device_ids: Sequence[str],
    ) -> None:
        """Verify that the discovered singleton registration is retired."""
        assert service_tag == "tag:mxm-security"
        assert tuple(expected_device_ids) == ("old-device",)
        observed.append("retire")

    def fake_apply(root: Path, plan: Path) -> Path:
        observed.append("apply")
        return plan

    def fake_enrollment(
        tailscale: TailscaleClient,
        *,
        service_tag: str,
        retired_device_ids: Sequence[str],
        expected_hostname: str,
        root: Path,
        environment_policy: Path,
        timeout_seconds: float = 600.0,
    ) -> TailscaleDevice:
        assert service_tag == "tag:mxm-security"
        assert expected_hostname == "mxm-security"
        observed.append("verify")
        return TailscaleDevice(
            id="new-device",
            name="mxm-security.tailnet.ts.net",
            tags=("tag:mxm-security",),
            connected_to_control=True,
        )

    monkeypatch.setattr(
        TailscaleClient,
        "from_environment",
        fake_client,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._retire_bootstrap_devices",
        fake_retirement,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.apply_opentofu_inherited",
        fake_apply,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._await_bootstrap_device",
        fake_enrollment,
    )

    result = apply_machine_bootstrap_inherited(
        root,
        policy,
        plan,
        expected_plan_sha256=machine_bootstrap_plan_sha256(plan),
        expected_service_tag="tag:mxm-security",
        expected_hostname="mxm-security",
        recovery_verified=True,
        confirmation="REBUILD hcloud_server.security",
    )

    assert observed == ["retire", "apply", "verify"]
    assert result.id == "new-device"


def test_retirement_aborts_when_device_deletion_fails() -> None:
    """Propagate a failed Tailscale deletion without reporting retirement."""
    device = TailscaleDevice(
        id="old-device",
        name="mxm-security.tailnet.ts.net",
        tags=("tag:mxm-security",),
    )

    client = MagicMock()
    client.list_devices.return_value = [device]
    client.delete_device.side_effect = TailscaleError("Device deletion denied")

    with pytest.raises(
        TailscaleError,
        match="Device deletion denied",
    ):
        _retire_bootstrap_devices(
            cast("TailscaleClient", client),
            "tag:mxm-security",
            ["old-device"],
        )

    client.delete_device.assert_called_once_with("old-device")
    client.list_devices.assert_called_once()


def test_retirement_times_out_when_registration_remains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject retirement when the deleted device remains registered."""
    device = TailscaleDevice(
        id="old-device",
        name="mxm-security.tailnet.ts.net",
        tags=("tag:mxm-security",),
    )

    client = MagicMock()
    client.list_devices.return_value = [device]

    calls = 0

    def fake_monotonic() -> float:
        """Advance the clock past the retirement deadline."""
        nonlocal calls
        calls += 1
        return 0.0 if calls == 1 else 61.0

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.time.monotonic",
        fake_monotonic,
    )

    with pytest.raises(
        MachineBootstrapError,
        match="Timed out verifying",
    ):
        _retire_bootstrap_devices(
            cast("TailscaleClient", client),
            "tag:mxm-security",
            ["old-device"],
        )

    client.delete_device.assert_called_once_with("old-device")
    assert client.list_devices.call_count == 2


def test_apply_aborts_before_opentofu_when_retirement_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Never apply OpenTofu after unsuccessful device retirement."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    policy = tmp_path / "environment.toml"

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._show_plan",
        fake_show_bootstrap_plan,
    )

    client = MagicMock()
    client.__enter__.return_value = client

    fake_client = MagicMock(return_value=client)
    fake_retirement = MagicMock(side_effect=TailscaleError("Retirement failed"))
    fake_apply = MagicMock()
    fake_enrollment = MagicMock()

    monkeypatch.setattr(
        TailscaleClient,
        "from_environment",
        fake_client,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._retire_bootstrap_devices",
        fake_retirement,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.apply_opentofu_inherited",
        fake_apply,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._await_bootstrap_device",
        fake_enrollment,
    )

    with pytest.raises(
        TailscaleError,
        match="Retirement failed",
    ):
        apply_machine_bootstrap_inherited(
            root,
            policy,
            plan,
            expected_plan_sha256=machine_bootstrap_plan_sha256(plan),
            expected_service_tag="tag:mxm-security",
            expected_hostname="mxm-security",
            recovery_verified=True,
            confirmation="REBUILD hcloud_server.security",
        )

    fake_retirement.assert_called_once()
    fake_apply.assert_not_called()
    fake_enrollment.assert_not_called()


def test_apply_does_not_verify_enrollment_after_opentofu_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Stop after a failed OpenTofu apply without claiming a new machine."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    policy = tmp_path / "environment.toml"

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._show_plan",
        fake_show_bootstrap_plan,
    )

    client = MagicMock()
    client.__enter__.return_value = client

    fake_client = MagicMock(return_value=client)
    fake_retirement = MagicMock()
    fake_apply = MagicMock(side_effect=OpenTofuError("OpenTofu apply failed"))
    fake_enrollment = MagicMock()

    monkeypatch.setattr(
        TailscaleClient,
        "from_environment",
        fake_client,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._retire_bootstrap_devices",
        fake_retirement,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap.apply_opentofu_inherited",
        fake_apply,
    )
    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._await_bootstrap_device",
        fake_enrollment,
    )

    with pytest.raises(
        OpenTofuError,
        match="OpenTofu apply failed",
    ):
        apply_machine_bootstrap_inherited(
            root,
            policy,
            plan,
            expected_plan_sha256=machine_bootstrap_plan_sha256(plan),
            expected_service_tag="tag:mxm-security",
            expected_hostname="mxm-security",
            recovery_verified=True,
            confirmation="REBUILD hcloud_server.security",
        )

    fake_retirement.assert_called_once()
    fake_apply.assert_called_once_with(root, plan)
    fake_enrollment.assert_not_called()


def test_enrollment_times_out_when_new_device_never_appears(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Require registration of a new device rather than assuming success."""
    client = MagicMock()
    client.list_devices.return_value = []

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

    fake_ssh = MagicMock()

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._bootstrap_ssh_ready",
        fake_ssh,
    )

    with pytest.raises(
        MachineBootstrapError,
        match="Timed out waiting for new Tailscale enrollment and SSH",
    ):
        _await_bootstrap_device(
            cast("TailscaleClient", client),
            service_tag="tag:mxm-security",
            retired_device_ids=["old-device"],
            expected_hostname="mxm-security",
            root=tmp_path,
            environment_policy=tmp_path / "environment.toml",
            timeout_seconds=0.0,
        )

    client.list_devices.assert_called_once()
    fake_ssh.assert_not_called()


def test_enrollment_rejects_machine_when_ssh_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A connected Tailscale registration is insufficient without SSH."""
    device = TailscaleDevice(
        id="new-device",
        name="mxm-security.tailnet.ts.net",
        tags=("tag:mxm-security",),
        connected_to_control=True,
    )

    client = MagicMock()
    client.list_devices.return_value = [device]

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

    fake_ssh = MagicMock(return_value=False)

    monkeypatch.setattr(
        "mxm.control.machine_bootstrap._bootstrap_ssh_ready",
        fake_ssh,
    )

    with pytest.raises(
        MachineBootstrapError,
        match="Timed out waiting for new Tailscale enrollment and SSH",
    ):
        _await_bootstrap_device(
            cast("TailscaleClient", client),
            service_tag="tag:mxm-security",
            retired_device_ids=["old-device"],
            expected_hostname="mxm-security",
            root=tmp_path,
            environment_policy=tmp_path / "environment.toml",
            timeout_seconds=0.0,
        )

    client.list_devices.assert_called_once()
    fake_ssh.assert_called_once()
