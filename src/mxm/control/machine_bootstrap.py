"""Plan, preflight, and apply bootstrap for named singleton machines.

OpenTofu provisions a Hetzner VM and a fresh, single-use Tailscale enrollment
key. First-boot enrollment establishes the machine's management identity.

Each singleton exclusively owns its Tailscale service tag. Replacement retires
all existing registrations carrying that tag, applies the reviewed saved plan,
and verifies that the replacement is reachable using Tailscale SSH.

Fleet provisioning and application-service restoration are outside this L1
mechanism. Saved plans can contain secrets and must never be logged.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from mxm.control.credentials import (
    CredentialError,
    filter_environment,
    load_credentials,
    load_environment_policy,
    run_with_credentials,
)
from mxm.control.opentofu import (
    OpenTofuError,
    _existing_plan_path,
    _validated_root,
    apply_opentofu_inherited,
    plan_opentofu,
)
from mxm.control.tailscale import (
    TailscaleClient,
    TailscaleDevice,
    TailscaleError,
    devices_with_tag,
)


class MachineBootstrapError(RuntimeError):
    """Raised when planning, preflight, or bootstrap execution fails."""


@dataclass(frozen=True, slots=True)
class MachineBootstrapPlan:
    """Validated machine and enrollment-key changes in a saved plan.

    Attributes:
        server_address: OpenTofu address of the created or replaced machine.
        server_actions: Planned machine lifecycle actions.
        key_address: OpenTofu address of its enrollment key.
        key_actions: Planned enrollment-key lifecycle actions.
        service_tag: Exact Tailscale tag assigned to the new machine.
    """

    server_address: str
    server_actions: tuple[str, ...]
    key_address: str
    key_actions: tuple[str, ...]
    service_tag: str


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def _resource_creation(
    raw_change: object,
) -> tuple[str, str | None, bool] | None:
    """Extract a managed resource's type, address and creation status.

    The planner examines Hetzner server resources and Tailscale enrollment
    key resources. Other resource types are outside the bootstrap
    coordination decision.

    Args:
        raw_change: An entry from OpenTofu's resource_changes array.

    Returns:
        Resource type, optional address and creation flag, or None for
        resources outside the relevant managed types.

    Raises:
        MachineBootstrapError: If a relevant resource change is malformed.
    """
    if not isinstance(raw_change, dict):
        raise MachineBootstrapError("OpenTofu plan has malformed resource change")

    change = cast("dict[str, object]", raw_change)

    if change.get("mode") != "managed":
        return None

    resource_type = change.get("type")

    if resource_type not in (
        "hcloud_server",
        "tailscale_tailnet_key",
    ):
        return None

    details = change.get("change")

    if not isinstance(details, dict):
        raise MachineBootstrapError("OpenTofu plan has malformed change details")

    actions = cast("dict[str, object]", details).get("actions")

    if not isinstance(actions, list):
        raise MachineBootstrapError("OpenTofu plan has malformed resource actions")

    typed_actions = cast("list[object]", actions)

    if not all(isinstance(action, str) for action in typed_actions):
        raise MachineBootstrapError("OpenTofu plan has malformed resource actions")

    address = change.get("address")

    if resource_type == "tailscale_tailnet_key" and (
        not isinstance(address, str) or not address
    ):
        raise MachineBootstrapError("Tailscale key has no valid resource address")

    return (
        str(resource_type),
        address if isinstance(address, str) else None,
        "create" in typed_actions,
    )


def _key_to_replace(plan: dict[str, object]) -> str | None:
    """Identify enrollment authority requiring renewal for machine creation.

    A new Hetzner VM requires a fresh Tailscale enrollment credential.

    If the OpenTofu plan already creates a Tailscale key, no additional
    replacement is necessary. Otherwise, exactly one existing enrollment
    key resource must be available for replacement.

    Args:
        plan: Decoded OpenTofu plan JSON.

    Returns:
        The address of the enrollment key to replace, or None when the
        plan already provides the required enrollment authority or does
        not create a VM.

    Raises:
        MachineBootstrapError: If the plan is malformed or enrollment
            authority cannot be identified unambiguously.
    """
    raw_changes = plan.get("resource_changes", [])

    if not isinstance(raw_changes, list):
        raise MachineBootstrapError("OpenTofu plan has invalid resource_changes")

    raw_changes = cast("list[object]", raw_changes)

    changes = [
        change
        for raw_change in raw_changes
        if (change := _resource_creation(raw_change)) is not None
    ]

    server_creation = any(
        resource_type == "hcloud_server" and creates
        for resource_type, _, creates in changes
    )

    keys = [
        (address, creates)
        for resource_type, address, creates in changes
        if resource_type == "tailscale_tailnet_key"
    ]

    if not server_creation or any(creates for _, creates in keys):
        return None

    if len(keys) != 1:
        raise MachineBootstrapError(
            "VM creation requires exactly one tailscale_tailnet_key in this root"
        )

    return keys[0][0]


def plan_machine_bootstrap(
    root: Path,
    environment_policy: Path,
    plan: Path,
) -> Path:
    """Create a saved machine-bootstrap plan with enrollment authority.

    The initial OpenTofu plan establishes the required infrastructure
    changes. When a Hetzner VM will be created, the planner ensures that
    the final plan also creates fresh Tailscale enrollment authority.

    The saved plan remains an ordinary OpenTofu plan, suitable for review
    and application using the established OpenTofu execution mechanism.

    Args:
        root: OpenTofu root containing the VM and enrollment key.
        environment_policy: Operator environment-filtering policy.
        plan: New path for the saved OpenTofu plan.

    Returns:
        Path to the final saved OpenTofu plan.

    Raises:
        MachineBootstrapError: If planning, credential execution or
            plan inspection fails.

    Note:
        Saved plans can contain transient enrollment credentials.
        Plans must remain private and their JSON contents must not
        be logged or printed.
    """
    try:
        final_plan = plan_opentofu(root, environment_policy, plan)
    except OpenTofuError as exc:
        raise MachineBootstrapError(str(exc)) from exc

    try:
        root_path = root.expanduser().resolve(strict=True)

        key_address = _key_to_replace(
            _show_plan(root_path, final_plan, environment_policy)
        )

        if key_address is None:
            return final_plan

        # Produce the final plan with fresh enrollment authority.
        final_plan.unlink()

        returncode = run_with_credentials(
            [
                "tofu",
                f"-chdir={root_path}",
                "plan",
                "-input=false",
                f"-replace={key_address}",
                f"-out={final_plan}",
            ],
            stack=root_path,
            environment_policy=environment_policy,
            restrictive_umask=True,
        )

        if returncode != 0:
            raise MachineBootstrapError(
                f"OpenTofu machine-bootstrap plan failed with exit status {returncode}"
            )

        mode = final_plan.lstat().st_mode

        if not stat.S_ISREG(mode):
            raise MachineBootstrapError("OpenTofu did not produce a regular plan file")

        final_plan.chmod(0o600)

        return final_plan

    except (CredentialError, OSError, MachineBootstrapError) as exc:
        final_plan.unlink(missing_ok=True)

        if isinstance(exc, MachineBootstrapError):
            raise

        raise MachineBootstrapError(
            "Unable to generate machine-bootstrap plan"
        ) from exc


# ---------------------------------------------------------------------------
# Saved-plan inspection
# ---------------------------------------------------------------------------


def _show_plan(
    root: Path,
    plan: Path,
    environment_policy: Path,
) -> dict[str, object]:
    """Read a saved OpenTofu plan as JSON.

    Plan inspection uses the filtered operator environment without injecting
    provider credentials. The resulting JSON is retained in process memory.

    Args:
        root: OpenTofu root directory.
        plan: Existing saved OpenTofu plan.
        environment_policy: Operator environment-filtering policy.

    Returns:
        Decoded OpenTofu plan as a dictionary.

    Raises:
        MachineBootstrapError: If plan inspection or decoding fails.
    """
    try:
        environment = filter_environment(
            os.environ,
            load_environment_policy(environment_policy),
        )

        result = subprocess.run(
            ["tofu", f"-chdir={root}", "show", "-json", str(plan)],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
    except (CredentialError, OSError) as exc:
        raise MachineBootstrapError("Unable to inspect saved OpenTofu plan") from exc

    if result.returncode != 0:
        raise MachineBootstrapError(
            f"OpenTofu plan inspection failed with exit status {result.returncode}"
        )

    try:
        decoded: object = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise MachineBootstrapError("OpenTofu returned invalid plan JSON") from exc

    if not isinstance(decoded, dict):
        raise MachineBootstrapError("OpenTofu plan JSON must be an object")

    return cast("dict[str, object]", decoded)


def _bootstrap_change(
    raw: object,
) -> tuple[str, str, tuple[str, ...], dict[str, object]] | None:
    """Extract a managed machine or enrollment-key resource change.

    Ignore unrelated resources and data sources; validate relevant changes.

    Args:
        raw: One entry from the OpenTofu resource_changes array.

    Returns:
        Resource type, address, actions, and details, or None if unrelated.

    Raises:
        MachineBootstrapError: If the resource change is malformed.
    """
    if not isinstance(raw, dict):
        raise MachineBootstrapError(
            "Machine-bootstrap plan contains an invalid resource"
        )

    resource = cast("dict[str, object]", raw)

    if resource.get("mode") != "managed":
        return None

    resource_type = resource.get("type")

    if resource_type not in ("hcloud_server", "tailscale_tailnet_key"):
        return None

    address = resource.get("address")
    details = resource.get("change")

    if not isinstance(address, str) or not address:
        raise MachineBootstrapError("Machine-bootstrap resource has no valid address")

    if not isinstance(details, dict):
        raise MachineBootstrapError(
            "Machine-bootstrap resource has invalid change details"
        )

    typed_details = cast("dict[str, object]", details)
    raw_actions = typed_details.get("actions")

    if not isinstance(raw_actions, list):
        raise MachineBootstrapError("Machine-bootstrap resource has invalid actions")

    actions = cast("list[object]", raw_actions)

    if not actions or not all(isinstance(action, str) for action in actions):
        raise MachineBootstrapError("Machine-bootstrap resource has invalid actions")

    return (
        str(resource_type),
        address,
        tuple(cast("list[str]", actions)),
        typed_details,
    )


def _bootstrap_service_tag(details: dict[str, object]) -> str:
    """Extract the single service tag declared by a planned enrollment key.

    Args:
        details: OpenTofu change details for the enrollment key.

    Returns:
        Exact Tailscale service tag.

    Raises:
        MachineBootstrapError: If tags are missing, ambiguous, or invalid.
    """
    after = details.get("after")

    if not isinstance(after, dict):
        raise MachineBootstrapError(
            "Tailscale enrollment key has no planned configuration"
        )

    raw_tags = cast("dict[str, object]", after).get("tags")

    if not isinstance(raw_tags, list):
        raise MachineBootstrapError(
            "Tailscale enrollment key must declare exactly one tag"
        )

    tags = cast("list[object]", raw_tags)

    if len(tags) != 1 or not isinstance(tags[0], str):
        raise MachineBootstrapError(
            "Tailscale enrollment key must declare exactly one tag"
        )

    tag = tags[0]

    if re.fullmatch(r"tag:[A-Za-z0-9][A-Za-z0-9_-]*", tag) is None:
        raise MachineBootstrapError(
            "Tailscale enrollment key has an invalid service tag"
        )

    return tag


def inspect_machine_bootstrap_plan(
    document: dict[str, object],
) -> MachineBootstrapPlan:
    """Validate machine creation and its fresh Tailscale enrollment key.

    Require exactly one managed Hetzner server and one enrollment key,
    both being created or replaced, with a single explicit service tag.

    Args:
        document: Decoded JSON from ``tofu show -json``.

    Returns:
        Validated machine-bootstrap plan metadata.

    Raises:
        MachineBootstrapError: If the machine, key, or service identity
            cannot be identified unambiguously.
    """
    raw_changes = document.get("resource_changes")

    if not isinstance(raw_changes, list):
        raise MachineBootstrapError(
            "Machine-bootstrap plan has invalid resource changes"
        )

    servers: list[tuple[str, tuple[str, ...]]] = []
    keys: list[tuple[str, tuple[str, ...], str]] = []

    for raw in cast("list[object]", raw_changes):
        change = _bootstrap_change(raw)

        if change is None:
            continue

        resource_type, address, actions, details = change

        if resource_type == "hcloud_server":
            servers.append((address, actions))
        else:
            keys.append(
                (
                    address,
                    actions,
                    _bootstrap_service_tag(details),
                )
            )

    if len(servers) != 1:
        raise MachineBootstrapError(
            "Machine bootstrap requires exactly one hcloud_server"
        )

    if len(keys) != 1:
        raise MachineBootstrapError(
            "Machine bootstrap requires exactly one tailscale_tailnet_key"
        )

    server_address, server_actions = servers[0]
    key_address, key_actions, service_tag = keys[0]

    creation_actions = {
        ("create",),
        ("delete", "create"),
        ("create", "delete"),
    }

    if server_actions not in creation_actions:
        raise MachineBootstrapError(
            "Machine bootstrap requires a server creation or replacement"
        )

    if key_actions not in creation_actions:
        raise MachineBootstrapError(
            "Machine bootstrap requires fresh enrollment-key creation"
        )

    return MachineBootstrapPlan(
        server_address=server_address,
        server_actions=server_actions,
        key_address=key_address,
        key_actions=key_actions,
        service_tag=service_tag,
    )


def validate_machine_bootstrap_apply_plan(
    document: dict[str, object],
) -> MachineBootstrapPlan:
    """Validate an OpenTofu plan for a controlled machine replacement.

    Require the machine and its enrollment key to be the only managed
    resources undergoing changes. Other managed resources may be present,
    but must have no-op actions.

    Args:
        document: Decoded JSON from ``tofu show -json``.

    Returns:
        Validated singleton-machine and enrollment-key changes.

    Raises:
        MachineBootstrapError: If any unrelated managed resource is changing.
    """
    inspection = inspect_machine_bootstrap_plan(document)
    permitted = {
        inspection.server_address,
        inspection.key_address,
    }

    raw_changes = document["resource_changes"]

    for raw in cast("list[object]", raw_changes):
        if not isinstance(raw, dict):
            raise MachineBootstrapError("Invalid resource in machine-bootstrap plan")

        resource = cast("dict[str, object]", raw)

        if resource.get("mode") != "managed":
            continue

        if resource.get("address") in permitted:
            continue

        details = resource.get("change")

        if not isinstance(details, dict):
            raise MachineBootstrapError(
                "Unrecognised resource change in machine-bootstrap plan"
            )

        actions = cast("dict[str, object]", details).get("actions")

        if actions != ["no-op"]:
            raise MachineBootstrapError(
                "Machine-bootstrap plan modifies an unrelated resource: "
                f"{resource.get('address')}"
            )

    return inspection


def machine_bootstrap_plan_sha256(plan: Path) -> str:
    """Calculate the SHA-256 digest of an existing saved OpenTofu plan.

    Hash the plan without displaying its potentially sensitive contents.

    Args:
        plan: Existing saved OpenTofu plan.

    Returns:
        Hexadecimal SHA-256 digest.

    Raises:
        MachineBootstrapError: If the plan cannot be read.
    """
    plan_path = _existing_plan_path(plan)

    try:
        with plan_path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise MachineBootstrapError(
            "Unable to calculate saved machine-bootstrap plan digest"
        ) from exc


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


def preflight_machine_bootstrap_credentials(
    root: Path,
    environment_policy: Path,
    plan: Path,
) -> Path:
    """Inspect a machine-bootstrap plan and discover retirement candidates.

    Validate the saved OpenTofu plan, derive its Tailscale service tag,
    and invoke a credential-bound worker for read-only device discovery.

    No Tailscale registrations or infrastructure resources are modified.

    Args:
        root: OpenTofu root containing the singleton machine.
        environment_policy: Operator environment-filtering policy.
        plan: Existing saved machine-bootstrap plan.

    Returns:
        Saved plan path after successful preflight.

    Raises:
        MachineBootstrapError: If plan inspection or device discovery fails.
    """
    try:
        root_path = _validated_root(root)
        plan_path = _existing_plan_path(plan)

        inspection = validate_machine_bootstrap_apply_plan(
            _show_plan(root_path, plan_path, environment_policy)
        )

        print(
            "PLAN      "
            f"{inspection.server_address} "
            f"{','.join(inspection.server_actions)}",
            flush=True,
        )
        print(
            f"KEY       {inspection.key_address} {','.join(inspection.key_actions)}",
            flush=True,
        )
        print(
            f"TAG       {inspection.service_tag}",
            flush=True,
        )

        returncode = run_with_credentials(
            [
                sys.executable,
                "-m",
                "mxm.control.machine_bootstrap",
                "preflight",
                "--root",
                str(root_path),
                "--plan",
                str(plan_path),
                "--service-tag",
                inspection.service_tag,
            ],
            stack=root_path,
            environment_policy=environment_policy,
            restrictive_umask=True,
        )

    except (CredentialError, OpenTofuError) as exc:
        raise MachineBootstrapError(
            f"Machine-bootstrap credential preflight failed: {exc}"
        ) from exc

    if returncode != 0:
        raise MachineBootstrapError(
            f"Machine-bootstrap credential worker failed with exit status {returncode}"
        )

    return plan_path


def _credential_preflight_worker(
    root: Path,
    plan: Path,
    *,
    service_tag: str,
) -> None:
    """Discover Tailscale devices matching the planned service identity.

    Execute inside the credential-bound worker using resolved OAuth
    credentials. Report exact retirement candidates without removing
    them or invoking OpenTofu apply.

    Args:
        root: OpenTofu root containing the singleton machine.
        plan: Existing saved machine-bootstrap plan.
        service_tag: Planned singleton service identity.
    """
    _validated_root(root)
    _existing_plan_path(plan)

    with TailscaleClient.from_environment() as tailscale:
        devices = tailscale.list_devices()

    matching = devices_with_tag(devices, service_tag)

    print(f"DEVICES   {len(devices)} registered")
    print(f"MATCHES   {len(matching)} for {service_tag}")

    for device in matching:
        if device.connected_to_control is True:
            status = "connected"
        elif device.connected_to_control is False:
            status = "disconnected"
        else:
            status = "unknown"

        print(f"  {device.id}\t{device.name!r}\t{status}")

    if not matching:
        print(
            "NOTICE    No tagged devices found; "
            "confirm existing registrations before cutover."
        )


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def apply_machine_bootstrap(
    root: Path,
    environment_policy: Path,
    plan: Path,
) -> Path:
    """Apply a saved singleton-machine plan through a credential-bound worker.

    Validate the plan without provider credentials, then execute retirement,
    OpenTofu apply, and SSH verification with stack-declared credentials.

    Args:
        root: OpenTofu root containing the singleton machine.
        environment_policy: Operator environment-filtering policy.
        plan: Existing saved OpenTofu plan.

    Returns:
        The saved plan path after successful machine bootstrap.

    Raises:
        MachineBootstrapError: If plan validation or worker execution fails.
    """
    try:
        root_path = _validated_root(root)
        plan_path = _existing_plan_path(plan)

        inspection = validate_machine_bootstrap_apply_plan(
            _show_plan(root_path, plan_path, environment_policy)
        )

        digest = machine_bootstrap_plan_sha256(plan_path)

        command = [
            sys.executable,
            "-m",
            "mxm.control.machine_bootstrap",
            "apply",
            "--root",
            str(root_path),
            "--environment-policy",
            str(environment_policy),
            "--plan",
            str(plan_path),
            "--service-tag",
            inspection.service_tag,
            "--expected-plan-sha256",
            digest,
        ]

        returncode = run_with_credentials(
            command,
            stack=root_path,
            environment_policy=environment_policy,
            restrictive_umask=True,
        )

    except (CredentialError, OpenTofuError) as exc:
        raise MachineBootstrapError(f"Machine-bootstrap apply failed: {exc}") from exc

    if returncode != 0:
        raise MachineBootstrapError(
            f"Machine-bootstrap apply worker failed with exit status {returncode}"
        )

    return plan_path


def _retire_bootstrap_devices(
    tailscale: TailscaleClient,
    service_tag: str,
    expected_device_ids: Sequence[str],
) -> None:
    """Retire the discovered registrations for a singleton service tag.

    Re-read the inventory immediately before deletion and refuse to proceed
    if registrations have changed. Verify removal before returning.

    Args:
        tailscale: Authenticated Tailscale API client.
        service_tag: Exclusive Tailscale identity of the singleton machine.
        expected_device_ids: Device IDs discovered at apply start.

    Raises:
        MachineBootstrapError: If the inventory changes or retirement times out.
        TailscaleError: If API discovery or deletion fails.
    """
    expected = tuple(expected_device_ids)

    if len(set(expected)) != len(expected) or any(not item for item in expected):
        raise MachineBootstrapError(
            "Discovered retirement device IDs must be unique and non-empty"
        )

    matching = devices_with_tag(
        tailscale.list_devices(),
        service_tag,
    )

    actual = {device.id for device in matching}

    if actual != set(expected):
        raise MachineBootstrapError(
            "Tailscale retirement candidates changed during discovery: "
            f"expected {sorted(expected)}, observed {sorted(actual)}"
        )

    for device in matching:
        print(f"RETIRE    {device.id} {device.name}", flush=True)
        tailscale.delete_device(device.id)

    deadline = time.monotonic() + 60.0

    while True:
        remaining = devices_with_tag(
            tailscale.list_devices(),
            service_tag,
        )

        if not remaining:
            print("VERIFIED  Previous Tailscale registrations removed", flush=True)
            return

        if any(device.id not in actual for device in remaining):
            raise MachineBootstrapError(
                "Unexpected Tailscale registration appeared during retirement"
            )

        if time.monotonic() >= deadline:
            raise MachineBootstrapError(
                "Timed out verifying Tailscale registration retirement"
            )

        time.sleep(3.0)


def _bootstrap_ssh_ready(
    device_name: str,
    environment: dict[str, str],
) -> bool:
    """Check whether a device accepts Tailscale SSH as the mxm user.

    Args:
        device_name: Name reported by the Tailscale API.
        environment: Filtered subprocess environment without provider secrets.

    Returns:
        True when the remote SSH command succeeds.

    Raises:
        MachineBootstrapError: If the local Tailscale SSH client cannot run.
    """
    try:
        result = subprocess.run(
            [
                "tailscale",
                "ssh",
                f"mxm@{device_name}",
                "true",
            ],
            check=False,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        return False
    except OSError as exc:
        raise MachineBootstrapError(
            "Unable to execute Tailscale SSH verification"
        ) from exc

    return result.returncode == 0


def _await_bootstrap_device(
    tailscale: TailscaleClient,
    *,
    service_tag: str,
    retired_device_ids: Sequence[str],
    root: Path,
    environment_policy: Path,
    timeout_seconds: float = 600.0,
) -> TailscaleDevice:
    """Wait for a new matching registration and successful SSH access.

    Exclude retired device IDs and require exactly one new matching device,
    control-plane connectivity, and successful Tailscale SSH.

    Args:
        tailscale: Authenticated Tailscale API client.
        service_tag: Singleton identity declared by the enrollment key.
        retired_device_ids: Registrations observed before replacement.
        root: OpenTofu root containing the machine.
        environment_policy: Operator environment-filtering policy.
        timeout_seconds: Maximum wait for enrollment and SSH.

    Returns:
        The newly registered, SSH-accessible Tailscale device.

    Raises:
        MachineBootstrapError: If registration is ambiguous or times out.
    """
    environment = filter_environment(
        os.environ,
        load_environment_policy(environment_policy),
    )

    # SSH does not require the provider or OAuth credentials used by OpenTofu.
    for name in load_credentials(root):
        environment.pop(name, None)

    environment.pop("TAILSCALE_OAUTH_CLIENT_ID", None)
    environment.pop("TAILSCALE_OAUTH_CLIENT_SECRET", None)

    retired_ids = set(retired_device_ids)
    deadline = time.monotonic() + timeout_seconds

    while True:
        matching = devices_with_tag(
            tailscale.list_devices(),
            service_tag,
        )

        new_devices = [device for device in matching if device.id not in retired_ids]

        if len(new_devices) > 1:
            raise MachineBootstrapError(
                "Multiple new Tailscale registrations match the service tag"
            )

        if new_devices:
            device = new_devices[0]

            if device.connected_to_control is True and _bootstrap_ssh_ready(
                device.name,
                environment,
            ):
                return device

        if time.monotonic() >= deadline:
            raise MachineBootstrapError(
                "Timed out waiting for new Tailscale enrollment and SSH"
            )

        time.sleep(10.0)


def apply_machine_bootstrap_inherited(
    root: Path,
    environment_policy: Path,
    plan: Path,
    *,
    expected_plan_sha256: str,
    expected_service_tag: str,
) -> TailscaleDevice:
    """Replace one singleton machine using inherited provider credentials.

    Revalidate plan identity, retire all existing registrations carrying its
    service tag, apply the saved plan, and verify new Tailscale SSH access.
    OpenBao service installation and restoration are outside this L1 operation.

    Args:
        root: OpenTofu root containing the singleton machine.
        environment_policy: Operator environment-filtering policy.
        plan: Saved OpenTofu machine-bootstrap plan.
        expected_plan_sha256: Digest recorded before entering the worker.
        expected_service_tag: Service identity read from the parent plan.

    Returns:
        Newly enrolled and SSH-accessible Tailscale device.

    Raises:
        MachineBootstrapError: If plan identity or bootstrap verification fails.
        OpenTofuError: If OpenTofu apply fails.
        TailscaleError: If Tailscale operations fail.
    """
    root_path = _validated_root(root)
    plan_path = _existing_plan_path(plan)

    if machine_bootstrap_plan_sha256(plan_path) != expected_plan_sha256:
        raise MachineBootstrapError(
            "Saved machine-bootstrap plan differs from the approved digest"
        )

    document = _show_plan(root_path, plan_path, environment_policy)
    inspection = validate_machine_bootstrap_apply_plan(document)

    if inspection.service_tag != expected_service_tag:
        raise MachineBootstrapError(
            "Saved plan service tag differs from the approved identity"
        )

    with TailscaleClient.from_environment() as tailscale:
        retired_device_ids = tuple(
            device.id
            for device in devices_with_tag(
                tailscale.list_devices(),
                inspection.service_tag,
            )
        )

        _retire_bootstrap_devices(
            tailscale,
            inspection.service_tag,
            retired_device_ids,
        )

        # The saved plan must still be identical after device retirement.
        if machine_bootstrap_plan_sha256(plan_path) != expected_plan_sha256:
            raise MachineBootstrapError(
                "Saved plan changed after Tailscale retirement; "
                "OpenTofu apply has not started"
            )

        print(f"APPLY     {inspection.server_address}", flush=True)

        apply_opentofu_inherited(root_path, plan_path)

        print("WAIT      Replacement Tailscale enrollment and SSH", flush=True)

        replacement = _await_bootstrap_device(
            tailscale,
            service_tag=inspection.service_tag,
            retired_device_ids=retired_device_ids,
            root=root_path,
            environment_policy=environment_policy,
        )

    print(
        f"VERIFIED  {replacement.id} {replacement.name} SSH accessible",
        flush=True,
    )

    return replacement


# ---------------------------------------------------------------------------
# Credential-bound worker
# ---------------------------------------------------------------------------


def _worker_main() -> int:
    """Dispatch credential-bound preflight or machine-bootstrap apply."""
    parser = argparse.ArgumentParser(
        description="MXM credential-bound machine-bootstrap worker."
    )

    parser.add_argument(
        "operation",
        choices=("preflight", "apply"),
    )
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--service-tag", required=True)

    parser.add_argument("--environment-policy", type=Path)
    parser.add_argument("--expected-plan-sha256")

    arguments = parser.parse_args()

    try:
        if arguments.operation == "preflight":
            _credential_preflight_worker(
                arguments.root,
                arguments.plan,
                service_tag=arguments.service_tag,
            )
            print("OK        Machine-bootstrap credential preflight")
            return 0

        if (
            arguments.environment_policy is None
            or arguments.expected_plan_sha256 is None
        ):
            parser.error(
                "Machine-bootstrap apply requires an environment policy "
                "and a plan digest"
            )

        apply_machine_bootstrap_inherited(
            arguments.root,
            arguments.environment_policy,
            arguments.plan,
            expected_plan_sha256=arguments.expected_plan_sha256,
            expected_service_tag=arguments.service_tag,
        )

    except (
        CredentialError,
        MachineBootstrapError,
        OpenTofuError,
        TailscaleError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("OK        Machine-bootstrap apply completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(_worker_main())
