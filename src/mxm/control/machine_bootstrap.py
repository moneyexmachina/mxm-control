"""Plan MXM machine bootstrap with first-boot Tailscale enrollment.

Machine bootstrap establishes a provisioned Hetzner VM and its initial
authenticated management identity.

OpenTofu manages the infrastructure declaration. Tailscale enrollment is
performed during first boot using a single-use enrollment credential.

The planning operation coordinates their lifecycles:

1. Create an ordinary OpenTofu plan.
2. Identify whether the plan creates a Hetzner VM.
3. Ensure that VM creation includes fresh Tailscale enrollment authority.
4. Save the resulting OpenTofu plan for review and application.

Applying the saved plan and verifying successful enrollment are separate
responsibilities.
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
    """Raised when a machine-bootstrap plan cannot be produced safely."""


@dataclass(frozen=True, slots=True)
class MachineBootstrapPlan:
    """Validated machine and enrollment-key changes in a saved plan.

    Attributes:
        server_address: OpenTofu address of the machine being created.
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


def _bootstrap_change(
    raw: object,
) -> tuple[str, str, tuple[str, ...], dict[str, object]] | None:
    """Extract a managed machine or enrollment-key resource change.

    Ignore unrelated resources and data sources. Validate the structure
    of relevant resource changes before returning their attributes.
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


def apply_machine_bootstrap(
    root: Path,
    environment_policy: Path,
    plan: Path,
    *,
    expected_hostname: str,
    recovery_verified: bool,
    confirmation: str,
) -> Path:
    """Launch an explicitly approved, credential-bound machine replacement.

    Validate the saved plan without provider credentials, then execute
    the lifecycle in a Python worker using stack-declared credentials.

    Returns:
        The saved OpenTofu plan path after successful replacement.

    Raises:
        MachineBootstrapError: If approval, validation, or execution fails.
    """
    if not recovery_verified:
        raise MachineBootstrapError(
            "Verified recovery material must be acknowledged before replacement"
        )

    try:
        root_path = _validated_root(root)
        plan_path = _existing_plan_path(plan)

        inspection = validate_machine_bootstrap_apply_plan(
            _show_plan(root_path, plan_path, environment_policy)
        )

        required_confirmation = f"REBUILD {inspection.server_address}"

        if confirmation != required_confirmation:
            raise MachineBootstrapError(
                f"Machine replacement requires confirmation: {required_confirmation}"
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
            "--expected-hostname",
            expected_hostname,
            "--confirmation",
            confirmation,
            "--recovery-verified",
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


def _bootstrap_service_tag(details: dict[str, object]) -> str:
    """Extract exactly one valid service tag from a planned enrollment key."""
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


def machine_bootstrap_plan_sha256(plan: Path) -> str:
    """Calculate the SHA-256 digest of an existing saved OpenTofu plan.

    Hash the plan without printing its potentially sensitive contents.
    """
    plan_path = _existing_plan_path(plan)

    try:
        with plan_path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise MachineBootstrapError(
            "Unable to calculate saved machine-bootstrap plan digest"
        ) from exc


def validate_machine_bootstrap_apply_plan(
    document: dict[str, object],
) -> MachineBootstrapPlan:
    """Validate an OpenTofu plan for a controlled machine replacement.

    Require the machine and its enrollment key to be the only managed
    resources undergoing changes. Other managed resources may be present,
    but must have no-op actions.

    Returns:
        The inspected machine-bootstrap plan.

    Raises:
        MachineBootstrapError: If additional managed resources are changing.
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


def _retire_bootstrap_devices(
    tailscale: TailscaleClient,
    service_tag: str,
    expected_device_ids: Sequence[str],
) -> None:
    """Retire exactly the approved registrations for one service tag.

    Re-read the live inventory immediately before deletion. Refuse to
    proceed if the exact matching set differs from the approved IDs.
    Verify that the registrations have disappeared before returning.
    """
    expected = tuple(expected_device_ids)

    if len(set(expected)) != len(expected) or any(not item for item in expected):
        raise MachineBootstrapError(
            "Approved retirement device IDs must be unique and non-empty"
        )

    matching = devices_with_tag(
        tailscale.list_devices(),
        service_tag,
    )

    actual = {device.id for device in matching}

    if actual != set(expected):
        raise MachineBootstrapError(
            "Tailscale retirement candidates changed since approval: "
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
    """Check whether the replacement machine accepts Tailscale SSH as mxm."""
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
    expected_hostname: str,
    root: Path,
    environment_policy: Path,
    timeout_seconds: float = 600.0,
) -> TailscaleDevice:
    """Wait for a new matching registration and successful SSH access.

    A previous device ID cannot satisfy the enrollment check. Require
    an unambiguous matching registration, the expected machine hostname,
    control-plane connectivity, and successful Tailscale SSH.

    Returns:
        The verified replacement Tailscale device.

    Raises:
        MachineBootstrapError: If enrollment is ambiguous or times out.
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

            hostname_matches = (
                device.name == expected_hostname
                or device.name.startswith(f"{expected_hostname}.")
            )

            if not hostname_matches:
                raise MachineBootstrapError(
                    "New Tailscale registration has an unexpected hostname: "
                    f"{device.name}"
                )

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
    expected_hostname: str,
    recovery_verified: bool,
    confirmation: str,
) -> TailscaleDevice:
    """Replace a machine inside an authorised operator environment.

    Revalidate the saved plan, retire only explicitly approved Tailscale
    registrations, apply the exact saved plan, and verify new enrollment
    and SSH connectivity.

    The recovery acknowledgement covers separately verified service
    recovery material. This operation does not restore application data.
    """
    if not recovery_verified:
        raise MachineBootstrapError(
            "Machine replacement requires verified service recovery material"
        )

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

    required_confirmation = f"REBUILD {inspection.server_address}"

    if confirmation != required_confirmation:
        raise MachineBootstrapError(
            f"Machine replacement requires confirmation: {required_confirmation}"
        )

    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
        expected_hostname,
    ):
        raise MachineBootstrapError("Invalid expected Tailscale hostname")

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
            expected_hostname=expected_hostname,
            root=root_path,
            environment_policy=environment_policy,
        )

    print(
        f"VERIFIED  {replacement.id} {replacement.name} SSH accessible",
        flush=True,
    )

    return replacement


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
        The decoded OpenTofu plan as a dictionary.

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

    The resulting saved plan is an ordinary OpenTofu plan and can be
    reviewed and applied using the established OpenTofu execution
    mechanism.

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


def preflight_machine_bootstrap_credentials(
    root: Path,
    environment_policy: Path,
    plan: Path,
) -> Path:
    """Inspect a machine-bootstrap plan and discover retirement candidates.

    Validate the saved OpenTofu plan, derive its Tailscale service tag,
    and invoke a credential-bound worker for read-only device discovery.

    No Tailscale registrations or infrastructure resources are modified.
    """
    try:
        root_path = _validated_root(root)
        plan_path = _existing_plan_path(plan)

        inspection = inspect_machine_bootstrap_plan(
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


def _worker_main() -> int:
    """Dispatch read-only preflight or approved machine replacement."""
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
    parser.add_argument("--expected-hostname")
    parser.add_argument("--confirmation")
    parser.add_argument("--recovery-verified", action="store_true")

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
            or arguments.expected_hostname is None
            or arguments.confirmation is None
            or not arguments.recovery_verified
        ):
            parser.error(
                "Machine-bootstrap apply requires environment policy, "
                "plan digest, hostname, confirmation, and recovery approval"
            )

        apply_machine_bootstrap_inherited(
            arguments.root,
            arguments.environment_policy,
            arguments.plan,
            expected_plan_sha256=arguments.expected_plan_sha256,
            expected_service_tag=arguments.service_tag,
            expected_hostname=arguments.expected_hostname,
            recovery_verified=arguments.recovery_verified,
            confirmation=arguments.confirmation,
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
