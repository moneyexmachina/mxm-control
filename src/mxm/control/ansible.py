"""Generic Ansible reconciliation for MXM estate system configuration.

The estate deployment root supplies the native Ansible inventory and playbook.
Ansible resolves the target and its remote user from the inventory; the control
mechanism uses the existing verified Tailscale SSH connection adapter.

Preview uses Ansible check/diff mode, which predicts changes but does not
produce a saved or immutable execution plan.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import cast

from mxm.control.tailscale_ansible import (
    TailscaleAnsibleError,
    prepare_tailscale_ansible,
    run_ansible,
)

_INVENTORY_TIMEOUT = 30.0

# Prevent estate inventory variables from replacing the verified Tailscale
# SSH transport. Other Ansible variables, including become and the remote
# Python interpreter, remain estate-owned.
_FORBIDDEN_CONNECTION_VARIABLES = frozenset(
    {
        "ansible_ssh_common_args",
        "ansible_ssh_extra_args",
        "ansible_ssh_args",
        "ansible_ssh_executable",
        "ansible_ssh_private_key_file",
        "ansible_private_key_file",
        "ansible_ssh_pass",
        "ansible_password",
        "ansible_ssh_host_key_checking",
        "ansible_host_key_checking",
        "ansible_port",
        "ansible_ssh_port",
    }
)


class AnsibleError(RuntimeError):
    """Raised when an Ansible configuration operation cannot be completed."""


class AnsibleMode(Enum):
    """Execution mode for an estate Ansible deployment."""

    PREVIEW = "preview"
    APPLY = "apply"


@dataclass(frozen=True, slots=True)
class AnsibleDeployment:
    """Validated paths to one estate-defined Ansible deployment.

    Attributes:
        root: Absolute path to the estate deployment directory.
        inventory: Native Ansible inventory file.
        playbook: Native Ansible playbook file.
    """

    root: Path
    inventory: Path
    playbook: Path


@dataclass(frozen=True, slots=True)
class AnsibleTarget:
    """Single machine identity resolved from the estate inventory.

    Attributes:
        inventory_name: Host identifier used by Ansible's --limit option.
        tailscale_host: Peer name supplied to the verified SSH adapter.
        user: Remote Unix account declared by the estate.
    """

    inventory_name: str
    tailscale_host: str
    user: str


def _validated_file(path: Path, *, description: str) -> Path:
    """Require a readable, regular, non-symlinked deployment file.

    Args:
        path: Expected file path.
        description: Name of the file for diagnostic messages.

    Returns:
        The validated file path.

    Raises:
        AnsibleError: If the file is unsuitable or unavailable.
    """
    if path.is_symlink():
        raise AnsibleError(f"{description} must not be a symbolic link: {path}")

    if not path.is_file():
        raise AnsibleError(f"{description} does not exist or is not a file: {path}")

    if not os.access(path, os.R_OK):
        raise AnsibleError(f"{description} is not readable: {path}")

    return path


def _validated_deployment(root: Path) -> AnsibleDeployment:
    """Resolve a deployment root and check its native Ansible files.

    Args:
        root: Directory containing inventory.yml and playbook.yml.

    Returns:
        Absolute validated deployment paths.

    Raises:
        AnsibleError: If the deployment directory or files are unavailable.
    """
    expanded = root.expanduser()

    if expanded.is_symlink():
        raise AnsibleError(
            f"Ansible deployment root must not be a symbolic link: {expanded}"
        )

    try:
        resolved = expanded.resolve(strict=True)
    except OSError as exc:
        raise AnsibleError(
            f"Ansible deployment root does not exist: {expanded}"
        ) from exc

    if not resolved.is_dir():
        raise AnsibleError(f"Ansible deployment root is not a directory: {resolved}")

    if not os.access(resolved, os.R_OK | os.X_OK):
        raise AnsibleError(f"Ansible deployment root is not accessible: {resolved}")

    return AnsibleDeployment(
        root=resolved,
        inventory=_validated_file(
            resolved / "inventory.yml",
            description="Ansible inventory",
        ),
        playbook=_validated_file(
            resolved / "playbook.yml",
            description="Ansible playbook",
        ),
    )


def _load_inventory(inventory: Path) -> dict[str, object]:
    """Ask Ansible to parse and resolve its own inventory format.

    Args:
        inventory: Native Ansible inventory file.

    Returns:
        Parsed inventory document with untrusted values typed as
        objects until they have been validated.

    Raises:
        AnsibleError: If inventory execution fails or returns invalid JSON.
    """
    try:
        result = subprocess.run(
            [
                "ansible-inventory",
                "--inventory",
                str(inventory),
                "--list",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=_INVENTORY_TIMEOUT,
            cwd=inventory.parent,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AnsibleError(f"Unable to run Ansible inventory: {exc}") from exc

    if result.returncode != 0:
        raise AnsibleError(
            f"Ansible inventory failed with exit status {result.returncode}"
        )

    try:
        data: object = json.loads(result.stdout)
    except ValueError as exc:
        raise AnsibleError("Invalid Ansible inventory JSON") from exc

    if not isinstance(data, dict):
        raise AnsibleError("Ansible inventory is not a JSON object")

    return cast("dict[str, object]", data)


def _single_host_variables(
    document: dict[str, object],
) -> tuple[str, dict[str, object]]:
    """Require exactly one host from Ansible's resolved host variables.

    Args:
        document: Parsed output of ansible-inventory --list.

    Returns:
        The inventory hostname and its resolved variables.

    Raises:
        AnsibleError: If the inventory is malformed or has other than one host.
    """
    raw_meta: object = document.get("_meta")

    if not isinstance(raw_meta, dict):
        raise AnsibleError("Ansible inventory has no host-variable metadata")

    meta = cast("dict[str, object]", raw_meta)
    raw_hostvars: object = meta.get("hostvars")

    if not isinstance(raw_hostvars, dict):
        raise AnsibleError("Ansible inventory has no host-variable mapping")

    hostvars = cast("dict[str, object]", raw_hostvars)

    if len(hostvars) != 1:
        raise AnsibleError(
            "Ansible deployment requires exactly one inventory target; "
            f"found {len(hostvars)}"
        )

    name, raw_variables = next(iter(hostvars.items()))

    if not name or not isinstance(raw_variables, dict):
        raise AnsibleError("Invalid Ansible inventory host variables")

    return name, cast("dict[str, object]", raw_variables)


def _validate_connection_variables(
    variables: dict[str, object],
) -> None:
    """Reject inventory settings that could change the verified SSH transport.

    Args:
        variables: Variables resolved by Ansible for the selected target.

    Raises:
        AnsibleError: If an inventory override conflicts with Tailscale SSH.
    """
    connection = variables.get("ansible_connection")

    if connection is not None and (
        not isinstance(connection, str)
        or connection not in {"ssh", "ansible.builtin.ssh"}
    ):
        raise AnsibleError("Ansible connection must use the standard SSH plugin")

    forbidden = _FORBIDDEN_CONNECTION_VARIABLES.intersection(variables)

    if forbidden:
        raise AnsibleError(
            "Ansible SSH transport override is not allowed: "
            + ", ".join(sorted(forbidden))
        )


def _resolve_target(deployment: AnsibleDeployment) -> AnsibleTarget:
    """Resolve the single Tailscale SSH target from the native inventory.

    Args:
        deployment: Validated estate Ansible deployment.

    Returns:
        Inventory hostname, Tailscale peer name, and remote Unix user.

    Raises:
        AnsibleError: If identity or transport declarations are unsuitable.
    """
    inventory_name, variables = _single_host_variables(
        _load_inventory(deployment.inventory)
    )

    _validate_connection_variables(variables)

    host = variables.get("ansible_host")
    user = variables.get("ansible_user")

    if not isinstance(host, str) or not host.strip():
        raise AnsibleError("Ansible inventory requires ansible_host")

    if not isinstance(user, str) or not user.strip():
        raise AnsibleError("Ansible inventory requires ansible_user")

    return AnsibleTarget(
        inventory_name=inventory_name,
        tailscale_host=host,
        user=user,
    )


def _execute_ansible(
    *,
    root: Path,
    mode: AnsibleMode,
) -> AnsibleDeployment:
    """Execute one estate-defined playbook through verified Tailscale SSH.

    Args:
        root: Estate directory containing native inventory and playbook.
        mode: Preview (check/diff) or normal application.

    Returns:
        The validated deployment after successful execution.

    Raises:
        AnsibleError: If validation, connection, or playbook execution fails.
    """
    deployment = _validated_deployment(root)
    target = _resolve_target(deployment)

    try:
        connection = prepare_tailscale_ansible(
            host=target.tailscale_host,
            user=target.user,
        )
    except TailscaleAnsibleError as exc:
        raise AnsibleError(f"Ansible connection preflight failed: {exc}") from exc

    command = [
        "ansible-playbook",
        "--inventory",
        str(deployment.inventory),
        "--limit",
        target.inventory_name,
        "--user",
        target.user,
        str(deployment.playbook),
    ]

    if mode is AnsibleMode.PREVIEW:
        command.extend(["--check", "--diff"])

    try:
        returncode = run_ansible(
            command,
            connection=connection,
            cwd=deployment.root,
        )
    except TailscaleAnsibleError as exc:
        raise AnsibleError(f"Ansible execution failed: {exc}") from exc

    if returncode != 0:
        raise AnsibleError(f"Ansible {mode.value} failed with exit status {returncode}")

    return deployment


def plan_ansible(*, root: Path) -> AnsibleDeployment:
    """Preview estate configuration using Ansible check and diff modes.

    This is a predictive execution, not a saved plan. Modules with limited
    check-mode support may omit changes.

    Args:
        root: Estate directory containing inventory.yml and playbook.yml.

    Returns:
        Validated deployment following a successful preview.

    Raises:
        AnsibleError: If preview cannot complete.
    """
    return _execute_ansible(
        root=root,
        mode=AnsibleMode.PREVIEW,
    )


def apply_ansible(*, root: Path) -> AnsibleDeployment:
    """Reconcile the estate target to its declared Ansible configuration.

    Args:
        root: Estate directory containing inventory.yml and playbook.yml.

    Returns:
        Validated deployment following successful application.

    Raises:
        AnsibleError: If application cannot complete.
    """
    return _execute_ansible(
        root=root,
        mode=AnsibleMode.APPLY,
    )
