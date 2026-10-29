"""OpenTofu reconciliation operations for MXM infrastructure.

An OpenTofu root module defines an independently managed infrastructure
configuration and its associated state.

This module provides three operations:

- Plan: create a saved OpenTofu plan for review and application.
- Check: identify differences between declared and realised state.
- Apply: execute exactly one existing, reviewed OpenTofu plan.

OpenTofu execution uses the operator credential environment declared
for the root module. Saved plans are protected with owner-only permissions.
"""

import os
import stat
import subprocess
from enum import Enum
from pathlib import Path

from mxm.control.credentials import CredentialError, run_with_credentials


class OpenTofuError(RuntimeError):
    """Raised when an OpenTofu control operation cannot be completed."""


class OpenTofuCheckResult(Enum):
    """Possible outcomes of an OpenTofu infrastructure check."""

    NO_CHANGE = "no-change"
    DRIFT = "drift"


def _validated_root(root: Path) -> Path:
    """Resolve and validate an OpenTofu root directory.

    Args:
        root: Directory containing the OpenTofu root module.

    Returns:
        The resolved absolute path to the root directory.

    Raises:
        OpenTofuError: If the root does not exist or is inaccessible.
    """
    try:
        resolved = root.expanduser().resolve(strict=True)
    except FileNotFoundError as exc:
        raise OpenTofuError(f"root does not exist: {root}") from exc

    if not resolved.is_dir():
        raise OpenTofuError(f"root is not a directory: {resolved}")

    if not os.access(resolved, os.R_OK | os.X_OK):
        raise OpenTofuError(f"root is not readable: {resolved}")

    return resolved


def _new_plan_path(plan: Path) -> Path:
    """Validate a destination for a new saved OpenTofu plan.

    The plan must not already exist. Its parent directory must be present
    and writable.

    Args:
        plan: Requested path for the new plan.

    Returns:
        The absolute plan path with its parent directory resolved.

    Raises:
        OpenTofuError: If the destination is unsuitable.
    """
    expanded = plan.expanduser()

    if expanded.exists() or expanded.is_symlink():
        raise OpenTofuError(f"plan output already exists: {expanded}")

    try:
        parent = expanded.parent.resolve(strict=True)
    except FileNotFoundError as exc:
        raise OpenTofuError(
            f"plan output directory does not exist: {expanded.parent}"
        ) from exc

    if not parent.is_dir():
        raise OpenTofuError(f"plan output parent is not a directory: {parent}")

    if not os.access(parent, os.W_OK | os.X_OK):
        raise OpenTofuError(f"plan output directory is not writable: {parent}")

    return parent / expanded.name


def _existing_plan_path(plan: Path) -> Path:
    """Validate an existing saved OpenTofu plan for application.

    Saved plans must be regular files with owner-only permissions.
    Symbolic links are not accepted.

    Args:
        plan: Path to an existing saved plan.

    Returns:
        The resolved absolute path to the validated plan.

    Raises:
        OpenTofuError: If the plan is missing, inaccessible, or unsuitable.
    """
    expanded = plan.expanduser()

    if expanded.is_symlink():
        raise OpenTofuError(f"plan must not be a symbolic link: {expanded}")

    try:
        resolved = expanded.resolve(strict=True)
    except FileNotFoundError as exc:
        raise OpenTofuError(f"plan does not exist: {expanded}") from exc

    try:
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise OpenTofuError(f"unable to inspect plan: {resolved}") from exc

    if not stat.S_ISREG(mode):
        raise OpenTofuError(f"plan is not a regular file: {resolved}")

    if mode & 0o077:
        raise OpenTofuError(f"plan permissions must be owner-only: {resolved}")

    if not os.access(resolved, os.R_OK):
        raise OpenTofuError(f"plan is not readable: {resolved}")

    return resolved


def _run(
    command: list[str],
    *,
    root: Path,
    environment_policy: Path,
    restrictive_umask: bool = False,
) -> int:
    """Execute OpenTofu with the root module's declared credentials.

    Credential resolution and process environment construction are
    delegated to the operator credential execution capability.

    Args:
        command: OpenTofu executable and command arguments.
        root: OpenTofu root containing optional credential bindings.
        environment_policy: Operator environment-filtering policy.
        restrictive_umask: Whether newly created files receive
            owner-only permissions.

    Returns:
        The OpenTofu subprocess exit status.

    Raises:
        OpenTofuError: If credential resolution or execution fails.
    """
    try:
        return run_with_credentials(
            command,
            stack=root,
            environment_policy=environment_policy,
            restrictive_umask=restrictive_umask,
        )
    except CredentialError as exc:
        raise OpenTofuError(f"OpenTofu execution failed: {exc}") from exc


def plan_opentofu(
    root: Path,
    environment_policy: Path,
    plan: Path,
) -> Path:
    """Create a saved OpenTofu plan without modifying realised state.

    The plan is generated with a restrictive umask and secured with
    owner-only file permissions.

    Args:
        root: OpenTofu root module to plan.
        environment_policy: Operator environment-filtering policy.
        plan: Destination for the new saved plan.

    Returns:
        The absolute path to the saved plan.

    Raises:
        OpenTofuError: If validation, execution, or plan creation fails.
    """
    root_path = _validated_root(root)
    plan_path = _new_plan_path(plan)

    returncode = _run(
        [
            "tofu",
            f"-chdir={root_path}",
            "plan",
            "-input=false",
            f"-out={plan_path}",
        ],
        root=root_path,
        environment_policy=environment_policy,
        restrictive_umask=True,
    )

    if returncode != 0:
        plan_path.unlink(missing_ok=True)
        raise OpenTofuError(f"OpenTofu plan failed with exit status {returncode}")

    try:
        mode = plan_path.lstat().st_mode
    except FileNotFoundError as exc:
        raise OpenTofuError(
            f"OpenTofu reported success but did not create plan: {plan_path}"
        ) from exc

    if not stat.S_ISREG(mode):
        plan_path.unlink(missing_ok=True)
        raise OpenTofuError(f"OpenTofu did not create a regular plan file: {plan_path}")

    try:
        plan_path.chmod(0o600)
    except OSError as exc:
        plan_path.unlink(missing_ok=True)
        raise OpenTofuError(
            f"unable to restrict plan permissions: {plan_path}"
        ) from exc

    return plan_path


def check_opentofu(
    root: Path,
    *,
    environment_policy: Path,
) -> OpenTofuCheckResult:
    """Check an OpenTofu root module for infrastructure drift.

    OpenTofu's detailed exit status distinguishes matching state,
    detected changes, and execution errors.

    Args:
        root: OpenTofu root module to check.
        environment_policy: Operator environment-filtering policy.

    Returns:
        NO_CHANGE when realised state matches the declaration,
        or DRIFT when OpenTofu identifies required changes.

    Raises:
        OpenTofuError: If validation or execution fails.
    """
    root_path = _validated_root(root)

    returncode = _run(
        [
            "tofu",
            f"-chdir={root_path}",
            "plan",
            "-input=false",
            "-detailed-exitcode",
        ],
        root=root_path,
        environment_policy=environment_policy,
    )

    if returncode == 0:
        return OpenTofuCheckResult.NO_CHANGE

    if returncode == 2:
        return OpenTofuCheckResult.DRIFT

    raise OpenTofuError(f"OpenTofu check failed with exit status {returncode}")


def apply_opentofu(
    root: Path,
    environment_policy: Path,
    plan: Path,
) -> Path:
    """Apply exactly one existing, reviewed OpenTofu plan.

    Application uses the saved plan directly, preserving the changes
    selected during the planning and review process.

    Args:
        root: OpenTofu root module associated with the plan.
        environment_policy: Operator environment-filtering policy.
        plan: Existing saved plan with owner-only permissions.

    Returns:
        The absolute path to the applied plan.

    Raises:
        OpenTofuError: If validation or application fails.
    """
    root_path = _validated_root(root)
    plan_path = _existing_plan_path(plan)

    returncode = _run(
        [
            "tofu",
            f"-chdir={root_path}",
            "apply",
            "-input=false",
            str(plan_path),
        ],
        root=root_path,
        environment_policy=environment_policy,
    )

    if returncode != 0:
        raise OpenTofuError(f"OpenTofu apply failed with exit status {returncode}")

    return plan_path


def apply_opentofu_inherited(root: Path, plan: Path) -> Path:
    """Apply a saved OpenTofu plan using inherited operator credentials.

    Execute OpenTofu directly, without initiating another Proton Pass
    credential-resolution process.

    This mechanism is intended for orchestration workers already
    executing inside an environment established by
    credentials.run_with_credentials().

    The caller is responsible for establishing the authorised credential
    environment before invoking this function.

    Args:
        root: OpenTofu root containing the infrastructure declarations.
        plan: Existing, reviewed, owner-readable saved plan.

    Returns:
        The validated path of the applied plan.

    Raises:
        OpenTofuError: If input validation, process execution, or
            the OpenTofu apply operation fails.
    """
    root_path = _validated_root(root)
    plan_path = _existing_plan_path(plan)

    command = [
        "tofu",
        f"-chdir={root_path}",
        "apply",
        "-input=false",
        str(plan_path),
    ]

    try:
        result = subprocess.run(
            command,
            check=False,
            umask=0o077,
        )
    except FileNotFoundError as exc:
        raise OpenTofuError("OpenTofu executable not found") from exc
    except OSError as exc:
        raise OpenTofuError(f"Unable to execute OpenTofu apply: {exc}") from exc

    if result.returncode != 0:
        raise OpenTofuError(
            f"OpenTofu apply failed with exit status {result.returncode}"
        )

    return plan_path
