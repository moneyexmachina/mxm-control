import os
import stat
from enum import Enum
from pathlib import Path

from mxm.control.credentials import CredentialError, run_with_credentials


class OpenTofuError(RuntimeError):
    """An OpenTofu control operation could not be completed."""


class OpenTofuCheckResult(Enum):
    NO_CHANGE = "no-change"
    DRIFT = "drift"


def _validated_stack(stack: Path) -> Path:
    try:
        resolved = stack.expanduser().resolve(strict=True)
    except FileNotFoundError as exc:
        raise OpenTofuError(f"stack does not exist: {stack}") from exc

    if not resolved.is_dir():
        raise OpenTofuError(f"stack is not a directory: {resolved}")
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise OpenTofuError(f"stack is not readable: {resolved}")

    return resolved


def _new_plan_path(plan: Path) -> Path:
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
    stack: Path,
    environment_policy: Path,
    restrictive_umask: bool = False,
) -> int:
    """Execute OpenTofu with credentials declared by the estate stack.

    Args:
        command: OpenTofu executable and command arguments.
        stack: Stack directory containing optional credential bindings.
        restrictive_umask: Whether to restrict newly created files
            to owner-only permissions.

    Returns:
        The subprocess exit status.

    Raises:
        OpenTofuError: If credential resolution or execution fails.
    """
    try:
        return run_with_credentials(
            command,
            stack=stack,
            environment_policy=environment_policy,
            restrictive_umask=restrictive_umask,
        )
    except CredentialError as exc:
        raise OpenTofuError(f"OpenTofu execution failed: {exc}") from exc


def plan_opentofu(stack: Path, environment_policy: Path, plan: Path) -> Path:
    """Create a saved OpenTofu plan without modifying realised state."""
    stack_path = _validated_stack(stack)
    plan_path = _new_plan_path(plan)

    returncode = _run(
        [
            "tofu",
            f"-chdir={stack_path}",
            "plan",
            "-input=false",
            f"-out={plan_path}",
        ],
        stack=stack_path,
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
    stack: Path,
    *,
    environment_policy: Path,
) -> OpenTofuCheckResult:
    """Check an OpenTofu stack for drift without saving a plan."""
    stack_path = _validated_stack(stack)

    returncode = _run(
        [
            "tofu",
            f"-chdir={stack_path}",
            "plan",
            "-input=false",
            "-detailed-exitcode",
        ],
        stack=stack_path,
        environment_policy=environment_policy,
    )

    if returncode == 0:
        return OpenTofuCheckResult.NO_CHANGE
    if returncode == 2:
        return OpenTofuCheckResult.DRIFT

    raise OpenTofuError(f"OpenTofu check failed with exit status {returncode}")


def apply_opentofu(stack: Path, environment_policy: Path, plan: Path) -> Path:
    """Apply exactly one existing, reviewed OpenTofu plan."""
    stack_path = _validated_stack(stack)
    plan_path = _existing_plan_path(plan)

    returncode = _run(
        [
            "tofu",
            f"-chdir={stack_path}",
            "apply",
            "-input=false",
            str(plan_path),
        ],
        environment_policy=environment_policy,
        stack=stack_path,
    )

    if returncode != 0:
        raise OpenTofuError(f"OpenTofu apply failed with exit status {returncode}")

    return plan_path
