"""Credential bindings for MXM estate-control operations.

Estate stacks declare required operator credentials in a stack-local
``credentials.toml`` file. The manifest maps environment variable names
to canonical Proton Pass secret references.

This module validates those declarations and invokes commands through
Proton Pass CLI when credential resolution is required.

Credential values are never retrieved into Python, logged, persisted,
or included in OpenTofu configuration or state by this mechanism.

Concrete credential identifiers and provider-specific bindings belong
to the estate repository, not to this reusable control package.
"""

import os
import re
import stat
import subprocess
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

CREDENTIALS_FILENAME = "credentials.toml"

_ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SECRET_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class CredentialError(RuntimeError):
    """Raised when credential configuration or execution fails."""


def _validate_reference(reference: str) -> None:
    """Validate a canonical Proton Pass secret reference.

    References use the form ``pass://SHARE_ID/ITEM_ID/FIELD``.
    Vault and item names are not accepted in place of identifiers.

    Args:
        reference: Proton Pass reference to validate.

    Raises:
        CredentialError: If the reference is malformed.
    """
    if not reference.startswith("pass://"):
        raise CredentialError(
            "Credential bindings must use canonical pass:// references"
        )

    components = reference.removeprefix("pass://").split("/")

    if len(components) != 3:
        raise CredentialError(
            "Credential reference must contain share ID, item ID, and field"
        )

    share_id, item_id, field = components

    if not (
        _SECRET_ID_PATTERN.fullmatch(share_id) and _SECRET_ID_PATTERN.fullmatch(item_id)
    ):
        raise CredentialError(
            "Credential reference contains an invalid share or item ID"
        )

    if not field or field != field.strip():
        raise CredentialError("Credential reference must specify a valid field")

    if any(ord(character) < 32 or ord(character) == 127 for character in field):
        raise CredentialError("Credential reference field contains a control character")


def _validate_bindings(data: object) -> dict[str, str]:
    """Validate a parsed credential manifest.

    Args:
        data: Parsed TOML document.

    Returns:
        Validated environment-variable-to-reference bindings.

    Raises:
        CredentialError: If the manifest has an invalid structure
            or contains an unsupported credential declaration.
    """
    if not isinstance(data, dict):
        raise CredentialError(
            "Credential manifest must contain only an [environment] table"
        )

    document = cast("dict[str, object]", data)

    if set(document) != {"environment"}:
        raise CredentialError(
            "Credential manifest must contain only an [environment] table"
        )

    raw_environment = document["environment"]

    if not isinstance(raw_environment, dict):
        raise CredentialError("Credential manifest [environment] must not be empty")

    environment = cast("dict[str, object]", raw_environment)

    if not environment:
        raise CredentialError("Credential manifest [environment] must not be empty")

    bindings: dict[str, str] = {}

    for name, reference in environment.items():
        if not _ENVIRONMENT_NAME_PATTERN.fullmatch(name):
            raise CredentialError(
                f"Invalid credential environment variable name: {name!r}"
            )

        if not isinstance(reference, str):
            raise CredentialError(f"Credential binding {name!r} must be a string")

        try:
            _validate_reference(reference)
        except CredentialError as exc:
            raise CredentialError(
                f"Invalid credential binding {name!r}: {exc}"
            ) from exc

        bindings[name] = reference

    return bindings


def load_credentials(stack: Path) -> dict[str, str]:
    """Load credential bindings declared by an estate stack.

    The manifest is optional. A stack without one requires no
    Proton Pass credential injection through this mechanism.

    Symbolic links, non-regular files, and malformed manifests are
    rejected rather than silently ignored.

    Args:
        stack: Directory containing the estate stack.

    Returns:
        A mapping of environment variable names to Proton Pass
        secret references, or an empty mapping if no manifest exists.

    Raises:
        CredentialError: If the stack or manifest cannot be read,
            or if the manifest contains invalid declarations.
    """
    stack_path = stack.expanduser().resolve()
    manifest = stack_path / CREDENTIALS_FILENAME

    if not stack_path.is_dir():
        raise CredentialError(
            f"Credential stack directory does not exist: {stack_path}"
        )

    if manifest.is_symlink():
        raise CredentialError(
            f"Credential manifest must not be a symbolic link: {manifest}"
        )

    if not manifest.exists():
        return {}

    try:
        if not stat.S_ISREG(manifest.stat().st_mode):
            raise CredentialError(
                f"Credential manifest is not a regular file: {manifest}"
            )

        with manifest.open("rb") as stream:
            data = tomllib.load(stream)

    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CredentialError(
            f"Unable to read credential manifest: {manifest}"
        ) from exc

    return _validate_bindings(data)


def run_with_credentials(
    command: Sequence[str],
    *,
    stack: Path,
    restrictive_umask: bool = False,
) -> int:
    """Execute a command with stack-declared operator credentials.

    If the stack declares credentials, their Proton Pass references
    are supplied to ``pass-cli run`` as environment variables.
    Proton Pass resolves them in the child execution environment.

    If the stack has no manifest, the command executes directly.

    Credential values are never materialised in this Python process.

    Args:
        command: Executable and arguments to run.
        stack: Estate stack supplying the credential bindings.
        restrictive_umask: Whether to use an owner-only file creation
            mask for the subprocess.

    Returns:
        The subprocess exit status.

    Raises:
        CredentialError: If credential declarations are invalid,
            the command is empty, or execution cannot be started.
    """
    if not command:
        raise CredentialError("Cannot execute an empty command")

    bindings = load_credentials(stack)

    environment: Mapping[str, str] | None = None
    executable = list(command)

    if bindings:
        environment = {**os.environ, **bindings}
        executable = ["pass-cli", "run", "--", *executable]

    try:
        completed = subprocess.run(
            executable,
            check=False,
            env=environment,
            umask=0o077 if restrictive_umask else -1,
        )
    except FileNotFoundError as exc:
        raise CredentialError(
            f"Required executable not found: {executable[0]}"
        ) from exc
    except OSError as exc:
        raise CredentialError(
            f"Unable to execute credential-bound command: {exc}"
        ) from exc

    return completed.returncode
