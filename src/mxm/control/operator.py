"""Human operator authentication for MXM estate control.

Delegates operator session management to Proton Pass CLI.

Proton Pass holds durable operator authority. This module manages access
to the existing Proton Pass session without retrieving, caching, or
persisting provider credentials.

Provider-specific credential resolution is a separate responsibility.
"""

import subprocess


class OperatorError(RuntimeError):
    """Raised when an operator authentication operation fails."""


def _run_pass_cli(*args: str) -> int:
    """Execute a Proton Pass CLI command.

    Args:
        *args: Command arguments passed to ``pass-cli``.

    Returns:
        The process exit status.

    Raises:
        OperatorError: If the Proton Pass CLI cannot be executed.
    """
    try:
        completed = subprocess.run(
            ["pass-cli", *args],
            check=False,
        )
    except FileNotFoundError as exc:
        raise OperatorError(
            "Proton Pass CLI is not installed or unavailable on PATH"
        ) from exc
    except OSError as exc:
        raise OperatorError(f"Unable to execute Proton Pass CLI: {exc}") from exc

    return completed.returncode


def login() -> None:
    """Establish or reuse an authenticated operator session.

    An existing Proton Pass session is reused when available.
    Otherwise, Proton Pass performs its native interactive login.

    Raises:
        OperatorError: If authentication cannot be established.
    """
    if status():
        return

    if _run_pass_cli("login") != 0:
        raise OperatorError("Proton Pass login failed")

    if not status():
        raise OperatorError("Proton Pass login completed without an available session")


def status() -> bool:
    """Check whether a Proton Pass session is available.

    Returns:
        True if ``pass-cli info`` succeeds; otherwise False.

    Note:
        Session availability does not necessarily imply that the
        session is unlocked or that individual secrets are accessible.
    """
    return _run_pass_cli("info") == 0


def logout() -> None:
    """Terminate the current Proton Pass operator session.

    Raises:
        OperatorError: If Proton Pass cannot terminate the session.
    """
    if _run_pass_cli("logout") != 0:
        raise OperatorError("Proton Pass logout failed")
