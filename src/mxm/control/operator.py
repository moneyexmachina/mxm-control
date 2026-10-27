"""Human operator authentication for MXM estate control.

Delegates operator session management to Proton Pass CLI.

Proton Pass holds durable operator authority. This module manages access
to the existing Proton Pass session without retrieving, caching, or
persisting provider credentials.

Provider-specific credential resolution is a separate responsibility.
"""

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class OperatorStatus:
    """Authentication status of the MXM operator's authority backends.

    Attributes:
        proton_pass: Whether a Proton Pass session is available.
        github: Whether GitHub CLI is authenticated.
    """

    proton_pass: bool
    github: bool

    @property
    def authenticated(self) -> bool:
        """Return whether all required operator backends are authenticated."""
        return self.proton_pass and self.github


def operator_status() -> OperatorStatus:
    """Inspect all supported operator authentication backends.

    Returns:
        Authentication availability for Proton Pass and GitHub.

    Raises:
        OperatorError: If a backend's CLI cannot be executed.
    """
    return OperatorStatus(
        proton_pass=status(),
        github=github_status(),
    )


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
    """Establish the operator's Proton Pass and GitHub sessions.

    Existing sessions are reused. Missing sessions are established
    using each provider's native authentication mechanism.

    Raises:
        OperatorError: If either authentication backend fails.
    """
    if not status():
        if _run_pass_cli("login") != 0:
            raise OperatorError("Proton Pass login failed")

        if not status():
            raise OperatorError(
                "Proton Pass login completed without an available session"
            )

    github_login()


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


def github_status() -> bool:
    """Check whether GitHub CLI has an authenticated session.

    Returns:
        True if GitHub CLI reports an authenticated github.com session.

    Raises:
        OperatorError: If GitHub CLI cannot be executed.
    """
    return _run_gh("auth", "status", "--hostname", "github.com") == 0


def github_login() -> None:
    """Establish or reuse the GitHub operator session.

    Existing authenticated GitHub CLI sessions are preserved.

    Raises:
        OperatorError: If GitHub authentication cannot be established.
    """
    if github_status():
        return

    if _run_gh("auth", "login", "--hostname", "github.com", "--web") != 0:
        raise OperatorError("GitHub CLI login failed")

    if not github_status():
        raise OperatorError(
            "GitHub CLI login completed without an authenticated session"
        )


def _run_gh(*args: str) -> int:
    """Execute a GitHub CLI authentication command.

    Args:
        *args: Arguments passed to ``gh``.

    Returns:
        The subprocess exit status.

    Raises:
        OperatorError: If GitHub CLI cannot be executed.
    """
    try:
        completed = subprocess.run(
            ["gh", *args],
            check=False,
        )
    except FileNotFoundError as exc:
        raise OperatorError("GitHub CLI is not installed") from exc
    except OSError as exc:
        raise OperatorError(f"Unable to execute GitHub CLI: {exc}") from exc

    return completed.returncode
