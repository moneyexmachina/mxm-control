"""Unit tests for MXM operator authentication.

All Proton Pass CLI subprocess calls are mocked. These tests must never
authenticate, terminate, or otherwise modify a real operator session.
"""

import subprocess
from typing import Any

import pytest

from mxm.control import operator


def completed(returncode: int) -> subprocess.CompletedProcess[str]:
    """Create a subprocess result with the requested exit status."""
    return subprocess.CompletedProcess(args=[], returncode=returncode)


def test_status_returns_true_for_existing_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful pass-cli info indicates an available session."""
    observed: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        assert kwargs["check"] is False
        return completed(0)

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    assert operator.status() is True
    assert observed == [["pass-cli", "info"]]


def test_status_returns_false_when_no_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed pass-cli info indicates no available session."""

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert command == ["pass-cli", "info"]
        return completed(1)

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    assert operator.status() is False


def test_login_reuses_existing_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Login must not reauthenticate an already authenticated operator."""
    observed: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return completed(0)

    monkeypatch.setattr(operator, "github_login", lambda: None)
    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    operator.login()

    assert observed == [["pass-cli", "info"]]


def test_login_establishes_new_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Login authenticates and verifies that the new session exists."""
    observed: list[list[str]] = []
    responses = iter([1, 0, 0])

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return completed(next(responses))

    monkeypatch.setattr(operator, "github_login", lambda: None)
    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    operator.login()

    assert observed == [
        ["pass-cli", "info"],
        ["pass-cli", "login"],
        ["pass-cli", "info"],
    ]


def test_login_fails_when_authentication_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed Proton Pass login must raise OperatorError."""
    observed: list[list[str]] = []
    responses = iter([1, 1])

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return completed(next(responses))

    monkeypatch.setattr(operator, "github_login", lambda: None)
    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    with pytest.raises(operator.OperatorError, match="Proton Pass login failed"):
        operator.login()

    assert observed == [
        ["pass-cli", "info"],
        ["pass-cli", "login"],
    ]


def test_login_fails_when_session_remains_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful login command must be followed by session verification."""
    responses = iter([1, 0, 1])

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return completed(next(responses))

    monkeypatch.setattr(operator, "github_login", lambda: None)
    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    with pytest.raises(
        operator.OperatorError,
        match="login completed without an available session",
    ):
        operator.login()


def test_logout_terminates_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logout delegates session termination to Proton Pass."""
    observed: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return completed(0)

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    operator.logout()

    assert observed == [["pass-cli", "logout"]]


def test_logout_failure_raises_operator_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed logout must not be reported as successful."""

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert command == ["pass-cli", "logout"]
        return completed(1)

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    with pytest.raises(operator.OperatorError, match="Proton Pass logout failed"):
        operator.logout()


def test_missing_pass_cli_raises_operator_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing Proton Pass executable produces a controlled error."""

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    with pytest.raises(
        operator.OperatorError,
        match="Proton Pass CLI is not installed",
    ):
        operator.status()


def test_pass_cli_execution_error_raises_operator_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Other OS-level execution failures are reported as operator errors."""

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("Permission denied")

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    with pytest.raises(
        operator.OperatorError,
        match="Unable to execute Proton Pass CLI",
    ):
        operator.status()


def test_github_status_returns_true_for_authenticated_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful GitHub CLI status indicates authentication."""
    observed: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        assert kwargs["check"] is False
        return completed(0)

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    assert operator.github_status() is True
    assert observed == [
        ["gh", "auth", "status", "--hostname", "github.com"],
    ]


def test_github_status_returns_false_when_unauthenticated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed GitHub CLI status indicates no authenticated session."""

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert command == ["gh", "auth", "status", "--hostname", "github.com"]
        return completed(1)

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    assert operator.github_status() is False


def test_github_login_reuses_existing_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An authenticated GitHub session must not trigger a new login."""
    observed: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return completed(0)

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    operator.github_login()

    assert observed == [
        ["gh", "auth", "status", "--hostname", "github.com"],
    ]


def test_github_login_establishes_new_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub login authenticates and verifies the resulting session."""
    observed: list[list[str]] = []
    responses = iter([1, 0, 0])

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return completed(next(responses))

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    operator.github_login()

    assert observed == [
        ["gh", "auth", "status", "--hostname", "github.com"],
        ["gh", "auth", "login", "--hostname", "github.com", "--web"],
        ["gh", "auth", "status", "--hostname", "github.com"],
    ]


def test_github_login_fails_when_authentication_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unsuccessful GitHub login raises OperatorError."""
    responses = iter([1, 1])

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return completed(next(responses))

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    with pytest.raises(
        operator.OperatorError,
        match="GitHub CLI login failed",
    ):
        operator.github_login()


def test_github_login_fails_when_session_remains_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub login success requires subsequent authentication verification."""
    responses = iter([1, 0, 1])

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return completed(next(responses))

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    with pytest.raises(
        operator.OperatorError,
        match="GitHub CLI login completed without an authenticated session",
    ):
        operator.github_login()


def test_missing_gh_cli_raises_operator_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing GitHub CLI executable produces a controlled error."""

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    monkeypatch.setattr(operator.subprocess, "run", fake_run)

    with pytest.raises(
        operator.OperatorError,
        match="GitHub CLI is not installed",
    ):
        operator.github_status()


def test_login_authenticates_both_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Combined login verifies Proton Pass before authenticating GitHub."""
    observed: list[str] = []

    def fake_status() -> bool:
        observed.append("proton-status")
        return True

    def fake_github_login() -> None:
        observed.append("github-login")

    monkeypatch.setattr(operator, "status", fake_status)
    monkeypatch.setattr(operator, "github_login", fake_github_login)

    operator.login()

    assert observed == ["proton-status", "github-login"]


def test_login_does_not_attempt_github_after_proton_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Proton Pass failure prevents subsequent GitHub authentication."""
    observed: list[str] = []

    monkeypatch.setattr(operator, "status", lambda: False)

    def fake_pass_cli(*args: str) -> int:
        assert args == ("login",)
        return 1

    def fake_github_login() -> None:
        observed.append("github-login")

    monkeypatch.setattr(operator, "_run_pass_cli", fake_pass_cli)
    monkeypatch.setattr(operator, "github_login", fake_github_login)

    with pytest.raises(
        operator.OperatorError,
        match="Proton Pass login failed",
    ):
        operator.login()

    assert observed == []


@pytest.mark.parametrize(
    ("proton_pass", "github", "authenticated"),
    [
        (True, True, True),
        (True, False, False),
        (False, True, False),
        (False, False, False),
    ],
)
def test_operator_status_aggregates_authentication(
    monkeypatch: pytest.MonkeyPatch,
    proton_pass: bool,
    github: bool,
    authenticated: bool,
) -> None:
    """Combined status requires both authentication backends."""
    monkeypatch.setattr(operator, "status", lambda: proton_pass)
    monkeypatch.setattr(operator, "github_status", lambda: github)

    result = operator.operator_status()

    assert result.proton_pass is proton_pass
    assert result.github is github
    assert result.authenticated is authenticated
