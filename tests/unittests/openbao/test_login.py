"""Unit tests for credential-bound OpenBao operator login.

Verify userpass authentication, security-admin session validation,
native CLI token storage, and secret-handling boundaries.

No real HTTP requests, Proton Pass access, or token-file writes occur.
"""

from __future__ import annotations

import io
import json
import re
import ssl
import subprocess
from urllib.error import URLError
from urllib.request import Request

import pytest

import mxm.control.openbao.login as login_module
from mxm.control.openbao.api import OpenBaoError

ADDRESS = "https://openbao.tail546174.ts.net"
USERNAME = "adminsecure"
PASSWORD = "synthetic-operator-password"
TOKEN = "synthetic-operator-token"
TTL = 1800


def _login_response(
    *,
    token: object = TOKEN,
    policies: object = None,
    ttl: object = TTL,
) -> bytes:
    """Build a synthetic OpenBao userpass authentication response."""
    if policies is None:
        policies = ["default", "security-admin"]

    return json.dumps(
        {
            "auth": {
                "client_token": token,
                "policies": policies,
                "lease_duration": ttl,
            }
        }
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# OpenBao userpass HTTPS authentication
# ---------------------------------------------------------------------------


def test_authenticate_userpass_submits_credentials_over_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Submit the password in a TLS-protected JSON request."""
    requests: list[Request] = []

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> io.BytesIO:
        requests.append(request)

        assert timeout == 10.0
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

        return io.BytesIO(_login_response())

    monkeypatch.setattr(login_module, "urlopen", fake_urlopen)

    result = login_module.authenticate_userpass(
        ADDRESS,
        username=USERNAME,
        password=PASSWORD,
    )

    assert result == login_module.OpenBaoSession(
        token=TOKEN,
        ttl=TTL,
    )

    assert len(requests) == 1
    request = requests[0]

    assert request.full_url == (f"{ADDRESS}/v1/auth/userpass/login/{USERNAME}")
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("Accept") == "application/json"

    assert isinstance(request.data, bytes)
    assert json.loads(request.data) == {"password": PASSWORD}

    assert PASSWORD not in request.full_url
    assert TOKEN not in request.full_url


def test_authenticate_userpass_encodes_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Encode usernames as a single API path component."""

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> io.BytesIO:
        assert request.full_url.endswith("/v1/auth/userpass/login/admin%2Foperator")
        return io.BytesIO(_login_response())

    monkeypatch.setattr(login_module, "urlopen", fake_urlopen)

    result = login_module.authenticate_userpass(
        ADDRESS,
        username="admin/operator",
        password=PASSWORD,
    )

    assert result.ttl == TTL


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("", PASSWORD),
        (USERNAME, ""),
    ],
)
def test_authenticate_userpass_requires_credentials(
    monkeypatch: pytest.MonkeyPatch,
    username: str,
    password: str,
) -> None:
    """Reject absent credentials before making an HTTP request."""

    def forbidden_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> io.BytesIO:
        pytest.fail("Missing credentials must prevent network access")

    monkeypatch.setattr(login_module, "urlopen", forbidden_urlopen)

    with pytest.raises(
        OpenBaoError,
        match="credentials are unavailable",
    ):
        login_module.authenticate_userpass(
            ADDRESS,
            username=username,
            password=password,
        )


def test_authenticate_userpass_rejects_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Never submit the operator password over plaintext HTTP."""

    def forbidden_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> io.BytesIO:
        pytest.fail("Plaintext HTTP must not be attempted")

    monkeypatch.setattr(login_module, "urlopen", forbidden_urlopen)

    with pytest.raises(OpenBaoError, match="HTTPS service origin"):
        login_module.authenticate_userpass(
            "http://openbao.example.test",
            username=USERNAME,
            password=PASSWORD,
        )


def test_authenticate_userpass_reports_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report authentication failure without exposing provider details."""

    def failing_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> io.BytesIO:
        raise URLError("synthetic-private-transport-error")

    monkeypatch.setattr(login_module, "urlopen", failing_urlopen)

    with pytest.raises(
        OpenBaoError,
        match="OpenBao operator authentication failed",
    ) as caught:
        login_module.authenticate_userpass(
            ADDRESS,
            username=USERNAME,
            password=PASSWORD,
        )

    assert PASSWORD not in str(caught.value)
    assert "synthetic-private-transport-error" not in str(caught.value)


def test_authenticate_userpass_rejects_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bound response buffering before parsing authentication data."""

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> io.BytesIO:
        return io.BytesIO(b"x" * (login_module._MAX_RESPONSE_BYTES + 1))

    monkeypatch.setattr(login_module, "urlopen", fake_urlopen)

    with pytest.raises(OpenBaoError, match="response too large"):
        login_module.authenticate_userpass(
            ADDRESS,
            username=USERNAME,
            password=PASSWORD,
        )


# ---------------------------------------------------------------------------
# Authenticated session validation
# ---------------------------------------------------------------------------


def test_parse_login_response_accepts_security_admin() -> None:
    """Accept the expected security-admin policy and 30-minute lifetime."""
    result = login_module._parse_login_response(_login_response())

    assert result.token == TOKEN
    assert result.ttl == TTL


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b"[]",
        b"{}",
        b'{"auth": null}',
        b'{"auth": []}',
    ],
)
def test_parse_login_response_rejects_malformed_response(
    payload: bytes,
) -> None:
    """Authentication requires a valid OpenBao auth response."""
    with pytest.raises(OpenBaoError):
        login_module._parse_login_response(payload)


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "token with spaces",
        "token\nwith-newline",
        "tökén",
    ],
)
def test_parse_login_response_rejects_invalid_token(
    token: object,
) -> None:
    """Require a nonempty, printable ASCII bearer token."""
    with pytest.raises(OpenBaoError, match="no valid token"):
        login_module._parse_login_response(_login_response(token=token))


@pytest.mark.parametrize(
    "policies",
    [
        [],
        ["default"],
        ["operator"],
        "security-admin",
        None,
    ],
)
def test_parse_login_response_requires_security_admin(
    policies: object,
) -> None:
    """Do not accept a session lacking the operator's required policy."""
    with pytest.raises(OpenBaoError):
        login_module._parse_login_response(
            _login_response(policies=policies)
            if policies is not None
            else json.dumps(
                {
                    "auth": {
                        "client_token": TOKEN,
                        "lease_duration": TTL,
                    }
                }
            ).encode("utf-8")
        )


@pytest.mark.parametrize(
    "ttl",
    [
        None,
        0,
        -1,
        1801,
        3600,
        "1800",
        1800.0,
        True,
    ],
)
def test_parse_login_response_rejects_invalid_lifetime(
    ttl: object,
) -> None:
    """Reject sessions outside the expected 30-minute maximum."""
    with pytest.raises(OpenBaoError, match="unexpected lifetime"):
        login_module._parse_login_response(_login_response(ttl=ttl))


# ---------------------------------------------------------------------------
# Native OpenBao CLI token storage
# ---------------------------------------------------------------------------


def test_store_session_uses_stdin_and_sanitized_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Store the token without putting credentials in argv or environment."""
    monkeypatch.setenv("BAO_TOKEN", "inherited-token")
    monkeypatch.setenv("VAULT_TOKEN", "inherited-vault-token")
    monkeypatch.setenv("MXM_OPENBAO_USERNAME", USERNAME)
    monkeypatch.setenv("MXM_OPENBAO_PASSWORD", PASSWORD)

    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        *,
        input: str,
        text: bool,
        stdout: int,
        stderr: int,
        env: dict[str, str],
        check: bool,
        timeout: float,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)

        assert command == [
            "bao",
            "login",
            "-address",
            ADDRESS,
            "-no-print",
            "-",
        ]

        assert input == f"{TOKEN}\n"
        assert text is True
        assert stdout == subprocess.DEVNULL
        assert stderr == subprocess.DEVNULL
        assert check is False
        assert timeout == 20.0
        assert umask == 0o077

        assert "BAO_TOKEN" not in env
        assert "VAULT_TOKEN" not in env
        assert "MXM_OPENBAO_USERNAME" not in env
        assert "MXM_OPENBAO_PASSWORD" not in env

        assert TOKEN not in str(command)
        assert PASSWORD not in str(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(login_module.subprocess, "run", fake_run)

    login_module._store_session(ADDRESS, TOKEN)

    assert len(calls) == 1


def test_store_session_reports_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report a failed native token-helper operation with its exit code."""

    def failing_run(
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["bao", "login"],
            returncode=1,
        )

    monkeypatch.setattr(login_module.subprocess, "run", failing_run)

    with pytest.raises(
        OpenBaoError,
        match=r"OpenBao CLI token storage failed \(exit 1\)",
    ):
        login_module._store_session(ADDRESS, TOKEN)


@pytest.mark.parametrize(
    ("failure", "expected_message"),
    [
        (
            FileNotFoundError("bao not installed"),
            "OpenBao CLI (bao) is not installed or unavailable on PATH",
        ),
        (
            subprocess.TimeoutExpired(["bao", "login"], 20),
            "OpenBao CLI token storage timed out",
        ),
        (
            OSError("synthetic execution failure"),
            "Unable to execute OpenBao CLI",
        ),
    ],
)
def test_store_session_reports_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    expected_message: str,
) -> None:
    """Distinguish CLI installation, timeout, and execution failures."""

    def failing_run(
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        raise failure

    monkeypatch.setattr(login_module.subprocess, "run", failing_run)

    with pytest.raises(
        OpenBaoError,
        match=re.escape(expected_message),
    ) as caught:
        login_module._store_session(ADDRESS, TOKEN)

    assert TOKEN not in str(caught.value)
    assert PASSWORD not in str(caught.value)


# ---------------------------------------------------------------------------
# Credential-bound child process
# ---------------------------------------------------------------------------


def test_login_openbao_uses_injected_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authenticate using child-only credentials and persist the session."""
    monkeypatch.setenv("MXM_OPENBAO_USERNAME", USERNAME)
    monkeypatch.setenv("MXM_OPENBAO_PASSWORD", PASSWORD)

    events: list[str] = []

    def fake_authenticate(
        address: str,
        *,
        username: str,
        password: str,
        timeout: float = 10.0,
    ) -> login_module.OpenBaoSession:
        assert address == ADDRESS
        assert username == USERNAME
        assert password == PASSWORD
        events.append("authenticate")
        return login_module.OpenBaoSession(
            token=TOKEN,
            ttl=TTL,
        )

    def fake_store(address: str, token: str) -> None:
        assert address == ADDRESS
        assert token == TOKEN
        events.append("store")

    monkeypatch.setattr(
        login_module,
        "authenticate_userpass",
        fake_authenticate,
    )
    monkeypatch.setattr(login_module, "_store_session", fake_store)

    result = login_module.login_openbao(ADDRESS)

    assert result == TTL
    assert events == ["authenticate", "store"]


def test_login_openbao_rejects_missing_injected_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The child cannot authenticate without its Proton Pass bindings."""
    monkeypatch.delenv("MXM_OPENBAO_USERNAME", raising=False)
    monkeypatch.delenv("MXM_OPENBAO_PASSWORD", raising=False)

    with pytest.raises(
        OpenBaoError,
        match="credentials are unavailable",
    ):
        login_module.login_openbao(ADDRESS)


def test_login_main_reports_success_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Print only a successful operator-session summary."""
    monkeypatch.setattr(
        login_module.sys,
        "argv",
        ["login", ADDRESS],
    )

    def fake_login(address: str) -> int:
        assert address == ADDRESS
        return TTL

    monkeypatch.setattr(login_module, "login_openbao", fake_login)

    result = login_module.main()
    output = capsys.readouterr()

    assert result == 0
    assert "OpenBao security-admin session (1800s)" in output.out
    assert output.err == ""
    assert TOKEN not in output.out
    assert PASSWORD not in output.out


def test_login_main_rejects_missing_address(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The credential-bound entry point requires a resolved address."""
    monkeypatch.setattr(
        login_module.sys,
        "argv",
        ["login"],
    )

    result = login_module.main()
    output = capsys.readouterr()

    assert result == 1
    assert "OpenBao service address required" in output.err


def test_login_main_reports_authentication_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Do not claim success when authentication fails."""
    monkeypatch.setattr(
        login_module.sys,
        "argv",
        ["login", ADDRESS],
    )

    def failing_login(address: str) -> int:
        raise OpenBaoError("OpenBao operator authentication failed")

    monkeypatch.setattr(login_module, "login_openbao", failing_login)

    result = login_module.main()
    output = capsys.readouterr()

    assert result == 1
    assert "ERROR: OpenBao operator authentication failed" in output.err
    assert "OK" not in output.out
    assert TOKEN not in output.err
