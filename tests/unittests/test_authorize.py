"""Unit tests for estate-declared machine authorization.

Exercise declaration validation, local OpenBao CLI operations, Tailscale SSH
transport, and transaction ordering without contacting external services.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

import mxm.control.authorize as authorization
from mxm.control.service import RegisteredService, ServiceError, ServiceTarget

_NAME = "mxm-factory-agent"
_ADDRESS = "https://openbao.tail546174.ts.net"
_ROLE_ID = "synthetic-role-id"
_WRAP_TOKEN = "synthetic-wrapping-token"

_MANIFEST = """\
[authorization]
provider = "openbao"
service = "openbao"
machine = "mxm-factory-agent"
user = "mxm"
approle = "factory-agent"
expected_policy = "factory-agent"
runtime_directory = "/run/mxm-openbao-proxy"
proxy_unit = "openbao-proxy.service"
proxy_address = "http://127.0.0.1:8201"
wrap_ttl = "10m"
"""


def _spec() -> authorization.AuthorizationSpec:
    """Return the existing factory appliance's authorization binding."""
    return authorization.AuthorizationSpec(
        service="openbao",
        machine=_NAME,
        user="mxm",
        approle="factory-agent",
        expected_policy="factory-agent",
        runtime_directory="/run/mxm-openbao-proxy",
        proxy_unit="openbao-proxy.service",
        proxy_address="http://127.0.0.1:8201",
        wrap_ttl="10m",
    )


def _manifest(root: Path, *, content: str = _MANIFEST) -> Path:
    """Write an isolated L3 authorization declaration for a test estate."""
    path = root / "stacks" / _NAME / "l3" / "authorization.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _service() -> RegisteredService:
    """Return the resolved OpenBao service without real estate discovery."""
    return RegisteredService(
        target=ServiceTarget(
            name="openbao",
            address=_ADDRESS,
            machine="mxm-security.tail546174.ts.net",
            user="mxm",
            unit="openbao.service",
        ),
        credentials=None,
    )


def _resolve_service(*, estate_root: Path, name: str) -> RegisteredService:
    """Resolve the synthetic service with the expected logical identity."""
    assert name == "openbao"
    return _service()


# ---------------------------------------------------------------------------
# Estate authorization declaration
# ---------------------------------------------------------------------------


def test_load_authorization_reads_declared_binding(tmp_path: Path) -> None:
    """Accept the agreed machine, AppRole, and proxy configuration."""
    _manifest(tmp_path)

    result = authorization.load_authorization(
        estate_root=tmp_path,
        name=_NAME,
    )

    assert result == _spec()


def test_load_authorization_requires_existing_manifest(tmp_path: Path) -> None:
    """A missing factory-agent declaration must not be inferred."""
    with pytest.raises(
        authorization.AuthorizationError,
        match="Unable to read authorization declaration",
    ):
        authorization.load_authorization(estate_root=tmp_path, name=_NAME)


def test_load_authorization_rejects_unsafe_target(tmp_path: Path) -> None:
    """The target name must not allow paths outside the estate."""
    with pytest.raises(
        authorization.AuthorizationError,
        match="Invalid authorization target name",
    ):
        authorization.load_authorization(estate_root=tmp_path, name="../other")


def test_load_authorization_rejects_symlink(tmp_path: Path) -> None:
    """Do not follow a substituted authorization declaration."""
    manifest = _manifest(tmp_path)
    other = tmp_path / "other.toml"
    other.write_text(_MANIFEST, encoding="utf-8")
    manifest.unlink()
    manifest.symlink_to(other)

    with pytest.raises(
        authorization.AuthorizationError,
        match="must not be a symlink",
    ):
        authorization.load_authorization(estate_root=tmp_path, name=_NAME)


@pytest.mark.parametrize(
    "content",
    [
        "[wrong]\nprovider = 'openbao'\n",
        _MANIFEST + "extra = 'unexpected'\n",
        _MANIFEST.replace('wrap_ttl = "10m"\n', ""),
        "[authorization\n",
    ],
)
def test_load_authorization_rejects_malformed_declaration(
    tmp_path: Path,
    content: str,
) -> None:
    """Reject unrecognized, incomplete, or unparsable estate authority."""
    _manifest(tmp_path, content=content)

    with pytest.raises(authorization.AuthorizationError):
        authorization.load_authorization(estate_root=tmp_path, name=_NAME)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ('provider = "openbao"', 'provider = "other"'),
        ('machine = "mxm-factory-agent"', 'machine = "other-machine"'),
        ('runtime_directory = "/run/mxm-openbao-proxy"', 'runtime_directory = "/tmp"'),
        (
            'runtime_directory = "/run/mxm-openbao-proxy"',
            'runtime_directory = "/run/../tmp"',
        ),
        (
            'proxy_address = "http://127.0.0.1:8201"',
            'proxy_address = "https://example.com"',
        ),
        ('proxy_unit = "openbao-proxy.service"', 'proxy_unit = "not-a-service"'),
        ('wrap_ttl = "10m"', 'wrap_ttl = "0m"'),
        ('approle = "factory-agent"', 'approle = "../../admin"'),
    ],
)
def test_load_authorization_rejects_invalid_values(
    tmp_path: Path,
    original: str,
    replacement: str,
) -> None:
    """Fail closed on undeclared identity or unsafe proxy parameters."""
    _manifest(tmp_path, content=_MANIFEST.replace(original, replacement))

    with pytest.raises(
        authorization.AuthorizationError,
        match="Invalid authorization declaration values",
    ):
        authorization.load_authorization(estate_root=tmp_path, name=_NAME)


# ---------------------------------------------------------------------------
# Subprocess and operator session boundary
# ---------------------------------------------------------------------------


def test_bao_environment_uses_resolved_endpoint_not_inherited_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the local CLI token helper without inherited bearer authority."""
    monkeypatch.setenv("BAO_TOKEN", "inherited-secret")
    monkeypatch.setenv("VAULT_TOKEN", "inherited-secret")
    monkeypatch.setenv("BAO_SKIP_VERIFY", "true")
    monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")
    monkeypatch.setenv("MXM_TEST_NON_SECRET", "preserved")

    environment = authorization._bao_environment(_ADDRESS)

    assert environment["BAO_ADDR"] == _ADDRESS
    assert environment["MXM_TEST_NON_SECRET"] == "preserved"
    for name in ("BAO_TOKEN", "VAULT_TOKEN", "BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"):
        assert name not in environment


def test_run_captures_output_and_passes_binary_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capture stdout and stderr and preserve stdin without shell execution."""
    command = ["synthetic-cli", "action"]
    payload = b"synthetic-payload"

    def fake_run(
        argv: list[str],
        *,
        input: bytes | None,
        capture_output: bool,
        env: dict[str, str] | None,
        timeout: float,
        check: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        assert argv == command
        assert input == payload
        assert capture_output is True
        assert env == {"TEST": "value"}
        assert timeout == 7.0
        assert check is False
        return subprocess.CompletedProcess(argv, 0, b"response", b"private stderr")

    monkeypatch.setattr(authorization.subprocess, "run", fake_run)

    assert (
        authorization._run(
            command,
            input_data=payload,
            environment={"TEST": "value"},
            timeout=7.0,
            failure="safe failure",
        )
        == b"response"
    )


@pytest.mark.parametrize("returncode", [1, 2])
def test_run_discards_child_error_output(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
) -> None:
    """Never incorporate potentially secret-bearing stderr into errors."""

    def fake_run(
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            ["bao"], returncode, b"private stdout", b"private stderr"
        )

    monkeypatch.setattr(authorization.subprocess, "run", fake_run)

    with pytest.raises(
        authorization.AuthorizationError, match="safe failure"
    ) as caught:
        authorization._run(["bao"], failure="safe failure")

    assert "private" not in str(caught.value)


@pytest.mark.parametrize(
    "exception",
    [FileNotFoundError("missing binary"), subprocess.TimeoutExpired(["bao"], 5)],
)
def test_run_converts_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    exception: Exception,
) -> None:
    """Wrap process startup failures and timeouts with a stable message."""

    def fake_run(
        *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        raise exception

    monkeypatch.setattr(authorization.subprocess, "run", fake_run)

    with pytest.raises(authorization.AuthorizationError, match="safe failure"):
        authorization._run(["bao"], failure="safe failure")


def test_ssh_uses_declared_machine_and_transfers_payload_on_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transport binary credentials via Tailscale SSH, never as arguments."""
    bundle = b"private bootstrap bundle"
    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        *,
        input_data: bytes | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 30.0,
        failure: str,
    ) -> bytes:
        calls.append(command)
        assert input_data == bundle
        assert timeout == 60.0
        assert failure == "Factory-appliance SSH operation failed"
        return b""

    monkeypatch.setattr(authorization, "_run", fake_run)

    authorization._ssh(_spec(), "cat >/dev/null", payload=bundle)

    assert len(calls) == 1
    assert calls[0][:3] == ["tailscale", "ssh", "mxm@mxm-factory-agent"]
    assert "bash -c" in calls[0][3]
    assert bundle.decode("ascii") not in str(calls[0])


# ---------------------------------------------------------------------------
# OpenBao AppRole bootstrap and credential delivery
# ---------------------------------------------------------------------------


def test_issue_bootstrap_reads_role_and_issues_wrapped_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue only a short-lived wrapping token, not a raw SecretID."""
    calls: list[list[str]] = []
    monkeypatch.setenv("BAO_TOKEN", "inherited-secret")

    def fake_run(
        command: list[str],
        *,
        input_data: bytes | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 30.0,
        failure: str,
    ) -> bytes:
        calls.append(command)
        assert environment is not None
        assert environment["BAO_ADDR"] == _ADDRESS
        assert "BAO_TOKEN" not in environment
        assert input_data is None
        if len(calls) == 1:
            return (_ROLE_ID + "\n").encode("ascii")
        return json.dumps({"wrap_info": {"token": _WRAP_TOKEN}}).encode("utf-8")

    monkeypatch.setattr(authorization, "_run", fake_run)

    assert authorization._issue_bootstrap(_ADDRESS, _spec()) == (
        _ROLE_ID,
        _WRAP_TOKEN,
    )
    assert calls == [
        ["bao", "read", "-field=role_id", "auth/approle/role/factory-agent/role-id"],
        [
            "bao",
            "write",
            "-wrap-ttl=10m",
            "-format=json",
            "-f",
            "auth/approle/role/factory-agent/secret-id",
        ],
    ]


@pytest.mark.parametrize(
    "response",
    [b"not-json", b"[]", b"{}", b'{"wrap_info": {}}'],
)
def test_issue_bootstrap_rejects_missing_wrapping_token(
    monkeypatch: pytest.MonkeyPatch,
    response: bytes,
) -> None:
    """Reject malformed wrapping replies before any delivery occurs."""
    calls = 0

    def fake_run(
        command: list[str],
        *,
        input_data: bytes | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 30.0,
        failure: str,
    ) -> bytes:
        nonlocal calls
        calls += 1
        return _ROLE_ID.encode("ascii") if calls == 1 else response

    monkeypatch.setattr(authorization, "_run", fake_run)

    with pytest.raises(authorization.AuthorizationError):
        authorization._issue_bootstrap(_ADDRESS, _spec())
    assert calls == 2


def test_archive_bootstrap_contains_only_transient_credentials() -> None:
    """Build exactly two restrictive files in an in-memory TAR bundle."""
    bundle = authorization._archive_bootstrap(_ROLE_ID, _WRAP_TOKEN)

    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:") as archive:
        assert archive.getnames() == ["role-id", "secret-id"]
        role = archive.getmember("role-id")
        wrapped = archive.getmember("secret-id")
        assert role.mode == 0o600
        assert wrapped.mode == 0o600
        role_stream = archive.extractfile(role)
        wrapped_stream = archive.extractfile(wrapped)
        assert role_stream is not None
        assert wrapped_stream is not None
        assert role_stream.read() == (_ROLE_ID + "\n").encode("ascii")
        assert wrapped_stream.read() == (_WRAP_TOKEN + "\n").encode("ascii")


def test_preflight_checks_existing_proxy_before_credential_issuance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Require the existing proxy unit and local verification tools."""
    scripts: list[str] = []

    def fake_ssh(
        spec: authorization.AuthorizationSpec,
        script: str,
        *,
        payload: bytes | None = None,
    ) -> bytes:
        assert spec == _spec()
        assert payload is None
        scripts.append(script)
        return b""

    monkeypatch.setattr(authorization, "_ssh", fake_ssh)
    authorization._preflight(_spec())

    assert len(scripts) == 1
    assert "systemctl cat openbao-proxy.service" in scripts[0]
    assert "command -v curl" in scripts[0]
    assert "command -v jq" in scripts[0]


def test_deliver_and_restart_installs_volatile_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transfer the TAR bundle and restart only the declared proxy service."""
    bundle = b"private archive"
    scripts: list[str] = []

    def fake_ssh(
        spec: authorization.AuthorizationSpec,
        script: str,
        *,
        payload: bytes | None = None,
    ) -> bytes:
        assert spec == _spec()
        assert payload == bundle
        scripts.append(script)
        return b""

    monkeypatch.setattr(authorization, "_ssh", fake_ssh)
    authorization._deliver_and_restart(_spec(), bundle)

    assert len(scripts) == 1
    assert "sudo -n install -d" in scripts[0]
    assert "--directory=/run/mxm-openbao-proxy" in scripts[0]
    assert "chmod 0600" in scripts[0]
    assert "sudo -n systemctl restart openbao-proxy.service" in scripts[0]
    assert bundle.decode("ascii") not in scripts[0]


def test_verify_checks_effective_policy_and_consumed_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify authentication, wrapping consumption, and running service."""
    scripts: list[str] = []

    def fake_ssh(
        spec: authorization.AuthorizationSpec,
        script: str,
        *,
        payload: bytes | None = None,
    ) -> bytes:
        assert spec == _spec()
        scripts.append(script)
        return b""

    monkeypatch.setattr(authorization, "_ssh", fake_ssh)
    authorization._verify(_spec())

    assert len(scripts) == 1
    assert "127.0.0.1:8201/v1/auth/token/lookup-self" in scripts[0]
    assert "factory-agent" in scripts[0]
    assert "test ! -e /run/mxm-openbao-proxy/secret-id" in scripts[0]
    assert "test -s /run/mxm-openbao-proxy/role-id" in scripts[0]
    assert "systemctl is-active --quiet openbao-proxy.service" in scripts[0]


# ---------------------------------------------------------------------------
# Transaction sequencing
# ---------------------------------------------------------------------------


def test_authorize_machine_completes_transaction_in_order(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Resolve, preflight, issue, deliver, and verify exactly once."""
    _manifest(tmp_path)
    calls: list[str] = []

    def fake_resolve(*, estate_root: Path, name: str) -> RegisteredService:
        assert estate_root == tmp_path
        assert name == "openbao"
        calls.append("resolve")
        return _service()

    def fake_preflight(spec: authorization.AuthorizationSpec) -> None:
        assert spec == _spec()
        calls.append("preflight")

    def fake_issue(
        address: str, spec: authorization.AuthorizationSpec
    ) -> tuple[str, str]:
        assert address == _ADDRESS
        assert spec == _spec()
        calls.append("issue")
        return _ROLE_ID, _WRAP_TOKEN

    def fake_deliver(spec: authorization.AuthorizationSpec, bundle: bytes) -> None:
        assert spec == _spec()
        assert bundle == authorization._archive_bootstrap(_ROLE_ID, _WRAP_TOKEN)
        calls.append("deliver")

    def fake_verify(spec: authorization.AuthorizationSpec) -> None:
        assert spec == _spec()
        calls.append("verify")

    monkeypatch.setattr(authorization, "resolve_service", fake_resolve)
    monkeypatch.setattr(authorization, "_preflight", fake_preflight)
    monkeypatch.setattr(authorization, "_issue_bootstrap", fake_issue)
    monkeypatch.setattr(authorization, "_deliver_and_restart", fake_deliver)
    monkeypatch.setattr(authorization, "_verify", fake_verify)

    authorization.authorize_machine(estate_root=tmp_path, name=_NAME)

    assert calls == ["resolve", "preflight", "issue", "deliver", "verify"]


def test_authorize_machine_stops_if_service_cannot_be_resolved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Never issue bootstrap authority if OpenBao discovery fails."""
    _manifest(tmp_path)

    def failing_resolve(*, estate_root: Path, name: str) -> RegisteredService:
        raise ServiceError("synthetic discovery failure")

    def forbidden_preflight(spec: authorization.AuthorizationSpec) -> None:
        pytest.fail("Discovery failure must prevent the transaction")

    monkeypatch.setattr(authorization, "resolve_service", failing_resolve)
    monkeypatch.setattr(authorization, "_preflight", forbidden_preflight)

    with pytest.raises(
        authorization.AuthorizationError,
        match="Unable to resolve OpenBao service",
    ):
        authorization.authorize_machine(estate_root=tmp_path, name=_NAME)


def test_authorize_machine_does_not_issue_after_failed_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not mint a SecretID if the existing proxy is not ready."""
    _manifest(tmp_path)
    monkeypatch.setattr(authorization, "resolve_service", _resolve_service)

    def failing_preflight(spec: authorization.AuthorizationSpec) -> None:
        raise authorization.AuthorizationError("proxy service unavailable")

    def forbidden_issue(
        address: str, spec: authorization.AuthorizationSpec
    ) -> tuple[str, str]:
        pytest.fail("Preflight failure must prevent SecretID issuance")

    monkeypatch.setattr(authorization, "_preflight", failing_preflight)
    monkeypatch.setattr(authorization, "_issue_bootstrap", forbidden_issue)

    with pytest.raises(
        authorization.AuthorizationError, match="proxy service unavailable"
    ):
        authorization.authorize_machine(estate_root=tmp_path, name=_NAME)


def test_authorize_machine_never_verifies_after_failed_delivery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not claim successful authorization after unsuccessful delivery."""
    _manifest(tmp_path)
    monkeypatch.setattr(authorization, "resolve_service", _resolve_service)

    def fake_preflight(spec: authorization.AuthorizationSpec) -> None:
        assert spec == _spec()

    def fake_issue(
        address: str,
        spec: authorization.AuthorizationSpec,
    ) -> tuple[str, str]:
        assert address == _ADDRESS
        assert spec == _spec()
        return _ROLE_ID, _WRAP_TOKEN

    monkeypatch.setattr(authorization, "_preflight", fake_preflight)
    monkeypatch.setattr(authorization, "_issue_bootstrap", fake_issue)

    def failing_delivery(spec: authorization.AuthorizationSpec, bundle: bytes) -> None:
        raise authorization.AuthorizationError("SSH delivery failed")

    def forbidden_verify(spec: authorization.AuthorizationSpec) -> None:
        pytest.fail("Failed delivery must not report verified authorization")

    monkeypatch.setattr(authorization, "_deliver_and_restart", failing_delivery)
    monkeypatch.setattr(authorization, "_verify", forbidden_verify)

    with pytest.raises(authorization.AuthorizationError, match="SSH delivery failed"):
        authorization.authorize_machine(estate_root=tmp_path, name=_NAME)
