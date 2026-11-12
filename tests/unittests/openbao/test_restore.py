"""Unit tests for estate-managed OpenBao Raft snapshot restoration.

Exercise the complete operator verb, appliance recovery coordinator, and
single-request HTTPS transport. External services are replaced with typed
fakes; local snapshot staging and checksum verification use real files.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import ssl
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

import mxm.control.openbao.restore as restore_module
from mxm.control.openbao.api import OpenBaoError
from mxm.control.openbao.initialise import OpenBaoInitialization
from mxm.control.openbao.restore import (
    OpenBaoRecoveryResult,
    OpenBaoRestorePlan,
    OpenBaoRestoreResult,
    OpenBaoRestoreUncertainError,
    restore_raft_snapshot,
)
from mxm.control.openbao.status import OpenBaoStatus
from mxm.control.openbao.unseal import OpenBaoUnsealResult, ShareProvider
from mxm.control.service import RegisteredService, ServiceError, ServiceTarget
from mxm.control.snapshot import SnapshotError

ADDRESS = "https://openbao.example.test"
TOKEN = "synthetic-restore-token"
SNAPSHOT_DATA = b"synthetic-openbao-raft-snapshot"
BOOTSTRAP_SHARE = "synthetic-temporary-share"
BOOTSTRAP_TOKEN = "synthetic-temporary-root-token"


def _digest(data: bytes = SNAPSHOT_DATA) -> str:
    """Hash the bytes of a synthetic Raft snapshot."""
    return hashlib.sha256(data).hexdigest()


def _snapshot(tmp_path: Path, data: bytes = SNAPSHOT_DATA) -> Path:
    """Write a synthetic snapshot to an isolated local file."""
    path = tmp_path / "openbao.snap"
    path.write_bytes(data)
    return path


def _status(*, initialized: bool = True, sealed: bool = False) -> OpenBaoStatus:
    """Return a synthetic seal-status response."""
    return OpenBaoStatus(
        initialized=initialized,
        sealed=sealed,
        version="2.6.5",
        seal_type="shamir",
        shares=3 if initialized else 0,
        threshold=2 if initialized else 0,
        progress=0,
    )


def _bootstrap() -> OpenBaoInitialization:
    """Return synthetic temporary 1-of-1 authority."""
    return OpenBaoInitialization(
        unseal_keys=(BOOTSTRAP_SHARE,),
        root_token=BOOTSTRAP_TOKEN,
    )


def _recovery_result(
    *,
    shares: int = 3,
    threshold: int = 2,
) -> OpenBaoRecoveryResult:
    """Construct a confirmed synthetic recovery result."""
    return OpenBaoRecoveryResult(
        restore=OpenBaoRestoreResult(
            sha256=_digest(),
            size=len(SNAPSHOT_DATA),
            forced=True,
        ),
        shares=shares,
        threshold=threshold,
    )


class FakeResponse:
    """Bounded, recording HTTP response."""

    def __init__(self, *, status: int = 200, payload: bytes = b"") -> None:
        self.status = status
        self.payload = payload
        self.read_limit: int | None = None

    def read(self, amount: int) -> bytes:
        """Record the requested maximum response length."""
        self.read_limit = amount
        return self.payload[:amount]


class FakeConnection:
    """HTTPS connection recording requests without contacting the network."""

    def __init__(
        self,
        response: FakeResponse,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.response = response
        self.failure = failure
        self.requests: list[tuple[str, str]] = []
        self.headers: list[tuple[str, str]] = []
        self.uploaded = bytearray()
        self.send_calls = 0
        self.response_requests = 0
        self.headers_finished = False
        self.closed = False

    def putrequest(self, method: str, path: str) -> None:
        """Record a requested endpoint."""
        self.requests.append((method, path))

    def putheader(self, name: str, value: str) -> None:
        """Record one request header."""
        self.headers.append((name, value))

    def endheaders(self) -> None:
        """Optionally simulate a failure after dispatch begins."""
        self.headers_finished = True
        if self.failure is not None:
            raise self.failure

    def send(self, data: bytes) -> None:
        """Record binary body chunks."""
        self.send_calls += 1
        self.uploaded.extend(data)

    def getresponse(self) -> FakeResponse:
        """Return the configured response."""
        self.response_requests += 1
        return self.response

    def close(self) -> None:
        """Record connection cleanup."""
        self.closed = True


def _mock_status(
    monkeypatch: pytest.MonkeyPatch,
    *,
    initialized: bool = True,
    sealed: bool = False,
) -> list[tuple[str, float]]:
    """Mock one stable OpenBao status and return the recorded requests."""
    calls: list[tuple[str, float]] = []

    def fake_status(address: str, *, timeout: float = 10.0) -> OpenBaoStatus:
        calls.append((address, timeout))
        return _status(initialized=initialized, sealed=sealed)

    monkeypatch.setattr(restore_module, "status_openbao", fake_status)
    return calls


def _mock_connection(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: int = 200,
    payload: bytes = b"",
    failure: Exception | None = None,
    port: int = 443,
    timeout: float = 120.0,
) -> FakeConnection:
    """Install typed HTTPS transport with TLS and parameter assertions."""
    connection = FakeConnection(
        FakeResponse(status=status, payload=payload),
        failure=failure,
    )

    def fake_https_connection(
        host: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> FakeConnection:
        assert host == "openbao.example.test"
        assert port == expected_port
        assert timeout == expected_timeout
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        return connection

    expected_port = port
    expected_timeout = timeout
    monkeypatch.setattr(
        restore_module.http.client,
        "HTTPSConnection",
        fake_https_connection,
    )
    return connection


# ---------------------------------------------------------------------------
# Authenticated Raft snapshot transport
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("status", [200, 204])
def test_raft_restore_submits_one_authenticated_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    force: bool,
    status: int,
) -> None:
    """Validate checksums, stream binary bytes and select the restore mode."""
    snapshot = _snapshot(tmp_path)
    statuses = _mock_status(monkeypatch)
    connection = _mock_connection(monkeypatch, status=status)

    result = restore_raft_snapshot(
        f"{ADDRESS}/",
        snapshot=snapshot,
        token=TOKEN,
        force=force,
        expected_sha256=_digest(),
    )

    endpoint = "/v1/sys/storage/raft/snapshot"
    if force:
        endpoint += "-force"

    assert result == OpenBaoRestoreResult(
        sha256=_digest(),
        size=len(SNAPSHOT_DATA),
        forced=force,
    )
    assert statuses == [(ADDRESS, 120.0)]
    assert connection.requests == [("POST", endpoint)]
    assert bytes(connection.uploaded) == SNAPSHOT_DATA
    assert connection.response_requests == 1
    assert connection.closed is True
    assert connection.headers_finished is True
    assert dict(connection.headers) == {
        "X-Vault-Token": TOKEN,
        "X-Vault-Request": "true",
        "Content-Type": "application/octet-stream",
        "Accept": "application/json",
        "Content-Length": str(len(SNAPSHOT_DATA)),
    }


def test_raft_restore_forwards_explicit_port_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Use a configured HTTPS port and timeout for the request."""
    statuses = _mock_status(monkeypatch)
    connection = _mock_connection(monkeypatch, port=8200, timeout=15.0)

    restore_raft_snapshot(
        f"{ADDRESS}:8200",
        snapshot=_snapshot(tmp_path),
        token=TOKEN,
        timeout=15.0,
    )

    assert statuses == [(f"{ADDRESS}:8200", 15.0)]
    assert len(connection.requests) == 1


def test_raft_restore_streams_in_bounded_chunks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Never buffer a large snapshot as a single HTTP body."""
    data = b"x" * (restore_module._CHUNK_SIZE * 2 + 17)
    _mock_status(monkeypatch)
    connection = _mock_connection(monkeypatch)

    result = restore_raft_snapshot(
        ADDRESS,
        snapshot=_snapshot(tmp_path, data),
        token=TOKEN,
    )

    assert result.sha256 == _digest(data)
    assert result.size == len(data)
    assert connection.send_calls == 3
    assert bytes(connection.uploaded) == data


def test_snapshot_checksum_and_validation(tmp_path: Path) -> None:
    """Hash the complete snapshot and rewind the stream before upload."""
    data = b"0123456789ABCDEF" * 10000
    snapshot = _snapshot(tmp_path, data)

    with snapshot.open("rb") as stream:
        assert restore_module._snapshot_checksum(stream) == _digest(data)
        assert stream.tell() == 0
        size, checksum = restore_module._validate_snapshot(
            stream,
            _digest(data).upper(),
        )

    assert (size, checksum) == (len(data), _digest(data))


@pytest.mark.parametrize(
    ("source", "expected_error"),
    [
        ("missing", "unable to open restore snapshot"),
        ("directory", "unable to open restore snapshot"),
        ("empty", "must not be empty"),
        ("mismatch", "SHA-256 mismatch"),
    ],
)
def test_raft_restore_rejects_invalid_snapshot_before_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
    expected_error: str,
) -> None:
    """Never inspect or mutate the appliance with invalid snapshot bytes."""
    snapshot = tmp_path / "openbao.snap"
    if source == "directory":
        snapshot.mkdir()
    elif source == "empty":
        snapshot.write_bytes(b"")
    elif source == "mismatch":
        snapshot.write_bytes(SNAPSHOT_DATA)

    def forbidden_status(address: str, *, timeout: float = 10.0) -> OpenBaoStatus:
        pytest.fail("invalid snapshot must fail before network preflight")

    monkeypatch.setattr(restore_module, "status_openbao", forbidden_status)

    with pytest.raises(OpenBaoError, match=expected_error):
        restore_raft_snapshot(
            ADDRESS,
            snapshot=snapshot,
            token=TOKEN,
            expected_sha256="0" * 64 if source == "mismatch" else None,
        )


@pytest.mark.parametrize(
    "token",
    ["", " ", "token with spaces", "token\nnext", "token\tvalue", "a\x00b", "tökén"],
)
def test_raft_restore_rejects_invalid_token(token: str) -> None:
    """Never place malformed credentials into HTTP headers."""
    with pytest.raises(OpenBaoError, match="invalid OpenBao restore token"):
        restore_module._validate_restore_parameters(token, None, 120.0)


@pytest.mark.parametrize(
    "checksum",
    ["", "abc", "0" * 63, "0" * 65, "g" * 64, "0" * 32 + "z" * 32],
)
def test_raft_restore_rejects_invalid_digest(checksum: str) -> None:
    """Require exactly 64 hexadecimal checksum characters."""
    with pytest.raises(OpenBaoError, match="expected SHA-256"):
        restore_module._validate_restore_parameters(TOKEN, checksum, 120.0)


@pytest.mark.parametrize(
    "timeout",
    [0.0, -1.0, float("inf"), float("-inf"), float("nan")],
)
def test_raft_restore_rejects_invalid_timeout(timeout: float) -> None:
    """Accept only finite, positive network deadlines."""
    with pytest.raises(OpenBaoError, match="timeout"):
        restore_module._validate_restore_parameters(TOKEN, None, timeout)


def test_raft_restore_requires_https(tmp_path: Path) -> None:
    """Reject HTTP even when supplied with a valid local snapshot."""
    with pytest.raises(OpenBaoError, match="HTTPS service origin"):
        restore_raft_snapshot(
            "http://openbao.example.test",
            snapshot=_snapshot(tmp_path),
            token=TOKEN,
        )


@pytest.mark.parametrize(
    ("initialized", "sealed", "expected_error"),
    [
        (False, False, "must be initialized"),
        (True, True, "must be unsealed"),
    ],
)
def test_raft_restore_requires_initialized_unsealed_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    initialized: bool,
    sealed: bool,
    expected_error: str,
) -> None:
    """Preflight target seal state before submitting snapshot bytes."""
    statuses = _mock_status(
        monkeypatch,
        initialized=initialized,
        sealed=sealed,
    )
    with pytest.raises(OpenBaoError, match=expected_error):
        restore_raft_snapshot(
            ADDRESS,
            snapshot=_snapshot(tmp_path),
            token=TOKEN,
        )
    assert len(statuses) == 1


def test_raft_restore_status_failure_prevents_submission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A failed preflight must not dispatch a destructive request."""

    def failing_status(address: str, *, timeout: float = 10.0) -> OpenBaoStatus:
        raise OpenBaoError("status unavailable")

    monkeypatch.setattr(restore_module, "status_openbao", failing_status)
    with pytest.raises(OpenBaoError, match="status unavailable"):
        restore_raft_snapshot(
            ADDRESS,
            snapshot=_snapshot(tmp_path),
            token=TOKEN,
        )


@pytest.mark.parametrize("http_status", [201, 301, 302, 400, 403, 409, 429, 500, 503])
def test_raft_restore_unexpected_response_is_uncertain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    http_status: int,
) -> None:
    """Report a potentially modified authority after a non-success reply."""
    _mock_status(monkeypatch)
    connection = _mock_connection(
        monkeypatch,
        status=http_status,
        payload=b"server-private-response",
    )
    with pytest.raises(OpenBaoRestoreUncertainError) as caught:
        restore_raft_snapshot(
            ADDRESS,
            snapshot=_snapshot(tmp_path),
            token=TOKEN,
        )
    assert len(connection.requests) == 1
    assert connection.closed is True
    assert TOKEN not in str(caught.value)
    assert "server-private-response" not in str(caught.value)


@pytest.mark.parametrize(
    "failure",
    [
        OSError("connection reset"),
        TimeoutError("request timed out"),
        http.client.HTTPException("invalid response"),
    ],
)
def test_raft_restore_transport_failure_is_uncertain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: Exception,
) -> None:
    """Do not retry after the snapshot request has been dispatched."""
    _mock_status(monkeypatch)
    connection = _mock_connection(monkeypatch, failure=failure)
    with pytest.raises(OpenBaoRestoreUncertainError, match="outcome is uncertain"):
        restore_raft_snapshot(
            ADDRESS,
            snapshot=_snapshot(tmp_path),
            token=TOKEN,
        )
    assert len(connection.requests) == 1
    assert connection.closed is True


def test_raft_restore_rejects_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Limit response buffering after destructive submission."""
    _mock_status(monkeypatch)
    connection = _mock_connection(
        monkeypatch,
        payload=b"x" * (restore_module._MAX_RESPONSE_BYTES + 1),
    )
    with pytest.raises(OpenBaoRestoreUncertainError, match="size limit"):
        restore_raft_snapshot(
            ADDRESS,
            snapshot=_snapshot(tmp_path),
            token=TOKEN,
        )
    assert connection.response.read_limit == restore_module._MAX_RESPONSE_BYTES + 1
    assert connection.closed is True


def test_raft_restore_rejects_short_upload() -> None:
    """Never accept a body shorter than the advertised Content-Length."""
    connection = FakeConnection(FakeResponse())
    with pytest.raises(OpenBaoRestoreUncertainError, match="changed during upload"):
        restore_module._send_snapshot(
            connection,
            io.BytesIO(b"abc"),
            size=10,
            token=TOKEN,
            force=False,
        )
    assert bytes(connection.uploaded) == b"abc"
    assert connection.response_requests == 0


def test_raft_restore_never_retries_and_closes_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """One uncertain submission leaves the opened snapshot closed."""
    _mock_status(monkeypatch)
    streams: list[io.BufferedReader] = []

    def failing_submit(
        address: str,
        stream: io.BufferedReader,
        *,
        size: int,
        token: str,
        force: bool,
        timeout: float,
    ) -> None:
        streams.append(stream)
        raise OpenBaoRestoreUncertainError("outcome uncertain")

    monkeypatch.setattr(restore_module, "_submit_restore", failing_submit)
    with pytest.raises(OpenBaoRestoreUncertainError):
        restore_raft_snapshot(
            ADDRESS,
            snapshot=_snapshot(tmp_path),
            token=TOKEN,
        )
    assert len(streams) == 1
    assert streams[0].closed is True


# ---------------------------------------------------------------------------
# Appliance-level recovery from a verified local snapshot
# ---------------------------------------------------------------------------


def _mock_recovery_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
    *,
    final_status: OpenBaoStatus | None = None,
    failure: str | None = None,
) -> None:
    """Record status, initialization, unseal, restore and verification order."""
    statuses = iter(
        [
            _status(initialized=False),
            final_status if final_status is not None else _status(sealed=True),
        ]
    )

    def fake_status(address: str, *, timeout: float = 10.0) -> OpenBaoStatus:
        assert address == ADDRESS
        assert timeout == 120.0
        events.append("status")
        return next(statuses)

    def fake_initialise(
        address: str,
        *,
        shares: int,
        threshold: int,
        timeout: float = 10.0,
    ) -> OpenBaoInitialization:
        assert (address, shares, threshold, timeout) == (ADDRESS, 1, 1, 120.0)
        events.append("initialise")
        return _bootstrap()

    def fake_unseal(
        address: str,
        *,
        get_share: ShareProvider,
        timeout: float = 10.0,
    ) -> OpenBaoUnsealResult:
        assert (address, timeout) == (ADDRESS, 120.0)
        events.append("unseal")
        if failure == "temporary unseal":
            raise OpenBaoError("temporary unseal failed")
        assert get_share(1, 1) == BOOTSTRAP_SHARE
        return OpenBaoUnsealResult(
            sealed=False,
            progress=0,
            shares=1,
            threshold=1,
        )

    def fake_restore(
        address: str,
        *,
        snapshot: Path,
        token: str,
        force: bool = False,
        expected_sha256: str | None = None,
        timeout: float = 120.0,
    ) -> OpenBaoRestoreResult:
        assert address == ADDRESS
        assert snapshot.is_file()
        assert token == BOOTSTRAP_TOKEN
        assert force is True
        assert expected_sha256 == _digest()
        assert timeout == 120.0
        events.append("restore")
        if failure == "snapshot restoration":
            raise OpenBaoRestoreUncertainError("snapshot outcome uncertain")
        return _recovery_result().restore

    monkeypatch.setattr(restore_module, "status_openbao", fake_status)
    monkeypatch.setattr(restore_module, "initialise_openbao", fake_initialise)
    monkeypatch.setattr(restore_module, "unseal_openbao", fake_unseal)
    monkeypatch.setattr(restore_module, "restore_raft_snapshot", fake_restore)


def _restart_for(events: list[str], *, failure: bool = False) -> Callable[[], None]:
    """Return a fully typed restart callback."""

    def restart() -> None:
        events.append("restart")
        if failure:
            raise RuntimeError("restart unavailable")

    return restart


def _no_restart() -> None:
    """No-op callback for preflight tests that never reach restart."""


def _recover(
    snapshot: Path,
    events: list[str],
    *,
    expected_shares: int = 3,
    expected_threshold: int = 2,
    restart_fails: bool = False,
    address: str = ADDRESS,
) -> OpenBaoRecoveryResult:
    """Call the appliance-level capability with synthetic authority."""
    return restore_module.restore_openbao_snapshot(
        address,
        snapshot=snapshot,
        expected_sha256=_digest(),
        restart=_restart_for(events, failure=restart_fails),
        expected_shares=expected_shares,
        expected_threshold=expected_threshold,
    )


def test_recovery_snapshot_completes_in_order(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Recover an existing authority using only temporary Shamir credentials."""
    events: list[str] = []
    _mock_recovery_lifecycle(monkeypatch, events)
    result = _recover(_snapshot(tmp_path), events, address=f"{ADDRESS}/")

    assert events == [
        "status",
        "initialise",
        "unseal",
        "restore",
        "restart",
        "status",
    ]
    assert result == _recovery_result()
    assert not hasattr(result, "authority")
    assert BOOTSTRAP_TOKEN not in repr(result)
    assert BOOTSTRAP_SHARE not in repr(result)
    assert events.count("unseal") == 1


def test_recovery_snapshot_accepts_custom_original_seal_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify caller-supplied original 5-of-3 seal parameters."""
    events: list[str] = []
    final = replace(_status(sealed=True), shares=5, threshold=3)
    _mock_recovery_lifecycle(monkeypatch, events, final_status=final)
    result = _recover(
        _snapshot(tmp_path),
        events,
        expected_shares=5,
        expected_threshold=3,
    )
    assert (result.shares, result.threshold) == (5, 3)


@pytest.mark.parametrize(
    ("shares", "threshold"),
    [(0, 0), (0, 1), (1, 0), (2, 3), (256, 1), (-1, 1)],
)
def test_recovery_rejects_invalid_original_seal_configuration(
    shares: int,
    threshold: int,
) -> None:
    """Require valid Shamir parameters before any OpenBao mutation."""
    with pytest.raises(OpenBaoError, match="recovery requires"):
        restore_module._validate_recovery_configuration(
            shares=shares,
            threshold=threshold,
            timeout=120.0,
        )


@pytest.mark.parametrize(
    "timeout",
    [0.0, -1.0, float("inf"), float("-inf"), float("nan")],
)
def test_recovery_rejects_invalid_timeout(timeout: float) -> None:
    """Recovery cannot accept invalid network deadlines."""
    with pytest.raises(OpenBaoError, match="timeout"):
        restore_module._validate_recovery_configuration(
            shares=3,
            threshold=2,
            timeout=timeout,
        )


@pytest.mark.parametrize("source", ["missing", "corrupt"])
def test_recovery_rejects_snapshot_before_status_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
) -> None:
    """Checksum and file validation precede all appliance state changes."""
    snapshot = tmp_path / "openbao.snap"
    if source == "corrupt":
        snapshot.write_bytes(SNAPSHOT_DATA)

    def forbidden_status(address: str, *, timeout: float = 10.0) -> OpenBaoStatus:
        pytest.fail("invalid snapshot must not contact the destination")

    monkeypatch.setattr(restore_module, "status_openbao", forbidden_status)
    with pytest.raises(OpenBaoError):
        restore_module.restore_openbao_snapshot(
            ADDRESS,
            snapshot=snapshot,
            expected_sha256="0" * 64 if source == "corrupt" else _digest(),
            restart=_no_restart,
        )


def test_recovery_refuses_initialized_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Never initialize a target already holding authoritative state."""
    events: list[str] = []

    def initialized_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> OpenBaoStatus:
        events.append("status")
        return _status(initialized=True)

    def forbidden_initialise(
        address: str,
        *,
        shares: int,
        threshold: int,
        timeout: float = 10.0,
    ) -> OpenBaoInitialization:
        pytest.fail("initialized destination must not be modified")

    monkeypatch.setattr(restore_module, "status_openbao", initialized_status)
    monkeypatch.setattr(restore_module, "initialise_openbao", forbidden_initialise)
    with pytest.raises(OpenBaoError, match="requires an uninitialized"):
        _recover(_snapshot(tmp_path), events)
    assert events == ["status"]


def test_recovery_status_error_prevents_initialization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An unavailable status endpoint is not permission to initialize."""

    def failing_status(address: str, *, timeout: float = 10.0) -> OpenBaoStatus:
        raise OpenBaoError("status unavailable")

    monkeypatch.setattr(restore_module, "status_openbao", failing_status)
    with pytest.raises(OpenBaoError, match="status unavailable"):
        restore_module.restore_openbao_snapshot(
            ADDRESS,
            snapshot=_snapshot(tmp_path),
            expected_sha256=_digest(),
            restart=_no_restart,
        )


@pytest.mark.parametrize(
    "failure",
    ["temporary unseal", "snapshot restoration", "appliance restart"],
)
def test_recovery_interruption_reports_phase_without_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    """Report the failed recovery phase without retaining bootstrap credentials."""
    events: list[str] = []
    _mock_recovery_lifecycle(monkeypatch, events, failure=failure)

    with pytest.raises(restore_module.OpenBaoRecoveryInterruptedError) as caught:
        _recover(
            _snapshot(tmp_path),
            events,
            restart_fails=failure == "appliance restart",
        )

    assert caught.value.phase == failure
    assert not hasattr(caught.value, "authority")
    assert BOOTSTRAP_TOKEN not in str(caught.value)
    assert BOOTSTRAP_SHARE not in repr(caught.value)
    assert events.count("initialise") == 1
    assert events.count("restore") <= 1
    assert events.count("restart") <= 1


@pytest.mark.parametrize(
    "final",
    [
        _status(initialized=False, sealed=True),
        _status(initialized=True, sealed=False),
        replace(_status(sealed=True), shares=1, threshold=1),
        replace(_status(sealed=True), seal_type="transit"),
    ],
)
def test_recovery_rejects_unexpected_restored_seal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    final: OpenBaoStatus,
) -> None:
    """Require initialized, sealed, matching original Shamir metadata."""
    events: list[str] = []
    _mock_recovery_lifecycle(monkeypatch, events, final_status=final)
    with pytest.raises(restore_module.OpenBaoRecoveryInterruptedError) as caught:
        _recover(_snapshot(tmp_path), events)
    assert caught.value.phase == "post-restore verification"
    assert not hasattr(caught.value, "authority")
    assert events[-2:] == ["restart", "status"]


def test_recovery_postrestore_status_failure_is_interrupted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Propagate an unknown post-restart status as uncertain recovery."""
    events: list[str] = []
    _mock_recovery_lifecycle(monkeypatch, events)

    def failing_verify(
        address: str,
        *,
        shares: int,
        threshold: int,
        timeout: float,
    ) -> None:
        events.append("verify")
        raise OpenBaoError("restored endpoint unavailable")

    monkeypatch.setattr(restore_module, "_verify_recovered_seal", failing_verify)
    with pytest.raises(restore_module.OpenBaoRecoveryInterruptedError) as caught:
        _recover(_snapshot(tmp_path), events)
    assert caught.value.phase == "post-restore verification"
    assert not hasattr(caught.value, "authority")
    assert events[-2:] == ["restart", "verify"]


def test_recovery_error_hierarchy_and_secret_safety() -> None:
    """Interruption errors report phases without retaining credentials."""
    error = restore_module.OpenBaoRecoveryInterruptedError("snapshot restoration")

    assert isinstance(error, OpenBaoError)
    assert isinstance(error, RuntimeError)
    assert isinstance(OpenBaoRestoreUncertainError("uncertain"), OpenBaoError)
    assert error.phase == "snapshot restoration"
    assert not hasattr(error, "authority")
    assert BOOTSTRAP_TOKEN not in str(error)
    assert BOOTSTRAP_SHARE not in repr(error)


# ---------------------------------------------------------------------------
# Top-level estate-managed operator verb
# ---------------------------------------------------------------------------


def _target() -> ServiceTarget:
    """Return a resolved, synthetic estate-managed OpenBao service."""
    return ServiceTarget(
        name="openbao",
        address=ADDRESS,
        machine="mxm-security.example.test",
        user="mxm",
        unit="openbao.service",
    )


def _mock_target(
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> ServiceTarget:
    """Install typed estate-resolution and OpenBao restart fakes."""
    target = _target()

    def fake_resolve(
        *,
        estate_root: Path,
        name: str,
    ) -> RegisteredService:
        assert estate_root.is_dir()
        assert name == "openbao"
        events.append("resolve")
        return RegisteredService(
            target=target,
            credentials=None,
        )

    def fake_restart(service_target: ServiceTarget) -> None:
        assert service_target == target
        events.append("restart")

    monkeypatch.setattr(restore_module, "resolve_service", fake_resolve)
    monkeypatch.setattr(restore_module, "restart_openbao", fake_restart)
    return target


def test_restore_openbao_coordinates_estate_snapshot_and_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Resolve target, stage with SHA-256, authorize, recover, then clean up."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    source = _snapshot(tmp_path)
    events: list[str] = []
    target = _mock_target(monkeypatch, events)
    staged_paths: list[Path] = []
    plans: list[OpenBaoRestorePlan] = []

    def authorize(plan: OpenBaoRestorePlan) -> bool:
        events.append("authorize")
        plans.append(plan)
        assert plan.address == target.address
        assert plan.machine == target.machine
        assert plan.snapshot_source == str(source)
        assert plan.snapshot_size == len(SNAPSHOT_DATA)
        assert plan.snapshot_sha256 == _digest()
        assert (plan.expected_shares, plan.expected_threshold) == (5, 3)
        return True

    def fake_recovery(
        address: str,
        *,
        snapshot: Path,
        expected_sha256: str,
        restart: Callable[[], None],
        expected_shares: int = 3,
        expected_threshold: int = 2,
        timeout: float = 120.0,
    ) -> OpenBaoRecoveryResult:
        events.append("recovery")
        assert address == ADDRESS
        assert snapshot != source
        assert snapshot.is_file()
        assert snapshot.read_bytes() == SNAPSHOT_DATA
        assert expected_sha256 == _digest()
        assert (expected_shares, expected_threshold, timeout) == (5, 3, 45.0)
        staged_paths.append(snapshot)
        restart()
        return _recovery_result(shares=5, threshold=3)

    monkeypatch.setattr(
        restore_module,
        "restore_openbao_snapshot",
        fake_recovery,
    )

    result = restore_module.restore_openbao(
        estate_root=root,
        snapshot_uri=str(source),
        authorize=authorize,
        expected_shares=5,
        expected_threshold=3,
        timeout=45.0,
    )

    assert result == _recovery_result(shares=5, threshold=3)
    assert events == ["resolve", "authorize", "recovery", "restart"]
    assert len(plans) == 1
    assert len(staged_paths) == 1
    assert not staged_paths[0].exists()
    assert source.is_file()


def test_restore_openbao_rejects_refused_authorization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Authorization refusal never reaches appliance mutation."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    source = _snapshot(tmp_path)
    events: list[str] = []
    _mock_target(monkeypatch, events)

    def refuse(plan: OpenBaoRestorePlan) -> bool:
        events.append("refuse")
        assert plan.snapshot_sha256 == _digest()
        return False

    def forbidden_recovery(
        address: str,
        *,
        snapshot: Path,
        expected_sha256: str,
        restart: Callable[[], None],
        expected_shares: int = 3,
        expected_threshold: int = 2,
        timeout: float = 120.0,
    ) -> OpenBaoRecoveryResult:
        pytest.fail("refused restoration must not modify OpenBao")

    monkeypatch.setattr(
        restore_module,
        "restore_openbao_snapshot",
        forbidden_recovery,
    )
    with pytest.raises(PermissionError, match="not authorized"):
        restore_module.restore_openbao(
            estate_root=root,
            snapshot_uri=str(source),
            authorize=refuse,
        )
    assert events == ["resolve", "refuse"]


def test_restore_openbao_propagates_authorization_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An exception in the approval callback aborts without mutation."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    source = _snapshot(tmp_path)
    events: list[str] = []
    _mock_target(monkeypatch, events)

    def unavailable_authorization(plan: OpenBaoRestorePlan) -> bool:
        raise RuntimeError("approval unavailable")

    with pytest.raises(RuntimeError, match="approval unavailable"):
        restore_module.restore_openbao(
            estate_root=root,
            snapshot_uri=str(source),
            authorize=unavailable_authorization,
        )
    assert events == ["resolve"]


def test_restore_openbao_validates_configuration_before_looking_up_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Invalid seal expectations abort before estate or snapshot I/O."""
    events: list[str] = []

    def forbidden_resolve(
        *,
        estate_root: Path,
        name: str,
    ) -> ServiceTarget:
        events.append("resolve")
        pytest.fail("invalid expectations must prevent resolution")

    def forbidden_approval(plan: OpenBaoRestorePlan) -> bool:
        pytest.fail("invalid expectations must prevent approval")

    monkeypatch.setattr(restore_module, "resolve_service", forbidden_resolve)
    with pytest.raises(OpenBaoError, match="recovery requires"):
        restore_module.restore_openbao(
            estate_root=tmp_path,
            snapshot_uri=str(tmp_path / "missing.snap"),
            authorize=forbidden_approval,
            expected_shares=2,
            expected_threshold=3,
        )
    assert events == []


def test_restore_openbao_rejects_unknown_service_before_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An unresolved service fails without reading the selected snapshot."""

    def failing_resolve(
        *,
        estate_root: Path,
        name: str,
    ) -> ServiceTarget:
        raise ServiceError("unavailable estate target")

    def forbidden_approval(plan: OpenBaoRestorePlan) -> bool:
        pytest.fail("unresolved target must prevent approval")

    monkeypatch.setattr(restore_module, "resolve_service", failing_resolve)
    with pytest.raises(ServiceError, match="unavailable estate target"):
        restore_module.restore_openbao(
            estate_root=tmp_path,
            snapshot_uri=str(tmp_path / "missing.snap"),
            authorize=forbidden_approval,
        )


def test_restore_openbao_rejects_missing_snapshot_without_approval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Failed snapshot staging never requests operator authorization."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    events: list[str] = []
    _mock_target(monkeypatch, events)

    def forbidden_approval(plan: OpenBaoRestorePlan) -> bool:
        pytest.fail("missing snapshot must prevent approval")

    with pytest.raises(SnapshotError, match="unable to acquire snapshot"):
        restore_module.restore_openbao(
            estate_root=root,
            snapshot_uri=str(tmp_path / "missing.snap"),
            authorize=forbidden_approval,
        )
    assert events == ["resolve"]


def test_restore_openbao_propagates_interruption_and_cleans_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Re-raise the identical interruption object while cleaning staged files."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    source = _snapshot(tmp_path)
    events: list[str] = []
    _mock_target(monkeypatch, events)
    interrupted = restore_module.OpenBaoRecoveryInterruptedError(
        "snapshot restoration",
    )
    staged_paths: list[Path] = []

    def approve(plan: OpenBaoRestorePlan) -> bool:
        return True

    def failing_recovery(
        address: str,
        *,
        snapshot: Path,
        expected_sha256: str,
        restart: Callable[[], None],
        expected_shares: int = 3,
        expected_threshold: int = 2,
        timeout: float = 120.0,
    ) -> OpenBaoRecoveryResult:
        staged_paths.append(snapshot)
        raise interrupted

    monkeypatch.setattr(
        restore_module,
        "restore_openbao_snapshot",
        failing_recovery,
    )
    with pytest.raises(restore_module.OpenBaoRecoveryInterruptedError) as caught:
        restore_module.restore_openbao(
            estate_root=root,
            snapshot_uri=str(source),
            authorize=approve,
        )

    assert caught.value is interrupted
    assert caught.value.phase == "snapshot restoration"
    assert not hasattr(caught.value, "authority")
    assert BOOTSTRAP_TOKEN not in str(caught.value)
    assert BOOTSTRAP_SHARE not in repr(caught.value)
    assert len(staged_paths) == 1
    assert not staged_paths[0].exists()


def test_restore_openbao_reports_restart_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The low-level coordinator reports failed service restarts as interrupted."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    source = _snapshot(tmp_path)
    events: list[str] = []
    _mock_target(monkeypatch, events)
    _mock_recovery_lifecycle(monkeypatch, events)

    def approve(plan: OpenBaoRestorePlan) -> bool:
        return True

    def failing_restart(target: ServiceTarget) -> None:
        events.append("restart")
        raise ServiceError("systemd outcome uncertain")

    monkeypatch.setattr(restore_module, "restart_openbao", failing_restart)

    with pytest.raises(restore_module.OpenBaoRecoveryInterruptedError) as caught:
        restore_module.restore_openbao(
            estate_root=root,
            snapshot_uri=str(source),
            authorize=approve,
        )

    assert caught.value.phase == "appliance restart"
    assert not hasattr(caught.value, "authority")
    assert events == ["resolve", "status", "initialise", "unseal", "restore", "restart"]


# ---------------------------------------------------------------------------
# Initialization interruption
# ---------------------------------------------------------------------------


def test_recovery_uncertain_initialization_reports_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An unknown initialization outcome stops recovery immediately."""
    events: list[str] = []
    _mock_recovery_lifecycle(monkeypatch, events)

    def failing_initialise(
        address: str,
        *,
        shares: int,
        threshold: int,
        timeout: float = 10.0,
    ) -> OpenBaoInitialization:
        events.append("initialise")
        raise OpenBaoError("initialization response lost")

    monkeypatch.setattr(
        restore_module,
        "initialise_openbao",
        failing_initialise,
    )

    with pytest.raises(restore_module.OpenBaoRecoveryInterruptedError) as caught:
        _recover(_snapshot(tmp_path), events)

    assert caught.value.phase == "temporary initialization"
    assert not hasattr(caught.value, "authority")
    assert events == ["status", "initialise"]
