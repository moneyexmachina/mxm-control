"""Unit tests for OpenBao initialization.

Verify Shamir configuration, lifecycle preconditions, HTTPS requests,
sensitive authority handling, and uncertain initialization outcomes.

No tests communicate with a live OpenBao instance.
"""

from __future__ import annotations

import base64
import http.client
import json
import ssl
from dataclasses import FrozenInstanceError
from typing import cast

import pytest

import mxm.control.openbao.initialise as initialise_module
from mxm.control.openbao.api import OpenBaoError
from mxm.control.openbao.initialise import (
    OpenBaoInitialization,
    OpenBaoInitializationUncertainError,
    initialise_openbao,
)
from mxm.control.openbao.status import OpenBaoStatus

ADDRESS = "https://openbao.example.test"

UNSEAL_KEY = base64.b64encode(b"test-unseal-key").decode("ascii")
ROOT_TOKEN = "test-initial-root-token"


def _status(*, initialized: bool = False) -> OpenBaoStatus:
    """Construct a lifecycle status for initialization preflight."""
    return OpenBaoStatus(
        initialized=initialized,
        sealed=True,
        version="2.6.5",
        seal_type="shamir",
        shares=3 if initialized else 0,
        threshold=2 if initialized else 0,
        progress=0,
    )


def _initialization_payload(
    *,
    keys: object | None = None,
    token: object = ROOT_TOKEN,
) -> bytes:
    """Build an OpenBao initialization response."""
    document = {
        "keys_base64": [UNSEAL_KEY] if keys is None else keys,
        "root_token": token,
    }
    return json.dumps(document).encode("utf-8")


def _mock_preflight(
    monkeypatch: pytest.MonkeyPatch,
    *,
    initialized: bool = False,
) -> None:
    """Replace live status inspection with a deterministic result."""

    def fake_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> OpenBaoStatus:
        assert address == ADDRESS
        assert timeout > 0
        return _status(initialized=initialized)

    monkeypatch.setattr(
        initialise_module,
        "status_openbao",
        fake_status,
    )


def _mock_initialization(
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload: bytes | None = None,
) -> None:
    """Replace the initialization POST without issuing HTTP requests."""

    def fake_post(
        address: str,
        *,
        shares: int,
        threshold: int,
        timeout: float,
    ) -> bytes:
        assert address == ADDRESS
        assert shares == 1
        assert threshold == 1
        assert timeout > 0
        return payload if payload is not None else _initialization_payload()

    monkeypatch.setattr(
        initialise_module,
        "_post_initialization",
        fake_post,
    )


class FakeResponse:
    """Minimal HTTP response used by the transport tests."""

    def __init__(self, status: int, payload: bytes) -> None:
        self.status = status
        self.payload = payload
        self.read_limit: int | None = None

    def read(self, amount: int) -> bytes:
        self.read_limit = amount
        return self.payload[:amount]


class FakeConnection:
    """Record requests without opening a network connection."""

    def __init__(
        self,
        response: FakeResponse,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.response = response
        self.failure = failure
        self.requests: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.closed = False
        self.response_requests = 0

    def request(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        self.requests.append((method, url, body, headers))

        if self.failure is not None:
            raise self.failure

    def getresponse(self) -> FakeResponse:
        self.response_requests += 1
        return self.response

    def close(self) -> None:
        self.closed = True


def _mock_connection(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: int = 200,
    payload: bytes | None = None,
    failure: Exception | None = None,
) -> FakeConnection:
    """Replace HTTPSConnection and return the observable fake."""
    response = FakeResponse(
        status,
        payload if payload is not None else _initialization_payload(),
    )
    connection = FakeConnection(response, failure=failure)

    def fake_https_connection(
        host: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> FakeConnection:
        assert host == "openbao.example.test"
        assert port == 443
        assert timeout == 10.0
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        return connection

    monkeypatch.setattr(
        initialise_module.http.client,
        "HTTPSConnection",
        fake_https_connection,
    )

    return connection


# ---------------------------------------------------------------------------
# Initialization capability
# ---------------------------------------------------------------------------


def test_initialises_uninitialized_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Initialization returns the generated recovery authority."""
    _mock_preflight(monkeypatch)
    _mock_initialization(monkeypatch)

    result = initialise_openbao(
        ADDRESS,
        shares=1,
        threshold=1,
    )

    assert result.unseal_keys == (UNSEAL_KEY,)
    assert result.root_token == ROOT_TOKEN


def test_normalizes_service_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize the HTTPS origin before making API requests."""
    _mock_preflight(monkeypatch)
    _mock_initialization(monkeypatch)

    result = initialise_openbao(
        f"{ADDRESS}/",
        shares=1,
        threshold=1,
    )

    assert result.root_token == ROOT_TOKEN


def test_forwards_custom_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the configured timeout for preflight and initialization."""
    observed: list[tuple[str, float]] = []

    def fake_status(
        address: str,
        *,
        timeout: float,
    ) -> OpenBaoStatus:
        observed.append(("status", timeout))
        return _status()

    def fake_post(
        address: str,
        *,
        shares: int,
        threshold: int,
        timeout: float,
    ) -> bytes:
        observed.append(("initialize", timeout))
        return _initialization_payload()

    monkeypatch.setattr(
        initialise_module,
        "status_openbao",
        fake_status,
    )
    monkeypatch.setattr(
        initialise_module,
        "_post_initialization",
        fake_post,
    )

    initialise_openbao(
        ADDRESS,
        shares=1,
        threshold=1,
        timeout=4.5,
    )

    assert observed == [
        ("status", 4.5),
        ("initialize", 4.5),
    ]


def test_rejects_already_initialized_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing OpenBao state must never be reinitialized."""
    _mock_preflight(monkeypatch, initialized=True)

    calls = 0

    def forbidden_post(
        address: str,
        *,
        shares: int,
        threshold: int,
        timeout: float,
    ) -> bytes:
        nonlocal calls
        calls += 1
        pytest.fail("initialization POST must not occur")

    monkeypatch.setattr(
        initialise_module,
        "_post_initialization",
        forbidden_post,
    )

    with pytest.raises(
        OpenBaoError,
        match="already initialized",
    ):
        initialise_openbao(
            ADDRESS,
            shares=1,
            threshold=1,
        )

    assert calls == 0


def test_preflight_failure_prevents_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unavailable status endpoint prevents initialization."""

    def failing_status(
        address: str,
        *,
        timeout: float,
    ) -> OpenBaoStatus:
        raise OpenBaoError("status unavailable")

    monkeypatch.setattr(
        initialise_module,
        "status_openbao",
        failing_status,
    )

    with pytest.raises(OpenBaoError, match="status unavailable"):
        initialise_openbao(
            ADDRESS,
            shares=1,
            threshold=1,
        )


# ---------------------------------------------------------------------------
# Initialization configuration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("shares", "threshold"),
    [
        (1, 1),
        (3, 2),
        (3, 3),
        (5, 3),
        (255, 255),
    ],
)
def test_accepts_valid_shamir_configurations(
    shares: int,
    threshold: int,
) -> None:
    """Accept valid Shamir share counts and thresholds."""
    initialise_module._validate_configuration(shares, threshold)


@pytest.mark.parametrize(
    ("shares", "threshold"),
    [
        (0, 0),
        (0, 1),
        (1, 0),
        (2, 3),
        (256, 1),
        (256, 256),
        (-1, 1),
        (3, -1),
    ],
)
def test_rejects_invalid_shamir_configurations(
    shares: int,
    threshold: int,
) -> None:
    """Require a valid positive threshold not exceeding share count."""
    with pytest.raises(
        OpenBaoError,
        match="initialization requires",
    ):
        initialise_module._validate_configuration(shares, threshold)


@pytest.mark.parametrize(
    ("shares", "threshold"),
    [
        (True, 1),
        (3, False),
        (1.0, 1),
        (3, 2.0),
    ],
)
def test_rejects_noninteger_configuration(
    shares: object,
    threshold: object,
) -> None:
    """Reject booleans and floats rather than coercing their values."""
    with pytest.raises(
        OpenBaoError,
        match="must be integers",
    ):
        initialise_module._validate_configuration(
            cast("int", shares),
            cast("int", threshold),
        )


@pytest.mark.parametrize("timeout", [0.0, -1.0, -10.0])
def test_rejects_invalid_timeout(timeout: float) -> None:
    """Initialization requires a positive network timeout."""
    with pytest.raises(
        OpenBaoError,
        match="timeout must be positive",
    ):
        initialise_openbao(
            ADDRESS,
            shares=1,
            threshold=1,
            timeout=timeout,
        )


def test_rejects_insecure_service_address() -> None:
    """Initialization is restricted to HTTPS service origins."""
    with pytest.raises(OpenBaoError, match="HTTPS service origin"):
        initialise_openbao(
            "http://openbao.example.test",
            shares=1,
            threshold=1,
        )


# ---------------------------------------------------------------------------
# HTTPS initialization request
# ---------------------------------------------------------------------------


def test_sends_correct_initialization_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use exactly one HTTPS POST with the requested Shamir configuration."""
    connection = _mock_connection(monkeypatch)

    payload = initialise_module._post_initialization(
        ADDRESS,
        shares=3,
        threshold=2,
        timeout=10.0,
    )

    assert payload == _initialization_payload()
    assert len(connection.requests) == 1

    method, url, body, headers = connection.requests[0]

    assert method == "POST"
    assert url == "/v1/sys/init"
    assert json.loads(body) == {
        "secret_shares": 3,
        "secret_threshold": 2,
    }
    assert headers == {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    assert connection.closed is True


def test_limits_initialization_response_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject responses exceeding the configured safety limit."""
    connection = _mock_connection(
        monkeypatch,
        payload=b"x" * (initialise_module._MAX_RESPONSE_BYTES + 1),
    )

    with pytest.raises(
        OpenBaoInitializationUncertainError,
        match="inspect instance state",
    ):
        initialise_module._post_initialization(
            ADDRESS,
            shares=1,
            threshold=1,
            timeout=10.0,
        )

    assert connection.response.read_limit == (initialise_module._MAX_RESPONSE_BYTES + 1)
    assert connection.closed is True


@pytest.mark.parametrize("http_status", [201, 301, 302, 400, 403, 500, 503])
def test_rejects_unexpected_initialization_status(
    monkeypatch: pytest.MonkeyPatch,
    http_status: int,
) -> None:
    """Unexpected HTTP responses must not be interpreted as success."""
    connection = _mock_connection(
        monkeypatch,
        status=http_status,
    )

    with pytest.raises(
        OpenBaoInitializationUncertainError,
        match="inspect instance state",
    ):
        initialise_module._post_initialization(
            ADDRESS,
            shares=1,
            threshold=1,
            timeout=10.0,
        )

    assert len(connection.requests) == 1
    assert connection.closed is True


# ---------------------------------------------------------------------------
# Sensitive initialization response
# ---------------------------------------------------------------------------


def test_initialization_authority_has_safe_representation() -> None:
    """Root tokens and unseal shares must not appear in repr output."""
    result = OpenBaoInitialization(
        unseal_keys=(UNSEAL_KEY,),
        root_token=ROOT_TOKEN,
    )

    representation = repr(result)

    assert ROOT_TOKEN not in representation
    assert UNSEAL_KEY not in representation


def test_initialization_authority_is_immutable() -> None:
    """Returned authority is represented by a frozen dataclass."""
    result = OpenBaoInitialization(
        unseal_keys=(UNSEAL_KEY,),
        root_token=ROOT_TOKEN,
    )

    with pytest.raises(FrozenInstanceError):
        result.root_token = "replacement"  # type: ignore[misc]


def test_parses_multiple_unseal_keys() -> None:
    """Initialization supports independently generated Shamir shares."""
    keys = [base64.b64encode(f"key-{index}".encode()).decode() for index in range(3)]

    result = initialise_module._parse_initialization(
        _initialization_payload(keys=keys),
        shares=3,
    )

    assert result.unseal_keys == tuple(keys)
    assert result.root_token == ROOT_TOKEN


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b"null",
        b"[]",
        b'"string"',
        b"{}",
        b'{"keys_base64":[]}',
    ],
)
def test_rejects_invalid_initialization_responses(
    payload: bytes,
) -> None:
    """Malformed or incomplete responses yield uncertain outcomes."""
    with pytest.raises(OpenBaoInitializationUncertainError):
        initialise_module._parse_initialization(
            payload,
            shares=1,
        )


@pytest.mark.parametrize(
    "keys",
    [
        [],
        ["", UNSEAL_KEY],
        [123],
        [True],
        ["not-base64"],
        ["%%%"],
        [""],
    ],
)
def test_rejects_invalid_unseal_keys(keys: object) -> None:
    """Reject incorrect share counts, types, and Base64 encodings."""
    with pytest.raises(OpenBaoInitializationUncertainError):
        initialise_module._parse_initialization(
            _initialization_payload(keys=keys),
            shares=1,
        )


@pytest.mark.parametrize(
    "token",
    ["", None, 123, True, [], {}],
)
def test_rejects_invalid_root_tokens(token: object) -> None:
    """Initialization must return a nonempty string root token."""
    with pytest.raises(OpenBaoInitializationUncertainError):
        initialise_module._parse_initialization(
            _initialization_payload(token=token),
            shares=1,
        )


def test_uncertain_errors_do_not_expose_authority() -> None:
    """Invalid response errors must not echo sensitive server data."""
    sensitive_payload = json.dumps(
        {
            "keys_base64": ["invalid-base64!!!"],
            "root_token": ROOT_TOKEN,
        }
    ).encode()

    with pytest.raises(
        OpenBaoInitializationUncertainError,
    ) as error:
        initialise_module._parse_initialization(
            sensitive_payload,
            shares=1,
        )

    assert ROOT_TOKEN not in str(error.value)
    assert "invalid-base64!!!" not in str(error.value)


# ---------------------------------------------------------------------------
# Uncertain outcomes and retry safety
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        OSError("connection reset"),
        TimeoutError("request timed out"),
        http.client.HTTPException("invalid HTTP response"),
    ],
)
def test_transport_failure_has_uncertain_outcome(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    """Failed initialization requests must be classified as uncertain."""
    connection = _mock_connection(
        monkeypatch,
        failure=failure,
    )

    with pytest.raises(
        OpenBaoInitializationUncertainError,
        match="do not retry automatically",
    ):
        initialise_module._post_initialization(
            ADDRESS,
            shares=1,
            threshold=1,
            timeout=10.0,
        )

    assert len(connection.requests) == 1
    assert connection.closed is True


def test_invalid_response_does_not_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed response must not trigger another initialization POST."""
    _mock_preflight(monkeypatch)

    attempts = 0

    def fake_post(
        address: str,
        *,
        shares: int,
        threshold: int,
        timeout: float,
    ) -> bytes:
        nonlocal attempts
        attempts += 1
        return b"invalid-json"

    monkeypatch.setattr(
        initialise_module,
        "_post_initialization",
        fake_post,
    )

    with pytest.raises(OpenBaoInitializationUncertainError):
        initialise_openbao(
            ADDRESS,
            shares=1,
            threshold=1,
        )

    assert attempts == 1


def test_success_does_not_make_second_status_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not risk losing received authority to a postflight failure."""
    status_calls = 0

    def fake_status(
        address: str,
        *,
        timeout: float,
    ) -> OpenBaoStatus:
        nonlocal status_calls
        status_calls += 1
        return _status()

    monkeypatch.setattr(
        initialise_module,
        "status_openbao",
        fake_status,
    )
    _mock_initialization(monkeypatch)

    result = initialise_openbao(
        ADDRESS,
        shares=1,
        threshold=1,
    )

    assert result.root_token == ROOT_TOKEN
    assert status_calls == 1
