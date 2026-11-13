"""Unit tests for the OpenBao Shamir unseal capabilities.

Exercise individual share submission and complete multi-share unseal
coordination, including lifecycle validation, progress, cancellation,
HTTPS transport, and uncertain outcomes.

No test requires a live OpenBao service or real credentials.
"""

from __future__ import annotations

import http.client
import json
import ssl
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

import mxm.control.openbao.unseal as unseal_module
from mxm.control.openbao.api import OpenBaoError
from mxm.control.openbao.status import OpenBaoStatus
from mxm.control.openbao.unseal import (
    OpenBaoUnsealResult,
    OpenBaoUnsealUncertainError,
    ShareProvider,
    submit_unseal_share,
    unseal_openbao,
)

ADDRESS = "https://openbao.example.test"
SHARE_1 = "dummy-share-one"
SHARE_2 = "dummy-share-two"


def _status(
    *,
    initialized: bool = True,
    sealed: bool = True,
    seal_type: str = "shamir",
    shares: int = 3,
    threshold: int = 2,
    progress: int = 0,
) -> OpenBaoStatus:
    """Construct a synthetic OpenBao seal-status result."""
    return OpenBaoStatus(
        initialized=initialized,
        sealed=sealed,
        version="2.6.5",
        seal_type=seal_type,
        shares=shares,
        threshold=threshold,
        progress=progress,
    )


def _result(
    *,
    sealed: bool = True,
    progress: int = 1,
    threshold: int = 2,
    shares: int = 3,
) -> OpenBaoUnsealResult:
    """Construct a synthetic unseal result."""
    return OpenBaoUnsealResult(
        sealed=sealed,
        progress=progress,
        threshold=threshold,
        shares=shares,
    )


def _payload(
    *,
    sealed: object = True,
    progress: object = 1,
    threshold: object = 2,
    shares: object = 3,
) -> bytes:
    """Construct a synthetic OpenBao unseal API response."""
    return json.dumps(
        {
            "sealed": sealed,
            "progress": progress,
            "t": threshold,
            "n": shares,
        }
    ).encode("utf-8")


def _mock_status(
    monkeypatch: pytest.MonkeyPatch,
    *statuses: OpenBaoStatus,
) -> list[tuple[str, float]]:
    """Supply successive seal-status responses and record requests."""
    responses: Iterator[OpenBaoStatus] = iter(statuses)
    calls: list[tuple[str, float]] = []

    def fake_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> OpenBaoStatus:
        calls.append((address, timeout))
        return next(responses)

    monkeypatch.setattr(
        unseal_module,
        "status_openbao",
        fake_status,
    )

    return calls


def _mock_post(
    monkeypatch: pytest.MonkeyPatch,
    *payloads: bytes,
) -> list[tuple[str, str, float]]:
    """Supply successive API responses and record share submissions."""
    responses: Iterator[bytes] = iter(payloads)
    calls: list[tuple[str, str, float]] = []

    def fake_post(
        address: str,
        *,
        share: str,
        timeout: float,
    ) -> bytes:
        calls.append((address, share, timeout))
        return next(responses)

    monkeypatch.setattr(
        unseal_module,
        "_post_unseal",
        fake_post,
    )

    return calls


@dataclass
class FakeResponse:
    """HTTP response implementing the properties used by the module."""

    status: int
    payload: bytes
    read_limit: int | None = None

    def read(self, amount: int) -> bytes:
        """Return at most the requested number of bytes."""
        self.read_limit = amount
        return self.payload[:amount]


class FakeConnection:
    """Record HTTPS requests without opening a network connection."""

    def __init__(
        self,
        response: FakeResponse,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.response = response
        self.failure = failure
        self.requests: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.response_requests = 0
        self.closed = False

    def request(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        """Record an outgoing request, optionally raising an error."""
        self.requests.append((method, url, body, headers))

        if self.failure is not None:
            raise self.failure

    def getresponse(self) -> FakeResponse:
        """Return the configured response."""
        self.response_requests += 1
        return self.response

    def close(self) -> None:
        """Record connection cleanup."""
        self.closed = True


def _mock_connection(
    monkeypatch: pytest.MonkeyPatch,
    *,
    http_status: int = 200,
    payload: bytes | None = None,
    failure: Exception | None = None,
    expected_port: int = 443,
    expected_timeout: float = 10.0,
) -> FakeConnection:
    """Replace HTTPSConnection with a strictly typed recording fake."""
    response = FakeResponse(
        status=http_status,
        payload=_payload() if payload is None else payload,
    )
    connection = FakeConnection(
        response,
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

    monkeypatch.setattr(
        unseal_module.http.client,
        "HTTPSConnection",
        fake_https_connection,
    )

    return connection


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sealed", "progress", "threshold", "remaining"),
    [
        (True, 0, 2, 2),
        (True, 1, 2, 1),
        (False, 0, 2, 0),
        (True, 0, 1, 1),
        (False, 0, 1, 0),
    ],
)
def test_result_reports_remaining_shares(
    sealed: bool,
    progress: int,
    threshold: int,
    remaining: int,
) -> None:
    """Report the number of additional shares needed."""
    result = _result(
        sealed=sealed,
        progress=progress,
        threshold=threshold,
    )

    assert result.remaining == remaining


def test_result_has_value_semantics() -> None:
    """Equivalent unseal states compare equal."""
    first = _result()
    second = _result()

    assert first == second
    assert hash(first) == hash(second)


def test_share_provider_is_callable() -> None:
    """The share callback interface accepts two integer arguments."""

    def provider(number: int, total: int) -> str:
        return f"share-{number}-of-{total}"

    callback: ShareProvider = provider

    assert callback(1, 2) == "share-1-of-2"


# ---------------------------------------------------------------------------
# Individual share submission
# ---------------------------------------------------------------------------


def test_submit_unseal_share_advances_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Submit one share and return the updated seal state."""
    _mock_status(monkeypatch, _status())
    calls = _mock_post(monkeypatch, _payload())

    result = submit_unseal_share(
        ADDRESS,
        share=SHARE_1,
    )

    assert result == _result()
    assert result.remaining == 1
    assert calls == [(ADDRESS, SHARE_1, 10.0)]


def test_submit_final_share_unseals_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The final share changes the state to unsealed."""
    _mock_status(monkeypatch, _status(progress=1))
    calls = _mock_post(
        monkeypatch,
        _payload(sealed=False, progress=0),
    )

    result = submit_unseal_share(
        ADDRESS,
        share=SHARE_2,
    )

    assert result.sealed is False
    assert result.remaining == 0
    assert len(calls) == 1


def test_submit_supports_single_share_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Support temporary initialization with a 1-of-1 seal."""
    _mock_status(
        monkeypatch,
        _status(shares=1, threshold=1),
    )
    calls = _mock_post(
        monkeypatch,
        _payload(
            sealed=False,
            progress=0,
            threshold=1,
            shares=1,
        ),
    )

    result = submit_unseal_share(
        ADDRESS,
        share=SHARE_1,
    )

    assert result.sealed is False
    assert result.threshold == 1
    assert result.remaining == 0
    assert len(calls) == 1


def test_submit_does_not_post_when_already_unsealed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not submit unnecessary shares."""
    _mock_status(
        monkeypatch,
        _status(sealed=False),
    )

    def forbidden_post(
        address: str,
        *,
        share: str,
        timeout: float,
    ) -> bytes:
        pytest.fail("already-unsealed instance must not receive a POST")

    monkeypatch.setattr(
        unseal_module,
        "_post_unseal",
        forbidden_post,
    )

    result = submit_unseal_share(
        ADDRESS,
        share=SHARE_1,
    )

    assert result.sealed is False
    assert result.remaining == 0


def test_submit_rejects_uninitialized_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse to submit shares before initialization."""
    _mock_status(
        monkeypatch,
        _status(initialized=False, shares=0, threshold=0),
    )

    with pytest.raises(OpenBaoError, match="not initialized"):
        submit_unseal_share(
            ADDRESS,
            share=SHARE_1,
        )


@pytest.mark.parametrize(
    "seal_type",
    ["awskms", "transit", "pkcs11", "unknown"],
)
def test_submit_rejects_non_shamir_seal(
    monkeypatch: pytest.MonkeyPatch,
    seal_type: str,
) -> None:
    """Reject seal types unsupported by this capability."""
    _mock_status(
        monkeypatch,
        _status(seal_type=seal_type),
    )

    with pytest.raises(OpenBaoError, match="Shamir"):
        submit_unseal_share(
            ADDRESS,
            share=SHARE_1,
        )


@pytest.mark.parametrize(
    ("shares", "threshold"),
    [
        (0, 0),
        (0, 1),
        (1, 0),
        (2, 3),
        (-1, 1),
    ],
)
def test_rejects_invalid_shamir_configuration(
    shares: int,
    threshold: int,
) -> None:
    """Reject inconsistent seal configurations."""
    with pytest.raises(
        OpenBaoError,
        match="invalid seal configuration",
    ):
        unseal_module._preflight_unseal(_status(shares=shares, threshold=threshold))


@pytest.mark.parametrize("progress", [-1, 2, 3])
def test_rejects_invalid_sealed_progress(progress: int) -> None:
    """Sealed progress must be nonnegative and below the threshold."""
    with pytest.raises(
        OpenBaoError,
        match="invalid unseal progress",
    ):
        unseal_module._preflight_unseal(_status(progress=progress))


def test_submit_preflight_failure_prevents_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed status inspection must prevent share submission."""

    def failing_status(
        address: str,
        *,
        timeout: float,
    ) -> OpenBaoStatus:
        raise OpenBaoError("status unavailable")

    monkeypatch.setattr(
        unseal_module,
        "status_openbao",
        failing_status,
    )

    with pytest.raises(OpenBaoError, match="status unavailable"):
        submit_unseal_share(
            ADDRESS,
            share=SHARE_1,
        )


# ---------------------------------------------------------------------------
# Share, address and timeout validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "share",
    [
        "",
        " ",
        "ABC DEF",
        "ABC\nDEF",
        "ABC\tDEF",
        "ABC\x00DEF",
        "ABCéDEF",
    ],
)
def test_rejects_invalid_share_input(share: str) -> None:
    """Reject empty, whitespace, control and non-ASCII shares."""
    with pytest.raises(OpenBaoError, match="unseal share"):
        unseal_module._validate_share(share)


@pytest.mark.parametrize(
    "share",
    [
        "ABC123",
        "abc+/=",
        "0123456789",
    ],
)
def test_accepts_printable_ascii_share_input(share: str) -> None:
    """Accept valid printable ASCII input."""
    unseal_module._validate_share(share)


@pytest.mark.parametrize(
    "timeout",
    [
        0.0,
        -1.0,
        float("inf"),
        float("-inf"),
        float("nan"),
    ],
)
def test_rejects_invalid_timeout(timeout: float) -> None:
    """Require positive finite request timeouts."""
    with pytest.raises(OpenBaoError, match="timeout"):
        unseal_module._validate_timeout(timeout)


def test_rejects_insecure_address() -> None:
    """Unseal operations must use HTTPS."""
    with pytest.raises(
        OpenBaoError,
        match="HTTPS service origin",
    ):
        submit_unseal_share(
            "http://openbao.example.test",
            share=SHARE_1,
        )


def test_submit_normalizes_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize the service origin before status and submission."""
    status_calls = _mock_status(monkeypatch, _status())
    post_calls = _mock_post(monkeypatch, _payload())

    submit_unseal_share(
        f"{ADDRESS}/",
        share=SHARE_1,
    )

    assert status_calls == [(ADDRESS, 10.0)]
    assert post_calls == [(ADDRESS, SHARE_1, 10.0)]


def test_submit_forwards_custom_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forward the configured timeout to both API operations."""
    status_calls = _mock_status(monkeypatch, _status())
    post_calls = _mock_post(monkeypatch, _payload())

    submit_unseal_share(
        ADDRESS,
        share=SHARE_1,
        timeout=4.5,
    )

    assert status_calls == [(ADDRESS, 4.5)]
    assert post_calls == [(ADDRESS, SHARE_1, 4.5)]


# ---------------------------------------------------------------------------
# Unseal response parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sealed", "progress", "threshold", "shares"),
    [
        (True, 0, 2, 3),
        (True, 1, 2, 3),
        (False, 0, 2, 3),
        (False, 0, 1, 1),
    ],
)
def test_parses_valid_responses(
    sealed: bool,
    progress: int,
    threshold: int,
    shares: int,
) -> None:
    """Parse intermediate and completed unseal states."""
    result = unseal_module._parse_unseal_response(
        _payload(
            sealed=sealed,
            progress=progress,
            threshold=threshold,
            shares=shares,
        )
    )

    assert result == _result(
        sealed=sealed,
        progress=progress,
        threshold=threshold,
        shares=shares,
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b"null",
        b"[]",
        b'"string"',
        b"{}",
        b'{"sealed":true}',
        b"\xff",
    ],
)
def test_rejects_invalid_response_documents(payload: bytes) -> None:
    """Malformed API responses have uncertain outcomes."""
    with pytest.raises(OpenBaoUnsealUncertainError):
        unseal_module._parse_unseal_response(payload)


@pytest.mark.parametrize(
    ("sealed", "progress", "threshold", "shares"),
    [
        ("true", 1, 2, 3),
        (1, 1, 2, 3),
        (True, True, 2, 3),
        (True, "1", 2, 3),
        (True, 1, False, 3),
        (True, 1, 2, "3"),
        (True, None, 2, 3),
    ],
)
def test_rejects_invalid_response_types(
    sealed: object,
    progress: object,
    threshold: object,
    shares: object,
) -> None:
    """Reject fields with incorrect JSON types."""
    with pytest.raises(OpenBaoUnsealUncertainError):
        unseal_module._parse_unseal_response(
            _payload(
                sealed=sealed,
                progress=progress,
                threshold=threshold,
                shares=shares,
            )
        )


@pytest.mark.parametrize(
    ("sealed", "progress", "threshold", "shares"),
    [
        (True, -1, 2, 3),
        (True, 2, 2, 3),
        (True, 3, 2, 3),
        (False, 1, 2, 3),
        (True, 0, 0, 3),
        (True, 0, 4, 3),
        (True, 0, 2, 0),
    ],
)
def test_rejects_inconsistent_response_state(
    sealed: bool,
    progress: int,
    threshold: int,
    shares: int,
) -> None:
    """Reject impossible Shamir unseal states."""
    with pytest.raises(
        OpenBaoUnsealUncertainError,
        match="inconsistent state",
    ):
        unseal_module._parse_unseal_response(
            _payload(
                sealed=sealed,
                progress=progress,
                threshold=threshold,
                shares=shares,
            )
        )


def test_submit_rejects_changed_seal_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detect a changed Shamir configuration during submission."""
    _mock_status(monkeypatch, _status())
    _mock_post(
        monkeypatch,
        _payload(threshold=3, shares=3),
    )

    with pytest.raises(
        OpenBaoUnsealUncertainError,
        match="configuration changed",
    ):
        submit_unseal_share(
            ADDRESS,
            share=SHARE_1,
        )


# ---------------------------------------------------------------------------
# HTTPS transport
# ---------------------------------------------------------------------------


def test_posts_exactly_one_share_over_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Submit one JSON request to the native OpenBao unseal endpoint."""
    connection = _mock_connection(monkeypatch)

    payload = unseal_module._post_unseal(
        ADDRESS,
        share=SHARE_1,
        timeout=10.0,
    )

    assert payload == _payload()
    assert len(connection.requests) == 1

    method, path, body, headers = connection.requests[0]

    assert method == "POST"
    assert path == "/v1/sys/unseal"
    assert json.loads(body) == {"key": SHARE_1}
    assert headers == {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    assert connection.response_requests == 1
    assert connection.closed is True


def test_supports_explicit_https_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve explicitly configured service ports."""
    _mock_connection(
        monkeypatch,
        expected_port=8200,
    )

    unseal_module._post_unseal(
        f"{ADDRESS}:8200",
        share=SHARE_1,
        timeout=10.0,
    )


def test_bounds_http_response_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject responses larger than the configured maximum."""
    connection = _mock_connection(
        monkeypatch,
        payload=b"x" * (unseal_module._MAX_RESPONSE_BYTES + 1),
    )

    with pytest.raises(
        OpenBaoUnsealUncertainError,
        match="size limit",
    ):
        unseal_module._post_unseal(
            ADDRESS,
            share=SHARE_1,
            timeout=10.0,
        )

    assert connection.response.read_limit == (unseal_module._MAX_RESPONSE_BYTES + 1)
    assert connection.closed is True


@pytest.mark.parametrize(
    "http_status",
    [201, 301, 302, 400, 403, 429, 500, 503],
)
def test_rejects_unexpected_http_status(
    monkeypatch: pytest.MonkeyPatch,
    http_status: int,
) -> None:
    """Only HTTP 200 is accepted as an unseal response."""
    connection = _mock_connection(
        monkeypatch,
        http_status=http_status,
    )

    with pytest.raises(OpenBaoUnsealUncertainError):
        unseal_module._post_unseal(
            ADDRESS,
            share=SHARE_1,
            timeout=10.0,
        )

    assert len(connection.requests) == 1
    assert connection.closed is True


@pytest.mark.parametrize(
    "failure",
    [
        OSError("connection reset"),
        TimeoutError("request timed out"),
        http.client.HTTPException("invalid response"),
    ],
)
def test_transport_failures_are_uncertain(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    """A share may have reached OpenBao before transport failure."""
    connection = _mock_connection(
        monkeypatch,
        failure=failure,
    )

    with pytest.raises(
        OpenBaoUnsealUncertainError,
        match="outcome is uncertain",
    ):
        unseal_module._post_unseal(
            ADDRESS,
            share=SHARE_1,
            timeout=10.0,
        )

    assert len(connection.requests) == 1
    assert connection.closed is True


def test_submit_never_retries_invalid_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed response must not cause a second POST."""
    _mock_status(monkeypatch, _status())
    calls = _mock_post(monkeypatch, b"invalid-json")

    with pytest.raises(OpenBaoUnsealUncertainError):
        submit_unseal_share(
            ADDRESS,
            share=SHARE_1,
        )

    assert len(calls) == 1


def test_submit_error_does_not_expose_share(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exception messages must not reveal submitted share material."""
    _mock_status(monkeypatch, _status())
    _mock_post(monkeypatch, b"invalid-json")

    with pytest.raises(OpenBaoUnsealUncertainError) as error:
        submit_unseal_share(
            ADDRESS,
            share=SHARE_1,
        )

    assert SHARE_1 not in str(error.value)


def test_submit_has_no_postflight_status_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the POST result without an additional status inspection."""
    status_calls = _mock_status(monkeypatch, _status())
    _mock_post(
        monkeypatch,
        _payload(sealed=False, progress=0),
    )

    result = submit_unseal_share(
        ADDRESS,
        share=SHARE_1,
    )

    assert result.sealed is False
    assert len(status_calls) == 1


# ---------------------------------------------------------------------------
# Complete multi-share coordination
# ---------------------------------------------------------------------------


def test_unseal_coordinates_two_of_three(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Request and submit two shares, stopping when unsealed."""
    status_calls = _mock_status(
        monkeypatch,
        _status(progress=0),
        _status(progress=0),
        _status(progress=1),
    )
    post_calls = _mock_post(
        monkeypatch,
        _payload(sealed=True, progress=1),
        _payload(sealed=False, progress=0),
    )

    requested: list[tuple[int, int]] = []

    def get_share(number: int, total: int) -> str:
        requested.append((number, total))
        return SHARE_1 if number == 1 else SHARE_2

    result = unseal_openbao(
        ADDRESS,
        get_share=get_share,
    )

    assert result == _result(sealed=False, progress=0)
    assert requested == [(1, 2), (2, 2)]
    assert post_calls == [
        (ADDRESS, SHARE_1, 10.0),
        (ADDRESS, SHARE_2, 10.0),
    ]
    assert len(status_calls) == 3


def test_unseal_coordinates_single_share_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unseal a temporary 1-of-1 instance with generated authority."""
    _mock_status(
        monkeypatch,
        _status(shares=1, threshold=1),
        _status(shares=1, threshold=1),
    )
    post_calls = _mock_post(
        monkeypatch,
        _payload(
            sealed=False,
            progress=0,
            threshold=1,
            shares=1,
        ),
    )

    requested: list[tuple[int, int]] = []

    def get_share(number: int, total: int) -> str:
        requested.append((number, total))
        return SHARE_1

    result = unseal_openbao(
        ADDRESS,
        get_share=get_share,
    )

    assert result.sealed is False
    assert result.threshold == 1
    assert requested == [(1, 1)]
    assert len(post_calls) == 1


def test_unseal_resumes_existing_partial_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only request the remaining share when progress already exists."""
    _mock_status(
        monkeypatch,
        _status(progress=1),
        _status(progress=1),
    )
    post_calls = _mock_post(
        monkeypatch,
        _payload(sealed=False, progress=0),
    )

    requested: list[tuple[int, int]] = []

    def get_share(number: int, total: int) -> str:
        requested.append((number, total))
        return SHARE_2

    result = unseal_openbao(
        ADDRESS,
        get_share=get_share,
    )

    assert result.sealed is False
    assert requested == [(2, 2)]
    assert post_calls == [(ADDRESS, SHARE_2, 10.0)]


def test_unseal_does_not_request_unnecessary_shares(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An already-unsealed instance requires no callback or POST."""
    status_calls = _mock_status(
        monkeypatch,
        _status(sealed=False),
    )

    def forbidden_share(number: int, total: int) -> str:
        pytest.fail("share must not be requested")

    def forbidden_post(
        address: str,
        *,
        share: str,
        timeout: float,
    ) -> bytes:
        pytest.fail("unseal POST must not occur")

    monkeypatch.setattr(
        unseal_module,
        "_post_unseal",
        forbidden_post,
    )

    result = unseal_openbao(
        ADDRESS,
        get_share=forbidden_share,
    )

    assert result.sealed is False
    assert result.remaining == 0
    assert len(status_calls) == 1


def test_unseal_propagates_callback_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation aborts without submitting a share."""
    _mock_status(monkeypatch, _status())

    class OperatorCancelled(Exception):
        """Synthetic operator cancellation."""

    def cancelled_share(number: int, total: int) -> str:
        raise OperatorCancelled

    with pytest.raises(OperatorCancelled):
        unseal_openbao(
            ADDRESS,
            get_share=cancelled_share,
        )


def test_unseal_cancelled_after_first_share(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation preserves server-side progress without another POST."""
    _mock_status(
        monkeypatch,
        _status(progress=0),
        _status(progress=0),
    )
    post_calls = _mock_post(
        monkeypatch,
        _payload(sealed=True, progress=1),
    )

    class OperatorCancelled(Exception):
        """Synthetic operator cancellation."""

    def get_share(number: int, total: int) -> str:
        if number == 1:
            return SHARE_1

        raise OperatorCancelled

    with pytest.raises(OperatorCancelled):
        unseal_openbao(
            ADDRESS,
            get_share=get_share,
        )

    assert len(post_calls) == 1
    assert post_calls[0][1] == SHARE_1


def test_unseal_rejects_nonadvancing_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop when a submission does not advance Shamir progress."""
    _mock_status(
        monkeypatch,
        _status(progress=0),
        _status(progress=0),
    )
    post_calls = _mock_post(
        monkeypatch,
        _payload(sealed=True, progress=0),
    )

    requested: list[tuple[int, int]] = []

    def get_share(number: int, total: int) -> str:
        requested.append((number, total))
        return SHARE_1

    with pytest.raises(
        OpenBaoUnsealUncertainError,
        match="did not advance",
    ):
        unseal_openbao(
            ADDRESS,
            get_share=get_share,
        )

    assert requested == [(1, 2)]
    assert len(post_calls) == 1


def test_unseal_aborts_on_uncertain_submission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not request additional shares after an ambiguous outcome."""
    _mock_status(
        monkeypatch,
        _status(progress=0),
        _status(progress=0),
    )

    post_calls = 0
    share_calls = 0

    def get_share(number: int, total: int) -> str:
        nonlocal share_calls
        share_calls += 1
        return SHARE_1

    def failing_post(
        address: str,
        *,
        share: str,
        timeout: float,
    ) -> bytes:
        nonlocal post_calls
        post_calls += 1
        raise OpenBaoUnsealUncertainError("outcome uncertain")

    monkeypatch.setattr(
        unseal_module,
        "_post_unseal",
        failing_post,
    )

    with pytest.raises(OpenBaoUnsealUncertainError):
        unseal_openbao(
            ADDRESS,
            get_share=get_share,
        )

    assert share_calls == 1
    assert post_calls == 1


def test_unseal_rejects_configuration_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop if the seal configuration changes during submission."""
    _mock_status(
        monkeypatch,
        _status(),
        _status(),
    )
    post_calls = _mock_post(
        monkeypatch,
        _payload(
            sealed=True,
            progress=1,
            threshold=3,
            shares=3,
        ),
    )

    def get_share(number: int, total: int) -> str:
        return SHARE_1

    with pytest.raises(
        OpenBaoUnsealUncertainError,
        match="configuration changed",
    ):
        unseal_openbao(
            ADDRESS,
            get_share=get_share,
        )

    assert len(post_calls) == 1


def test_unseal_propagates_initial_status_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not ask for secrets when the initial status is unavailable."""

    def failing_status(
        address: str,
        *,
        timeout: float,
    ) -> OpenBaoStatus:
        raise OpenBaoError("status unavailable")

    def forbidden_share(number: int, total: int) -> str:
        pytest.fail("share must not be requested")

    monkeypatch.setattr(
        unseal_module,
        "status_openbao",
        failing_status,
    )

    with pytest.raises(OpenBaoError, match="status unavailable"):
        unseal_openbao(
            ADDRESS,
            get_share=forbidden_share,
        )


def test_unseal_forwards_timeout_on_each_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the configured timeout throughout a multi-share operation."""
    status_calls = _mock_status(
        monkeypatch,
        _status(progress=0),
        _status(progress=0),
        _status(progress=1),
    )
    post_calls = _mock_post(
        monkeypatch,
        _payload(progress=1),
        _payload(sealed=False, progress=0),
    )

    def get_share(number: int, total: int) -> str:
        return SHARE_1 if number == 1 else SHARE_2

    result = unseal_openbao(
        ADDRESS,
        get_share=get_share,
        timeout=4.5,
    )

    assert result.sealed is False
    assert status_calls == [(ADDRESS, 4.5)] * 3
    assert [call[2] for call in post_calls] == [4.5, 4.5]


def test_unseal_normalizes_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize the HTTPS origin for the complete lifecycle."""
    status_calls = _mock_status(
        monkeypatch,
        _status(shares=1, threshold=1),
        _status(shares=1, threshold=1),
    )
    post_calls = _mock_post(
        monkeypatch,
        _payload(
            sealed=False,
            progress=0,
            threshold=1,
            shares=1,
        ),
    )

    def get_share(number: int, total: int) -> str:
        return SHARE_1

    unseal_openbao(
        f"{ADDRESS}/",
        get_share=get_share,
    )

    assert all(address == ADDRESS for address, _ in status_calls)
    assert all(address == ADDRESS for address, _, _ in post_calls)


# ---------------------------------------------------------------------------
# Exception hierarchy and safety
# ---------------------------------------------------------------------------


def test_uncertain_error_uses_common_openbao_hierarchy() -> None:
    """Expose lifecycle errors through the shared exception family."""
    assert issubclass(OpenBaoUnsealUncertainError, OpenBaoError)
    assert issubclass(OpenBaoUnsealUncertainError, RuntimeError)


def test_unseal_error_does_not_expose_share(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Coordinator errors must not echo submitted secret material."""
    _mock_status(
        monkeypatch,
        _status(),
        _status(),
    )
    _mock_post(monkeypatch, b"invalid-json")

    def get_share(number: int, total: int) -> str:
        return SHARE_1

    with pytest.raises(OpenBaoUnsealUncertainError) as error:
        unseal_openbao(
            ADDRESS,
            get_share=get_share,
        )

    assert SHARE_1 not in str(error.value)
