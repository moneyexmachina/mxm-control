"""Unit tests for OpenBao initialization and seal-state inspection.

Exercise the status capability, response parsing, and HTTPS transport
without connecting to a live OpenBao instance.
"""

from __future__ import annotations

import json
import ssl
from email.message import Message
from io import BytesIO
from typing import BinaryIO
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

import mxm.control.openbao.status as status_module
from mxm.control.openbao.api import OpenBaoError
from mxm.control.openbao.status import OpenBaoStatus, status_openbao

ADDRESS = "https://openbao.example.test"

VALID_STATUS: dict[str, object] = {
    "initialized": True,
    "sealed": False,
    "version": "2.6.5",
    "type": "shamir",
    "n": 3,
    "t": 2,
    "progress": 0,
}


def _status_payload(**overrides: object) -> bytes:
    """Build a status response with selected field overrides."""
    return json.dumps({**VALID_STATUS, **overrides}).encode("utf-8")


def _mock_status_response(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    """Replace the HTTP boundary with a deterministic response."""

    def fake_request(address: str, *, timeout: float) -> bytes:
        assert address == ADDRESS
        assert timeout == 10.0
        return payload

    monkeypatch.setattr(
        status_module,
        "_request_seal_status",
        fake_request,
    )


# ---------------------------------------------------------------------------
# Status capability
# ---------------------------------------------------------------------------


def test_returns_typed_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid responses produce an immutable, typed status result."""
    _mock_status_response(monkeypatch, _status_payload())

    result = status_openbao(ADDRESS)

    assert result == OpenBaoStatus(
        initialized=True,
        sealed=False,
        version="2.6.5",
        seal_type="shamir",
        shares=3,
        threshold=2,
        progress=0,
    )


@pytest.mark.parametrize(
    ("initialized", "sealed", "shares", "threshold"),
    [
        (False, True, 0, 0),
        (True, True, 3, 2),
        (True, False, 3, 2),
    ],
)
def test_reports_lifecycle_states(
    monkeypatch: pytest.MonkeyPatch,
    initialized: bool,
    sealed: bool,
    shares: int,
    threshold: int,
) -> None:
    """Report initialization and sealing without imposing policy."""
    _mock_status_response(
        monkeypatch,
        _status_payload(
            initialized=initialized,
            sealed=sealed,
            n=shares,
            t=threshold,
        ),
    )

    result = status_openbao(ADDRESS)

    assert result.initialized is initialized
    assert result.sealed is sealed
    assert result.shares == shares
    assert result.threshold == threshold


def test_reports_unseal_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve partial unseal progress from OpenBao."""
    _mock_status_response(
        monkeypatch,
        _status_payload(sealed=True, progress=1),
    )

    result = status_openbao(ADDRESS)

    assert result.progress == 1
    assert result.sealed is True


def test_accepts_trailing_slash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize an origin with a trailing slash."""
    _mock_status_response(monkeypatch, _status_payload())

    result = status_openbao(f"{ADDRESS}/")

    assert result.initialized is True


def test_forwards_custom_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forward caller-selected timeouts to the HTTP transport."""
    observed_timeout: float | None = None

    def fake_request(address: str, *, timeout: float) -> bytes:
        nonlocal observed_timeout
        assert address == ADDRESS
        observed_timeout = timeout
        return _status_payload()

    monkeypatch.setattr(
        status_module,
        "_request_seal_status",
        fake_request,
    )

    status_openbao(ADDRESS, timeout=3.5)

    assert observed_timeout == 3.5


# ---------------------------------------------------------------------------
# HTTPS transport
# ---------------------------------------------------------------------------


def test_requests_seal_status_over_verified_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use GET and a certificate-verifying TLS context."""
    received_url: str | None = None
    received_method: str | None = None
    received_timeout: float | None = None
    received_context: ssl.SSLContext | None = None

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> BinaryIO:
        nonlocal received_url
        nonlocal received_method
        nonlocal received_timeout
        nonlocal received_context

        received_url = request.full_url
        received_method = request.get_method()
        received_timeout = timeout
        received_context = context

        return BytesIO(_status_payload())

    monkeypatch.setattr(
        status_module,
        "urlopen",
        fake_urlopen,
    )

    result = status_openbao(ADDRESS, timeout=4.0)

    assert result.initialized is True
    assert received_url == f"{ADDRESS}/v1/sys/seal-status"
    assert received_method == "GET"
    assert received_timeout == 4.0
    assert received_context is not None
    assert received_context.verify_mode == ssl.CERT_REQUIRED
    assert received_context.check_hostname is True


@pytest.mark.parametrize("http_status", [501, 503])
def test_accepts_lifecycle_http_status_codes(
    monkeypatch: pytest.MonkeyPatch,
    http_status: int,
) -> None:
    """OpenBao may return valid lifecycle JSON with HTTP 501 or 503."""
    payload = _status_payload(
        initialized=http_status != 501,
        sealed=True,
    )

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> BinaryIO:
        raise HTTPError(
            url=request.full_url,
            code=http_status,
            msg="OpenBao lifecycle status",
            hdrs=Message(),
            fp=BytesIO(payload),
        )

    monkeypatch.setattr(
        status_module,
        "urlopen",
        fake_urlopen,
    )

    result = status_openbao(ADDRESS)

    assert result.initialized is (http_status != 501)
    assert result.sealed is True


@pytest.mark.parametrize("http_status", [400, 401, 403, 404, 500, 502])
def test_rejects_unexpected_http_status(
    monkeypatch: pytest.MonkeyPatch,
    http_status: int,
) -> None:
    """Unexpected HTTP errors become OpenBaoError."""

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> BinaryIO:
        raise HTTPError(
            url=request.full_url,
            code=http_status,
            msg="Request failed",
            hdrs=Message(),
            fp=BytesIO(b"{}"),
        )

    monkeypatch.setattr(
        status_module,
        "urlopen",
        fake_urlopen,
    )

    with pytest.raises(OpenBaoError, match=f"HTTP {http_status}"):
        status_openbao(ADDRESS)


@pytest.mark.parametrize(
    "failure",
    [
        URLError("connection refused"),
        TimeoutError("connection timed out"),
        OSError("network unavailable"),
    ],
)
def test_translates_connection_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    """Connection failures become domain-specific errors."""

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> BinaryIO:
        raise failure

    monkeypatch.setattr(
        status_module,
        "urlopen",
        fake_urlopen,
    )

    with pytest.raises(
        OpenBaoError,
        match="unable to connect to OpenBao service",
    ):
        status_openbao(ADDRESS)


# ---------------------------------------------------------------------------
# Status response validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not json",
        b"{invalid}",
        b"null",
        b"[]",
        b'"string"',
    ],
)
def test_rejects_invalid_status_documents(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    """Reject malformed JSON and non-object responses."""
    _mock_status_response(monkeypatch, payload)

    with pytest.raises(OpenBaoError, match="OpenBao"):
        status_openbao(ADDRESS)


@pytest.mark.parametrize(
    "missing_field",
    [
        "initialized",
        "sealed",
        "version",
        "type",
        "n",
        "t",
        "progress",
    ],
)
def test_rejects_missing_status_fields(
    monkeypatch: pytest.MonkeyPatch,
    missing_field: str,
) -> None:
    """All required status fields must be present."""
    document = dict(VALID_STATUS)
    del document[missing_field]

    _mock_status_response(
        monkeypatch,
        json.dumps(document).encode("utf-8"),
    )

    with pytest.raises(
        OpenBaoError,
        match=f"invalid or missing field: {missing_field}",
    ):
        status_openbao(ADDRESS)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("initialized", "true"),
        ("sealed", 1),
        ("version", None),
        ("type", 123),
        ("n", True),
        ("t", "2"),
        ("progress", False),
    ],
)
def test_rejects_invalid_status_field_types(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    invalid_value: object,
) -> None:
    """Reject invalid types, including booleans in integer fields."""
    _mock_status_response(
        monkeypatch,
        _status_payload(**{field: invalid_value}),
    )

    with pytest.raises(
        OpenBaoError,
        match=f"invalid or missing field: {field}",
    ):
        status_openbao(ADDRESS)


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("timeout", [0.0, -1.0, -10.0])
def test_rejects_nonpositive_timeout(timeout: float) -> None:
    """Require a positive request timeout."""
    with pytest.raises(
        OpenBaoError,
        match="timeout must be positive",
    ):
        status_openbao(ADDRESS, timeout=timeout)
