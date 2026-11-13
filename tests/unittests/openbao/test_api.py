"""Unit tests for shared OpenBao API foundations.

Verify service-origin validation and error semantics without network
access or a running OpenBao instance.
"""

from __future__ import annotations

import pytest

from mxm.control.openbao.api import OpenBaoError, validated_address

# ---------------------------------------------------------------------------
# Valid OpenBao service addresses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        (
            "https://openbao.example.test",
            "https://openbao.example.test",
        ),
        (
            "https://openbao.example.test/",
            "https://openbao.example.test",
        ),
        (
            "https://openbao.tail546174.ts.net",
            "https://openbao.tail546174.ts.net",
        ),
        (
            "https://openbao.example.test:8200",
            "https://openbao.example.test:8200",
        ),
        (
            "https://openbao.example.test:443/",
            "https://openbao.example.test:443",
        ),
        (
            "https://127.0.0.1:8200",
            "https://127.0.0.1:8200",
        ),
        (
            "https://[::1]:8200",
            "https://[::1]:8200",
        ),
    ],
)
def test_accepts_valid_https_origins(
    address: str,
    expected: str,
) -> None:
    """Accept valid HTTPS origins and remove a trailing slash."""
    assert validated_address(address) == expected


# ---------------------------------------------------------------------------
# Invalid OpenBao service addresses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "",
        " ",
        "openbao.example.test",
        "openbao.example.test:8200",
        "http://openbao.example.test",
        "ftp://openbao.example.test",
        "ssh://openbao.example.test",
        "https://",
        "https:///openbao.example.test",
        "https://user@openbao.example.test",
        "https://user:password@openbao.example.test",
        "https://openbao.example.test/v1/sys",
        "https://openbao.example.test/path/",
        "https://openbao.example.test?token=secret",
        "https://openbao.example.test/#fragment",
        "https://openbao.example.test:invalid",
        "https://openbao.example.test:99999",
        "https://openbao.example.test:0",
        "https://openbao.example.test:-1",
        "https://[invalid-ipv6",
    ],
)
def test_rejects_invalid_service_origins(address: str) -> None:
    """Reject addresses that are not valid HTTPS service origins."""
    with pytest.raises(OpenBaoError):
        validated_address(address)


@pytest.mark.parametrize(
    "address",
    [
        "https://user@openbao.example.test",
        "https://user:password@openbao.example.test",
    ],
)
def test_rejects_embedded_credentials(address: str) -> None:
    """Credentials must never be embedded in OpenBao service addresses."""
    with pytest.raises(
        OpenBaoError,
        match="HTTPS service origin",
    ):
        validated_address(address)


@pytest.mark.parametrize(
    "address",
    [
        "https://openbao.example.test/v1/sys/seal-status",
        "https://openbao.example.test/v1/sys/init",
        "https://openbao.example.test/?token=secret",
        "https://openbao.example.test/#fragment",
    ],
)
def test_rejects_api_paths_queries_and_fragments(address: str) -> None:
    """Capabilities, not callers, construct OpenBao API paths."""
    with pytest.raises(
        OpenBaoError,
        match="HTTPS service origin",
    ):
        validated_address(address)


@pytest.mark.parametrize(
    "address",
    [
        "https://openbao.example.test:not-a-port",
        "https://openbao.example.test:99999",
        "https://openbao.example.test:0",
        "https://openbao.example.test:-1",
    ],
)
def test_rejects_invalid_ports(address: str) -> None:
    """Reject malformed and out-of-range service ports."""
    with pytest.raises(
        OpenBaoError,
        match=r"port|address",
    ):
        validated_address(address)


def test_preserves_explicit_nondefault_port() -> None:
    """Do not rewrite a caller-specified service port."""
    address = "https://openbao.example.test:8200"

    assert validated_address(address) == address


def test_does_not_require_a_live_service() -> None:
    """Address validation is purely syntactic and performs no I/O."""
    address = "https://does-not-exist.invalid"

    assert validated_address(address) == address


# ---------------------------------------------------------------------------
# Shared error type
# ---------------------------------------------------------------------------


def test_openbao_error_is_runtime_error() -> None:
    """OpenBao failures use the established control-plane error convention."""
    error = OpenBaoError("operation failed")

    assert isinstance(error, RuntimeError)
    assert str(error) == "operation failed"
