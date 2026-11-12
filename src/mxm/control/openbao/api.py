"""Shared API foundations for OpenBao lifecycle capabilities.

Provide common error handling and service-address validation for
OpenBao operations.

OpenBao endpoints are accessed over verified HTTPS. Service addresses
are supplied by callers and are not embedded in this module.

HTTP request execution remains with the individual capabilities until
shared transport requirements are established.
"""

from __future__ import annotations

from urllib.parse import urlsplit


class OpenBaoError(RuntimeError):
    """Raised when an OpenBao lifecycle operation cannot be completed."""


def validated_address(address: str) -> str:
    """Validate and normalize an HTTPS OpenBao service origin.

    Args:
        address: HTTPS origin of the OpenBao service.

    Returns:
        The normalized service origin without a trailing slash.

    Raises:
        OpenBaoError: If the address is not a valid HTTPS origin.

    User information, paths, query strings, and fragments are not
    permitted. Individual capabilities append their own API paths.
    """
    try:
        parsed = urlsplit(address)

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise OpenBaoError("OpenBao address must be an HTTPS service origin")

        port = parsed.port

    except ValueError as exc:
        raise OpenBaoError("invalid OpenBao service address or port") from exc

    if port is not None and not 1 <= port <= 65535:
        raise OpenBaoError("invalid OpenBao service port")

    return address.rstrip("/")


__all__ = [
    "OpenBaoError",
    "validated_address",
]
