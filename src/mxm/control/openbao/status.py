"""Read-only OpenBao initialization and seal-state inspection.

Retrieve OpenBao status through the unauthenticated HTTPS API.

This capability does not authenticate, initialize, unseal, or modify
OpenBao state. Service addresses are supplied by callers.
"""

from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from mxm.control.openbao.api import OpenBaoError, validated_address


@dataclass(frozen=True)
class OpenBaoStatus:
    """Observed initialization and seal state of an OpenBao instance."""

    initialized: bool
    sealed: bool
    version: str
    seal_type: str
    shares: int
    threshold: int
    progress: int


def _request_seal_status(
    address: str,
    *,
    timeout: float,
) -> bytes:
    """Retrieve unauthenticated seal status over verified HTTPS."""
    request = Request(
        f"{address}/v1/sys/seal-status",
        headers={"Accept": "application/json"},
        method="GET",
    )

    try:
        with urlopen(
            request,
            timeout=timeout,
            context=ssl.create_default_context(),
        ) as response:
            return response.read()

    except HTTPError as exc:
        # OpenBao can return lifecycle state JSON with HTTP 501 or 503.
        if exc.code in (501, 503):
            return exc.read()

        raise OpenBaoError(f"OpenBao status request failed: HTTP {exc.code}") from exc

    except (URLError, OSError, TimeoutError) as exc:
        raise OpenBaoError("unable to connect to OpenBao service") from exc


def _parse_seal_status(payload: bytes) -> OpenBaoStatus:
    """Validate and interpret an OpenBao seal-status response."""
    try:
        document: object = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OpenBaoError("OpenBao returned invalid status JSON") from exc

    if not isinstance(document, dict):
        raise OpenBaoError("OpenBao status must be a JSON object")

    data = cast("dict[str, object]", document)

    required_types: dict[str, type] = {
        "initialized": bool,
        "sealed": bool,
        "version": str,
        "type": str,
        "n": int,
        "t": int,
        "progress": int,
    }

    for field, expected_type in required_types.items():
        value = data.get(field)

        if type(value) is not expected_type:
            raise OpenBaoError(f"OpenBao status has invalid or missing field: {field}")

    return OpenBaoStatus(
        initialized=cast("bool", data["initialized"]),
        sealed=cast("bool", data["sealed"]),
        version=cast("str", data["version"]),
        seal_type=cast("str", data["type"]),
        shares=cast("int", data["n"]),
        threshold=cast("int", data["t"]),
        progress=cast("int", data["progress"]),
    )


def status_openbao(
    address: str,
    *,
    timeout: float = 10.0,
) -> OpenBaoStatus:
    """Inspect an OpenBao instance without authentication.

    Args:
        address: HTTPS origin of the OpenBao service.
        timeout: HTTP connection and response timeout in seconds.

    Returns:
        The observed initialization and seal state.

    Raises:
        OpenBaoError: If the service cannot be reached or its response
            cannot be validated.

    This operation never modifies OpenBao state.
    """
    origin = validated_address(address)

    if timeout <= 0:
        raise OpenBaoError("OpenBao timeout must be positive")

    payload = _request_seal_status(origin, timeout=timeout)

    return _parse_seal_status(payload)


__all__ = [
    "OpenBaoStatus",
    "status_openbao",
]
