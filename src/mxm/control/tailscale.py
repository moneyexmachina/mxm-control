"""Tailscale device management for the MXM control plane.

Provide synchronous, typed access to the Tailscale management API.

The module supports OAuth client-credentials authentication, device
discovery, exact tag matching, and explicit device deletion.

Credentials are supplied by the caller, normally from the operator's
credential-bound execution environment. This module does not resolve
secrets or make machine lifecycle decisions.

Machine bootstrap owns the selection, retirement, and verification
workflow built on these operations.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import cast

import httpx

_API_BASE_URL = "https://api.tailscale.com/api/v2/"
_HTTP_TIMEOUT = 30.0
_TOKEN_EXPIRY_MARGIN = 60.0
_DEVICE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]+")


class TailscaleError(RuntimeError):
    """Raised when a Tailscale management operation fails."""


@dataclass(frozen=True, slots=True)
class TailscaleDevice:
    """A device registered in a Tailscale tailnet.

    Attributes:
        id: Device identifier, preferring Tailscale's nodeId.
        name: Device name reported by the control plane.
        tags: Tags assigned to the device.
        connected_to_control: Current control-plane connection status,
            or None if not reported by the API.
    """

    id: str
    name: str
    tags: tuple[str, ...]
    connected_to_control: bool | None = None


def _json_object(response: httpx.Response) -> dict[str, object]:
    """Decode an HTTP response as a JSON object."""
    try:
        document: object = response.json()
    except ValueError:
        raise TailscaleError("Invalid Tailscale API JSON response") from None

    if not isinstance(document, dict):
        raise TailscaleError("Expected a Tailscale API JSON object")

    return cast("dict[str, object]", document)


def _parse_device(raw: object) -> TailscaleDevice:
    """Validate and decode one device from the Tailscale API."""
    if not isinstance(raw, dict):
        raise TailscaleError("Invalid Tailscale device record")

    device = cast("dict[str, object]", raw)

    device_id = device.get("nodeId") or device.get("id")
    name = device.get("name")
    tags = device.get("tags", [])
    connected = device.get("connectedToControl")

    if not isinstance(device_id, str) or not _DEVICE_ID_PATTERN.fullmatch(device_id):
        raise TailscaleError("Invalid Tailscale device identifier")

    if not isinstance(name, str) or not name:
        raise TailscaleError("Invalid Tailscale device name")
    if tags is None:
        typed_tags: list[object] = []
    elif isinstance(tags, list):
        typed_tags = cast("list[object]", tags)
    else:
        raise TailscaleError("Invalid Tailscale device tags")

    if not all(isinstance(tag, str) for tag in typed_tags):
        raise TailscaleError("Invalid Tailscale device tags")

    if connected is not None and not isinstance(connected, bool):
        raise TailscaleError("Invalid Tailscale device connection status")

    return TailscaleDevice(
        id=device_id,
        name=name,
        tags=tuple(cast("list[str]", typed_tags)),
        connected_to_control=connected,
    )


def devices_with_tag(
    devices: Sequence[TailscaleDevice],
    tag: str,
) -> list[TailscaleDevice]:
    """Select devices carrying an exact Tailscale tag.

    Args:
        devices: Devices to inspect.
        tag: Complete tag, such as ``tag:mxm-security``.

    Returns:
        Matching devices in their original order.

    Raises:
        TailscaleError: If the tag is invalid.
    """
    if not tag.startswith("tag:") or len(tag) <= len("tag:"):
        raise TailscaleError(f"Invalid Tailscale tag: {tag!r}")

    return [device for device in devices if tag in device.tags]


class TailscaleClient:
    """Synchronous client for the Tailscale management API.

    Authenticate using OAuth client credentials and reuse the resulting
    short-lived access token until it approaches expiration.

    The caller owns machine lifecycle policy and explicitly selects
    device identifiers for deletion.

    An optional HTTP client permits isolated unit testing with
    ``httpx.MockTransport``.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize the API client with resolved OAuth credentials."""
        if (
            not client_id
            or not client_secret
            or client_id.startswith("pass://")
            or client_secret.startswith("pass://")
        ):
            raise TailscaleError("Resolved Tailscale OAuth credentials are required")

        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None
        self._token_expires_at = 0.0

        self._owns_http_client = http_client is None
        self._http = http_client or httpx.Client(
            base_url=_API_BASE_URL,
            timeout=_HTTP_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        )

    @classmethod
    def from_environment(cls) -> TailscaleClient:
        """Create a client from resolved operator environment variables.

        The calling process must already be running inside the approved
        credential environment.
        """
        return cls(
            client_id=os.environ.get("TAILSCALE_OAUTH_CLIENT_ID", ""),
            client_secret=os.environ.get("TAILSCALE_OAUTH_CLIENT_SECRET", ""),
        )

    def __enter__(self) -> TailscaleClient:
        """Enter the client's managed lifetime."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release HTTP resources owned by this client."""
        self.close()

    def close(self) -> None:
        """Close the internally owned HTTP connection pool."""
        if self._owns_http_client:
            self._http.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Execute one API request with controlled failure reporting."""
        try:
            response = self._http.request(
                method,
                path,
                data=data,
                headers=headers,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise TailscaleError(
                f"Tailscale API {method} {path} "
                f"returned HTTP {exc.response.status_code}"
            ) from None
        except httpx.RequestError:
            raise TailscaleError(
                f"Tailscale API {method} {path} request failed"
            ) from None

        return response

    def _token(self) -> str:
        """Obtain or reuse a short-lived OAuth access token."""
        if self._access_token is not None and time.monotonic() < self._token_expires_at:
            return self._access_token

        response = self._request(
            "POST",
            "oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )

        document = _json_object(response)
        token = document.get("access_token")
        token_type = document.get("token_type")
        expires_in = document.get("expires_in")

        if not isinstance(token, str) or not token:
            raise TailscaleError("Invalid Tailscale OAuth access token")

        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise TailscaleError("Invalid Tailscale OAuth token type")

        if (
            not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or expires_in <= 0
        ):
            raise TailscaleError("Invalid Tailscale OAuth token lifetime")

        self._access_token = token
        self._token_expires_at = time.monotonic() + max(
            0.0,
            expires_in - _TOKEN_EXPIRY_MARGIN,
        )

        return token

    def _authorized_request(
        self,
        method: str,
        path: str,
    ) -> httpx.Response:
        """Execute an API request using the current OAuth token."""
        return self._request(
            method,
            path,
            headers={"Authorization": f"Bearer {self._token()}"},
        )

    def list_devices(self) -> list[TailscaleDevice]:
        """List devices registered in the authenticated tailnet.

        Returns:
            Validated device records, including tags and connection
            status where available.

        Raises:
            TailscaleError: If authentication, the API request, or
                response validation fails.
        """
        response = self._authorized_request(
            "GET",
            "tailnet/-/devices",
        )

        document = _json_object(response)
        raw_devices = document.get("devices")

        if not isinstance(raw_devices, list):
            raise TailscaleError("Tailscale device listing has no valid devices array")
        devices = [_parse_device(raw) for raw in cast("list[object]", raw_devices)]
        identifiers = [device.id for device in devices]

        if len(identifiers) != len(set(identifiers)):
            raise TailscaleError(
                "Tailscale device listing contains duplicate identifiers"
            )

        return devices

    def delete_device(self, device_id: str) -> None:
        """Remove one explicitly identified device registration.

        Args:
            device_id: Exact nodeId or device ID to remove.

        Raises:
            TailscaleError: If the identifier is invalid or the API
                operation fails.

        Removing a device revokes its Tailscale membership immediately.
        The calling orchestration operation is responsible for deciding
        whether and when to perform this action.
        """
        if not _DEVICE_ID_PATTERN.fullmatch(device_id):
            raise TailscaleError("Invalid Tailscale device identifier")

        self._authorized_request(
            "DELETE",
            f"device/{device_id}",
        )
