"""Unit tests for the Tailscale management API client.

All HTTP interactions use httpx.MockTransport. The tests exercise
OAuth authentication, device discovery, tag selection, deletion,
response validation, token expiration, and failure handling.

No external Tailscale API requests or device mutations are performed.
"""

from collections.abc import Callable, Generator
from contextlib import contextmanager
from urllib.parse import parse_qs

import httpx
import pytest

from mxm.control.tailscale import (
    TailscaleClient,
    TailscaleDevice,
    TailscaleError,
    devices_with_tag,
)

_API_BASE_URL = "https://api.tailscale.com/api/v2/"
_OAUTH_PATH = "/api/v2/oauth/token"
_DEVICES_PATH = "/api/v2/tailnet/-/devices"

type RequestHandler = Callable[[httpx.Request], httpx.Response]


def _device(
    *,
    device_id: str = "1001",
    name: str = "mxm-security.tailnet.ts.net",
    tags: list[str] | None = None,
    connected: bool = True,
) -> dict[str, object]:
    """Construct a representative Tailscale API device record."""
    return {
        "nodeId": device_id,
        "name": name,
        "tags": tags if tags is not None else ["tag:mxm-security"],
        "connectedToControl": connected,
    }


def _oauth_handler(
    operation_handler: RequestHandler,
    *,
    expires_in: int = 3600,
) -> RequestHandler:
    """Authenticate OAuth requests and delegate API operations."""

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == _OAUTH_PATH:
            assert request.method == "POST"
            assert request.headers["content-type"].startswith(
                "application/x-www-form-urlencoded"
            )

            form = parse_qs(request.content.decode())

            assert form == {
                "grant_type": ["client_credentials"],
                "client_id": ["test-client-id"],
                "client_secret": ["test-client-secret"],
            }

            return httpx.Response(
                200,
                json={
                    "access_token": "test-access-token",
                    "token_type": "Bearer",
                    "expires_in": expires_in,
                },
            )

        assert request.headers["authorization"] == ("Bearer test-access-token")

        return operation_handler(request)

    return handle


@contextmanager
def _client(handler: RequestHandler) -> Generator[TailscaleClient]:
    """Create a Tailscale client backed by a mock HTTP transport."""
    transport = httpx.MockTransport(handler)

    with httpx.Client(
        base_url=_API_BASE_URL,
        transport=transport,
        trust_env=False,
    ) as http_client:
        with TailscaleClient(
            "test-client-id",
            "test-client-secret",
            http_client=http_client,
        ) as tailscale:
            yield tailscale


def test_list_devices() -> None:
    """List devices and preserve their identities and metadata."""
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)

        assert request.method == "GET"
        assert request.url.path == _DEVICES_PATH

        return httpx.Response(
            200,
            json={
                "devices": [
                    _device(),
                    _device(
                        device_id="1002",
                        name="mxm-factory-agent.tailnet.ts.net",
                        tags=["tag:mxm-factory-agent"],
                        connected=False,
                    ),
                ]
            },
        )

    with _client(_oauth_handler(handle)) as tailscale:
        devices = tailscale.list_devices()

    assert devices == [
        TailscaleDevice(
            id="1001",
            name="mxm-security.tailnet.ts.net",
            tags=("tag:mxm-security",),
            connected_to_control=True,
        ),
        TailscaleDevice(
            id="1002",
            name="mxm-factory-agent.tailnet.ts.net",
            tags=("tag:mxm-factory-agent",),
            connected_to_control=False,
        ),
    ]

    assert len(requests) == 1


def test_list_devices_accepts_empty_tailnet() -> None:
    """An empty devices array represents a valid empty tailnet."""

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == _DEVICES_PATH
        return httpx.Response(200, json={"devices": []})

    with _client(_oauth_handler(handle)) as tailscale:
        assert tailscale.list_devices() == []


def test_list_devices_accepts_id_fallback() -> None:
    """Use the device ID when nodeId is not provided."""
    record = _device()
    record.pop("nodeId")
    record["id"] = "2001"
    record.pop("connectedToControl")

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"devices": [record]})

    with _client(_oauth_handler(handle)) as tailscale:
        devices = tailscale.list_devices()

    assert devices == [
        TailscaleDevice(
            id="2001",
            name="mxm-security.tailnet.ts.net",
            tags=("tag:mxm-security",),
            connected_to_control=None,
        )
    ]


def test_devices_with_tag_matches_exact_membership() -> None:
    """Device selection uses tags rather than names or prefixes."""
    devices = [
        TailscaleDevice(
            id="1001",
            name="mxm-security.tailnet.ts.net",
            tags=("tag:mxm-security",),
        ),
        TailscaleDevice(
            id="1002",
            name="mxm-security-1.tailnet.ts.net",
            tags=("tag:mxm-security", "tag:shared"),
        ),
        TailscaleDevice(
            id="1003",
            name="mxm-security-2.tailnet.ts.net",
            tags=("tag:other",),
        ),
        TailscaleDevice(
            id="1004",
            name="mxm-factory-agent.tailnet.ts.net",
            tags=("tag:mxm-security-dev",),
        ),
    ]

    matching = devices_with_tag(devices, "tag:mxm-security")

    assert [device.id for device in matching] == ["1001", "1002"]


def test_devices_with_tag_returns_empty_for_no_matches() -> None:
    """No matching devices is a valid discovery result."""
    devices = [
        TailscaleDevice(
            id="1001",
            name="mxm-factory-agent",
            tags=("tag:mxm-factory-agent",),
        )
    ]

    assert devices_with_tag(devices, "tag:mxm-security") == []


@pytest.mark.parametrize(
    "tag",
    ["", "mxm-security", "tag:", "TAG:mxm-security"],
)
def test_devices_with_tag_rejects_invalid_tag(tag: str) -> None:
    """Reject incomplete and non-Tailscale tag identifiers."""
    with pytest.raises(TailscaleError, match="Invalid Tailscale tag"):
        devices_with_tag([], tag)


def test_delete_device() -> None:
    """Delete exactly the requested device registration."""
    deleted: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert request.url.path == "/api/v2/device/1001"

        deleted.append(request.url.path)
        return httpx.Response(204)

    with _client(_oauth_handler(handle)) as tailscale:
        tailscale.delete_device("1001")

    assert deleted == ["/api/v2/device/1001"]


@pytest.mark.parametrize(
    "device_id",
    [
        "",
        "../devices",
        "1001/other",
        "1001?force=true",
        "1001 1002",
        "1001\n1002",
    ],
)
def test_delete_device_rejects_invalid_identifier(
    device_id: str,
) -> None:
    """Reject malformed identifiers before issuing an API request."""

    def unexpected_request(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"Unexpected HTTP request: {request.url}")

    with _client(unexpected_request) as tailscale:
        with pytest.raises(
            TailscaleError,
            match="Invalid Tailscale device identifier",
        ):
            tailscale.delete_device(device_id)


def test_oauth_token_reused_across_operations() -> None:
    """Reuse one OAuth token for multiple API requests."""
    oauth_requests = 0
    api_requests = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal oauth_requests, api_requests

        if request.url.path == _OAUTH_PATH:
            oauth_requests += 1

            return httpx.Response(
                200,
                json={
                    "access_token": "shared-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        assert request.headers["authorization"] == ("Bearer shared-token")

        api_requests += 1

        if request.method == "GET":
            return httpx.Response(200, json={"devices": []})

        assert request.method == "DELETE"
        return httpx.Response(204)

    with _client(handle) as tailscale:
        assert tailscale.list_devices() == []
        tailscale.delete_device("1001")
        assert tailscale.list_devices() == []

    assert oauth_requests == 1
    assert api_requests == 3


def test_oauth_token_renewed_before_expiration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Renew OAuth authority when the cached token approaches expiry."""
    clock = [1000.0]
    issued_tokens: list[str] = []
    observed_tokens: list[str] = []

    monkeypatch.setattr(
        "mxm.control.tailscale.time.monotonic",
        lambda: clock[0],
    )

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == _OAUTH_PATH:
            token = f"token-{len(issued_tokens) + 1}"
            issued_tokens.append(token)

            return httpx.Response(
                200,
                json={
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        observed_tokens.append(request.headers["authorization"])

        return httpx.Response(200, json={"devices": []})

    with _client(handle) as tailscale:
        tailscale.list_devices()

        clock[0] += 3500
        tailscale.list_devices()

        clock[0] += 50
        tailscale.list_devices()

    assert issued_tokens == ["token-1", "token-2"]
    assert observed_tokens == [
        "Bearer token-1",
        "Bearer token-1",
        "Bearer token-2",
    ]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([], "Expected a Tailscale API JSON object"),
        ({}, "valid devices array"),
        ({"devices": None}, "valid devices array"),
        ({"devices": "invalid"}, "valid devices array"),
        ({"devices": [None]}, "Invalid Tailscale device record"),
        ({"devices": [42]}, "Invalid Tailscale device record"),
    ],
)
def test_list_devices_rejects_invalid_document(
    payload: object,
    message: str,
) -> None:
    """Reject invalid top-level API response structures."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _client(_oauth_handler(handle)) as tailscale:
        with pytest.raises(TailscaleError, match=message):
            tailscale.list_devices()


@pytest.mark.parametrize(
    ("record", "message"),
    [
        (
            {"nodeId": None, "name": "host", "tags": []},
            "Invalid Tailscale device identifier",
        ),
        (
            {"nodeId": "../bad", "name": "host", "tags": []},
            "Invalid Tailscale device identifier",
        ),
        (
            {"nodeId": "1001", "name": "", "tags": []},
            "Invalid Tailscale device name",
        ),
        (
            {"nodeId": "1001", "name": "host", "tags": "tag:mxm"},
            "Invalid Tailscale device tags",
        ),
        (
            {"nodeId": "1001", "name": "host", "tags": [42]},
            "Invalid Tailscale device tags",
        ),
        (
            {
                "nodeId": "1001",
                "name": "host",
                "tags": [],
                "connectedToControl": "true",
            },
            "Invalid Tailscale device connection status",
        ),
    ],
)
def test_list_devices_rejects_invalid_device(
    record: dict[str, object],
    message: str,
) -> None:
    """Reject incomplete or malformed device metadata."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"devices": [record]})

    with _client(_oauth_handler(handle)) as tailscale:
        with pytest.raises(TailscaleError, match=message):
            tailscale.list_devices()


def test_list_devices_rejects_duplicate_identifiers() -> None:
    """Reject ambiguous device identities in an API response."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "devices": [
                    _device(device_id="1001"),
                    _device(device_id="1001", name="another-host"),
                ]
            },
        )

    with _client(_oauth_handler(handle)) as tailscale:
        with pytest.raises(TailscaleError, match="duplicate identifiers"):
            tailscale.list_devices()


def test_list_devices_rejects_invalid_json() -> None:
    """Report malformed JSON through the Tailscale error boundary."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"not a JSON document",
        )

    with _client(_oauth_handler(handle)) as tailscale:
        with pytest.raises(
            TailscaleError,
            match="Invalid Tailscale API JSON response",
        ):
            tailscale.list_devices()


@pytest.mark.parametrize(
    ("token_response", "message"),
    [
        (
            {
                "access_token": "",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
            "Invalid Tailscale OAuth access token",
        ),
        (
            {
                "access_token": "token",
                "token_type": "Basic",
                "expires_in": 3600,
            },
            "Invalid Tailscale OAuth token type",
        ),
        (
            {
                "access_token": "token",
                "token_type": "Bearer",
                "expires_in": 0,
            },
            "Invalid Tailscale OAuth token lifetime",
        ),
        (
            {
                "access_token": "token",
                "token_type": "Bearer",
                "expires_in": True,
            },
            "Invalid Tailscale OAuth token lifetime",
        ),
    ],
)
def test_oauth_rejects_invalid_token_response(
    token_response: dict[str, object],
    message: str,
) -> None:
    """Reject incomplete OAuth credentials and invalid expiration data."""

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == _OAUTH_PATH
        return httpx.Response(200, json=token_response)

    with _client(handle) as tailscale:
        with pytest.raises(TailscaleError, match=message):
            tailscale.list_devices()


@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
def test_list_devices_reports_api_failure(status_code: int) -> None:
    """Translate failed API requests into a safe management error."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            json={"message": "API request failed"},
        )

    with _client(_oauth_handler(handle)) as tailscale:
        with pytest.raises(
            TailscaleError,
            match=f"returned HTTP {status_code}",
        ):
            tailscale.list_devices()


@pytest.mark.parametrize("status_code", [401, 403, 404, 500])
def test_delete_device_reports_api_failure(status_code: int) -> None:
    """Never silently accept unsuccessful device deletion."""

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        return httpx.Response(status_code)

    with _client(_oauth_handler(handle)) as tailscale:
        with pytest.raises(
            TailscaleError,
            match=f"returned HTTP {status_code}",
        ):
            tailscale.delete_device("1001")


def test_oauth_failure_prevents_device_operations() -> None:
    """Abort management operations when OAuth authentication fails."""
    requests: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)

        assert request.url.path == _OAUTH_PATH
        return httpx.Response(403)

    with _client(handle) as tailscale:
        with pytest.raises(TailscaleError, match="returned HTTP 403"):
            tailscale.delete_device("1001")

    assert requests == [_OAUTH_PATH]


def test_network_failure_is_reported() -> None:
    """Translate transport failures into TailscaleError."""

    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "Connection unavailable",
            request=request,
        )

    with _client(handle) as tailscale:
        with pytest.raises(
            TailscaleError,
            match="request failed",
        ):
            tailscale.list_devices()


@pytest.mark.parametrize(
    ("client_id", "client_secret"),
    [
        ("", "secret"),
        ("client-id", ""),
        ("pass://reference", "secret"),
        ("client-id", "pass://reference"),
    ],
)
def test_client_requires_resolved_credentials(
    client_id: str,
    client_secret: str,
) -> None:
    """Reject missing credentials and unresolved Proton Pass references."""
    with pytest.raises(
        TailscaleError,
        match="Resolved Tailscale OAuth credentials are required",
    ):
        TailscaleClient(client_id, client_secret)


def test_from_environment_reads_resolved_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read resolved OAuth credentials from the operator environment."""
    monkeypatch.setenv("TAILSCALE_OAUTH_CLIENT_ID", "resolved-id")
    monkeypatch.setenv("TAILSCALE_OAUTH_CLIENT_SECRET", "resolved-secret")

    with TailscaleClient.from_environment() as tailscale:
        assert isinstance(tailscale, TailscaleClient)


def test_from_environment_rejects_missing_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an execution environment without OAuth authority."""
    monkeypatch.delenv("TAILSCALE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("TAILSCALE_OAUTH_CLIENT_SECRET", raising=False)

    with pytest.raises(TailscaleError, match="Resolved Tailscale"):
        TailscaleClient.from_environment()


def test_client_does_not_close_injected_http_client() -> None:
    """Preserve caller ownership of an injected HTTP connection pool."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    http_client = httpx.Client(
        base_url=_API_BASE_URL,
        transport=httpx.MockTransport(handle),
        trust_env=False,
    )

    with TailscaleClient(
        "test-client-id",
        "test-client-secret",
        http_client=http_client,
    ) as tailscale:
        assert isinstance(tailscale, TailscaleClient)

    assert not http_client.is_closed
    http_client.close()
    assert http_client.is_closed


@pytest.mark.parametrize(
    "tags",
    [None, []],
)
def test_list_devices_accepts_untagged_device(
    tags: list[str] | None,
) -> None:
    """Accept devices with absent, null, or empty tag information."""
    record: dict[str, object] = {
        "nodeId": "1001",
        "name": "untagged-device",
        "connectedToControl": True,
    }

    if tags is not None:
        record["tags"] = tags

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"devices": [record]},
        )

    with _client(_oauth_handler(handle)) as tailscale:
        devices = tailscale.list_devices()

    assert devices[0].tags == ()
    assert devices_with_tag(devices, "tag:mxm-security") == []


def test_list_devices_accepts_null_tags() -> None:
    """Treat a null tag collection as having no reported tags."""
    record = _device()
    record["tags"] = None

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"devices": [record]},
        )

    with _client(_oauth_handler(handle)) as tailscale:
        devices = tailscale.list_devices()

    assert devices[0].tags == ()
