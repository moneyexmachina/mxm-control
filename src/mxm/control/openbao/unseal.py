"""OpenBao Shamir unseal capabilities.

Submit individual Shamir shares through verified HTTPS, or coordinate
a complete unseal operation using a caller-provided share callback.

Interactive input belongs to the operator layer, not this module.

Shares are never logged, persisted, or included in error messages.
Ambiguous submissions are never retried automatically.
"""

from __future__ import annotations

import http.client
import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit

from mxm.control.openbao.api import OpenBaoError, validated_address
from mxm.control.openbao.status import OpenBaoStatus, status_openbao

_MAX_RESPONSE_BYTES = 64 * 1024

ShareProvider = Callable[[int, int], str]


class OpenBaoUnsealUncertainError(OpenBaoError):
    """A share may have been accepted, but its outcome is unknown."""


@dataclass(frozen=True)
class OpenBaoUnsealResult:
    """State of an OpenBao Shamir unseal operation."""

    sealed: bool
    progress: int
    threshold: int
    shares: int

    @property
    def remaining(self) -> int:
        """Number of additional shares required by the reported state."""
        if not self.sealed:
            return 0

        return max(0, self.threshold - self.progress)


def _validate_share(share: str) -> None:
    """Reject empty or malformed input before contacting OpenBao."""
    if not share:
        raise OpenBaoError("unseal share must not be empty")

    if not share.isascii() or not share.isprintable():
        raise OpenBaoError("unseal share must contain printable ASCII characters")

    if any(character.isspace() for character in share):
        raise OpenBaoError("unseal share must not contain whitespace")


def _preflight_unseal(status: OpenBaoStatus) -> OpenBaoUnsealResult:
    """Validate the target's Shamir seal configuration."""
    if not status.initialized:
        raise OpenBaoError("OpenBao instance is not initialized")

    if status.seal_type != "shamir":
        raise OpenBaoError("OpenBao instance does not use a Shamir seal")

    if not 1 <= status.threshold <= status.shares:
        raise OpenBaoError("OpenBao has an invalid seal configuration")

    if status.sealed and not 0 <= status.progress < status.threshold:
        raise OpenBaoError("OpenBao has invalid unseal progress")

    return OpenBaoUnsealResult(
        sealed=status.sealed,
        progress=status.progress,
        threshold=status.threshold,
        shares=status.shares,
    )


def _parse_unseal_response(payload: bytes) -> OpenBaoUnsealResult:
    """Parse the unseal response without exposing its contents."""
    try:
        document: object = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OpenBaoUnsealUncertainError(
            "OpenBao returned invalid unseal JSON; "
            "inspect seal status before continuing"
        ) from exc

    if not isinstance(document, dict):
        raise OpenBaoUnsealUncertainError("OpenBao returned an invalid unseal response")

    data = cast("dict[str, object]", document)

    sealed = data.get("sealed")
    progress = data.get("progress")
    threshold = data.get("t")
    shares = data.get("n")

    if (
        type(sealed) is not bool
        or type(progress) is not int
        or type(threshold) is not int
        or type(shares) is not int
    ):
        raise OpenBaoUnsealUncertainError(
            "OpenBao unseal response has missing or invalid fields"
        )

    if (
        not 1 <= threshold <= shares
        or progress < 0
        or (sealed and progress >= threshold)
        or (not sealed and progress != 0)
    ):
        raise OpenBaoUnsealUncertainError(
            "OpenBao unseal response has inconsistent state"
        )

    return OpenBaoUnsealResult(
        sealed=sealed,
        progress=progress,
        threshold=threshold,
        shares=shares,
    )


def _post_unseal(
    address: str,
    *,
    share: str,
    timeout: float,
) -> bytes:
    """Submit one share through HTTPS without retries or redirects."""
    origin = urlsplit(address)
    hostname = origin.hostname

    if hostname is None:
        raise OpenBaoError("OpenBao service address has no hostname")

    body = json.dumps({"key": share}).encode("utf-8")

    connection = http.client.HTTPSConnection(
        host=hostname,
        port=origin.port or 443,
        timeout=timeout,
        context=ssl.create_default_context(),
    )

    try:
        connection.request(
            "POST",
            "/v1/sys/unseal",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        response = connection.getresponse()
        payload = response.read(_MAX_RESPONSE_BYTES + 1)

        if response.status != 200:
            raise OpenBaoUnsealUncertainError(
                "OpenBao rejected or could not process the unseal request; "
                "inspect seal status before continuing"
            )

        if len(payload) > _MAX_RESPONSE_BYTES:
            raise OpenBaoUnsealUncertainError(
                "OpenBao unseal response exceeded the size limit; "
                "inspect seal status before continuing"
            )

        return payload

    except (OSError, http.client.HTTPException) as exc:
        raise OpenBaoUnsealUncertainError(
            "OpenBao unseal outcome is uncertain; inspect seal status before continuing"
        ) from exc

    finally:
        connection.close()


def _validate_timeout(timeout: float) -> None:
    """Require a positive, finite network timeout."""
    if not 0 < timeout < float("inf"):
        raise OpenBaoError("OpenBao timeout must be positive and finite")


def submit_unseal_share(
    address: str,
    *,
    share: str,
    timeout: float = 10.0,
) -> OpenBaoUnsealResult:
    """Submit exactly one Shamir share to an initialized instance.

    Already-unsealed instances are returned without submitting the share.

    A submission is attempted at most once. Transport or response
    failures propagate as uncertain outcomes.
    """
    origin = validated_address(address)
    _validate_share(share)
    _validate_timeout(timeout)

    status = status_openbao(origin, timeout=timeout)
    current = _preflight_unseal(status)

    if not current.sealed:
        return current

    payload = _post_unseal(
        origin,
        share=share,
        timeout=timeout,
    )

    result = _parse_unseal_response(payload)

    if result.threshold != current.threshold or result.shares != current.shares:
        raise OpenBaoUnsealUncertainError(
            "OpenBao seal configuration changed during unseal; "
            "inspect seal status before continuing"
        )

    return result


def unseal_openbao(
    address: str,
    *,
    get_share: ShareProvider,
    timeout: float = 10.0,
) -> OpenBaoUnsealResult:
    """Coordinate a complete Shamir unseal operation.

    Args:
        address: HTTPS origin of the OpenBao service.
        get_share: Callback accepting the next share number and total
            threshold, returning one unseal share.
        timeout: Network timeout for each API request.

    Returns:
        Final OpenBao seal state, with sealed=False.

    Raises:
        OpenBaoError: Invalid configuration or lifecycle state.
        OpenBaoUnsealUncertainError: A submission has an uncertain
            outcome or does not advance the expected state.

    The callback may prompt an operator or supply temporary bootstrap
    authority programmatically.

    Shares are requested individually and never accumulated by this
    function. Cancellation and callback exceptions propagate unchanged.

    Any failure terminates the operation without automatic retries.
    """
    origin = validated_address(address)
    _validate_timeout(timeout)

    status = status_openbao(origin, timeout=timeout)
    current = _preflight_unseal(status)

    while current.sealed:
        share_number = current.progress + 1

        share = get_share(
            share_number,
            current.threshold,
        )

        result = submit_unseal_share(
            origin,
            share=share,
            timeout=timeout,
        )

        if result.sealed and result.progress <= current.progress:
            raise OpenBaoUnsealUncertainError(
                "OpenBao unseal progress did not advance; "
                "inspect seal status before continuing"
            )

        current = result

    return current


__all__ = [
    "OpenBaoUnsealResult",
    "OpenBaoUnsealUncertainError",
    "ShareProvider",
    "submit_unseal_share",
    "unseal_openbao",
]
