"""Operator-authorized restoration of an estate-managed OpenBao authority.

``restore_openbao`` is the public, end-to-end operator capability. It resolves
OpenBao from the authoritative estate, acquires a selected snapshot through
``staged_snapshot``, presents an immutable recovery plan for authorization,
and delegates appliance recovery to ``restore_openbao_snapshot``.

``restore_openbao_snapshot`` performs the appliance-level recovery sequence:
validate the snapshot and destination, initialize temporary 1-of-1 Shamir
authority, unseal, force-restore the snapshot, restart the appliance, and
verify the restored seal configuration.

Temporary initialization credentials are used internally and exist only
for the duration of the recovery process. They are not persisted or returned.

``restore_raft_snapshot`` provides the lower-level authenticated HTTPS
transport for a single Raft snapshot restoration request.

Restoration replaces authoritative Raft state and is destructive and
non-idempotent. Operator authorization is required before any mutation.
Neither initialization nor restoration is automatically retried.

The staged SHA-256 checksum verifies consistency of the acquired bytes,
not independent authenticity of the snapshot source.

An interrupted recovery reports its failure phase without assuming the
destination is unchanged. Operators must inspect the appliance state before
deciding whether to verify the restored authority or reset the destination
and retry.

After successful restoration, the appliance remains sealed. It must be
unsealed using the original Shamir shares. Authentication and verification
of recovered secrets are separate operator operations.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import math
import os
import re
import ssl
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
from urllib.parse import urlsplit

from mxm.control.openbao.api import OpenBaoError, validated_address
from mxm.control.openbao.initialise import (
    OpenBaoInitialization,
    initialise_openbao,
)
from mxm.control.openbao.lifecycle import restart_openbao
from mxm.control.openbao.status import status_openbao
from mxm.control.openbao.unseal import unseal_openbao
from mxm.control.service import resolve_service
from mxm.control.snapshot import staged_snapshot

_CHUNK_SIZE = 64 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024


class OpenBaoRestoreUncertainError(OpenBaoError):
    """The snapshot may have been applied, but the outcome is unknown."""


@dataclass(frozen=True)
class OpenBaoRestoreResult:
    """Confirmed result of a Raft snapshot restore request."""

    sha256: str
    size: int
    forced: bool


def _validate_restore_parameters(
    token: str,
    expected_sha256: str | None,
    timeout: float,
) -> None:
    """Validate authority, optional checksum, and network timeout."""
    if (
        not token
        or not token.isascii()
        or not token.isprintable()
        or any(character.isspace() for character in token)
    ):
        raise OpenBaoError("invalid OpenBao restore token")

    if (
        expected_sha256 is not None
        and re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256) is None
    ):
        raise OpenBaoError("expected SHA-256 must be 64 hexadecimal characters")

    if not math.isfinite(timeout) or timeout <= 0:
        raise OpenBaoError("OpenBao restore timeout must be positive and finite")


def _snapshot_checksum(stream: BinaryIO) -> str:
    """Hash a local snapshot without loading it into memory."""
    digest = hashlib.sha256()

    while chunk := stream.read(_CHUNK_SIZE):
        digest.update(chunk)

    stream.seek(0)
    return digest.hexdigest()


def _validate_snapshot(
    stream: BinaryIO,
    expected_sha256: str | None,
) -> tuple[int, str]:
    """Verify the opened snapshot before any restore request."""
    metadata = os.fstat(stream.fileno())

    if not stat.S_ISREG(metadata.st_mode):
        raise OpenBaoError("restore snapshot must be a regular file")

    if metadata.st_size <= 0:
        raise OpenBaoError("restore snapshot must not be empty")

    checksum = _snapshot_checksum(stream)

    if expected_sha256 is not None and not hmac.compare_digest(
        checksum, expected_sha256.lower()
    ):
        raise OpenBaoError("restore snapshot SHA-256 mismatch")

    return metadata.st_size, checksum


def _restore_endpoint(force: bool) -> str:
    """Select the normal or explicitly forced restore endpoint."""
    if force:
        return "/v1/sys/storage/raft/snapshot-force"

    return "/v1/sys/storage/raft/snapshot"


class _SnapshotConnection(Protocol):
    """Minimal HTTP connection interface for snapshot streaming."""

    def putrequest(self, method: str, url: str, /) -> None: ...

    def putheader(self, name: str, value: str, /) -> None: ...

    def endheaders(self) -> None: ...

    def send(self, data: bytes, /) -> None: ...


def _send_snapshot(
    connection: _SnapshotConnection,
    stream: BinaryIO,
    *,
    size: int,
    token: str,
    force: bool,
) -> None:
    """Stream the binary snapshot with a fixed Content-Length."""
    connection.putrequest(
        "POST",
        _restore_endpoint(force),
    )
    connection.putheader("X-Vault-Token", token)
    connection.putheader("X-Vault-Request", "true")
    connection.putheader("Content-Type", "application/octet-stream")
    connection.putheader("Accept", "application/json")
    connection.putheader("Content-Length", str(size))
    connection.endheaders()

    sent = 0

    while chunk := stream.read(_CHUNK_SIZE):
        connection.send(chunk)
        sent += len(chunk)

    if sent != size:
        raise OpenBaoRestoreUncertainError(
            "snapshot changed during upload; inspect OpenBao state before recovery"
        )


def _submit_restore(
    address: str,
    stream: BinaryIO,
    *,
    size: int,
    token: str,
    force: bool,
    timeout: float,
) -> None:
    """Submit exactly one restore request through verified HTTPS."""
    origin = urlsplit(address)
    hostname = origin.hostname

    if hostname is None:
        raise OpenBaoError("OpenBao service address has no hostname")

    connection = http.client.HTTPSConnection(
        host=hostname,
        port=origin.port or 443,
        timeout=timeout,
        context=ssl.create_default_context(),
    )

    try:
        _send_snapshot(
            connection,
            stream,
            size=size,
            token=token,
            force=force,
        )

        response = connection.getresponse()
        payload = response.read(_MAX_RESPONSE_BYTES + 1)

        if response.status not in (200, 204):
            raise OpenBaoRestoreUncertainError(
                "OpenBao restore did not return a successful response; "
                "inspect appliance state before recovery"
            )

        if len(payload) > _MAX_RESPONSE_BYTES:
            raise OpenBaoRestoreUncertainError(
                "OpenBao restore response exceeded the size limit; "
                "inspect appliance state before recovery"
            )

    except (OSError, http.client.HTTPException) as exc:
        raise OpenBaoRestoreUncertainError(
            "OpenBao restore outcome is uncertain; "
            "inspect appliance state before recovery"
        ) from exc

    finally:
        connection.close()


def restore_raft_snapshot(
    address: str,
    *,
    snapshot: Path,
    token: str,
    force: bool = False,
    expected_sha256: str | None = None,
    timeout: float = 120.0,
) -> OpenBaoRestoreResult:
    """Restore a local Raft snapshot to an initialized, unsealed OpenBao.

    Args:
        address: HTTPS origin of the destination OpenBao service.
        snapshot: Local path to the staged Raft snapshot.
        token: OpenBao token authorized to restore Raft snapshots.
        force: Explicitly bypass snapshot seal-key compatibility checks.
        expected_sha256: Optional checksum verified before upload.
        timeout: Network timeout in seconds.

    Returns:
        Confirmation of the submitted snapshot's checksum, size, and mode.

    Raises:
        OpenBaoError: Invalid input, snapshot, or destination precondition.
        OpenBaoRestoreUncertainError: A restore request may have
            changed storage, but its outcome could not be confirmed.

    The caller must establish authorization to replace destination state
    before invoking this function. A successful response does not prove
    that the restored appliance is healthy or ready for unsealing.
    """
    origin = validated_address(address)

    _validate_restore_parameters(
        token,
        expected_sha256,
        timeout,
    )

    try:
        stream = snapshot.open("rb")
    except OSError as exc:
        raise OpenBaoError("unable to open restore snapshot") from exc

    with stream:
        try:
            size, checksum = _validate_snapshot(
                stream,
                expected_sha256,
            )
        except OSError as exc:
            raise OpenBaoError("unable to validate restore snapshot") from exc

        status = status_openbao(origin, timeout=timeout)

        if not status.initialized:
            raise OpenBaoError("OpenBao must be initialized before snapshot restore")

        if status.sealed:
            raise OpenBaoError("OpenBao must be unsealed before snapshot restore")

        _submit_restore(
            origin,
            stream,
            size=size,
            token=token,
            force=force,
            timeout=timeout,
        )

    return OpenBaoRestoreResult(
        sha256=checksum,
        size=size,
        forced=force,
    )


@dataclass(frozen=True, slots=True)
class OpenBaoRestorePlan:
    """Immutable description submitted for approval before any mutation.

    The checksum is computed by snapshot staging; it is not an operator
    argument or an independent assertion of snapshot provenance.
    """

    address: str
    machine: str
    snapshot_source: str
    snapshot_size: int
    snapshot_sha256: str
    expected_shares: int
    expected_threshold: int


@dataclass(frozen=True)
class OpenBaoRecoveryResult:
    """Completed snapshot recovery, awaiting normal operator unseal."""

    restore: OpenBaoRestoreResult
    shares: int
    threshold: int


class OpenBaoRecoveryInterruptedError(OpenBaoError):
    """Recovery stopped; inspect appliance state before resetting or retrying."""

    def __init__(self, phase: str) -> None:
        super().__init__(
            f"OpenBao recovery interrupted during {phase}; "
            "inspect appliance state before taking further action"
        )
        self.phase = phase


def _validate_recovery_snapshot(
    snapshot: Path,
    expected_sha256: str,
) -> None:
    """Validate the recovery snapshot before modifying OpenBao state."""
    if re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256) is None:
        raise OpenBaoError("expected SHA-256 must be 64 hexadecimal characters")

    try:
        with snapshot.open("rb") as stream:
            _validate_snapshot(stream, expected_sha256)
    except OSError as exc:
        raise OpenBaoError("unable to validate recovery snapshot") from exc


def _validate_recovery_configuration(
    *,
    shares: int,
    threshold: int,
    timeout: float,
) -> None:
    """Validate the expected original Shamir configuration."""
    if type(shares) is not int or type(threshold) is not int:
        raise OpenBaoError("recovery seal configuration must contain integers")

    if not 1 <= threshold <= shares <= 255:
        raise OpenBaoError("recovery requires 1 <= threshold <= shares <= 255")

    if not math.isfinite(timeout) or timeout <= 0:
        raise OpenBaoError("OpenBao recovery timeout must be positive and finite")


def _require_empty_recovery_target(
    address: str,
    *,
    timeout: float,
) -> None:
    """Require a fresh, uninitialized OpenBao target."""
    status = status_openbao(address, timeout=timeout)

    if status.initialized:
        raise OpenBaoError("recovery requires an uninitialized OpenBao target")


def _unseal_temporary_authority(
    address: str,
    authority: OpenBaoInitialization,
    *,
    timeout: float,
) -> None:
    """Unseal temporary 1-of-1 authority without interactive entry."""

    def get_share(number: int, total: int) -> str:
        if number != 1 or total != 1:
            raise OpenBaoError("unexpected temporary recovery seal configuration")

        if len(authority.unseal_keys) != 1:
            raise OpenBaoError("temporary recovery authority has invalid share count")

        return authority.unseal_keys[0]

    result = unseal_openbao(
        address,
        get_share=get_share,
        timeout=timeout,
    )

    if result.sealed or result.threshold != 1 or result.shares != 1:
        raise OpenBaoError("temporary OpenBao authority was not fully unsealed")


def _verify_recovered_seal(
    address: str,
    *,
    shares: int,
    threshold: int,
    timeout: float,
) -> None:
    """Verify the expected restored Shamir seal configuration."""
    status = status_openbao(address, timeout=timeout)

    if not status.initialized:
        raise OpenBaoError("restored OpenBao instance is not initialized")

    if not status.sealed:
        raise OpenBaoError("restored OpenBao instance is not sealed")

    if (
        status.seal_type != "shamir"
        or status.shares != shares
        or status.threshold != threshold
    ):
        raise OpenBaoError(
            "restored OpenBao seal configuration does not match expectations"
        )


def _restart_recovered_appliance(
    restart: Callable[[], None],
) -> None:
    """Restart the appliance; report interruption if the outcome is uncertain."""
    try:
        restart()
    except Exception:
        raise OpenBaoRecoveryInterruptedError(
            "appliance restart",
        ) from None


def _verify_recovered_appliance(
    address: str,
    *,
    shares: int,
    threshold: int,
    timeout: float,
) -> None:
    """Check the restored appliance after its controller restart."""
    try:
        _verify_recovered_seal(
            address,
            shares=shares,
            threshold=threshold,
            timeout=timeout,
        )
    except OpenBaoError:
        raise OpenBaoRecoveryInterruptedError(
            "post-restore verification",
        ) from None


def restore_openbao_snapshot(
    address: str,
    *,
    snapshot: Path,
    expected_sha256: str,
    restart: Callable[[], None],
    expected_shares: int = 3,
    expected_threshold: int = 2,
    timeout: float = 120.0,
) -> OpenBaoRecoveryResult:
    """Recover an OpenBao appliance from an already-staged local snapshot.

    This lower-level capability accepts an explicit address, a verified local
    snapshot and a supervised restart callback. ``restore_openbao`` normally
    supplies these values after estate resolution, staging and authorization.

    The snapshot must already be staged locally. Its checksum is
    verified before the target is initialized.

    The operation requires a fresh, uninitialized target and uses
    temporary 1-of-1 Shamir authority exclusively for force restore.

    The restart callback must restart the OpenBao appliance and return
    only after its HTTPS status endpoint is reachable again.

    Success means the target is initialized, sealed, and reports the
    expected original Shamir configuration. It does not prove that
    the restored secrets or authentication configuration are usable.

    Normal operator unseal, login, and application verification are
    separate lifecycle operations.

    Recovery is non-idempotent. Failed steps are never retried
    automatically.
    """
    origin = validated_address(address)

    _validate_recovery_configuration(
        shares=expected_shares,
        threshold=expected_threshold,
        timeout=timeout,
    )

    _validate_recovery_snapshot(
        snapshot,
        expected_sha256,
    )

    _require_empty_recovery_target(
        origin,
        timeout=timeout,
    )

    try:
        authority = initialise_openbao(
            origin,
            shares=1,
            threshold=1,
            timeout=timeout,
        )
    except OpenBaoError:
        raise OpenBaoRecoveryInterruptedError(
            "temporary initialization",
        ) from None

    try:
        _unseal_temporary_authority(
            origin,
            authority,
            timeout=timeout,
        )
    except OpenBaoError:
        raise OpenBaoRecoveryInterruptedError(
            "temporary unseal",
        ) from None

    try:
        restored = restore_raft_snapshot(
            origin,
            snapshot=snapshot,
            token=authority.root_token,
            force=True,
            expected_sha256=expected_sha256,
            timeout=timeout,
        )
    except OpenBaoError:
        raise OpenBaoRecoveryInterruptedError(
            "snapshot restoration",
        ) from None

    _restart_recovered_appliance(
        restart,
    )

    _verify_recovered_appliance(
        origin,
        shares=expected_shares,
        threshold=expected_threshold,
        timeout=timeout,
    )

    return OpenBaoRecoveryResult(
        restore=restored,
        shares=expected_shares,
        threshold=expected_threshold,
    )


def restore_openbao(
    *,
    estate_root: Path,
    snapshot_uri: str,
    authorize: Callable[[OpenBaoRestorePlan], bool],
    expected_shares: int = 3,
    expected_threshold: int = 2,
    timeout: float = 120.0,
) -> OpenBaoRecoveryResult:
    """Restore the estate-managed OpenBao authority from a selected snapshot.

    This is the sole public operator-level restore verb. Its caller supplies
    the estate root, snapshot URI and an authorization callback;
    it does not supply a checksum, destination address, bootstrap credentials
    or restart mechanism.
    First validate the expected Shamir configuration, resolve the destination
    service through the estate and stage the selected snapshot. Staging hashes
    bytes as they arrive and yields a private local file for the lifetime of
    the context. An immutable plan (including source, size and digest) is
    passed to ``authorize``; only an exact True return permits mutation.

    After approval, ``restore_openbao_snapshot`` rechecks the staged checksum
    before initializing the target. The supplied restart callback delegates
    to the estate-managed systemd service operation. Neither this function
    nor its lower-level components retry destructive requests automatically.

    Args:
        estate_root: mxm-estate root directory.
        snapshot_uri: Local or UPath/fsspec-compatible snapshot location.
        authorize: Operator-controlled approval callback. Must return True
            to authorize the exact staged artifact and resolved target.
        expected_shares: Expected Shamir share count after recovery.
        expected_threshold: Expected threshold after recovery.
        timeout: HTTPS operation timeout in seconds.

    Returns:
        Recovery metadata after the restored appliance is initialized,
        sealed and reports the expected Shamir configuration.

    Raises:
        ServiceError: Estate resolution or connection preflight fails.
        SnapshotError: Snapshot acquisition or integrity verification fails.
        PermissionError: Operator does not approve the recovery plan.
        OpenBaoError: Validation or recovery fails before temporary
            initialization is confirmed.
        OpenBaoRecoveryInterruptedError: Recovery is interrupted after
            temporary initialization; inspect appliance state before retrying.

    No mutation occurs before the approval callback returns True. After
    approval, failure does not imply that destination state is unchanged.
    In particular, initialization or restore failures can have uncertain
    effects; a caller must never blindly repeat the operation.
    """
    _validate_recovery_configuration(
        shares=expected_shares,
        threshold=expected_threshold,
        timeout=timeout,
    )
    target = resolve_service(
        estate_root=estate_root,
        name="openbao",
    ).target

    with staged_snapshot(snapshot_uri) as snapshot:
        plan = OpenBaoRestorePlan(
            address=target.address,
            machine=target.machine,
            snapshot_source=snapshot.source,
            snapshot_size=snapshot.size,
            snapshot_sha256=snapshot.sha256,
            expected_shares=expected_shares,
            expected_threshold=expected_threshold,
        )

        if authorize(plan) is not True:
            raise PermissionError("OpenBao restoration was not authorized")

        def restart() -> None:
            """Restart exactly the estate-resolved OpenBao systemd unit."""
            restart_openbao(target)

        return restore_openbao_snapshot(
            target.address,
            snapshot=snapshot.path,
            expected_sha256=snapshot.sha256,
            restart=restart,
            expected_shares=expected_shares,
            expected_threshold=expected_threshold,
            timeout=timeout,
        )


__all__ = [
    "OpenBaoRecoveryInterruptedError",
    "OpenBaoRecoveryResult",
    "OpenBaoRestorePlan",
    "OpenBaoRestoreResult",
    "OpenBaoRestoreUncertainError",
    "restore_openbao",
    "restore_openbao_snapshot",
    "restore_raft_snapshot",
]
