"""Snapshot acquisition and integrity verification for MXM estate control.

Snapshot locations are addressed through universal-pathlib/fsspec,
supporting local files, SSH/SFTP, and compatible object stores.

Snapshots are streamed into private temporary storage, verified, and
made available to the calling capability for the duration of a context.

This module does not interpret snapshot contents or modify remote state.
"""

from __future__ import annotations

import hashlib
import re
import stat
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from upath import UPath

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
_CHUNK_SIZE = 1024 * 1024


class SnapshotError(RuntimeError):
    """Raised when snapshot acquisition or verification fails."""


@dataclass(frozen=True)
class StagedSnapshot:
    """A locally staged, integrity-checked snapshot artifact.

    Attributes:
        source: Original snapshot location.
        path: Temporary local filesystem path.
        size: Number of bytes in the snapshot.
        sha256: SHA-256 digest of the retrieved bytes.

    The path remains valid only within the staging context.
    """

    source: str
    path: Path
    size: int
    sha256: str


@contextmanager
def staged_snapshot(
    source: str,
    *,
    expected_sha256: str | None = None,
) -> Generator[StagedSnapshot]:
    """Retrieve and verify a snapshot from a storage location.

    Args:
        source: Local path or fsspec-compatible URI.
        expected_sha256: Optional trusted SHA-256 digest of the
            expected snapshot contents.

    Yields:
        A verified snapshot staged in a private local directory.

    Raises:
        SnapshotError: If acquisition or verification fails.

    The snapshot is streamed rather than loaded into memory.
    Temporary files are removed when the context exits, including
    when the caller raises an exception.

    A calculated checksum establishes the identity of the retrieved
    bytes. Authenticity requires comparison against a trusted
    expected checksum supplied by the caller.
    """
    if not source or not source.strip():
        raise SnapshotError("snapshot source must not be empty")

    if expected_sha256 is not None and not _SHA256_PATTERN.fullmatch(expected_sha256):
        raise SnapshotError(
            "expected SHA-256 must be 64 lowercase hexadecimal characters"
        )

    with tempfile.TemporaryDirectory(prefix="mxm-snapshot-") as directory:
        destination = Path(directory) / "snapshot"
        digest = hashlib.sha256()
        size = 0

        try:
            location = UPath(source)

            # The private temporary directory has owner-only access.
            # The staged file itself is also created owner-only.
            with (
                location.open("rb") as input_stream,
                destination.open("xb") as output_stream,
            ):
                destination.chmod(0o600)

                while chunk := input_stream.read(_CHUNK_SIZE):
                    output_stream.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)

        except (OSError, ValueError, ImportError) as exc:
            raise SnapshotError(
                f"unable to acquire snapshot from {source!r}: {exc}"
            ) from exc

        if size == 0:
            raise SnapshotError("snapshot is empty")

        checksum = digest.hexdigest()

        if expected_sha256 is not None and checksum != expected_sha256:
            raise SnapshotError(
                "snapshot checksum mismatch: "
                f"expected={expected_sha256}, actual={checksum}"
            )

        yield StagedSnapshot(
            source=source,
            path=destination,
            size=size,
            sha256=checksum,
        )


@dataclass(frozen=True)
class PublishedSnapshot:
    """A snapshot published and verified at a storage location.

    Attributes:
        destination: URI of the published snapshot.
        size: Number of published bytes.
        sha256: SHA-256 digest verified against the stored object.
    """

    destination: str
    size: int
    sha256: str


def _validated_snapshot_source(source: Path) -> Path:
    """Resolve and validate a non-empty, regular snapshot source."""
    source_path = source.expanduser()

    if source_path.is_symlink():
        raise SnapshotError(
            f"snapshot source must not be a symbolic link: {source_path}"
        )

    try:
        resolved = source_path.resolve(strict=True)

        if not stat.S_ISREG(resolved.stat().st_mode):
            raise SnapshotError(f"snapshot source is not a regular file: {resolved}")

        if resolved.stat().st_size == 0:
            raise SnapshotError("snapshot is empty")

    except OSError as exc:
        raise SnapshotError(
            f"unable to inspect snapshot source: {source_path}"
        ) from exc

    return resolved


def _snapshot_checksum(source: Path) -> tuple[int, str]:
    """Calculate the size and SHA-256 digest of a local snapshot."""
    digest = hashlib.sha256()
    size = 0

    try:
        with source.open("rb") as stream:
            while chunk := stream.read(_CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise SnapshotError(f"unable to read snapshot source: {source}") from exc

    if size == 0:
        raise SnapshotError("snapshot is empty")

    return size, digest.hexdigest()


def _write_snapshot(
    source: Path,
    destination: str,
) -> tuple[int, str]:
    """Stream a snapshot to a new destination without overwriting."""
    digest = hashlib.sha256()
    size = 0

    try:
        location = UPath(destination)

        # Exclusive creation avoids a check-then-write race where
        # supported by the storage backend.
        with (
            source.open("rb") as input_stream,
            location.open("xb") as output_stream,
        ):
            while chunk := input_stream.read(_CHUNK_SIZE):
                output_stream.write(chunk)
                digest.update(chunk)
                size += len(chunk)

    except FileExistsError as exc:
        raise SnapshotError(
            f"snapshot destination already exists: {destination}"
        ) from exc

    except (OSError, ValueError, ImportError, NotImplementedError) as exc:
        raise SnapshotError(
            f"unable to publish snapshot to {destination!r}: {exc}"
        ) from exc

    return size, digest.hexdigest()


def _verify_published_snapshot(
    destination: str,
    *,
    size: int,
    sha256: str,
) -> None:
    """Verify published bytes independently through the storage backend."""
    with staged_snapshot(
        destination,
        expected_sha256=sha256,
    ) as verified:
        if verified.size != size:
            raise SnapshotError(
                "published snapshot size mismatch: "
                f"expected={size}, actual={verified.size}"
            )


def publish_snapshot(
    source: Path,
    destination: str,
) -> PublishedSnapshot:
    """Publish and verify a snapshot at an fsspec-compatible location.

    The destination must not already exist. Source bytes are streamed,
    then independently read back and verified.

    Raises:
        SnapshotError: If validation, publication, or verification fails.

    Note:
        Exclusive creation and atomic visibility depend on the storage
        backend. A failed operation may leave a partial destination.
    """
    if not destination or not destination.strip():
        raise SnapshotError("snapshot destination must not be empty")

    source_path = _validated_snapshot_source(source)
    expected_size, expected_sha256 = _snapshot_checksum(source_path)

    written_size, written_sha256 = _write_snapshot(
        source_path,
        destination,
    )

    if (written_size, written_sha256) != (
        expected_size,
        expected_sha256,
    ):
        raise SnapshotError("snapshot source changed during publication")

    _verify_published_snapshot(
        destination,
        size=expected_size,
        sha256=expected_sha256,
    )

    return PublishedSnapshot(
        destination=destination,
        size=expected_size,
        sha256=expected_sha256,
    )


__all__ = [
    "PublishedSnapshot",
    "SnapshotError",
    "StagedSnapshot",
    "publish_snapshot",
    "staged_snapshot",
]
