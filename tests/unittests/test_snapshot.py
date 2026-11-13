"""Unit tests for snapshot acquisition and integrity verification.

Tests exercise the snapshot lifecycle without requiring external
storage, credentials, SSH access, or network connectivity.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import BinaryIO

import pytest

from mxm.control import snapshot as snapshot_module
from mxm.control.snapshot import (
    SnapshotError,
    publish_snapshot,
    staged_snapshot,
)


def _sha256(data: bytes) -> str:
    """Calculate the expected digest independently of the capability."""
    return hashlib.sha256(data).hexdigest()


def test_stages_local_snapshot(tmp_path: Path) -> None:
    """Snapshot bytes and metadata are preserved exactly."""
    data = b"mxm-openbao-snapshot\x00\x01\x02"
    source = tmp_path / "source.snap"
    source.write_bytes(data)

    with staged_snapshot(str(source)) as snapshot:
        assert snapshot.source == str(source)
        assert snapshot.path.is_file()
        assert snapshot.path != source
        assert snapshot.path.read_bytes() == data
        assert snapshot.size == len(data)
        assert snapshot.sha256 == _sha256(data)


def test_removes_staged_snapshot_after_context(tmp_path: Path) -> None:
    """Temporary artifacts are removed after successful consumption."""
    source = tmp_path / "source.snap"
    source.write_bytes(b"snapshot")

    with staged_snapshot(str(source)) as snapshot:
        staged_path = snapshot.path
        staged_directory = staged_path.parent

        assert staged_path.exists()
        assert staged_directory.exists()

    assert not staged_path.exists()
    assert not staged_directory.exists()
    assert source.exists()


def test_removes_staged_snapshot_on_caller_failure(tmp_path: Path) -> None:
    """Consumer exceptions do not leave recovery artifacts behind."""
    source = tmp_path / "source.snap"
    source.write_bytes(b"snapshot")

    staged_path: Path | None = None

    with pytest.raises(RuntimeError, match="consumer failed"):
        with staged_snapshot(str(source)) as snapshot:
            staged_path = snapshot.path
            raise RuntimeError("consumer failed")

    assert staged_path is not None
    assert not staged_path.exists()
    assert not staged_path.parent.exists()


def test_staged_snapshot_has_owner_only_permissions(
    tmp_path: Path,
) -> None:
    """Snapshot staging does not expose sensitive bytes to other users."""
    source = tmp_path / "source.snap"
    source.write_bytes(b"confidential snapshot")

    with staged_snapshot(str(source)) as snapshot:
        file_mode = stat.S_IMODE(snapshot.path.stat().st_mode)
        directory_mode = stat.S_IMODE(snapshot.path.parent.stat().st_mode)

        assert file_mode == 0o600
        assert directory_mode == 0o700


def test_accepts_matching_expected_checksum(tmp_path: Path) -> None:
    """A trusted matching digest permits snapshot consumption."""
    data = b"verified snapshot"
    source = tmp_path / "source.snap"
    source.write_bytes(data)

    with staged_snapshot(
        str(source),
        expected_sha256=_sha256(data),
    ) as snapshot:
        assert snapshot.sha256 == _sha256(data)


def test_rejects_checksum_mismatch(tmp_path: Path) -> None:
    """Retrieved bytes must match an explicitly supplied digest."""
    source = tmp_path / "source.snap"
    source.write_bytes(b"actual snapshot")

    wrong_checksum = _sha256(b"different snapshot")

    with pytest.raises(SnapshotError, match="checksum mismatch"):
        with staged_snapshot(
            str(source),
            expected_sha256=wrong_checksum,
        ):
            pytest.fail("snapshot must not be exposed")


@pytest.mark.parametrize(
    "checksum",
    [
        "",
        "abc",
        "0" * 63,
        "0" * 65,
        "G" * 64,
        "A" * 64,
        "0" * 63 + " ",
    ],
)
def test_rejects_invalid_expected_checksum(
    tmp_path: Path,
    checksum: str,
) -> None:
    """Only canonical lowercase SHA-256 digests are accepted."""
    source = tmp_path / "source.snap"
    source.write_bytes(b"snapshot")

    with pytest.raises(SnapshotError, match="expected SHA-256"):
        with staged_snapshot(
            str(source),
            expected_sha256=checksum,
        ):
            pytest.fail("invalid checksum must be rejected")


@pytest.mark.parametrize(
    "source",
    [
        "",
        " ",
        "\t",
        "\n",
    ],
)
def test_rejects_empty_source(source: str) -> None:
    """A snapshot must have an explicitly defined storage location."""
    with pytest.raises(SnapshotError, match="source must not be empty"):
        with staged_snapshot(source):
            pytest.fail("invalid source must be rejected")


def test_rejects_empty_snapshot(tmp_path: Path) -> None:
    """Empty storage objects are not valid recovery snapshots."""
    source = tmp_path / "empty.snap"
    source.touch()

    with pytest.raises(SnapshotError, match="snapshot is empty"):
        with staged_snapshot(str(source)):
            pytest.fail("empty snapshot must not be exposed")


def test_rejects_missing_snapshot(tmp_path: Path) -> None:
    """Missing storage objects produce the domain-specific error."""
    source = tmp_path / "missing.snap"

    with pytest.raises(SnapshotError, match="unable to acquire snapshot"):
        with staged_snapshot(str(source)):
            pytest.fail("missing snapshot must not be exposed")


def test_streams_large_snapshots_in_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acquisition supports data larger than the transfer chunk size."""
    chunk_size = 1024
    monkeypatch.setattr(snapshot_module, "_CHUNK_SIZE", chunk_size)

    data = os.urandom(chunk_size * 5 + 123)
    source = tmp_path / "large.snap"
    source.write_bytes(data)

    with staged_snapshot(str(source)) as snapshot:
        assert snapshot.size == len(data)
        assert snapshot.sha256 == _sha256(data)
        assert snapshot.path.read_bytes() == data


def test_uses_upath_for_remote_locations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Storage resolution is delegated to UPath, not implemented here."""
    data = b"remote snapshot"
    fixture = tmp_path / "remote.snap"
    fixture.write_bytes(data)

    uri = "ssh://mxm@monolith/home/mxm/recovery/snapshot.snap"
    received_locations: list[str] = []

    def fake_upath(location: str) -> Path:
        received_locations.append(location)
        return fixture

    monkeypatch.setattr(snapshot_module, "UPath", fake_upath)

    with staged_snapshot(uri) as snapshot:
        assert snapshot.source == uri
        assert snapshot.path.read_bytes() == data

    assert received_locations == [uri]


def test_translates_storage_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend failures do not leak arbitrary filesystem exceptions."""

    class FailingLocation:
        def open(self, mode: str) -> BinaryIO:
            raise OSError("storage unavailable")

    def fake_upath(source: str) -> FailingLocation:
        return FailingLocation()

    monkeypatch.setattr(
        snapshot_module,
        "UPath",
        fake_upath,
    )

    with pytest.raises(
        SnapshotError,
        match="unable to acquire snapshot",
    ):
        with staged_snapshot("ssh://mxm@monolith/backup.snap"):
            pytest.fail("failed acquisition must not yield a snapshot")


# ---------------------------------------------------------------------------
# Snapshot publication
# ---------------------------------------------------------------------------


def test_publishes_snapshot(tmp_path: Path) -> None:
    """Published bytes and metadata match the original snapshot."""
    data = b"mxm-openbao-snapshot\x00\x01\x02"
    source = tmp_path / "source.snap"
    destination = tmp_path / "published.snap"
    source.write_bytes(data)

    result = publish_snapshot(source, str(destination))

    assert result.destination == str(destination)
    assert result.size == len(data)
    assert result.sha256 == _sha256(data)
    assert destination.read_bytes() == data
    assert source.read_bytes() == data


def test_published_snapshot_can_be_staged(tmp_path: Path) -> None:
    """Publishing and staging compose without losing integrity."""
    data = b"round-trip snapshot"
    source = tmp_path / "source.snap"
    destination = tmp_path / "published.snap"
    source.write_bytes(data)

    published = publish_snapshot(source, str(destination))

    with staged_snapshot(
        published.destination,
        expected_sha256=published.sha256,
    ) as staged:
        assert staged.path.read_bytes() == data
        assert staged.size == published.size
        assert staged.sha256 == published.sha256


def test_rejects_existing_destination(tmp_path: Path) -> None:
    """Publication must never overwrite an existing snapshot."""
    source = tmp_path / "source.snap"
    destination = tmp_path / "existing.snap"

    source.write_bytes(b"new snapshot")
    destination.write_bytes(b"existing snapshot")

    with pytest.raises(
        SnapshotError,
        match="destination already exists",
    ):
        publish_snapshot(source, str(destination))

    assert destination.read_bytes() == b"existing snapshot"


def test_rejects_empty_publication_source(tmp_path: Path) -> None:
    """An empty snapshot must not be published."""
    source = tmp_path / "empty.snap"
    destination = tmp_path / "published.snap"
    source.touch()

    with pytest.raises(SnapshotError, match="snapshot is empty"):
        publish_snapshot(source, str(destination))

    assert not destination.exists()


def test_rejects_missing_publication_source(tmp_path: Path) -> None:
    """Missing sources fail before destination creation."""
    source = tmp_path / "missing.snap"
    destination = tmp_path / "published.snap"

    with pytest.raises(
        SnapshotError,
        match="unable to inspect snapshot source",
    ):
        publish_snapshot(source, str(destination))

    assert not destination.exists()


@pytest.mark.parametrize(
    "destination",
    ["", " ", "\t", "\n"],
)
def test_rejects_empty_publication_destination(
    tmp_path: Path,
    destination: str,
) -> None:
    """Publication requires an explicit destination."""
    source = tmp_path / "source.snap"
    source.write_bytes(b"snapshot")

    with pytest.raises(
        SnapshotError,
        match="destination must not be empty",
    ):
        publish_snapshot(source, destination)


def test_rejects_publication_source_directory(tmp_path: Path) -> None:
    """A directory cannot be used as a snapshot source."""
    source = tmp_path / "directory"
    destination = tmp_path / "published.snap"
    source.mkdir()

    with pytest.raises(
        SnapshotError,
        match="source is not a regular file",
    ):
        publish_snapshot(source, str(destination))

    assert not destination.exists()


def test_rejects_publication_source_symlink(tmp_path: Path) -> None:
    """Publication does not follow source symlinks."""
    actual = tmp_path / "actual.snap"
    source = tmp_path / "linked.snap"
    destination = tmp_path / "published.snap"

    actual.write_bytes(b"snapshot")
    source.symlink_to(actual)

    with pytest.raises(
        SnapshotError,
        match="must not be a symbolic link",
    ):
        publish_snapshot(source, str(destination))

    assert not destination.exists()


def test_publishes_large_snapshot_in_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publication handles snapshots larger than the transfer chunk."""
    chunk_size = 1024
    monkeypatch.setattr(snapshot_module, "_CHUNK_SIZE", chunk_size)

    data = os.urandom(chunk_size * 5 + 123)
    source = tmp_path / "source.snap"
    destination = tmp_path / "published.snap"
    source.write_bytes(data)

    result = publish_snapshot(source, str(destination))

    assert result.size == len(data)
    assert result.sha256 == _sha256(data)
    assert destination.read_bytes() == data


def test_detects_corrupted_published_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read-back verification detects bytes differing from the source."""
    source = tmp_path / "source.snap"
    destination = tmp_path / "published.snap"
    corrupted = tmp_path / "corrupted.snap"

    source.write_bytes(b"correct snapshot")
    corrupted.write_bytes(b"corrupted snapshot")

    resolutions = 0

    def fake_upath(location: str) -> Path:
        nonlocal resolutions
        resolutions += 1

        if resolutions == 1:
            # Publication writes to the intended destination.
            return destination

        # Simulate a backend returning corrupted bytes on read-back.
        return corrupted

    monkeypatch.setattr(snapshot_module, "UPath", fake_upath)

    with pytest.raises(
        SnapshotError,
        match="checksum mismatch",
    ):
        publish_snapshot(source, str(destination))

    assert destination.read_bytes() == b"correct snapshot"
    assert resolutions == 2


def test_translates_publication_storage_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Storage write failures become SnapshotError."""
    source = tmp_path / "source.snap"
    source.write_bytes(b"snapshot")

    unavailable = tmp_path / "missing-directory" / "snapshot.snap"

    def fake_upath(location: str) -> Path:
        return unavailable

    monkeypatch.setattr(snapshot_module, "UPath", fake_upath)

    with pytest.raises(
        SnapshotError,
        match="unable to publish snapshot",
    ):
        publish_snapshot(source, "ssh://mxm@monolith/snapshot.snap")

    assert not unavailable.exists()
