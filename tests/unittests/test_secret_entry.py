"""Unit tests for interactive, masked terminal secret entry.

Exercise character input, progress display, validation, cancellation,
and terminal cleanup without exposing credentials or requiring a
controlling terminal.
"""

from __future__ import annotations

import os
import pty
import termios

import pytest

import mxm.control.secret_entry as entry


def _script_input(
    monkeypatch: pytest.MonkeyPatch,
    data: bytes,
) -> list[bytes]:
    """Supply deterministic terminal input and capture display output."""
    incoming = iter(bytes((value,)) for value in data)
    emitted: list[bytes] = []

    def fake_read(fd: int) -> bytes:
        assert fd == 9
        return next(incoming, b"")

    def fake_write(fd: int, payload: bytes) -> None:
        assert fd == 9
        emitted.append(payload)

    monkeypatch.setattr(entry, "_read_byte", fake_read)
    monkeypatch.setattr(entry, "_write_terminal", fake_write)

    return emitted


# ---------------------------------------------------------------------------
# Character entry and masking
# ---------------------------------------------------------------------------


def test_entry_masks_secret_and_counts_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Display progress without revealing entered characters."""
    displayed = _script_input(monkeypatch, b"ABC123\r")

    result = entry._read_secret(
        9,
        "Unseal share 1 of 2",
        6,
    )

    output = b"".join(displayed).decode("utf-8")

    assert result == "ABC123"
    assert "Unseal share 1 of 2" in output
    assert "[0/6]" in output
    assert "[3/6]" in output
    assert "[6/6]" in output
    assert "ABC123" not in output
    assert "ABC" not in output


def test_unknown_length_displays_question_mark(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Show progress even when no exact length is configured."""
    displayed = _script_input(monkeypatch, b"ABC\n")

    assert entry._read_secret(9, "Secret", None) == "ABC"

    output = b"".join(displayed).decode("utf-8")
    assert "[0/?]" in output
    assert "[3/?]" in output


@pytest.mark.parametrize("backspace", [b"\x08", b"\x7f"])
def test_backspace_removes_last_character(
    monkeypatch: pytest.MonkeyPatch,
    backspace: bytes,
) -> None:
    """Both common Backspace encodings update the secret and counter."""
    displayed = _script_input(
        monkeypatch,
        b"AB" + backspace + b"C\r",
    )

    result = entry._read_secret(9, "Share", 2)

    output = b"".join(displayed).decode("utf-8")

    assert result == "AC"
    assert output.count("[1/2]") >= 2
    assert "[2/2]" in output
    assert "AB" not in output


def test_backspace_on_empty_secret_is_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backspace before entry must not corrupt the input buffer."""
    displayed = _script_input(monkeypatch, b"\x7fA\n")

    assert entry._read_secret(9, "Share", 1) == "A"
    assert "[1/1]" in b"".join(displayed).decode("utf-8")


@pytest.mark.parametrize("submit", [b"\r", b"\n"])
def test_accepts_both_enter_encodings(
    monkeypatch: pytest.MonkeyPatch,
    submit: bytes,
) -> None:
    """Accept carriage return and newline as submission."""
    _script_input(monkeypatch, b"ABC" + submit)

    assert entry._read_secret(9, "Share", 3) == "ABC"


def test_empty_secret_cannot_be_submitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty submission rings the bell and leaves entry active."""
    displayed = _script_input(monkeypatch, b"\rA\n")

    assert entry._read_secret(9, "Share", None) == "A"
    assert b"\a" in displayed


# ---------------------------------------------------------------------------
# Length and character validation
# ---------------------------------------------------------------------------


def test_short_submission_requires_correction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enter does not accept a secret shorter than the configured length."""
    displayed = _script_input(monkeypatch, b"AB\nC\r")

    assert entry._read_secret(9, "Share", 3) == "ABC"
    assert b"\a" in displayed


def test_excess_characters_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Input beyond the expected length is rejected rather than truncated."""
    displayed = _script_input(monkeypatch, b"ABCD\r")

    assert entry._read_secret(9, "Share", 3) == "ABC"
    assert b"\a" in displayed
    assert "[4/3]" not in b"".join(displayed).decode("utf-8")


def test_rejects_whitespace_and_control_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept only printable, non-whitespace ASCII characters."""
    displayed = _script_input(
        monkeypatch,
        b"A B\tC\x00D\n",
    )

    assert entry._read_secret(9, "Share", 4) == "ABCD"
    assert displayed.count(b"\a") == 3


def test_rejects_non_ascii_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UTF-8 multibyte input must not enter an ASCII secret."""
    displayed = _script_input(
        monkeypatch,
        b"A\xc3\xa9B\n",
    )

    assert entry._read_secret(9, "Share", 2) == "AB"
    assert displayed.count(b"\a") == 2


@pytest.mark.parametrize(
    "expected_length",
    [
        0,
        -1,
        4097,
        True,
        False,
        1.5,
        "44",
    ],
)
def test_rejects_invalid_expected_length(
    monkeypatch: pytest.MonkeyPatch,
    expected_length: object,
) -> None:
    """Invalid length configurations must fail before opening the TTY."""

    def forbidden_open() -> int:
        pytest.fail("terminal must not be opened for invalid configuration")

    monkeypatch.setattr(entry, "_open_tty", forbidden_open)

    with pytest.raises(ValueError, match="expected_length"):
        entry.prompt_secret(
            "Share",
            expected_length=expected_length,  # pyright: ignore[reportArgumentType]
        )


@pytest.mark.parametrize(
    "label",
    [
        "",
        "\x1bBAD",
        "Share\nNext line",
        "Share\rOverwrite",
    ],
)
def test_rejects_invalid_labels(
    monkeypatch: pytest.MonkeyPatch,
    label: str,
) -> None:
    """Reject empty and control-character-bearing terminal labels."""

    def forbidden_open() -> int:
        pytest.fail("terminal must not be opened for invalid label")

    monkeypatch.setattr(entry, "_open_tty", forbidden_open)

    with pytest.raises(ValueError, match="label"):
        entry.prompt_secret(label)


# ---------------------------------------------------------------------------
# Cancellation and paste rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cancel",
    [
        b"\x1b",
        b"\x03",
        b"\x04",
        b"",
    ],
)
def test_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    cancel: bytes,
) -> None:
    """Esc, Ctrl+C, Ctrl+D and EOF cancel secret entry."""
    _script_input(monkeypatch, cancel)

    with pytest.raises(
        entry.SecretEntryCancelled,
        match="cancelled",
    ):
        entry._read_secret(9, "Share", None)


def test_cancellation_discards_partial_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation must not return a partially entered credential."""
    displayed = _script_input(monkeypatch, b"SECRET\x1b")

    with pytest.raises(entry.SecretEntryCancelled) as error:
        entry._read_secret(9, "Share", 6)

    assert "SECRET" not in str(error.value)
    assert b"SECRET" not in b"".join(displayed)


def test_bracketed_paste_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject the initial ESC byte of a bracketed-paste sequence."""
    _script_input(
        monkeypatch,
        b"\x1b[200~ABC123\x1b[201~",
    )

    with pytest.raises(entry.SecretEntryCancelled):
        entry._read_secret(9, "Share", 6)


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------


def test_terminal_write_handles_partial_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Continue writing until all non-secret display bytes are emitted."""
    written = bytearray()

    def fake_write(fd: int, data: bytes) -> int:
        assert fd == 9
        count = min(2, len(data))
        written.extend(data[:count])
        return count

    monkeypatch.setattr(entry.os, "write", fake_write)

    entry._write_terminal(9, b"progress")

    assert bytes(written) == b"progress"


def test_render_uses_masked_indicator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Show the count and entry indicator, not the underlying secret."""
    emitted: list[bytes] = []

    def fake_write(fd: int, payload: bytes) -> None:
        assert fd == 9
        emitted.append(payload)

    monkeypatch.setattr(entry, "_write_terminal", fake_write)

    entry._render(9, "Share", 0, 44)
    entry._render(9, "Share", 12, 44)

    assert b"[0/44] -" in emitted[0]
    assert b"[12/44] *" in emitted[1]
    assert all(payload.startswith(b"\r\x1b[2K") for payload in emitted)


# ---------------------------------------------------------------------------
# Controlling terminal and lifecycle
# ---------------------------------------------------------------------------


def test_requires_controlling_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail rather than silently read credentials from redirected stdin."""

    def missing_tty(path: str, flags: int) -> int:
        assert path == "/dev/tty"
        assert flags & os.O_RDWR
        raise OSError("no controlling terminal")

    monkeypatch.setattr(entry.os, "open", missing_tty)

    with pytest.raises(
        entry.SecretEntryError,
        match="interactive terminal required",
    ):
        entry.prompt_secret("Share")


@pytest.mark.parametrize("cancel", [False, True])
def test_terminal_settings_restored(
    monkeypatch: pytest.MonkeyPatch,
    cancel: bool,
) -> None:
    """Restore terminal settings after success or operator cancellation."""
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    displayed: list[bytes] = []

    try:

        def fake_open() -> int:
            return os.dup(slave)

        def fake_write(fd: int, payload: bytes) -> None:
            displayed.append(payload)

        def fake_read_secret(
            fd: int,
            label: str,
            expected_length: int | None,
        ) -> str:
            assert label == "Share"
            assert expected_length == 4

            settings = termios.tcgetattr(fd)
            assert not (settings[3] & termios.ECHO)
            assert not (settings[3] & termios.ICANON)

            if cancel:
                raise entry.SecretEntryCancelled("secret entry cancelled")

            return "TEST"

        monkeypatch.setattr(entry, "_open_tty", fake_open)
        monkeypatch.setattr(entry, "_write_terminal", fake_write)
        monkeypatch.setattr(entry, "_read_secret", fake_read_secret)

        if cancel:
            with pytest.raises(entry.SecretEntryCancelled):
                entry.prompt_secret("Share", expected_length=4)
        else:
            assert entry.prompt_secret("Share", expected_length=4) == "TEST"

        assert termios.tcgetattr(slave) == original
        assert displayed[0] == b"\x1b[?2004h"
        assert displayed[-1] == b"\x1b[?2004l\r\n"

    finally:
        os.close(slave)
        os.close(master)


def test_keyboard_interrupt_becomes_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Convert Ctrl+C interruption into the public cancellation error."""
    master, slave = pty.openpty()

    try:

        def fake_open() -> int:
            return os.dup(slave)

        def fake_write(fd: int, payload: bytes) -> None:
            pass

        def interrupted_read(
            fd: int,
            label: str,
            expected_length: int | None,
        ) -> str:
            raise KeyboardInterrupt

        monkeypatch.setattr(entry, "_open_tty", fake_open)
        monkeypatch.setattr(entry, "_write_terminal", fake_write)
        monkeypatch.setattr(entry, "_read_secret", interrupted_read)

        with pytest.raises(
            entry.SecretEntryCancelled,
            match="cancelled",
        ):
            entry.prompt_secret("Share", expected_length=4)

    finally:
        os.close(slave)
        os.close(master)


def test_secret_entry_errors_are_runtime_errors() -> None:
    """Expose a consistent exception hierarchy to CLI consumers."""
    assert issubclass(entry.SecretEntryError, RuntimeError)
    assert issubclass(entry.SecretEntryCancelled, entry.SecretEntryError)
