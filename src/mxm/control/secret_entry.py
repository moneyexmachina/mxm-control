"""Interactive, masked entry of ASCII secrets from a POSIX terminal.

The terminal displays only progress, never secret characters. A controlling
TTY is mandatory: stdin redirection cannot silently supply credentials.
"""

from __future__ import annotations

import os
import termios
import tty


class SecretEntryError(RuntimeError):
    """Secret entry is unavailable or incorrectly configured."""


class SecretEntryCancelled(SecretEntryError):
    """The operator cancelled secret entry."""


def _open_tty() -> int:
    try:
        return os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError as exc:
        raise SecretEntryError(
            "interactive terminal required for secret entry"
        ) from exc


def _write_terminal(fd: int, data: bytes) -> None:
    """Write terminal-control and progress output, never secret characters."""
    while data:
        data = data[os.write(fd, data) :]


def _read_byte(fd: int) -> bytes:
    return os.read(fd, 1)


def _render(
    fd: int,
    label: str,
    count: int,
    expected_length: int | None,
) -> None:
    """Display the character count and a masked entry indicator."""
    total = str(expected_length) if expected_length is not None else "?"
    indicator = "*" if count else "-"

    _write_terminal(
        fd,
        f"\r\x1b[2K{label} [{count}/{total}] {indicator}".encode(),
    )


def _read_secret(
    fd: int,
    label: str,
    expected_length: int | None,
) -> str:
    """Read one ASCII secret, rejecting escape sequences and invalid input."""
    chars: list[str] = []
    _render(fd, label, 0, expected_length)

    while True:
        key = _read_byte(fd)

        if key in (b"", b"\x03", b"\x04", b"\x1b"):
            raise SecretEntryCancelled("secret entry cancelled")

        if key in (b"\r", b"\n"):
            if chars and (expected_length is None or len(chars) == expected_length):
                return "".join(chars)

            _write_terminal(fd, b"\a")
            continue

        if key in (b"\x08", b"\x7f"):
            if chars:
                chars.pop()
                _render(fd, label, len(chars), expected_length)
            continue

        if len(key) == 1 and 33 <= key[0] <= 126:
            if expected_length is not None and len(chars) >= expected_length:
                _write_terminal(fd, b"\a")
                continue

            chars.append(chr(key[0]))
            _render(fd, label, len(chars), expected_length)

        else:
            _write_terminal(fd, b"\a")


def prompt_secret(
    label: str,
    *,
    expected_length: int | None = None,
) -> str:
    """Read a secret with masked progress and explicit cancellation.

    ``label`` should identify progress, e.g. ``"Unseal share 1 of 2"``.
    ``expected_length`` optionally enforces exact ASCII character count.

    Esc, Ctrl-C, Ctrl-D and EOF cancel. Backspace edits. Enter accepts.

    Bracketed paste is requested from the terminal; its leading escape
    sequence cancels entry. Unbracketed paste cannot reliably be
    distinguished from keystrokes by a terminal application.
    """
    if not label or not label.isprintable():
        raise ValueError("label must be nonempty printable text")

    if expected_length is not None and (
        type(expected_length) is not int or not 1 <= expected_length <= 4096
    ):
        raise ValueError("expected_length must be an integer from 1 to 4096")

    fd = _open_tty()

    try:
        original = termios.tcgetattr(fd)

        try:
            tty.setcbreak(fd)
            _write_terminal(fd, b"\x1b[?2004h")

            try:
                return _read_secret(
                    fd,
                    label,
                    expected_length,
                )
            except KeyboardInterrupt as exc:
                raise SecretEntryCancelled("secret entry cancelled") from exc

        finally:
            _write_terminal(fd, b"\x1b[?2004l\r\n")
            termios.tcsetattr(fd, termios.TCSADRAIN, original)
            termios.tcflush(fd, termios.TCIFLUSH)

    finally:
        os.close(fd)


__all__ = [
    "SecretEntryCancelled",
    "SecretEntryError",
    "prompt_secret",
]
