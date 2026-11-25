"""Unit tests for estate-declared graphical console access.

Verify service resolution, workstation prerequisites, Tailscale SSH
forwarding, noVNC/browser orchestration, lifecycle monitoring, and
subprocess cleanup.

All external processes and network operations are mocked. These tests
must not connect to the estate or open graphical applications.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import mxm.control.console as console
from mxm.control.service import (
    ConsoleTarget,
    RegisteredService,
    ServiceError,
    ServiceTarget,
)


@pytest.fixture
def registered_service() -> RegisteredService:
    """Provide an example estate service with a VNC console."""
    return RegisteredService(
        target=ServiceTarget(
            name="example",
            address="https://example.invalid",
            machine="example.tailnet.invalid",
            user="operator",
            unit="example.service",
        ),
        credentials=None,
        console=ConsoleTarget(
            protocol="vnc",
            port=5907,
        ),
    )


def _process(*, returncode: int | None = None) -> MagicMock:
    """Create a subprocess mock retaining its mock-specific interface."""
    process = MagicMock(spec=subprocess.Popen)
    process.poll.return_value = returncode
    process.returncode = returncode
    return process


# ---------------------------------------------------------------------------
# Estate service resolution
# ---------------------------------------------------------------------------


def test_resolve_console_uses_estate_registry(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Resolve console identity through the estate service registry."""
    resolver = MagicMock(return_value=registered_service)
    monkeypatch.setattr(console, "resolve_service", resolver)

    result = console._resolve_console("example")

    assert result is registered_service
    resolver.assert_called_once_with(
        estate_root=Path.home() / "mxm-estate",
        name="example",
    )


def test_resolve_console_rejects_unregistered_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Translate service registry failures into ConsoleError."""
    resolver = MagicMock(
        side_effect=ServiceError("Unknown service"),
    )
    monkeypatch.setattr(console, "resolve_service", resolver)

    with pytest.raises(console.ConsoleError, match="Unknown service"):
        console._resolve_console("missing")


def test_resolve_console_rejects_missing_console(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Reject services without a graphical console declaration."""
    service = RegisteredService(
        target=registered_service.target,
        credentials=None,
        console=None,
    )

    monkeypatch.setattr(
        console,
        "resolve_service",
        MagicMock(return_value=service),
    )

    with pytest.raises(console.ConsoleError, match="no console declaration"):
        console._resolve_console("example")


def test_resolve_console_rejects_unsupported_protocol(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Reject console protocols unsupported by the implementation."""
    service = RegisteredService(
        target=registered_service.target,
        credentials=None,
        console=ConsoleTarget(
            protocol="rdp",
            port=3389,
        ),
    )

    monkeypatch.setattr(
        console,
        "resolve_service",
        MagicMock(return_value=service),
    )

    with pytest.raises(
        console.ConsoleError,
        match="Unsupported console protocol",
    ):
        console._resolve_console("example")


# ---------------------------------------------------------------------------
# Local workstation prerequisites
# ---------------------------------------------------------------------------


def test_check_dependencies_accepts_installed_tools(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Accept installed executables and noVNC browser assets."""
    assets = tmp_path / "novnc"
    assets.mkdir()
    (assets / "vnc.html").write_text("test")

    monkeypatch.setattr(console, "_NOVNC_DIR", assets)
    monkeypatch.setattr(
        console.shutil,
        "which",
        MagicMock(return_value="/usr/bin/program"),
    )

    console._check_dependencies()


def test_check_dependencies_rejects_missing_program(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report a missing required workstation executable."""

    def find_program(name: str) -> str | None:
        return None if name == "websockify" else "/usr/bin/program"

    monkeypatch.setattr(console.shutil, "which", find_program)

    with pytest.raises(console.ConsoleError, match="websockify"):
        console._check_dependencies()


def test_check_dependencies_rejects_missing_novnc_assets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Require the installed noVNC browser application."""
    monkeypatch.setattr(console, "_NOVNC_DIR", tmp_path)
    monkeypatch.setattr(
        console.shutil,
        "which",
        MagicMock(return_value="/usr/bin/program"),
    )

    with pytest.raises(
        console.ConsoleError,
        match="noVNC assets absent",
    ):
        console._check_dependencies()


def test_check_local_ports_accepts_available_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept free workstation-side TCP ports."""
    available = MagicMock(return_value=True)
    monkeypatch.setattr(console, "_port_available", available)

    console._check_local_ports()

    assert available.call_count == 2
    available.assert_any_call(console._LOCAL_VNC_PORT)
    available.assert_any_call(console._LOCAL_WEB_PORT)


def test_check_local_ports_rejects_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an existing local listener."""
    monkeypatch.setattr(
        console,
        "_port_available",
        MagicMock(return_value=False),
    )

    with pytest.raises(console.ConsoleError, match="already in use"):
        console._check_local_ports()


# ---------------------------------------------------------------------------
# SSH tunnel and noVNC proxy
# ---------------------------------------------------------------------------


def test_start_tunnel_uses_resolved_service(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Forward the estate-declared remote VNC port through Tailscale."""
    process = _process()
    popen = MagicMock(return_value=process)

    monkeypatch.setattr(console.subprocess, "Popen", popen)

    result = console._start_tunnel(registered_service)

    assert result is process
    popen.assert_called_once_with(
        [
            "tailscale",
            "ssh",
            "operator@example.tailnet.invalid",
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-L",
            "127.0.0.1:5901:127.0.0.1:5907",
        ]
    )


def test_start_tunnel_rejects_missing_console(
    registered_service: RegisteredService,
) -> None:
    """Never start a tunnel without a resolved console endpoint."""
    service = RegisteredService(
        target=registered_service.target,
        credentials=None,
        console=None,
    )

    with pytest.raises(
        console.ConsoleError,
        match="no graphical console",
    ):
        console._start_tunnel(service)


def test_start_proxy_uses_one_browser_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Serve noVNC and exit after the browser's VNC connection closes."""
    process = _process()
    popen = MagicMock(return_value=process)

    monkeypatch.setattr(console.subprocess, "Popen", popen)
    monkeypatch.setattr(console.time, "sleep", MagicMock())

    result = console._start_proxy()

    assert result is process
    popen.assert_called_once_with(
        [
            "websockify",
            "--run-once",
            "--timeout",
            "120",
            "--web",
            str(console._NOVNC_DIR),
            "127.0.0.1:6080",
            "127.0.0.1:5901",
        ]
    )


def test_start_proxy_detects_immediate_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a proxy that exits during startup."""
    process = _process(returncode=1)

    monkeypatch.setattr(
        console.subprocess,
        "Popen",
        MagicMock(return_value=process),
    )
    monkeypatch.setattr(console.time, "sleep", MagicMock())

    with pytest.raises(
        console.ConsoleError,
        match="failed to start",
    ):
        console._start_proxy()


# ---------------------------------------------------------------------------
# Firefox integration
# ---------------------------------------------------------------------------


def test_console_url_is_loopback_only() -> None:
    """The noVNC browser endpoint must use workstation loopback."""
    assert console._console_url() == ("http://127.0.0.1:6080/vnc.html?autoconnect=1")


def test_open_browser_opens_firefox_tab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Open the remote console in the existing Firefox instance."""
    runner = MagicMock()
    monkeypatch.setattr(console.subprocess, "run", runner)

    console._open_browser("example")

    runner.assert_called_once_with(
        [
            "firefox",
            "--new-tab",
            "http://127.0.0.1:6080/vnc.html?autoconnect=1",
        ],
        check=True,
    )


# ---------------------------------------------------------------------------
# Lifecycle monitoring
# ---------------------------------------------------------------------------


def test_wait_for_proxy_exit_on_browser_disconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A completed browser session ends monitoring successfully."""
    proxy = _process()
    tunnel = _process()

    proxy.poll.side_effect = [None, 0]
    proxy.returncode = 0

    monkeypatch.setattr(console.time, "sleep", MagicMock())

    console._wait_for_proxy_exit(proxy, tunnel)


def test_wait_for_proxy_exit_detects_ssh_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detect termination of the SSH tunnel during a VNC session."""
    proxy = _process()
    tunnel = _process(returncode=255)

    monkeypatch.setattr(console.time, "sleep", MagicMock())

    with pytest.raises(
        console.ConsoleError,
        match="SSH tunnel ended",
    ):
        console._wait_for_proxy_exit(proxy, tunnel)


def test_wait_for_proxy_exit_detects_proxy_failure() -> None:
    """Do not report an unsuccessful proxy exit as normal closure."""
    proxy = _process(returncode=1)
    tunnel = _process()

    with pytest.raises(
        console.ConsoleError,
        match="proxy exited with 1",
    ):
        console._wait_for_proxy_exit(proxy, tunnel)


# ---------------------------------------------------------------------------
# Subprocess cleanup
# ---------------------------------------------------------------------------


def test_stop_terminates_running_process() -> None:
    """Gracefully terminate a running local child process."""
    process = _process()
    process.wait.return_value = 0

    console._stop(process)

    process.terminate.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=console._PROCESS_STOP_TIMEOUT)
    process.kill.assert_not_called()


def test_stop_does_not_terminate_exited_process() -> None:
    """Do not signal an already-exited child process."""
    process = _process(returncode=0)

    console._stop(process)

    process.terminate.assert_not_called()
    process.kill.assert_not_called()


def test_stop_escalates_after_timeout() -> None:
    """Kill a child that does not terminate within the grace period."""
    process = _process()
    process.wait.side_effect = [
        subprocess.TimeoutExpired(
            cmd="test",
            timeout=console._PROCESS_STOP_TIMEOUT,
        ),
        0,
    ]

    console._stop(process)

    process.terminate.assert_called_once_with()
    process.kill.assert_called_once_with()
    assert process.wait.call_count == 2


# ---------------------------------------------------------------------------
# Complete console orchestration
# ---------------------------------------------------------------------------


def test_run_console_cleans_up_after_normal_session(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Release proxy before SSH after the browser session finishes."""
    tunnel = _process()
    proxy = _process()
    events: list[str] = []

    monkeypatch.setattr(
        console,
        "_start_tunnel",
        MagicMock(return_value=tunnel),
    )
    monkeypatch.setattr(
        console,
        "_start_proxy",
        MagicMock(return_value=proxy),
    )
    monkeypatch.setattr(console, "_wait_listening", MagicMock())
    monkeypatch.setattr(console, "_open_browser", MagicMock())
    monkeypatch.setattr(console, "_wait_for_proxy_exit", MagicMock())

    def stop(process: subprocess.Popen[bytes]) -> None:
        events.append("proxy" if process is proxy else "tunnel")

    monkeypatch.setattr(console, "_stop", stop)

    console._run_console("example", registered_service)

    assert events == ["proxy", "tunnel"]


def test_run_console_cleans_up_after_browser_failure(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Release both local processes when Firefox cannot be launched."""
    tunnel = _process()
    proxy = _process()
    stopped: list[subprocess.Popen[bytes]] = []

    monkeypatch.setattr(
        console,
        "_start_tunnel",
        MagicMock(return_value=tunnel),
    )
    monkeypatch.setattr(
        console,
        "_start_proxy",
        MagicMock(return_value=proxy),
    )
    monkeypatch.setattr(console, "_wait_listening", MagicMock())
    monkeypatch.setattr(
        console,
        "_open_browser",
        MagicMock(side_effect=OSError("Firefox unavailable")),
    )

    def record_stop(process: subprocess.Popen[bytes]) -> None:
        stopped.append(process)

    monkeypatch.setattr(console, "_stop", record_stop)

    with pytest.raises(OSError, match="Firefox unavailable"):
        console._run_console("example", registered_service)

    assert stopped == [proxy, tunnel]


def test_run_console_cleans_up_after_proxy_failure(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Clean up the tunnel when the proxy cannot be started."""
    tunnel = _process()
    stopped: list[subprocess.Popen[bytes]] = []

    monkeypatch.setattr(
        console,
        "_start_tunnel",
        MagicMock(return_value=tunnel),
    )
    monkeypatch.setattr(
        console,
        "_start_proxy",
        MagicMock(side_effect=OSError("Proxy unavailable")),
    )
    monkeypatch.setattr(console, "_wait_listening", MagicMock())

    def record_stop(process: subprocess.Popen[bytes]) -> None:
        stopped.append(process)

    monkeypatch.setattr(console, "_stop", record_stop)

    with pytest.raises(OSError, match="Proxy unavailable"):
        console._run_console("example", registered_service)

    assert stopped == [tunnel]


# ---------------------------------------------------------------------------
# Public operator capability
# ---------------------------------------------------------------------------


def test_open_console_orchestrates_resolved_service(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Resolve, validate and open the requested graphical console."""
    events: list[str] = []

    monkeypatch.setattr(
        console,
        "_resolve_console",
        MagicMock(return_value=registered_service),
    )

    def check_dependencies() -> None:
        events.append("dependencies")

    def check_ports() -> None:
        events.append("ports")

    def run_console(
        service_name: str,
        service: RegisteredService,
    ) -> None:
        assert service_name == "example"
        assert service is registered_service
        events.append("run")

    monkeypatch.setattr(
        console,
        "_check_dependencies",
        check_dependencies,
    )
    monkeypatch.setattr(
        console,
        "_check_local_ports",
        check_ports,
    )
    monkeypatch.setattr(
        console,
        "_run_console",
        run_console,
    )

    console.open_console("example")

    assert events == ["dependencies", "ports", "run"]


def test_open_console_handles_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Ctrl+C terminates the temporary operator-console command."""
    monkeypatch.setattr(
        console,
        "_resolve_console",
        MagicMock(return_value=registered_service),
    )
    monkeypatch.setattr(console, "_check_dependencies", MagicMock())
    monkeypatch.setattr(console, "_check_local_ports", MagicMock())
    monkeypatch.setattr(
        console,
        "_run_console",
        MagicMock(side_effect=KeyboardInterrupt),
    )

    console.open_console("example")


def test_open_console_wraps_operating_system_errors(
    monkeypatch: pytest.MonkeyPatch,
    registered_service: RegisteredService,
) -> None:
    """Translate process failures into the public ConsoleError type."""
    monkeypatch.setattr(
        console,
        "_resolve_console",
        MagicMock(return_value=registered_service),
    )
    monkeypatch.setattr(console, "_check_dependencies", MagicMock())
    monkeypatch.setattr(console, "_check_local_ports", MagicMock())
    monkeypatch.setattr(
        console,
        "_run_console",
        MagicMock(side_effect=OSError("Process unavailable")),
    )

    with pytest.raises(
        console.ConsoleError,
        match="Process unavailable",
    ):
        console.open_console("example")
