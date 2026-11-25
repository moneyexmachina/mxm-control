"""Open temporary browser consoles for estate-declared services.

Resolve a service's graphical console from mxm-estate, establish an
authenticated Tailscale SSH TCP tunnel, and present its VNC desktop
in Firefox through a local noVNC/websockify proxy.

This module provides generic operator-access machinery. Machine
identity, SSH user, console protocol, and remote port are declared
by the estate.

Closing the browser's VNC connection terminates the temporary local
proxy and SSH tunnel. It does not stop, restart, authenticate, or
log out the remote service.

No broker credentials are collected or stored by this module.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from contextlib import ExitStack
from pathlib import Path

from mxm.control.service import RegisteredService, ServiceError, resolve_service


class ConsoleError(RuntimeError):
    """Failed to open or maintain an estate service's graphical console."""


# Local operator-workstation configuration, not estate declarations.
_LOCAL_HOST = "127.0.0.1"
_LOCAL_VNC_PORT = 5901
_LOCAL_WEB_PORT = 6080
_NOVNC_DIR = Path("/usr/share/novnc")

_TUNNEL_STARTUP_TIMEOUT = 15.0
_PROXY_STARTUP_DELAY = 0.4
_POLL_INTERVAL = 0.25
_PROCESS_STOP_TIMEOUT = 3.0


def _require_program(name: str) -> None:
    """Require an executable in the operator workstation's PATH."""
    if shutil.which(name) is None:
        raise ConsoleError(f"Missing workstation program: {name}")


def _check_dependencies() -> None:
    """Verify the tools and browser assets needed for VNC access."""
    for program in ("tailscale", "websockify", "firefox"):
        _require_program(program)

    if not (_NOVNC_DIR / "vnc.html").is_file():
        raise ConsoleError("noVNC assets absent: install the novnc package")


def _port_available(port: int) -> bool:
    """Check whether a local TCP port can currently be bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((_LOCAL_HOST, port))
        except OSError:
            return False

    return True


def _check_local_ports() -> None:
    """Reject collisions with existing local console sessions."""
    for port in (_LOCAL_VNC_PORT, _LOCAL_WEB_PORT):
        if not _port_available(port):
            raise ConsoleError(
                f"Local port {port} is already in use; "
                "close any previous console tunnel or proxy"
            )


def _resolve_console(service_name: str) -> RegisteredService:
    """Resolve and validate an estate-declared graphical console."""
    try:
        registered = resolve_service(
            estate_root=Path.home() / "mxm-estate",
            name=service_name,
        )
    except ServiceError as exc:
        raise ConsoleError(
            f"Unable to resolve console service {service_name!r}: {exc}"
        ) from exc

    console = registered.console

    if console is None:
        raise ConsoleError(
            f"Estate service {service_name!r} has no console declaration"
        )

    if console.protocol != "vnc":
        raise ConsoleError(f"Unsupported console protocol: {console.protocol}")

    return registered


def _wait_listening(
    port: int,
    child: subprocess.Popen[bytes],
    timeout: float,
) -> None:
    """Wait for a subprocess to establish its local TCP listener."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise ConsoleError(
                f"Process exited before local port {port} became available "
                f"(exit code {child.returncode})"
            )

        try:
            with socket.create_connection(
                (_LOCAL_HOST, port),
                timeout=0.25,
            ):
                return
        except OSError:
            time.sleep(0.1)

    raise ConsoleError(f"Timed out waiting for local port {port}")


def _stop(child: subprocess.Popen[bytes]) -> None:
    """Terminate a local child process, escalating if necessary."""
    if child.poll() is not None:
        return

    child.terminate()

    try:
        child.wait(timeout=_PROCESS_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def _start_tunnel(
    registered: RegisteredService,
) -> subprocess.Popen[bytes]:
    """Forward the estate-declared VNC endpoint over Tailscale SSH."""
    console = registered.console

    if console is None:
        raise ConsoleError("Resolved service has no graphical console")

    target = registered.target

    command = [
        "tailscale",
        "ssh",
        f"{target.user}@{target.machine}",
        "-N",
        "-o",
        "ExitOnForwardFailure=yes",
        "-L",
        (f"{_LOCAL_HOST}:{_LOCAL_VNC_PORT}:{_LOCAL_HOST}:{console.port}"),
    ]

    return subprocess.Popen(command)


def _start_proxy() -> subprocess.Popen[bytes]:
    """Serve noVNC and proxy one browser WebSocket session to VNC."""
    command = [
        "websockify",
        "--run-once",
        "--timeout",
        "120",
        "--web",
        str(_NOVNC_DIR),
        f"{_LOCAL_HOST}:{_LOCAL_WEB_PORT}",
        f"{_LOCAL_HOST}:{_LOCAL_VNC_PORT}",
    ]

    proxy = subprocess.Popen(command)

    # Do not open a synthetic WebSocket connection here: --run-once
    # reserves the first VNC client session for Firefox.
    time.sleep(_PROXY_STARTUP_DELAY)

    if proxy.poll() is not None:
        raise ConsoleError(
            f"noVNC proxy failed to start (exit code {proxy.returncode})"
        )

    return proxy


def _console_url() -> str:
    """Return the local URL for the noVNC browser client."""
    return f"http://{_LOCAL_HOST}:{_LOCAL_WEB_PORT}/vnc.html?autoconnect=1"


def _open_browser(service_name: str) -> None:
    """Open the remote graphical console in the existing Firefox."""
    url = _console_url()

    print(
        f"Opening {service_name} console in Firefox: {url}",
        flush=True,
    )

    subprocess.run(
        ["firefox", "--new-tab", url],
        check=True,
    )

    print(
        "Close the noVNC tab to release the temporary console.",
        flush=True,
    )


def _wait_for_proxy_exit(
    proxy: subprocess.Popen[bytes],
    tunnel: subprocess.Popen[bytes],
) -> None:
    """Monitor the browser connection and underlying SSH transport."""
    while proxy.poll() is None:
        if tunnel.poll() is not None:
            raise ConsoleError("Tailscale SSH tunnel ended unexpectedly")

        time.sleep(_POLL_INTERVAL)

    if proxy.returncode != 0:
        raise ConsoleError(f"noVNC proxy exited with {proxy.returncode}")


def _run_console(
    service_name: str,
    registered: RegisteredService,
) -> None:
    """Run one temporary console with deterministic process cleanup."""
    with ExitStack() as cleanup:
        tunnel = _start_tunnel(registered)
        cleanup.callback(_stop, tunnel)

        _wait_listening(
            _LOCAL_VNC_PORT,
            tunnel,
            _TUNNEL_STARTUP_TIMEOUT,
        )

        proxy = _start_proxy()
        cleanup.callback(_stop, proxy)

        _open_browser(service_name)
        _wait_for_proxy_exit(proxy, tunnel)

    print(
        f"{service_name} console closed; remote service remains running.",
        flush=True,
    )


def open_console(service_name: str) -> None:
    """Open an estate-declared VNC console in Firefox.

    Resolve the requested service through the mxm-estate registry.

    The estate provides the machine, SSH identity, console protocol,
    and remote TCP port. The operator workstation provides Tailscale,
    websockify, noVNC, and Firefox.

    The command remains active until the first browser VNC session
    closes. Ctrl+C also closes the local console infrastructure.

    Neither normal cleanup nor interruption changes the remote
    service's process or authentication state.

    Args:
        service_name: Logical name from mxm-estate/authority/services.toml.

    Raises:
        ConsoleError: If resolution, dependencies, startup, browser
            launch, or the active console transport fails.
    """
    registered = _resolve_console(service_name)

    _check_dependencies()
    _check_local_ports()

    try:
        _run_console(service_name, registered)
    except KeyboardInterrupt:
        print(
            f"Closing {service_name} console.",
            flush=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ConsoleError(f"Unable to open {service_name} console: {exc}") from exc


__all__ = [
    "ConsoleError",
    "open_console",
]
