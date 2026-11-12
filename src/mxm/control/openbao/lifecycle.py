"""Supervised lifecycle operations for the estate-managed OpenBao service.

Use the existing verified Tailscale SSH and Ansible transport to
operate the OpenBao systemd service.

Lifecycle operations are separate from estate service discovery.
The caller supplies an already-resolved ServiceTarget.

Restarts are never retried automatically. A restart whose outcome
cannot be verified is reported as uncertain.
"""

from __future__ import annotations

import math
import time

from mxm.control.openbao.api import OpenBaoError
from mxm.control.openbao.status import status_openbao
from mxm.control.service import (
    ServiceError,
    ServiceRestartUncertainError,
    ServiceTarget,
)
from mxm.control.tailscale_ansible import (
    TailscaleAnsibleError,
    prepare_tailscale_ansible,
    run_ansible,
)


def _validate_restart_target(target: ServiceTarget) -> None:
    """Restrict restart authority to the supported OpenBao service."""
    if target.name != "openbao" or target.unit != "openbao.service":
        raise ServiceError("Unsupported service restart target")


def _verify_service_ready(
    target: ServiceTarget,
    *,
    timeout: float,
) -> None:
    """Wait for the OpenBao HTTPS status endpoint after restart.

    Only read-only status requests are retried. A reachable OpenBao
    endpoint counts as ready even when the authority is sealed.
    """
    deadline = time.monotonic() + timeout

    while True:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            raise ServiceRestartUncertainError(
                "Service restart completed but HTTPS readiness could not be verified"
            )

        try:
            status_openbao(
                target.address,
                timeout=min(10.0, remaining),
            )
        except OpenBaoError:
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
            continue

        return


def restart_openbao(
    target: ServiceTarget,
    *,
    readiness_timeout: float = 60.0,
) -> None:
    """Restart the estate-managed OpenBao service exactly once.

    Use the existing verified Tailscale SSH and Ansible transport.

    The restart is executed by systemd, which supervises the Podman
    Quadlet container. Verify the systemd unit and application HTTPS
    endpoint before returning.

    A failure after dispatching the restart request is potentially
    ambiguous. Never automatically retry the restart.

    Args:
        target: Resolved OpenBao service identity.
        readiness_timeout: Maximum time to wait for HTTPS readiness.

    Raises:
        ServiceError: If the target or connection preflight is invalid.
        ServiceRestartUncertainError: If the restart or its subsequent
            verification cannot be confirmed.
    """
    _validate_restart_target(target)

    if not math.isfinite(readiness_timeout) or readiness_timeout <= 0:
        raise ServiceError("Service readiness timeout must be positive and finite")

    try:
        connection = prepare_tailscale_ansible(
            host=target.machine,
            user=target.user,
        )
    except TailscaleAnsibleError as exc:
        raise ServiceError("Unable to prepare verified service connection") from exc

    command = [
        "ansible",
        "-i",
        f"{connection.host},",
        "all",
        "-u",
        connection.user,
        "--become",
        "-m",
        "ansible.builtin.systemd_service",
        "-a",
        f"name={target.unit} state=restarted",
    ]

    try:
        returncode = run_ansible(
            command,
            connection=connection,
        )
    except TailscaleAnsibleError:
        raise ServiceRestartUncertainError(
            "Service restart outcome uncertain"
        ) from None

    if returncode != 0:
        raise ServiceRestartUncertainError(
            "Service restart did not return a successful result"
        )

    # Check the systemd supervisor without changing service state.
    check_command = [
        "ansible",
        "-i",
        f"{connection.host},",
        "all",
        "-u",
        connection.user,
        "-m",
        "ansible.builtin.command",
        "-a",
        f"systemctl is-active --quiet {target.unit}",
    ]

    try:
        check_returncode = run_ansible(
            check_command,
            connection=connection,
        )
    except TailscaleAnsibleError:
        raise ServiceRestartUncertainError(
            "Unable to verify restarted systemd service"
        ) from None

    if check_returncode != 0:
        raise ServiceRestartUncertainError(
            "Restarted systemd service is not confirmed active"
        )

    _verify_service_ready(
        target,
        timeout=readiness_timeout,
    )


__all__ = [
    "restart_openbao",
]
