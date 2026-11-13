"""Unit tests for the OpenBao service lifecycle."""

import math
from collections.abc import Sequence
from pathlib import Path

import pytest

from mxm.control import service
from mxm.control.openbao import lifecycle
from mxm.control.openbao.api import OpenBaoError
from mxm.control.tailscale_ansible import (
    TailscaleAnsibleConnection,
    TailscaleAnsibleError,
)

# ---------------------------------------------------------------------------
# Supervised service restart
# ---------------------------------------------------------------------------


def _restart_target() -> service.ServiceTarget:
    """Return the known OpenBao service target."""
    return service.ServiceTarget(
        name="openbao",
        address="https://openbao.tail546174.ts.net",
        machine="mxm-security.tail546174.ts.net",
        user="mxm",
        unit="openbao.service",
    )


def _restart_connection() -> TailscaleAnsibleConnection:
    """Return a synthetic verified Tailscale SSH connection."""
    return TailscaleAnsibleConnection(
        host="mxm-security.tail546174.ts.net",
        user="mxm",
        host_key_alias="mxm-security.tail546174.ts.net.",
        known_hosts=Path("/synthetic/tailscale/ssh_known_hosts"),
    )


def _mock_restart_transport(
    monkeypatch: pytest.MonkeyPatch,
    *,
    returncodes: tuple[int, ...] = (0, 0),
) -> list[list[str]]:
    """Mock verified SSH preparation and record Ansible commands."""
    connection = _restart_connection()
    commands: list[list[str]] = []
    results = iter(returncodes)

    def fake_prepare(
        *,
        host: str,
        user: str,
    ) -> TailscaleAnsibleConnection:
        assert host == "mxm-security.tail546174.ts.net"
        assert user == "mxm"
        return connection

    def fake_run(
        command: Sequence[str],
        *,
        connection: TailscaleAnsibleConnection,
        cwd: Path | None = None,
    ) -> int:
        assert connection == _restart_connection()
        assert cwd is None
        commands.append(list(command))
        return next(results)

    monkeypatch.setattr(
        lifecycle,
        "prepare_tailscale_ansible",
        fake_prepare,
    )
    monkeypatch.setattr(
        lifecycle,
        "run_ansible",
        fake_run,
    )

    return commands


def test_restart_openbao_uses_systemd_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restart the declared Quadlet unit and verify systemd state."""
    commands = _mock_restart_transport(monkeypatch)
    readiness: list[tuple[service.ServiceTarget, float]] = []

    def fake_ready(
        target: service.ServiceTarget,
        *,
        timeout: float,
    ) -> None:
        readiness.append((target, timeout))

    monkeypatch.setattr(
        lifecycle,
        "_verify_service_ready",
        fake_ready,
    )

    target = _restart_target()

    lifecycle.restart_openbao(
        target,
        readiness_timeout=30.0,
    )

    assert commands == [
        [
            "ansible",
            "-i",
            "mxm-security.tail546174.ts.net,",
            "all",
            "-u",
            "mxm",
            "--become",
            "-m",
            "ansible.builtin.systemd_service",
            "-a",
            "name=openbao.service state=restarted",
        ],
        [
            "ansible",
            "-i",
            "mxm-security.tail546174.ts.net,",
            "all",
            "-u",
            "mxm",
            "-m",
            "ansible.builtin.command",
            "-a",
            "systemctl is-active --quiet openbao.service",
        ],
    ]

    assert readiness == [(target, 30.0)]

    restart_commands = [
        command
        for command in commands
        if any("state=restarted" in argument for argument in command)
    ]
    assert len(restart_commands) == 1


def test_restart_rejects_unsupported_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject unsupported services before preparing remote access."""
    commands = _mock_restart_transport(monkeypatch)

    target = service.ServiceTarget(
        name="postgres",
        address="https://postgres.example.ts.net",
        machine="mxm-security.example.ts.net",
        user="mxm",
        unit="postgres.service",
    )

    with pytest.raises(
        service.ServiceError,
        match="Unsupported service restart target",
    ):
        lifecycle.restart_openbao(target)

    assert commands == []


def test_restart_rejects_wrong_systemd_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not allow a caller to substitute an arbitrary service unit."""
    commands = _mock_restart_transport(monkeypatch)
    original = _restart_target()

    target = service.ServiceTarget(
        name=original.name,
        address=original.address,
        machine=original.machine,
        user=original.user,
        unit="ssh.service",
    )

    with pytest.raises(
        service.ServiceError,
        match="Unsupported service restart target",
    ):
        lifecycle.restart_openbao(target)

    assert commands == []


@pytest.mark.parametrize(
    "timeout",
    [
        0.0,
        -1.0,
        math.inf,
        -math.inf,
        math.nan,
    ],
)
def test_restart_rejects_invalid_readiness_timeout(
    monkeypatch: pytest.MonkeyPatch,
    timeout: float,
) -> None:
    """Validate readiness deadlines before any remote operation."""
    commands = _mock_restart_transport(monkeypatch)

    with pytest.raises(
        service.ServiceError,
        match="readiness timeout",
    ):
        lifecycle.restart_openbao(
            _restart_target(),
            readiness_timeout=timeout,
        )

    assert commands == []


def test_restart_preflight_failure_is_not_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failed SSH preparation must not dispatch a restart."""
    calls: list[str] = []

    def failing_prepare(
        *,
        host: str,
        user: str,
    ) -> TailscaleAnsibleConnection:
        calls.append("preflight")
        raise TailscaleAnsibleError("SSH unavailable")

    monkeypatch.setattr(
        lifecycle,
        "prepare_tailscale_ansible",
        failing_prepare,
    )

    with pytest.raises(
        service.ServiceError,
        match="Unable to prepare verified service connection",
    ) as caught:
        lifecycle.restart_openbao(_restart_target())

    assert not isinstance(
        caught.value,
        service.ServiceRestartUncertainError,
    )
    assert calls == ["preflight"]


def test_restart_transport_failure_is_uncertain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transport failure after dispatch is not automatically retried."""
    connection = _restart_connection()
    commands: list[list[str]] = []

    def fake_prepare(
        *,
        host: str,
        user: str,
    ) -> TailscaleAnsibleConnection:
        assert host == "mxm-security.tail546174.ts.net"
        assert user == "mxm"
        return connection

    monkeypatch.setattr(
        lifecycle,
        "prepare_tailscale_ansible",
        fake_prepare,
    )

    def failing_run(
        command: Sequence[str],
        *,
        connection: TailscaleAnsibleConnection,
        cwd: Path | None = None,
    ) -> int:
        commands.append(list(command))
        raise TailscaleAnsibleError("SSH connection lost")

    monkeypatch.setattr(lifecycle, "run_ansible", failing_run)

    with pytest.raises(
        service.ServiceRestartUncertainError,
        match="outcome uncertain",
    ):
        lifecycle.restart_openbao(_restart_target())

    assert len(commands) == 1
    assert any("state=restarted" in argument for argument in commands[0])


def test_restart_nonzero_exit_is_uncertain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed restart response must not trigger another restart."""
    commands = _mock_restart_transport(
        monkeypatch,
        returncodes=(1,),
    )

    with pytest.raises(
        service.ServiceRestartUncertainError,
        match="did not return a successful result",
    ):
        lifecycle.restart_openbao(_restart_target())

    assert len(commands) == 1
    assert any("state=restarted" in argument for argument in commands[0])


def test_restart_systemd_verification_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful restart request requires active-unit verification."""
    commands = _mock_restart_transport(
        monkeypatch,
        returncodes=(0, 3),
    )

    with pytest.raises(
        service.ServiceRestartUncertainError,
        match="not confirmed active",
    ):
        lifecycle.restart_openbao(_restart_target())

    assert len(commands) == 2
    assert (
        sum(
            any("state=restarted" in argument for argument in command)
            for command in commands
        )
        == 1
    )


def test_restart_systemd_check_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed read-only verification leaves the restart outcome uncertain."""
    connection = _restart_connection()
    commands: list[list[str]] = []

    def fake_prepare(
        *,
        host: str,
        user: str,
    ) -> TailscaleAnsibleConnection:
        assert host == "mxm-security.tail546174.ts.net"
        assert user == "mxm"
        return connection

    monkeypatch.setattr(
        lifecycle,
        "prepare_tailscale_ansible",
        fake_prepare,
    )

    def fake_run(
        command: Sequence[str],
        *,
        connection: TailscaleAnsibleConnection,
        cwd: Path | None = None,
    ) -> int:
        commands.append(list(command))

        if len(commands) == 2:
            raise TailscaleAnsibleError("verification disconnected")

        return 0

    monkeypatch.setattr(lifecycle, "run_ansible", fake_run)

    with pytest.raises(
        service.ServiceRestartUncertainError,
        match="Unable to verify restarted systemd service",
    ):
        lifecycle.restart_openbao(_restart_target())

    assert len(commands) == 2
    assert (
        sum(
            any("state=restarted" in argument for argument in command)
            for command in commands
        )
        == 1
    )


def test_restart_readiness_failure_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failed HTTPS readiness must not cause another systemd restart."""
    commands = _mock_restart_transport(monkeypatch)

    def failing_ready(
        target: service.ServiceTarget,
        *,
        timeout: float,
    ) -> None:
        raise service.ServiceRestartUncertainError(
            "HTTPS readiness could not be verified"
        )

    monkeypatch.setattr(
        lifecycle,
        "_verify_service_ready",
        failing_ready,
    )

    with pytest.raises(
        service.ServiceRestartUncertainError,
        match="HTTPS readiness",
    ):
        lifecycle.restart_openbao(_restart_target())

    assert len(commands) == 2
    assert (
        sum(
            any("state=restarted" in argument for argument in command)
            for command in commands
        )
        == 1
    )


# ---------------------------------------------------------------------------
# HTTPS readiness verification
# ---------------------------------------------------------------------------


def test_openbao_ready_accepts_sealed_openbao(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Readiness requires API reachability, not an unsealed authority."""
    addresses: list[str] = []

    def fake_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> object:
        addresses.append(address)
        return object()

    monkeypatch.setattr(lifecycle, "status_openbao", fake_status)

    lifecycle._verify_service_ready(
        _restart_target(),
        timeout=10.0,
    )

    assert addresses == [
        "https://openbao.tail546174.ts.net",
    ]


def test_openbao_ready_retries_only_status_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transient HTTPS failures permit read-only polling."""
    attempts: list[str] = []
    sleeps: list[float] = []

    def fake_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> object:
        attempts.append(address)

        if len(attempts) == 1:
            raise OpenBaoError("HTTPS temporarily unavailable")

        return object()

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(lifecycle, "status_openbao", fake_status)
    monkeypatch.setattr(lifecycle.time, "sleep", fake_sleep)

    lifecycle._verify_service_ready(
        _restart_target(),
        timeout=10.0,
    )

    assert len(attempts) == 2
    assert attempts == [
        "https://openbao.tail546174.ts.net",
        "https://openbao.tail546174.ts.net",
    ]
    assert len(sleeps) == 1
    assert 0.0 <= sleeps[0] <= 1.0


def test_openbao_ready_expires_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop polling when the readiness deadline has expired."""
    clock = iter([0.0, 1.0])
    requests: list[str] = []

    def fake_monotonic() -> float:
        return next(clock)

    def forbidden_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> object:
        requests.append(address)
        pytest.fail("No request should occur after deadline expiration")

    monkeypatch.setattr(
        lifecycle.time,
        "monotonic",
        fake_monotonic,
    )
    monkeypatch.setattr(
        lifecycle,
        "status_openbao",
        forbidden_status,
    )

    with pytest.raises(
        service.ServiceRestartUncertainError,
        match="HTTPS readiness",
    ):
        lifecycle._verify_service_ready(
            _restart_target(),
            timeout=1.0,
        )

    assert requests == []
