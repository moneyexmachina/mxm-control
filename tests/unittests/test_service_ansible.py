"""Unit tests for Ansible/Tailscale service resolution."""

from dataclasses import dataclass
from pathlib import Path

import pytest

from mxm.control import service_ansible
from mxm.control.ansible import AnsibleError
from mxm.control.service import ServiceError, ServiceTarget
from mxm.control.tailscale_ansible import TailscaleAnsibleError

MACHINE = "mxm-security.tail546174.ts.net"
TAILNET_DOMAIN = "tail546174.ts.net"


@dataclass(frozen=True)
class _AnsibleTarget:
    """Minimal estate-declared Ansible target."""

    tailscale_host: str = "mxm-security"
    user: str = "mxm"


def _mock_discovery(
    monkeypatch: pytest.MonkeyPatch,
    *,
    machine: str = MACHINE,
) -> list[tuple[str, str]]:
    """Replace external discovery and record the resolution sequence."""
    calls: list[tuple[str, str]] = []

    def fake_deployment(root: Path) -> Path:
        calls.append(("deployment", str(root)))
        return root

    def fake_target(deployment: Path) -> _AnsibleTarget:
        calls.append(("inventory", str(deployment)))
        return _AnsibleTarget()

    def fake_hostname(host: str) -> str:
        calls.append(("tailscale", host))
        return machine

    monkeypatch.setattr(
        service_ansible,
        "_validated_deployment",
        fake_deployment,
    )
    monkeypatch.setattr(
        service_ansible,
        "_resolve_target",
        fake_target,
    )
    monkeypatch.setattr(
        service_ansible,
        "_resolve_tailscale_hostname",
        fake_hostname,
    )

    return calls


@pytest.mark.parametrize("name", ["openbao", "prefect"])
def test_resolve_ansible_tailscale_service(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
) -> None:
    """Resolve a logical service without hardcoding its identity."""
    root = tmp_path / "deployment"
    root.mkdir()

    calls = _mock_discovery(monkeypatch)

    result = service_ansible.resolve_ansible_tailscale_service(
        deployment_root=root,
        name=name,
    )

    assert result == ServiceTarget(
        name=name,
        address=f"https://{name}.{TAILNET_DOMAIN}",
        machine=MACHINE,
        user="mxm",
        unit=f"{name}.service",
    )

    assert calls == [
        ("deployment", str(root)),
        ("inventory", str(root)),
        ("tailscale", "mxm-security"),
    ]


def test_resolve_canonicalizes_trailing_dns_dot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Accept a canonical Tailscale hostname with a trailing DNS dot."""
    _mock_discovery(
        monkeypatch,
        machine=f"{MACHINE}.",
    )

    result = service_ansible.resolve_ansible_tailscale_service(
        deployment_root=tmp_path,
        name="openbao",
    )

    assert result.machine == MACHINE
    assert result.address == f"https://openbao.{TAILNET_DOMAIN}"


@pytest.mark.parametrize(
    "name",
    [
        "",
        "OpenBao",
        "open_bao",
        "openbao.example",
        "-openbao",
        "openbao-",
        "../openbao",
        "openbao/service",
    ],
)
def test_reject_invalid_service_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
) -> None:
    """Reject invalid DNS labels before invoking estate discovery."""
    calls = _mock_discovery(monkeypatch)

    with pytest.raises(
        ServiceError,
        match="Invalid Ansible/Tailscale service name",
    ):
        service_ansible.resolve_ansible_tailscale_service(
            deployment_root=tmp_path,
            name=name,
        )

    assert calls == []


@pytest.mark.parametrize(
    "machine",
    [
        "mxm-security",
        "mxm-security.example",
        "mxm-security..ts.net",
        "mxm_security.tail546174.ts.net",
        "",
    ],
)
def test_reject_invalid_tailscale_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    machine: str,
) -> None:
    """Require a valid canonical Tailscale machine DNS name."""
    _mock_discovery(
        monkeypatch,
        machine=machine,
    )

    with pytest.raises(ServiceError):
        service_ansible.resolve_ansible_tailscale_service(
            deployment_root=tmp_path,
            name="openbao",
        )


def test_report_invalid_ansible_deployment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Translate Ansible deployment failures into service errors."""

    def failing_deployment(root: Path) -> Path:
        raise AnsibleError("Invalid Ansible deployment")

    monkeypatch.setattr(
        service_ansible,
        "_validated_deployment",
        failing_deployment,
    )

    with pytest.raises(
        ServiceError,
        match="Unable to resolve estate service openbao",
    ):
        service_ansible.resolve_ansible_tailscale_service(
            deployment_root=tmp_path,
            name="openbao",
        )


def test_report_invalid_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Translate Ansible inventory resolution failures."""
    _mock_discovery(monkeypatch)

    def failing_target(deployment: Path) -> _AnsibleTarget:
        raise AnsibleError("Unable to resolve inventory target")

    monkeypatch.setattr(
        service_ansible,
        "_resolve_target",
        failing_target,
    )

    with pytest.raises(
        ServiceError,
        match="Unable to resolve estate service openbao",
    ):
        service_ansible.resolve_ansible_tailscale_service(
            deployment_root=tmp_path,
            name="openbao",
        )


def test_report_tailscale_discovery_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Translate Tailscale discovery failures into service errors."""
    _mock_discovery(monkeypatch)

    def failing_hostname(host: str) -> str:
        raise TailscaleAnsibleError("Machine not found")

    monkeypatch.setattr(
        service_ansible,
        "_resolve_tailscale_hostname",
        failing_hostname,
    )

    with pytest.raises(
        ServiceError,
        match="Unable to resolve estate service openbao",
    ):
        service_ansible.resolve_ansible_tailscale_service(
            deployment_root=tmp_path,
            name="openbao",
        )
