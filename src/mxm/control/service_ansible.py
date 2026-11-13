"""Resolve estate services deployed through Ansible and Tailscale.

The estate registry identifies the deployment providing a logical service.
This module resolves the deployment's Ansible inventory and Tailscale
machine identity into an operator-facing service target.

The ansible-tailscale resolver uses these deployment conventions:

- Tailscale Serve publishes https://<service>.<tailnet-domain>.
- The supervising systemd unit is <service>.service.

No estate stack paths or service registrations are defined here.
"""

from __future__ import annotations

import re
from pathlib import Path

from mxm.control.ansible import (
    AnsibleError,
    _resolve_target,
    _validated_deployment,
)
from mxm.control.service import ServiceError, ServiceTarget
from mxm.control.tailscale_ansible import (
    TailscaleAnsibleError,
    _resolve_tailscale_hostname,
)

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_DNS_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" r"(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
)


def _tailnet_domain(machine: str) -> str:
    """Extract the domain from a canonical Tailscale machine DNS name."""
    canonical = machine.rstrip(".").lower()

    if _DNS_NAME.fullmatch(canonical) is None:
        raise ServiceError("Invalid canonical Tailscale DNS name")

    _, separator, domain = canonical.partition(".")

    if not separator or not domain or "." not in domain:
        raise ServiceError("Tailscale machine has no valid tailnet domain")

    return domain


def resolve_ansible_tailscale_service(
    *,
    deployment_root: Path,
    name: str,
) -> ServiceTarget:
    """Resolve a service from its estate-declared Ansible deployment.

    The deployment supplies the target machine and remote Unix account.
    Tailscale resolves the canonical machine hostname.

    The service address and systemd unit follow the conventions of the
    ansible-tailscale resolver.

    Args:
        deployment_root: Directory containing the authoritative Ansible
            inventory.yml and playbook.yml.
        name: Logical service name supplied by the estate registry.

    Returns:
        Resolved service endpoint and machine/runtime identity.

    Raises:
        ServiceError: If the service name, deployment, inventory, or
            Tailscale identity cannot be resolved.
    """
    if _DNS_LABEL.fullmatch(name) is None:
        raise ServiceError(f"Invalid Ansible/Tailscale service name: {name}")

    try:
        deployment = _validated_deployment(deployment_root)
        target = _resolve_target(deployment)

        machine = _resolve_tailscale_hostname(
            target.tailscale_host,
        ).rstrip(".")

        domain = _tailnet_domain(machine)

    except (AnsibleError, TailscaleAnsibleError, ValueError) as exc:
        raise ServiceError(f"Unable to resolve estate service {name}: {exc}") from exc

    return ServiceTarget(
        name=name,
        address=f"https://{name}.{domain}",
        machine=machine,
        user=target.user,
        unit=f"{name}.service",
    )


__all__ = [
    "resolve_ansible_tailscale_service",
]
