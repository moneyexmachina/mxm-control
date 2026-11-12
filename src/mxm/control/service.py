"""Resolve logical services declared by the MXM estate.

The estate owns the authoritative service registry at
authority/services.toml.

This module resolves logical service names into their declared
deployments, selects the appropriate technology-specific resolver,
and returns operator-facing service identities.

Physical service discovery belongs to the selected resolver.
Application lifecycle operations belong to their respective modules.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast


class ServiceError(RuntimeError):
    """Raised when an estate service cannot be resolved."""


class ServiceRestartUncertainError(ServiceError):
    """A dispatched service restart has an unverified outcome."""


@dataclass(frozen=True, slots=True)
class ServiceTarget:
    """Resolved operator-facing identity of an estate service.

    Attributes:
        name: Logical service name.
        address: HTTPS service origin.
        machine: Canonical Tailscale machine hostname.
        user: Estate-declared remote Unix account.
        unit: systemd service unit supervising the application.
    """

    name: str
    address: str
    machine: str
    user: str
    unit: str


@dataclass(frozen=True, slots=True)
class RegisteredService:
    """Resolved estate service and its operator credential directory.

    Attributes:
        target: Service identity resolved by the declared mechanism.
        credentials: Optional directory containing credentials.toml.
    """

    target: ServiceTarget
    credentials: Path | None


def _declared_directory(
    estate_root: Path,
    value: object,
    *,
    field: str,
) -> Path:
    """Resolve an estate-relative directory declared in the registry."""
    if not isinstance(value, str) or not value:
        raise ServiceError(f"Invalid service registry field: {field}")

    relative = Path(value)

    if relative.is_absolute() or ".." in relative.parts:
        raise ServiceError(f"Invalid estate-relative path: {field}")

    try:
        path = (estate_root / relative).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ServiceError(f"Service registry directory not found: {field}") from exc

    if not path.is_relative_to(estate_root) or not path.is_dir():
        raise ServiceError(f"Invalid service registry directory: {field}")

    return path


def _load_service_registration(
    estate_root: Path,
    name: str,
) -> dict[str, object]:
    """Load one logical service declaration from the estate registry."""
    registry = estate_root / "authority" / "services.toml"

    try:
        with registry.open("rb") as stream:
            document = cast("dict[str, object]", tomllib.load(stream))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ServiceError(
            f"Unable to read estate service registry: {registry}"
        ) from exc

    raw_services = document.get("services")

    if not isinstance(raw_services, dict):
        raise ServiceError("Estate service registry requires a [services] table")

    services = cast("dict[str, object]", raw_services)
    raw_registration = services.get(name)

    if not isinstance(raw_registration, dict):
        raise ServiceError(f"Service not registered in estate: {name}")

    return cast("dict[str, object]", raw_registration)


def resolve_service(
    *,
    estate_root: Path,
    name: str,
) -> RegisteredService:
    """Resolve a logical service through the authoritative estate registry.

    Args:
        estate_root: Root of the mxm-estate repository.
        name: Unique logical service name registered by the estate.

    Returns:
        Resolved service target and optional credential directory.

    Raises:
        ServiceError: If the estate registry, service declaration,
            deployment, or physical service identity cannot be resolved.
    """
    try:
        root = estate_root.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ServiceError("Estate root not found") from exc

    if not root.is_dir():
        raise ServiceError("Estate root is not a directory")

    registration = _load_service_registration(root, name)

    resolver = registration.get("resolver")

    if not isinstance(resolver, str) or not resolver:
        raise ServiceError(f"Service {name} has no valid resolver declaration")

    deployment = _declared_directory(
        root,
        registration.get("deployment"),
        field=f"{name}.deployment",
    )

    credentials: Path | None = None

    if "credentials" in registration:
        credentials = _declared_directory(
            root,
            registration["credentials"],
            field=f"{name}.credentials",
        )

    if resolver == "ansible-tailscale":
        # Import locally: the technology-specific resolver uses the
        # shared ServiceTarget and ServiceError types from this module.
        from mxm.control.service_ansible import (
            resolve_ansible_tailscale_service,
        )

        target = resolve_ansible_tailscale_service(
            deployment_root=deployment,
            name=name,
        )
    else:
        raise ServiceError(f"Unsupported service resolver: {resolver}")

    return RegisteredService(
        target=target,
        credentials=credentials,
    )


__all__ = [
    "RegisteredService",
    "ServiceError",
    "ServiceRestartUncertainError",
    "ServiceTarget",
    "resolve_service",
]
