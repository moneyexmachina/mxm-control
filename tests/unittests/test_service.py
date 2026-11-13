"""Unit tests for estate-declared logical service resolution.

The estate registry owns logical service bindings.
Technology-specific resolvers own physical service discovery.

These tests do not contact Ansible, Tailscale, or OpenBao.
"""

from pathlib import Path

import pytest

from mxm.control import service, service_ansible

REGISTRY = """\
[services.openbao]
resolver = "ansible-tailscale"
deployment = "stacks/mxm-security/l2"
credentials = "stacks/mxm-security/l3"
"""


def _create_estate(
    tmp_path: Path,
    *,
    document: str | None = REGISTRY,
    deployment: bool = True,
    credentials: bool = True,
) -> Path:
    """Create a synthetic estate with its authoritative registry."""
    root = tmp_path / "mxm-estate"
    authority = root / "authority"
    authority.mkdir(parents=True)

    if document is not None:
        (authority / "services.toml").write_text(
            document,
            encoding="utf-8",
        )

    stack = root / "stacks" / "mxm-security"

    if deployment:
        (stack / "l2").mkdir(parents=True)

    if credentials:
        (stack / "l3").mkdir(parents=True)

    return root


def _target(name: str = "openbao") -> service.ServiceTarget:
    """Return a synthetic resolved operator service."""
    return service.ServiceTarget(
        name=name,
        address=f"https://{name}.tail546174.ts.net",
        machine="mxm-security.tail546174.ts.net",
        user="mxm",
        unit=f"{name}.service",
    )


def _mock_ansible_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[Path, str]]:
    """Record physical resolution without contacting the network."""
    calls: list[tuple[Path, str]] = []

    def fake_resolver(
        *,
        deployment_root: Path,
        name: str,
    ) -> service.ServiceTarget:
        calls.append((deployment_root, name))
        return _target(name)

    monkeypatch.setattr(
        service_ansible,
        "resolve_ansible_tailscale_service",
        fake_resolver,
    )

    return calls


def test_resolve_registered_openbao(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Resolve the singleton service using estate-owned declarations."""
    root = _create_estate(tmp_path)
    calls = _mock_ansible_resolver(monkeypatch)

    resolved = service.resolve_service(
        estate_root=root,
        name="openbao",
    )

    assert resolved == service.RegisteredService(
        target=_target(),
        credentials=root / "stacks" / "mxm-security" / "l3",
    )

    assert calls == [
        (
            root / "stacks" / "mxm-security" / "l2",
            "openbao",
        ),
    ]


def test_resolve_service_is_independent_of_stack_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Deployment locations are supplied by the estate, not Python."""
    document = """\
[services.openbao]
resolver = "ansible-tailscale"
deployment = "stacks/another-machine/l2"
credentials = "stacks/another-machine/l3"
"""
    root = _create_estate(tmp_path, document=document)

    deployment = root / "stacks" / "another-machine" / "l2"
    credentials = root / "stacks" / "another-machine" / "l3"

    deployment.mkdir(parents=True)
    credentials.mkdir(parents=True)

    calls = _mock_ansible_resolver(monkeypatch)

    resolved = service.resolve_service(
        estate_root=root,
        name="openbao",
    )

    assert resolved.target == _target()
    assert resolved.credentials == credentials
    assert calls == [(deployment, "openbao")]


def test_resolve_another_logical_service(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Registry lookup and dispatch do not hardcode OpenBao."""
    document = """\
[services.prefect]
resolver = "ansible-tailscale"
deployment = "stacks/mxm-security/l2"
"""
    root = _create_estate(tmp_path, document=document)
    calls = _mock_ansible_resolver(monkeypatch)

    resolved = service.resolve_service(
        estate_root=root,
        name="prefect",
    )

    assert resolved.target == _target("prefect")
    assert resolved.credentials is None

    assert calls == [
        (
            root / "stacks" / "mxm-security" / "l2",
            "prefect",
        ),
    ]


def test_credentials_are_optional(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Services may have no operator credential manifest."""
    document = """\
[services.openbao]
resolver = "ansible-tailscale"
deployment = "stacks/mxm-security/l2"
"""
    root = _create_estate(tmp_path, document=document)
    _mock_ansible_resolver(monkeypatch)

    resolved = service.resolve_service(
        estate_root=root,
        name="openbao",
    )

    assert resolved.target == _target()
    assert resolved.credentials is None


def test_reject_missing_estate_root(tmp_path: Path) -> None:
    """Do not guess an alternative estate location."""
    with pytest.raises(
        service.ServiceError,
        match="Estate root not found",
    ):
        service.resolve_service(
            estate_root=tmp_path / "missing",
            name="openbao",
        )


def test_reject_non_directory_estate_root(tmp_path: Path) -> None:
    """The estate root must be a directory."""
    root = tmp_path / "not-a-directory"
    root.write_text("invalid", encoding="utf-8")

    with pytest.raises(
        service.ServiceError,
        match="Estate root is not a directory",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_reject_missing_registry(tmp_path: Path) -> None:
    """The registry is required for logical service resolution."""
    root = _create_estate(tmp_path, document=None)

    with pytest.raises(
        service.ServiceError,
        match="Unable to read estate service registry",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_reject_invalid_toml(tmp_path: Path) -> None:
    """Malformed estate declarations must fail explicitly."""
    root = _create_estate(
        tmp_path,
        document="[services.openbao\n",
    )

    with pytest.raises(
        service.ServiceError,
        match="Unable to read estate service registry",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


@pytest.mark.parametrize(
    "document",
    [
        "",
        '[other]\nname = "openbao"\n',
        'services = "invalid"\n',
    ],
)
def test_reject_missing_services_table(
    tmp_path: Path,
    document: str,
) -> None:
    """Require the estate registry's expected structure."""
    root = _create_estate(tmp_path, document=document)

    with pytest.raises(
        service.ServiceError,
        match=r"requires a \[services\] table",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_reject_unregistered_service(tmp_path: Path) -> None:
    """Never infer a service binding absent from the registry."""
    root = _create_estate(tmp_path)

    with pytest.raises(
        service.ServiceError,
        match="Service not registered in estate: prefect",
    ):
        service.resolve_service(
            estate_root=root,
            name="prefect",
        )


@pytest.mark.parametrize(
    "document",
    [
        """\
[services.openbao]
deployment = "stacks/mxm-security/l2"
""",
        """\
[services.openbao]
resolver = 42
deployment = "stacks/mxm-security/l2"
""",
        """\
[services.openbao]
resolver = ""
deployment = "stacks/mxm-security/l2"
""",
    ],
)
def test_reject_missing_or_invalid_resolver(
    tmp_path: Path,
    document: str,
) -> None:
    """Every service must declare its resolution mechanism."""
    root = _create_estate(tmp_path, document=document)

    with pytest.raises(
        service.ServiceError,
        match="has no valid resolver declaration",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_reject_unsupported_resolver(tmp_path: Path) -> None:
    """Do not silently substitute another resolution mechanism."""
    document = """\
[services.openbao]
resolver = "unknown-technology"
deployment = "stacks/mxm-security/l2"
"""
    root = _create_estate(tmp_path, document=document)

    with pytest.raises(
        service.ServiceError,
        match="Unsupported service resolver: unknown-technology",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


@pytest.mark.parametrize(
    "declaration",
    [
        "",
        'deployment = ""',
        "deployment = 42",
        'deployment = "../outside"',
        'deployment = "/tmp/outside"',
    ],
)
def test_reject_invalid_deployment_path(
    tmp_path: Path,
    declaration: str,
) -> None:
    """Require a valid estate-relative deployment directory."""
    document = f'[services.openbao]\nresolver = "ansible-tailscale"\n{declaration}\n'
    root = _create_estate(tmp_path, document=document)

    with pytest.raises(service.ServiceError):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_reject_missing_deployment_directory(tmp_path: Path) -> None:
    """A declared deployment must exist."""
    root = _create_estate(
        tmp_path,
        deployment=False,
    )

    with pytest.raises(
        service.ServiceError,
        match=r"Service registry directory not found: openbao.deployment",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_reject_missing_credentials_directory(tmp_path: Path) -> None:
    """A declared credential directory must exist."""
    root = _create_estate(
        tmp_path,
        credentials=False,
    )

    with pytest.raises(
        service.ServiceError,
        match=r"Service registry directory not found: openbao.credentials",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_reject_deployment_symlink_outside_estate(tmp_path: Path) -> None:
    """A service declaration cannot escape the estate via symlinks."""
    root = _create_estate(
        tmp_path,
        deployment=False,
    )

    outside = tmp_path / "outside"
    outside.mkdir()

    deployment = root / "stacks" / "mxm-security" / "l2"
    deployment.symlink_to(outside, target_is_directory=True)

    with pytest.raises(
        service.ServiceError,
        match=r"Invalid service registry directory: openbao.deployment",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_reject_credentials_symlink_outside_estate(tmp_path: Path) -> None:
    """Credential locations must remain inside the estate."""
    root = _create_estate(
        tmp_path,
        credentials=False,
    )

    outside = tmp_path / "outside"
    outside.mkdir()

    credentials = root / "stacks" / "mxm-security" / "l3"
    credentials.symlink_to(outside, target_is_directory=True)

    with pytest.raises(
        service.ServiceError,
        match=r"Invalid service registry directory: openbao.credentials",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )


def test_propagate_physical_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A failed physical lookup must not produce a synthetic target."""
    root = _create_estate(tmp_path)

    def failing_resolver(
        *,
        deployment_root: Path,
        name: str,
    ) -> service.ServiceTarget:
        raise service.ServiceError("Tailscale machine not found")

    monkeypatch.setattr(
        service_ansible,
        "resolve_ansible_tailscale_service",
        failing_resolver,
    )

    with pytest.raises(
        service.ServiceError,
        match="Tailscale machine not found",
    ):
        service.resolve_service(
            estate_root=root,
            name="openbao",
        )
