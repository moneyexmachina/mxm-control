"""Activate an estate-declared OpenBao AppRole on an existing appliance.

An authenticated human operator issues response-wrapped AppRole bootstrap
credentials, delivers them over Tailscale SSH, and verifies the remote proxy.
This operation does not provision the appliance or change OpenBao policies.
"""

from __future__ import annotations

import io
import json
import os
import re
import shlex
import subprocess
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from mxm.control.service import ServiceError, resolve_service

_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_ROLE = re.compile(r"^[a-zA-Z0-9_-]+$")
_UNIT = re.compile(r"^[a-zA-Z0-9_.@-]+\.service$")
_TTL = re.compile(r"^[1-9][0-9]*[smh]$")
_KEYS = frozenset(
    {
        "provider",
        "service",
        "machine",
        "user",
        "approle",
        "expected_policy",
        "runtime_directory",
        "proxy_unit",
        "proxy_address",
        "wrap_ttl",
    }
)


class AuthorizationError(RuntimeError):
    """An authorization precondition or transaction failed."""


@dataclass(frozen=True, slots=True)
class AuthorizationSpec:
    """Estate-owned binding between a machine and its OpenBao identity."""

    service: str
    machine: str
    user: str
    approle: str
    expected_policy: str
    runtime_directory: str
    proxy_unit: str
    proxy_address: str
    wrap_ttl: str


def load_authorization(*, estate_root: Path, name: str) -> AuthorizationSpec:
    """Read an existing machine's L3 authorization declaration."""
    if _NAME.fullmatch(name) is None:
        raise AuthorizationError("Invalid authorization target name")

    manifest = estate_root / "stacks" / name / "l3" / "authorization.toml"
    if manifest.is_symlink():
        raise AuthorizationError("Authorization declaration must not be a symlink")

    try:
        with manifest.open("rb") as stream:
            document: object = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AuthorizationError("Unable to read authorization declaration") from exc

    if set(document) != {"authorization"}:
        raise AuthorizationError("Expected a single [authorization] table")

    raw = cast("dict[str, object]", document)["authorization"]
    if not isinstance(raw, dict):
        raise AuthorizationError("Invalid [authorization] table")

    table = cast("dict[str, object]", raw)
    if set(table) != set(_KEYS) or any(
        not isinstance(value, str) or not value for value in table.values()
    ):
        raise AuthorizationError("Invalid authorization declaration fields")

    def field(key: str) -> str:
        return cast("str", table[key])

    spec = AuthorizationSpec(
        service=field("service"),
        machine=field("machine"),
        user=field("user"),
        approle=field("approle"),
        expected_policy=field("expected_policy"),
        runtime_directory=field("runtime_directory"),
        proxy_unit=field("proxy_unit"),
        proxy_address=field("proxy_address"),
        wrap_ttl=field("wrap_ttl"),
    )

    runtime = Path(spec.runtime_directory)
    proxy = urlsplit(spec.proxy_address)
    if (
        field("provider") != "openbao"
        or spec.machine != name
        or _NAME.fullmatch(spec.service) is None
        or _NAME.fullmatch(spec.machine) is None
        or _NAME.fullmatch(spec.user) is None
        or _ROLE.fullmatch(spec.approle) is None
        or _ROLE.fullmatch(spec.expected_policy) is None
        or _UNIT.fullmatch(spec.proxy_unit) is None
        or _TTL.fullmatch(spec.wrap_ttl) is None
        or not runtime.is_absolute()
        or runtime.parts[:2] != ("/", "run")
        or len(runtime.parts) < 3
        or ".." in runtime.parts
        or proxy.scheme != "http"
        or proxy.hostname != "127.0.0.1"
        or proxy.port is None
        or proxy.path != ""
        or proxy.query != ""
        or proxy.fragment != ""
        or proxy.username is not None
        or proxy.password is not None
    ):
        raise AuthorizationError("Invalid authorization declaration values")

    return spec


def _run(
    command: list[str],
    *,
    input_data: bytes | None = None,
    environment: dict[str, str] | None = None,
    timeout: float = 30.0,
    failure: str,
) -> bytes:
    """Run a bounded subprocess without displaying captured credentials."""
    try:
        completed = subprocess.run(
            command,
            input=input_data,
            env=environment,
            timeout=timeout,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuthorizationError(failure) from exc

    if completed.returncode != 0:
        raise AuthorizationError(failure)
    return completed.stdout


def _ssh(
    spec: AuthorizationSpec, script: str, *, payload: bytes | None = None
) -> bytes:
    """Run a fixed remote bash script on the declared appliance."""
    remote = "bash -c " + shlex.quote("set -euo pipefail\n" + script)
    return _run(
        ["tailscale", "ssh", f"{spec.user}@{spec.machine}", remote],
        input_data=payload,
        timeout=60.0,
        failure="Factory-appliance SSH operation failed",
    )


def _bao_environment(address: str) -> dict[str, str]:
    """Select the resolved OpenBao endpoint and locally cached session."""
    environment = os.environ.copy()
    for key in ("BAO_TOKEN", "VAULT_TOKEN", "BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"):
        environment.pop(key, None)
    environment["BAO_ADDR"] = address
    return environment


def _single_line(value: str, label: str) -> str:
    if (
        not value
        or not value.isascii()
        or not value.isprintable()
        or any(character.isspace() for character in value)
    ):
        raise AuthorizationError(f"OpenBao returned an invalid {label}")
    return value


def _issue_bootstrap(address: str, spec: AuthorizationSpec) -> tuple[str, str]:
    """Obtain the RoleID and a wrapping token, never the raw SecretID."""
    environment = _bao_environment(address)
    path = f"auth/approle/role/{spec.approle}"
    role_id = _single_line(
        _run(
            ["bao", "read", "-field=role_id", f"{path}/role-id"],
            environment=environment,
            failure="Unable to read declared OpenBao AppRole RoleID",
        )
        .decode("utf-8")
        .strip(),
        "AppRole RoleID",
    )
    wrapped_response = _run(
        [
            "bao",
            "write",
            f"-wrap-ttl={spec.wrap_ttl}",
            "-format=json",
            "-f",
            f"{path}/secret-id",
        ],
        environment=environment,
        failure="Unable to issue response-wrapped AppRole SecretID",
    )
    try:
        document: object = json.loads(wrapped_response)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthorizationError("Invalid OpenBao wrapping response") from exc
    if not isinstance(document, dict):
        raise AuthorizationError("Invalid OpenBao wrapping response")
    raw_wrap = cast("dict[str, object]", document).get("wrap_info")
    if not isinstance(raw_wrap, dict):
        raise AuthorizationError("OpenBao did not return a wrapping token")
    token = cast("dict[str, object]", raw_wrap).get("token")
    if not isinstance(token, str):
        raise AuthorizationError("OpenBao did not return a wrapping token")
    return role_id, _single_line(token, "wrapping token")


def _archive_bootstrap(role_id: str, wrapped_token: str) -> bytes:
    """Build the credential bundle in memory, not on local disk."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for filename, value in (("role-id", role_id), ("secret-id", wrapped_token)):
            data = (value + "\n").encode("ascii")
            member = tarfile.TarInfo(filename)
            member.size = len(data)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def _preflight(spec: AuthorizationSpec) -> None:
    """Check appliance prerequisites before issuing a credential."""
    script = (
        f"systemctl cat {shlex.quote(spec.proxy_unit)} >/dev/null\n"
        "command -v curl >/dev/null\n"
        "command -v jq >/dev/null\n"
    )
    _ssh(spec, script)


def _deliver_and_restart(spec: AuthorizationSpec, bundle: bytes) -> None:
    """Install transient credentials and activate the existing proxy."""
    directory = shlex.quote(spec.runtime_directory)
    user = shlex.quote(spec.user)
    unit = shlex.quote(spec.proxy_unit)
    script = "\n".join(
        [
            f"sudo -n install -d -o {user} -g {user} -m 0700 {directory}",
            f"sudo -n tar --extract --file=- --directory={directory} --no-same-owner",
            f"sudo -n chown {user}:{user} {directory}/role-id {directory}/secret-id",
            f"sudo -n chmod 0600 {directory}/role-id {directory}/secret-id",
            f"sudo -n systemctl restart {unit}",
        ]
    )
    _ssh(spec, script, payload=bundle)


def _verify(spec: AuthorizationSpec) -> None:
    """Verify the proxy's effective policy and bootstrap consumption."""
    directory = shlex.quote(spec.runtime_directory)
    policy = shlex.quote(spec.expected_policy)
    endpoint = shlex.quote(spec.proxy_address + "/v1/auth/token/lookup-self")
    unit = shlex.quote(spec.proxy_unit)
    script = "\n".join(
        [
            "response=''",
            "for attempt in $(seq 1 30); do",
            (
                "  if response=$(curl --fail --silent --show-error "
                f"{endpoint} 2>/dev/null); then break; fi"
            ),
            "  sleep 1",
            "done",
            'test -n "$response"',
            (
                f"jq -e --arg policy {policy} "
                "'.data.policies | index($policy) != null' "
                '<<<"$response" >/dev/null'
            ),
            f"test ! -e {directory}/secret-id",
            f"test -s {directory}/role-id",
            f"systemctl is-active --quiet {unit}",
        ]
    )
    _ssh(spec, script)


def authorize_machine(*, estate_root: Path, name: str) -> None:
    """Authorize the declared existing appliance and verify its proxy."""
    spec = load_authorization(estate_root=estate_root, name=name)
    try:
        registered = resolve_service(estate_root=estate_root, name=spec.service)
        address = registered.target.address
    except ServiceError as exc:
        raise AuthorizationError("Unable to resolve OpenBao service") from exc

    _preflight(spec)
    role_id, wrapped_token = _issue_bootstrap(address, spec)
    bundle = _archive_bootstrap(role_id, wrapped_token)
    _deliver_and_restart(spec, bundle)
    _verify(spec)
