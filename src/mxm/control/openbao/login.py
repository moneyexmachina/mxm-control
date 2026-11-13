"""Credential-bound OpenBao operator authentication.

This module runs as a child of pass-cli run. Proton Pass resolves
MXM_OPENBAO_USERNAME and MXM_OPENBAO_PASSWORD into this child process.

Authenticate through the OpenBao userpass HTTPS API, verify the
operator policy and session lifetime, then use the native OpenBao
CLI to store the resulting session token.

Neither passwords nor session tokens are passed as CLI arguments
or printed.
"""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
from dataclasses import dataclass
from typing import cast
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from mxm.control.openbao.api import OpenBaoError, validated_address

_REQUIRED_POLICY = "security-admin"
_MAX_TTL = 30 * 60
_MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class OpenBaoSession:
    """Authenticated operator session, before local token storage."""

    token: str
    ttl: int


def _parse_login_response(payload: bytes) -> OpenBaoSession:
    """Validate the authenticated identity without exposing the token."""
    try:
        document: object = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OpenBaoError("Invalid OpenBao authentication response") from exc

    if not isinstance(document, dict):
        raise OpenBaoError("Invalid OpenBao authentication response")

    response = cast("dict[str, object]", document)
    raw_auth = response.get("auth")

    if not isinstance(raw_auth, dict):
        raise OpenBaoError("OpenBao authentication returned no session")

    auth = cast("dict[str, object]", raw_auth)
    token = auth.get("client_token")
    policies = auth.get("policies")
    ttl = auth.get("lease_duration")

    if (
        not isinstance(token, str)
        or not token
        or not token.isascii()
        or not token.isprintable()
        or any(character.isspace() for character in token)
    ):
        raise OpenBaoError("OpenBao authentication returned no valid token")

    if not isinstance(policies, list):
        raise OpenBaoError("OpenBao authentication returned no policies")

    policy_names = cast("list[object]", policies)

    if _REQUIRED_POLICY not in policy_names:
        raise OpenBaoError("OpenBao session lacks security-admin policy")

    if type(ttl) is not int or not 0 < ttl <= _MAX_TTL:
        raise OpenBaoError("OpenBao session has an unexpected lifetime")

    return OpenBaoSession(token=token, ttl=ttl)


def authenticate_userpass(
    address: str,
    *,
    username: str,
    password: str,
    timeout: float = 10.0,
) -> OpenBaoSession:
    """Authenticate the operator against OpenBao's userpass backend."""
    origin = validated_address(address)

    if not username or not password:
        raise OpenBaoError("OpenBao operator credentials are unavailable")

    endpoint = f"{origin}/v1/auth/userpass/login/{quote(username, safe='')}"

    request = Request(
        endpoint,
        data=json.dumps({"password": password}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(
            request,
            timeout=timeout,
            context=ssl.create_default_context(),
        ) as response:
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, URLError, TimeoutError) as exc:
        raise OpenBaoError("OpenBao operator authentication failed") from exc

    if len(payload) > _MAX_RESPONSE_BYTES:
        raise OpenBaoError("OpenBao authentication response too large")

    return _parse_login_response(payload)


def _store_session(address: str, token: str) -> None:
    """Store the token using OpenBao's native CLI token helper."""
    environment = os.environ.copy()

    # Never allow an inherited token to override the new session.
    environment.pop("BAO_TOKEN", None)
    environment.pop("VAULT_TOKEN", None)

    # The native CLI does not need the Proton Pass credentials.
    environment.pop("MXM_OPENBAO_USERNAME", None)
    environment.pop("MXM_OPENBAO_PASSWORD", None)

    try:
        result = subprocess.run(
            ["bao", "login", "-address", address, "-no-print", "-"],
            input=f"{token}\n",
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=False,
            timeout=20.0,
            umask=0o077,
        )
    except FileNotFoundError as exc:
        raise OpenBaoError(
            "OpenBao CLI (bao) is not installed or unavailable on PATH"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise OpenBaoError("OpenBao CLI token storage timed out") from exc
    except OSError as exc:
        raise OpenBaoError("Unable to execute OpenBao CLI") from exc

    if result.returncode != 0:
        raise OpenBaoError(
            f"OpenBao CLI token storage failed (exit {result.returncode})"
        )

    if result.returncode != 0:
        raise OpenBaoError("Unable to store OpenBao operator session")


def login_openbao(address: str) -> int:
    """Establish and store an operator session from injected credentials."""
    username = os.environ.get("MXM_OPENBAO_USERNAME", "")
    password = os.environ.get("MXM_OPENBAO_PASSWORD", "")

    session = authenticate_userpass(
        address,
        username=username,
        password=password,
    )

    _store_session(validated_address(address), session.token)

    return session.ttl


def main() -> int:
    """Execute the credential-bound login from the parent control CLI."""
    if len(sys.argv) != 2:
        print("ERROR: OpenBao service address required", file=sys.stderr)
        return 1

    try:
        ttl = login_openbao(sys.argv[1])
    except OpenBaoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"OK        OpenBao security-admin session ({ttl}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
