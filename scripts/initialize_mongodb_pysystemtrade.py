"""Provision the PySystemTrade MongoDB credential and application account.

Run on forge. Proton Pass supplies MongoDB administrator authority; the
OpenBao operator session stores the application password. An independent
PyMongo worker on mxm-dev creates or verifies the restricted database user.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast

_ADMIN_USERNAME_ENV = "MXM_MONGODB_ADMIN_USERNAME"
_ADMIN_PASSWORD_ENV = "MXM_MONGODB_ADMIN_PASSWORD"
_WORKER_FILE = "mongodb_pysystemtrade_worker.py"
_REMOTE_PYTHON = "/home/mxm/mxm-pysystemtrade/.venv/bin/python"
_KV_PATH = "mxm-dev/pysystemtrade/mongodb"
_APP_USERNAME = "pysystemtrade"


def _read_application_password(environment: dict[str, str]) -> str | None:
    """Read and validate the existing KV-v2 credential, if readable."""
    result = subprocess.run(
        ["bao", "kv", "get", "-format=json", "-mount=kv", _KV_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env=environment,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        return None

    raw: object = json.loads(result.stdout)
    if not isinstance(raw, dict):
        raise ValueError("Invalid OpenBao secret structure")

    document = cast("dict[str, object]", raw)
    outer = document.get("data")
    if not isinstance(outer, dict):
        raise ValueError("Invalid OpenBao secret structure")

    data = cast("dict[str, object]", outer).get("data")
    if not isinstance(data, dict):
        raise ValueError("Invalid OpenBao secret structure")

    credential = cast("dict[str, object]", data)
    password = credential.get("password")

    if (
        set(credential) != {"username", "password"}
        or credential.get("username") != _APP_USERNAME
        or not isinstance(password, str)
        or not password
    ):
        raise ValueError("Unexpected OpenBao credential")

    return password


def _ensure_application_password(address: str) -> str:
    """Reuse an existing password, or create one without overwriting it."""
    environment = os.environ.copy()

    for name in (
        _ADMIN_USERNAME_ENV,
        _ADMIN_PASSWORD_ENV,
        "BAO_TOKEN",
        "VAULT_TOKEN",
    ):
        environment.pop(name, None)

    environment["BAO_ADDR"] = address

    password = _read_application_password(environment)
    if password is not None:
        return password

    candidate = secrets.token_urlsafe(48)
    payload = json.dumps({"username": _APP_USERNAME, "password": candidate})

    result = subprocess.run(
        ["bao", "kv", "put", "-cas=0", "-mount=kv", _KV_PATH, "-"],
        input=payload,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        env=environment,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("OpenBao create-only write failed; inspect credential state")

    if _read_application_password(environment) != candidate:
        raise ValueError("Stored application credential failed verification")

    return candidate


def _credential_worker(*, host: str, user: str, bao_address: str) -> int:
    """Resolve both authorities and stream credentials to the remote worker."""
    admin_username = os.environ.get(_ADMIN_USERNAME_ENV, "")
    admin_password = os.environ.get(_ADMIN_PASSWORD_ENV, "")

    if (
        admin_username != "mxm-admin"
        or not admin_password
        or admin_password.startswith("pass://")
    ):
        print("ERROR: Invalid MongoDB administrator credentials", file=sys.stderr)
        return 1

    try:
        source = Path(__file__).with_name(_WORKER_FILE).read_text(encoding="utf-8")
        app_password = _ensure_application_password(bao_address)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("ERROR: Application credential provisioning failed", file=sys.stderr)
        return 1

    environment = os.environ.copy()
    for name in (
        _ADMIN_USERNAME_ENV,
        _ADMIN_PASSWORD_ENV,
        "BAO_TOKEN",
        "VAULT_TOKEN",
    ):
        environment.pop(name, None)

    command = f"{shlex.quote(_REMOTE_PYTHON)} -c {shlex.quote(source)}"

    payload = json.dumps(
        {
            "admin_username": admin_username,
            "admin_password": admin_password,
            "app_username": _APP_USERNAME,
            "app_password": app_password,
        }
    )

    try:
        result = subprocess.run(
            ["tailscale", "ssh", f"{user}@{host}", command],
            input=payload,
            text=True,
            check=False,
            timeout=90,
            env=environment,
            umask=0o077,
        )
    except (OSError, subprocess.TimeoutExpired):
        print("ERROR: Remote commissioning outcome uncertain", file=sys.stderr)
        return 1

    return result.returncode


def _operator_main(root: Path) -> int:
    """Find the estate target and start the Proton Pass-bound worker."""
    from mxm.control.ansible import (
        AnsibleError,
        _resolve_target,
        _validated_deployment,
    )
    from mxm.control.credentials import CredentialError, run_with_credentials
    from mxm.control.service import ServiceError, resolve_service
    from mxm.control.tailscale_ansible import (
        TailscaleAnsibleError,
        prepare_tailscale_ansible,
    )

    try:
        stack = root.expanduser().resolve(strict=True)

        if stack.parts[-4:] != ("stacks", "mxm-dev", "l3", "mongodb"):
            raise ValueError("Expected mxm-dev MongoDB deployment root")

        estate = stack.parents[3]
        target = _resolve_target(_validated_deployment(stack))

        connection = prepare_tailscale_ansible(
            host=target.tailscale_host,
            user=target.user,
        )
        openbao = resolve_service(estate_root=estate, name="openbao")

        return run_with_credentials(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--credential-worker",
                "--ssh-host",
                connection.host,
                "--ssh-user",
                connection.user,
                "--bao-address",
                openbao.target.address,
            ],
            stack=stack,
            environment_policy=estate / "authority" / "environment.toml",
            restrictive_umask=True,
        )
    except (
        AnsibleError,
        CredentialError,
        ServiceError,
        TailscaleAnsibleError,
        OSError,
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch operator mode or the credential-bound child process."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)

    parser.add_argument(
        "--credential-worker",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--ssh-host", help=argparse.SUPPRESS)
    parser.add_argument("--ssh-user", help=argparse.SUPPRESS)
    parser.add_argument("--bao-address", help=argparse.SUPPRESS)

    args = parser.parse_args(argv)

    if args.credential_worker:
        if (
            args.root is not None
            or not args.ssh_host
            or not args.ssh_user
            or not args.bao_address
        ):
            parser.error("Invalid credential worker invocation")

        return _credential_worker(
            host=args.ssh_host,
            user=args.ssh_user,
            bao_address=args.bao_address,
        )

    if args.root is None or args.ssh_host or args.ssh_user or args.bao_address:
        parser.error("Operator invocation requires --root")

    return _operator_main(args.root)


if __name__ == "__main__":
    raise SystemExit(main())
