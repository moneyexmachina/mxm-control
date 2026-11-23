"""Bootstrap or verify the mxm-dev MongoDB administrator.

The operator runs this script on forge. Administrator credentials are resolved
by mxm-control from the estate's Proton Pass bindings and streamed over
Tailscale SSH. The remote worker uses PyMongo and never receives credentials
in process arguments, environment variables, or source files.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

_USERNAME_ENV = "MXM_MONGODB_ADMIN_USERNAME"
_PASSWORD_ENV = "MXM_MONGODB_ADMIN_PASSWORD"
_WORKER_FILE = "mongodb_admin_worker.py"
_REMOTE_PYTHON = "/home/mxm/mxm-pysystemtrade/.venv/bin/python"


def _credential_worker(*, host: str, user: str) -> int:
    """Stream Proton Pass credentials to a PyMongo worker on mxm-dev.

    The worker enters the MongoDB container's network namespace to reach
    mongod via localhost, as required for initial user creation.
    """
    username = os.environ.get(_USERNAME_ENV, "")
    password = os.environ.get(_PASSWORD_ENV, "")

    if username != "mxm-admin" or not password or password.startswith("pass://"):
        print("ERROR: Invalid MongoDB administrator authority", file=sys.stderr)
        return 1

    source = Path(__file__).with_name(_WORKER_FILE).read_text(encoding="utf-8")

    # Only non-secret Python source is placed in command arguments.
    shell_program = (
        "set -eu; "
        "pid=$(podman inspect --format '{{.State.Pid}}' mxm-mongodb); "
        'case "$pid" in ""|*[!0-9]*) exit 2 ;; esac; '
        '[ "$pid" -gt 1 ]; '
        'exec nsenter --target "$pid" --net -- '
        "setpriv --reuid=mxm --regid=mxm --init-groups -- "
        f'{_REMOTE_PYTHON} -c "$1"'
    )
    remote_command = (
        "sudo -n /bin/sh -c "
        + shlex.quote(shell_program)
        + " mongodb-admin-worker "
        + shlex.quote(source)
    )

    environment = os.environ.copy()
    environment.pop(_USERNAME_ENV, None)
    environment.pop(_PASSWORD_ENV, None)

    try:
        result = subprocess.run(
            ["tailscale", "ssh", f"{user}@{host}", remote_command],
            input=json.dumps({"username": username, "password": password}),
            text=True,
            check=False,
            timeout=90,
            env=environment,
            umask=0o077,
        )
    except (OSError, subprocess.TimeoutExpired):
        print(
            "ERROR: MongoDB bootstrap outcome uncertain; inspect database state",
            file=sys.stderr,
        )
        return 1

    if result.returncode != 0:
        print(
            "ERROR: MongoDB administrator bootstrap/verification failed; "
            "database state may have changed",
            file=sys.stderr,
        )

    return result.returncode


def _operator_main(root: Path) -> int:
    """Resolve the authoritative estate target and launch the secret worker."""
    from mxm.control.ansible import (
        AnsibleError,
        _resolve_target,
        _validated_deployment,
    )
    from mxm.control.credentials import CredentialError, run_with_credentials
    from mxm.control.tailscale_ansible import (
        TailscaleAnsibleError,
        prepare_tailscale_ansible,
    )

    try:
        stack = root.expanduser().resolve(strict=True)

        if stack.parts[-4:] != ("stacks", "mxm-dev", "l3", "mongodb"):
            raise ValueError("Expected mxm-dev MongoDB L3 deployment root")

        target = _resolve_target(_validated_deployment(stack))
        connection = prepare_tailscale_ansible(
            host=target.tailscale_host,
            user=target.user,
        )

        return run_with_credentials(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--credential-worker",
                "--ssh-host",
                connection.host,
                "--ssh-user",
                connection.user,
            ],
            stack=stack,
            environment_policy=stack.parents[3] / "authority" / "environment.toml",
            restrictive_umask=True,
        )
    except (
        AnsibleError,
        CredentialError,
        TailscaleAnsibleError,
        OSError,
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Select the operator entry point or credential-bound worker mode."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument(
        "--credential-worker",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--ssh-host", help=argparse.SUPPRESS)
    parser.add_argument("--ssh-user", help=argparse.SUPPRESS)

    args = parser.parse_args(argv)

    if args.credential_worker:
        if args.root is not None or not args.ssh_host or not args.ssh_user:
            parser.error("Invalid credential worker invocation")

        return _credential_worker(host=args.ssh_host, user=args.ssh_user)

    if args.root is None or args.ssh_host or args.ssh_user:
        parser.error("Operator invocation requires --root")

    return _operator_main(args.root)


if __name__ == "__main__":
    raise SystemExit(main())
