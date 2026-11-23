"""Bootstrap or verify the MXM MongoDB administrator with PyMongo.

Run in the MongoDB container's network namespace so first-user creation
can use MongoDB's localhost exception. Read credentials from standard input.
"""

from __future__ import annotations

import json
import sys
from typing import cast

from pymongo import MongoClient
from pymongo.errors import OperationFailure, PyMongoError


def _has_root_role(password: str) -> bool:
    """Authenticate in a fresh client and check the effective root role."""
    with MongoClient[dict[str, object]](
        host="127.0.0.1",
        port=27017,
        username="mxm-admin",
        password=password,
        authSource="admin",
        directConnection=True,
        serverSelectionTimeoutMS=5000,
    ) as client:
        status = client.admin.command("connectionStatus")

    return any(
        role["role"] == "root" and role["db"] == "admin"
        for role in status["authInfo"]["authenticatedUserRoles"]
    )


def _create_first_admin(password: str) -> None:
    """Attempt first-user creation; MongoDB rejects an existing account."""
    with MongoClient[dict[str, object]](
        "mongodb://127.0.0.1:27017",
        directConnection=True,
        serverSelectionTimeoutMS=5000,
    ) as client:
        client.admin.command(
            "createUser",
            "mxm-admin",
            pwd=password,
            roles=[{"role": "root", "db": "admin"}],
        )


def main() -> int:
    """Verify the administrator, or create it once and verify again."""
    try:
        raw: object = json.load(sys.stdin)

        if not isinstance(raw, dict):
            raise ValueError("Invalid credentials")

        credentials = cast(dict[str, object], raw)

        if credentials.get("username") != "mxm-admin":
            raise ValueError("Invalid credentials")

        password = credentials.get("password")

        if not isinstance(password, str) or not password:
            raise ValueError("Invalid credentials")

    except (ValueError, TypeError):
        print("ERROR: Invalid administrator credential input", file=sys.stderr)
        return 1

    created = False

    try:
        try:
            has_root = _has_root_role(password)
        except OperationFailure as exc:
            if exc.code != 18:
                raise

            _create_first_admin(password)
            created = True
            has_root = _has_root_role(password)

    except PyMongoError:
        print(
            "ERROR: MongoDB administrator bootstrap/verification failed; "
            "state may have changed",
            file=sys.stderr,
        )
        return 1

    if not has_root:
        print("ERROR: MongoDB administrator lacks root role", file=sys.stderr)
        return 1

    message = "created and verified" if created else "already present and verified"
    print(f"OK: MongoDB administrator {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
