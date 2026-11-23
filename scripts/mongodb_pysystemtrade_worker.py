"""Create or verify the restricted PySystemTrade MongoDB user.

Run on mxm-dev with PyMongo installed. Read both administrator and application
credentials as JSON from stdin; never place credentials in command arguments.
"""

from __future__ import annotations

import json
import sys
from typing import cast

from pymongo import MongoClient
from pymongo.errors import PyMongoError

_DATABASE = "mxm_pysystemtrade"
_ADMIN_USER = "mxm-admin"
_APP_USER = "pysystemtrade"
_EXPECTED_ROLES = [{"role": "readWrite", "db": _DATABASE}]


def _read_passwords() -> tuple[str, str]:
    """Validate the credential envelope supplied by the operator process."""
    raw: object = json.load(sys.stdin)
    if not isinstance(raw, dict):
        raise ValueError("Invalid credential envelope")

    data = cast(dict[str, object], raw)
    admin_password = data.get("admin_password")
    app_password = data.get("app_password")

    if (
        data.get("admin_username") != _ADMIN_USER
        or data.get("app_username") != _APP_USER
        or not isinstance(admin_password, str)
        or not admin_password
        or not isinstance(app_password, str)
        or not app_password
    ):
        raise ValueError("Invalid credential envelope")

    return admin_password, app_password


def _user_exists(client: MongoClient[dict[str, object]]) -> bool:
    """Return whether the account exists; reject any unexpected role or shape."""
    result = client[_DATABASE].command("usersInfo", _APP_USER)
    raw_users: object = result.get("users")
    if not isinstance(raw_users, list):
        raise ValueError("Unexpected usersInfo result")

    users = cast(list[object], raw_users)
    if not users:
        return False
    if len(users) != 1 or not isinstance(users[0], dict):
        raise ValueError("Unexpected MongoDB user record")

    user = cast(dict[str, object], users[0])
    if (
        user.get("user") != _APP_USER
        or user.get("db") != _DATABASE
        or user.get("roles") != _EXPECTED_ROLES
    ):
        raise ValueError("Application user has unexpected privileges")
    return True


def _ensure_user(admin_password: str, app_password: str) -> bool:
    """Create the application account only when absent; never modify it."""
    with MongoClient[dict[str, object]](
        host="127.0.0.1",
        port=27017,
        username=_ADMIN_USER,
        password=admin_password,
        authSource="admin",
        directConnection=True,
        serverSelectionTimeoutMS=5000,
    ) as client:
        if _user_exists(client):
            return False

        client[_DATABASE].command(
            "createUser",
            _APP_USER,
            pwd=app_password,
            roles=_EXPECTED_ROLES,
        )
        if not _user_exists(client):
            raise ValueError("MongoDB user creation could not be verified")
    return True


def _verify_login(app_password: str) -> None:
    """Authenticate the application account on an independent connection."""
    with MongoClient[dict[str, object]](
        host="127.0.0.1",
        port=27017,
        username=_APP_USER,
        password=app_password,
        authSource=_DATABASE,
        directConnection=True,
        serverSelectionTimeoutMS=5000,
    ) as client:
        result = client[_DATABASE].command("connectionStatus")

    raw_auth: object = result.get("authInfo")
    if not isinstance(raw_auth, dict):
        raise ValueError("Unexpected authentication response")
    auth = cast(dict[str, object], raw_auth)
    if auth.get("authenticatedUsers") != [{"user": _APP_USER, "db": _DATABASE}]:
        raise ValueError("Application identity could not be verified")


def main() -> int:
    """Commission the application user and independently verify its login."""
    try:
        admin_password, app_password = _read_passwords()
    except (ValueError, TypeError):
        print("ERROR: Invalid MongoDB credential input", file=sys.stderr)
        return 1

    try:
        created = _ensure_user(admin_password, app_password)
        _verify_login(app_password)
    except (PyMongoError, ValueError):
        print(
            "ERROR: MongoDB user commissioning failed; state may have changed",
            file=sys.stderr,
        )
        return 1

    state = "created and verified" if created else "already present and verified"
    print(f"OK: PySystemTrade MongoDB user {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
