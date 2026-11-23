"""Write PySystemTrade's authenticated MongoDB URI from the mxm-dev OpenBao proxy.

Run as mxm on mxm-dev. Only the mongo_host setting is changed; the secret
remains in the local private configuration file with owner-only permissions.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import cast
from urllib.parse import quote
from urllib.request import ProxyHandler, build_opener

_KV_URL = "http://127.0.0.1:8201/v1/kv/data/mxm-dev/pysystemtrade/mongodb"
_CONFIG = Path.home() / "mxm-pysystemtrade/private/private_config.yaml"
_DATABASE = "mxm_pysystemtrade"
_USERNAME = "pysystemtrade"


def _mongodb_uri() -> str:
    """Read the application credential through mxm-dev's authenticated proxy."""
    opener = build_opener(ProxyHandler({}))
    with opener.open(_KV_URL, timeout=10) as response:
        raw: object = json.load(response)

    if not isinstance(raw, dict):
        raise ValueError("Invalid OpenBao response")
    envelope = cast(dict[str, object], raw)

    raw_outer = envelope.get("data")
    if not isinstance(raw_outer, dict):
        raise ValueError("Invalid OpenBao response")
    outer = cast(dict[str, object], raw_outer)

    raw_secret = outer.get("data")
    if not isinstance(raw_secret, dict):
        raise ValueError("Invalid OpenBao secret")
    secret = cast(dict[str, object], raw_secret)

    username = secret.get("username")
    password = secret.get("password")
    if username != _USERNAME or not isinstance(password, str) or not password:
        raise ValueError("Invalid MongoDB application credential")

    return (
        f"mongodb://{quote(_USERNAME, safe='')}:{quote(password, safe='')}"
        f"@127.0.0.1:27017/?authSource={_DATABASE}"
    )


def _update_config(uri: str) -> bool:
    """Replace only mongo_host, atomically, without leaking the secret."""
    if _CONFIG.is_symlink() or not _CONFIG.is_file():
        raise ValueError("Expected an existing regular private_config.yaml")

    original = _CONFIG.read_text(encoding="utf-8")

    if not re.search(r"(?m)^mongo_db:[ \t]*mxm_pysystemtrade[ \t]*$", original):
        raise ValueError("Unexpected PySystemTrade MongoDB database")

    matches = list(re.finditer(r"(?m)^mongo_host[ \t]*:[^\r\n]*(?:\r?\n|$)", original))
    if len(matches) != 1:
        raise ValueError("Expected exactly one top-level mongo_host setting")

    match = matches[0]
    newline = "\n" if match.group().endswith("\n") else ""
    replacement = f"mongo_host: {json.dumps(uri)}{newline}"
    updated = original[: match.start()] + replacement + original[match.end() :]

    if updated == original:
        os.chmod(_CONFIG, 0o600)
        return False

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=_CONFIG.parent,
            prefix=".private_config.",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(updated)
            output.flush()
            os.fsync(output.fileno())

        os.replace(temporary, _CONFIG)
        os.chmod(_CONFIG, 0o600)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    return True


def main() -> int:
    """Fetch the existing OpenBao secret and configure PySystemTrade locally."""
    try:
        updated = _update_config(_mongodb_uri())
    except (OSError, ValueError):
        print(
            "ERROR: OpenBao credential retrieval or config update failed",
            file=sys.stderr,
        )
        return 1

    action = "updated" if updated else "already configured"
    print(f"OK: PySystemTrade MongoDB URI {action}; config mode 0600")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
