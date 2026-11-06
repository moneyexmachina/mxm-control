"""Tailscale SSH transport integration for Ansible.

Provide a reusable connection adapter allowing Ansible to manage machines
through Tailscale SSH without introducing separate SSH credentials or
requiring a conventional SSH daemon on the target.

Tailscale remains responsible for machine identity, authentication,
authorisation, and trusted SSH host-key distribution.

Ansible uses its standard OpenSSH connection plugin, configured with
Tailscale's transport and verified host-key inventory.

This module provides connection preparation and execution mechanisms only.
Estate-specific inventory, playbooks, target selection, and privilege
policies belong to the caller.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

_HOST_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")
_USER_PATTERN = re.compile(r"[a-z_][a-z0-9_-]*")

_TAILSCALE_STATUS_TIMEOUT = 15.0
_TAILSCALE_SSH_TIMEOUT = 60.0
_HOST_KEY_LOOKUP_TIMEOUT = 10.0
_ANSIBLE_TIMEOUT = 3600.0


class TailscaleAnsibleError(RuntimeError):
    """Raised when Tailscale-backed Ansible execution cannot proceed."""


@dataclass(frozen=True, slots=True)
class TailscaleAnsibleConnection:
    """Resolved Tailscale SSH connection parameters for an Ansible target.

    Attributes:
        host: Canonical Tailscale DNS hostname without its trailing dot.
        user: Remote Unix account used for SSH.
        host_key_alias: Exact hostname used in Tailscale's SSH host-key
            inventory, including its trailing dot where applicable.
        known_hosts: Path to Tailscale's verified SSH host-key inventory.
    """

    host: str
    user: str
    host_key_alias: str
    known_hosts: Path

    def environment(
        self,
        inherited: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        """Construct an Ansible environment using Tailscale SSH.

        Configure Ansible's standard SSH connection plugin to use the
        Tailscale transport and trusted host-key inventory.

        Host-key verification remains mandatory.

        Args:
            inherited: Base process environment. When omitted, the
                current process environment is inherited.

        Returns:
            A new environment mapping containing the required Ansible
            SSH configuration.
        """
        environment = dict(os.environ if inherited is None else inherited)

        options = [
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "CanonicalizeHostname=no",
            "-o",
            f"HostKeyAlias={self.host_key_alias}",
            "-o",
            "ProxyCommand=tailscale nc %h %p",
        ]

        environment["ANSIBLE_SSH_COMMON_ARGS"] = shlex.join(options)
        environment["ANSIBLE_HOST_KEY_CHECKING"] = "True"

        return environment


def _run(
    command: Sequence[str],
    *,
    timeout: float,
    environment: Mapping[str, str] | None = None,
    capture_output: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess without invoking a shell.

    Args:
        command: Executable and its arguments.
        timeout: Maximum execution time in seconds.
        environment: Optional explicit process environment.
        capture_output: Whether to capture standard output and error.
        cwd: Optional working directory for the child process.

    Returns:
        The completed subprocess result.

    Raises:
        TailscaleAnsibleError: If the executable cannot be started
            or the operation times out.
    """
    if not command:
        raise TailscaleAnsibleError("Empty subprocess command")

    try:
        return subprocess.run(
            list(command),
            check=False,
            text=True,
            capture_output=capture_output,
            timeout=timeout,
            env=(dict(environment) if environment is not None else None),
            cwd=cwd,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TailscaleAnsibleError(
            f"Unable to execute {command[0]}: {type(exc).__name__}"
        ) from exc


def _validate_identity(host: str, user: str) -> None:
    """Validate operator-supplied Tailscale SSH identity fields.

    Args:
        host: Requested Tailscale hostname.
        user: Requested remote Unix account.

    Raises:
        TailscaleAnsibleError: If either identifier is malformed.
    """
    if (
        not _HOST_PATTERN.fullmatch(host)
        or ".." in host
        or not _USER_PATTERN.fullmatch(user)
    ):
        raise TailscaleAnsibleError("Invalid Tailscale hostname or SSH username")


def _load_tailscale_peers() -> dict[str, object]:
    """Retrieve and validate the local Tailscale peer inventory.

    Returns:
        Mapping of Tailscale peer identifiers to unvalidated peer records.

    Raises:
        TailscaleAnsibleError: If Tailscale status cannot be retrieved
            or its peer inventory has an invalid structure.
    """
    result = _run(
        ["tailscale", "status", "--json"],
        timeout=_TAILSCALE_STATUS_TIMEOUT,
    )

    if result.returncode != 0:
        raise TailscaleAnsibleError("Unable to query local Tailscale status")

    try:
        document: object = json.loads(result.stdout)
    except ValueError as exc:
        raise TailscaleAnsibleError("Invalid Tailscale status JSON") from exc

    if not isinstance(document, dict):
        raise TailscaleAnsibleError("Invalid Tailscale status structure")

    status = cast("dict[str, object]", document)
    raw_peers: object = status.get("Peer")

    if not isinstance(raw_peers, dict):
        raise TailscaleAnsibleError("Tailscale status has no peer inventory")

    return cast("dict[str, object]", raw_peers)


def _matching_peer_dns_name(
    raw_peer: object,
    requested: str,
) -> str | None:
    """Match a requested machine name against one Tailscale peer.

    Both short hostnames and canonical DNS names are supported.
    Matching is case-insensitive and ignores a trailing DNS dot.

    Args:
        raw_peer: Unvalidated Tailscale peer record.
        requested: Normalised machine name to match.

    Returns:
        The peer's canonical DNS name if it matches, otherwise None.
    """
    if not isinstance(raw_peer, dict):
        return None

    peer = cast("dict[str, object]", raw_peer)

    dns_name = peer.get("DNSName")
    short_name = peer.get("HostName")

    if not isinstance(dns_name, str) or not dns_name:
        return None

    names = {dns_name.rstrip(".").casefold()}

    if isinstance(short_name, str):
        names.add(short_name.casefold())

    if requested not in names:
        return None

    return dns_name


def _resolve_tailscale_hostname(host: str) -> str:
    """Resolve a machine to its canonical Tailscale DNS hostname.

    Query the local Tailscale peer inventory and require an unambiguous
    match against the requested short or fully qualified hostname.

    Args:
        host: Short or fully qualified Tailscale hostname.

    Returns:
        Canonical DNS name reported by Tailscale, including its
        trailing dot where present.

    Raises:
        TailscaleAnsibleError: If the requested machine cannot be
            resolved uniquely or has an invalid canonical hostname.
    """
    requested = host.rstrip(".").casefold()
    peers = _load_tailscale_peers()

    matches = [
        dns_name
        for raw_peer in peers.values()
        if (
            dns_name := _matching_peer_dns_name(
                raw_peer,
                requested,
            )
        )
        is not None
    ]

    if len(matches) != 1:
        raise TailscaleAnsibleError(
            "Expected exactly one matching Tailscale peer "
            f"for {host!r}; found {len(matches)}"
        )

    canonical = matches[0]

    if not _HOST_PATTERN.fullmatch(canonical) or ".." in canonical:
        raise TailscaleAnsibleError("Invalid canonical Tailscale hostname")

    return canonical


def _tailscale_known_hosts_path() -> Path:
    """Locate the SSH host-key inventory maintained by Tailscale.

    Returns:
        The expected path to Tailscale's ssh_known_hosts file.

    The path is based on the operator's XDG configuration directory.
    """
    config_home = Path(
        os.environ.get(
            "XDG_CONFIG_HOME",
            str(Path.home() / ".config"),
        )
    ).expanduser()

    return config_home / "tailscale" / "ssh_known_hosts"


def prepare_tailscale_ansible(
    *,
    host: str,
    user: str,
) -> TailscaleAnsibleConnection:
    """Prepare and verify a Tailscale SSH connection for Ansible.

    Resolve the machine identity, establish a successful Tailscale SSH
    connection, and verify that its canonical hostname is present in
    Tailscale's trusted SSH host-key inventory.

    No remote configuration changes are performed.

    Args:
        host: Short or fully qualified Tailscale machine name.
        user: Remote Unix account.

    Returns:
        Verified connection parameters suitable for Ansible execution.

    Raises:
        TailscaleAnsibleError: If identity resolution, Tailscale SSH
            access, or host-key verification fails.
    """
    _validate_identity(host, user)

    canonical = _resolve_tailscale_hostname(host)
    known_hosts = _tailscale_known_hosts_path()

    # Use Tailscale's own SSH wrapper to establish access and refresh
    # its control-plane-derived host-key inventory.
    result = _run(
        [
            "tailscale",
            "ssh",
            f"{user}@{host}",
            "true",
        ],
        timeout=_TAILSCALE_SSH_TIMEOUT,
    )

    if result.returncode != 0:
        raise TailscaleAnsibleError(f"Tailscale SSH preflight failed for {user}@{host}")

    if not known_hosts.is_file():
        raise TailscaleAnsibleError(
            "Tailscale SSH did not provide its host-key inventory"
        )

    # Tailscale records canonical DNS names with a trailing dot.
    # OpenSSH must use the same identity for strict host-key lookup.
    result = _run(
        [
            "ssh-keygen",
            "-F",
            canonical,
            "-f",
            str(known_hosts),
        ],
        timeout=_HOST_KEY_LOOKUP_TIMEOUT,
    )

    if result.returncode != 0:
        raise TailscaleAnsibleError(f"No verified SSH host key found for {canonical}")

    return TailscaleAnsibleConnection(
        host=canonical.rstrip("."),
        user=user,
        host_key_alias=canonical,
        known_hosts=known_hosts,
    )


def run_ansible(
    command: Sequence[str],
    *,
    connection: TailscaleAnsibleConnection,
    cwd: Path | None = None,
) -> int:
    """Execute Ansible using the prepared Tailscale SSH transport.

    The caller supplies the Ansible command, inventory, playbook, and
    additional arguments. This module supplies the verified connection
    environment and optional execution directory.

    Args:
        command: Ansible executable and command arguments.
        connection: Previously prepared Tailscale SSH connection.
        cwd: Working directory used for native Ansible configuration
            discovery, including ansible.cfg and relative paths.

    Returns:
        The Ansible subprocess exit status.

    Raises:
        TailscaleAnsibleError: If the command is unsupported or cannot
            be executed.
    """
    if not command or Path(command[0]).name not in {"ansible", "ansible-playbook"}:
        raise TailscaleAnsibleError("Expected ansible or ansible-playbook executable")

    result = _run(
        command,
        timeout=_ANSIBLE_TIMEOUT,
        environment=connection.environment(),
        capture_output=False,
        cwd=cwd,
    )

    return result.returncode


def check_ansible_ssh(
    *,
    host: str,
    user: str,
) -> None:
    """Verify Ansible connectivity through Tailscale SSH.

    Perform a Tailscale SSH preflight followed by an Ansible ping
    using the verified transport.

    This checks remote command execution and Python availability.
    It does not modify the remote machine or verify privilege
    escalation.

    Args:
        host: Tailscale machine name.
        user: Remote Unix account.

    Raises:
        TailscaleAnsibleError: If Tailscale or Ansible connectivity
            verification fails.
    """
    connection = prepare_tailscale_ansible(
        host=host,
        user=user,
    )

    result = run_ansible(
        [
            "ansible",
            "-i",
            f"{connection.host},",
            "all",
            "-u",
            connection.user,
            "-m",
            "ansible.builtin.ping",
        ],
        connection=connection,
    )

    if result != 0:
        raise TailscaleAnsibleError(
            f"Ansible SSH preflight failed with exit status {result}"
        )
