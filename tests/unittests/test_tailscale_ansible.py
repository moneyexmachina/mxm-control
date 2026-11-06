"""Unit tests for the Ansible transport backed by Tailscale SSH.

External commands are mocked: no tailnet, SSH server, or Ansible required.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from mxm.control import tailscale_ansible as sut

_CANONICAL_HOST = "mxm-security.tail.example.ts.net."


def _inventory(*peers: dict[str, object]) -> str:
    """Build a representative Tailscale status response."""
    return json.dumps(
        {"Peer": {f"peer-{index}": peer for index, peer in enumerate(peers)}}
    )


def _valid_inventory() -> str:
    """Return one valid peer with short and canonical names."""
    return _inventory({"HostName": "mxm-security", "DNSName": _CANONICAL_HOST})


@dataclass
class _FakeCommands:
    """Simulate the external commands used by the adapter."""

    status_json: str = field(default_factory=_valid_inventory)
    status_returncode: int = 0
    ssh_returncode: int = 0
    key_returncode: int = 0
    ansible_returncode: int = 0
    calls: list[tuple[str, ...]] = field(default_factory=list[tuple[str, ...]])
    ansible_environment: dict[str, str] | None = None
    ansible_capture_output: bool | None = None
    ansible_cwd: Path | None = None

    def __call__(
        self,
        command: Sequence[str],
        *,
        timeout: float,
        environment: Mapping[str, str] | None = None,
        capture_output: bool = True,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Return a controlled result and record external command arguments."""
        args = tuple(command)
        self.calls.append(args)
        returncode = 0
        stdout = ""

        if args == ("tailscale", "status", "--json"):
            returncode, stdout = self.status_returncode, self.status_json
        elif args[:2] == ("tailscale", "ssh"):
            returncode = self.ssh_returncode
        elif args[:1] == ("ssh-keygen",):
            returncode = self.key_returncode
        elif args[:1] in (("ansible",), ("ansible-playbook",)):
            returncode = self.ansible_returncode
            self.ansible_environment = (
                dict(environment) if environment is not None else None
            )
            self.ansible_capture_output = capture_output
            self.ansible_cwd = cwd

        else:
            pytest.fail(f"Unexpected external command: {args}")

        return subprocess.CompletedProcess(
            args=list(args),
            returncode=returncode,
            stdout=stdout,
            stderr="",
        )


@pytest.fixture
def fake_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> _FakeCommands:
    """Install a fake command runner and an isolated Tailscale host-key file."""
    config_home = tmp_path / "config"
    known_hosts = config_home / "tailscale" / "ssh_known_hosts"
    known_hosts.parent.mkdir(parents=True)
    known_hosts.write_text("mocked Tailscale host-key inventory\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

    runner = _FakeCommands()
    monkeypatch.setattr(sut, "_run", runner)
    return runner


def test_connection_environment_preserves_verified_tailscale_ssh(
    tmp_path: Path,
) -> None:
    """Keep strict host-key checking and route through Tailscale."""
    connection = sut.TailscaleAnsibleConnection(
        host=_CANONICAL_HOST.rstrip("."),
        user="mxm",
        host_key_alias=_CANONICAL_HOST,
        known_hosts=tmp_path / "ssh_known_hosts",
    )
    inherited = {"PATH": "/usr/bin", "ANSIBLE_HOST_KEY_CHECKING": "False"}

    environment = connection.environment(inherited)

    assert inherited["ANSIBLE_HOST_KEY_CHECKING"] == "False"
    assert environment["PATH"] == "/usr/bin"
    assert environment["ANSIBLE_HOST_KEY_CHECKING"] == "True"
    options = environment["ANSIBLE_SSH_COMMON_ARGS"]
    assert f"UserKnownHostsFile={connection.known_hosts}" in options
    assert "StrictHostKeyChecking=yes" in options
    assert "UpdateHostKeys=no" in options
    assert f"HostKeyAlias={_CANONICAL_HOST}" in options
    assert "ProxyCommand=tailscale nc %h %p" in options


@pytest.mark.parametrize(
    "host",
    [
        "mxm-security",
        "MXM-SECURITY",
        "mxm-security.tail.example.ts.net",
        _CANONICAL_HOST,
    ],
)
def test_prepare_resolves_short_and_canonical_names(
    fake_commands: _FakeCommands,
    host: str,
) -> None:
    """Use the canonical Tailscale name regardless of the supplied form."""
    connection = sut.prepare_tailscale_ansible(host=host, user="mxm")

    assert connection.host == _CANONICAL_HOST.rstrip(".")
    assert connection.host_key_alias == _CANONICAL_HOST
    assert connection.user == "mxm"
    assert fake_commands.calls[0] == ("tailscale", "status", "--json")
    assert fake_commands.calls[1] == (
        "tailscale",
        "ssh",
        f"mxm@{host}",
        "true",
    )
    assert fake_commands.calls[2] == (
        "ssh-keygen",
        "-F",
        _CANONICAL_HOST,
        "-f",
        str(connection.known_hosts),
    )


@pytest.mark.parametrize(
    ("status", "returncode", "message"),
    [
        ("", 1, "Unable to query local Tailscale status"),
        ("not JSON", 0, "Invalid Tailscale status JSON"),
        ("[]", 0, "Invalid Tailscale status structure"),
        ("{}", 0, "Tailscale status has no peer inventory"),
        ('{"Peer": []}', 0, "Tailscale status has no peer inventory"),
    ],
)
def test_prepare_rejects_invalid_tailscale_status(
    fake_commands: _FakeCommands,
    status: str,
    returncode: int,
    message: str,
) -> None:
    """Malformed or unavailable peer inventory prevents SSH execution."""
    fake_commands.status_json = status
    fake_commands.status_returncode = returncode

    with pytest.raises(sut.TailscaleAnsibleError, match=message):
        sut.prepare_tailscale_ansible(host="mxm-security", user="mxm")

    assert fake_commands.calls == [("tailscale", "status", "--json")]


@pytest.mark.parametrize(
    ("status", "host", "message"),
    [
        (_inventory(), "missing", "found 0"),
        (
            _inventory(
                {"HostName": "duplicate", "DNSName": "duplicate.a.ts.net."},
                {"HostName": "duplicate", "DNSName": "duplicate.b.ts.net."},
            ),
            "duplicate",
            "found 2",
        ),
        (
            _inventory({"HostName": "bad", "DNSName": "invalid..ts.net."}),
            "bad",
            "Invalid canonical Tailscale hostname",
        ),
    ],
)
def test_prepare_rejects_missing_ambiguous_or_malformed_peer(
    fake_commands: _FakeCommands,
    status: str,
    host: str,
    message: str,
) -> None:
    """Accept only one peer with a well-formed canonical hostname."""
    fake_commands.status_json = status

    with pytest.raises(sut.TailscaleAnsibleError, match=message):
        sut.prepare_tailscale_ansible(host=host, user="mxm")


@pytest.mark.parametrize(
    ("host", "user"),
    [
        ("bad;hostname", "mxm"),
        ("bad..hostname", "mxm"),
        ("mxm-security", "mxm;whoami"),
    ],
)
def test_prepare_rejects_invalid_identity_without_subprocesses(
    fake_commands: _FakeCommands,
    host: str,
    user: str,
) -> None:
    """Reject malformed identity fields before contacting Tailscale."""
    with pytest.raises(sut.TailscaleAnsibleError, match="Invalid Tailscale"):
        sut.prepare_tailscale_ansible(host=host, user=user)

    assert fake_commands.calls == []


@pytest.mark.parametrize(
    ("ssh_code", "key_code", "message"),
    [
        (1, 0, "Tailscale SSH preflight failed"),
        (0, 1, "No verified SSH host key found"),
    ],
)
def test_prepare_rejects_failed_ssh_or_host_key_lookup(
    fake_commands: _FakeCommands,
    ssh_code: int,
    key_code: int,
    message: str,
) -> None:
    """Never hand an unverified connection to Ansible."""
    fake_commands.ssh_returncode = ssh_code
    fake_commands.key_returncode = key_code

    with pytest.raises(sut.TailscaleAnsibleError, match=message):
        sut.prepare_tailscale_ansible(host="mxm-security", user="mxm")


def test_prepare_requires_tailscale_host_key_file(
    fake_commands: _FakeCommands,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing Tailscale-managed host-key inventory fails closed."""
    monkeypatch.setenv(
        "XDG_CONFIG_HOME",
        str(tmp_path / "nonexistent"),
    )

    with pytest.raises(
        sut.TailscaleAnsibleError,
        match="did not provide its host-key inventory",
    ):
        sut.prepare_tailscale_ansible(host="mxm-security", user="mxm")

    assert not any(call[:1] == ("ssh-keygen",) for call in fake_commands.calls)


def test_run_ansible_scopes_connection_environment(
    fake_commands: _FakeCommands,
) -> None:
    """Execute Ansible with the authenticated Tailscale transport options."""
    connection = sut.prepare_tailscale_ansible(
        host="mxm-security",
        user="mxm",
    )
    fake_commands.ansible_returncode = 2

    result = sut.run_ansible(
        ["ansible-playbook", "-i", "inventory.ini", "playbook.yml"],
        connection=connection,
    )

    assert result == 2
    assert fake_commands.calls[-1] == (
        "ansible-playbook",
        "-i",
        "inventory.ini",
        "playbook.yml",
    )
    assert fake_commands.ansible_capture_output is False

    environment = fake_commands.ansible_environment
    assert environment is not None
    assert environment["ANSIBLE_HOST_KEY_CHECKING"] == "True"
    assert "ProxyCommand=tailscale nc %h %p" in environment["ANSIBLE_SSH_COMMON_ARGS"]


@pytest.mark.parametrize(
    "command",
    [
        [],
        ["sh", "-c", "echo unexpected"],
    ],
)
def test_run_ansible_rejects_other_executables(
    fake_commands: _FakeCommands,
    command: list[str],
) -> None:
    """Only Ansible executables are accepted by the generic runner."""
    connection = sut.prepare_tailscale_ansible(
        host="mxm-security",
        user="mxm",
    )
    call_count = len(fake_commands.calls)

    with pytest.raises(sut.TailscaleAnsibleError, match="Expected ansible"):
        sut.run_ansible(command, connection=connection)

    assert len(fake_commands.calls) == call_count


def test_check_ansible_ssh_runs_read_only_ping(
    fake_commands: _FakeCommands,
) -> None:
    """Preflight reaches the machine using Ansible's ping module."""
    sut.check_ansible_ssh(host="mxm-security", user="mxm")

    assert fake_commands.calls[-1] == (
        "ansible",
        "-i",
        "mxm-security.tail.example.ts.net,",
        "all",
        "-u",
        "mxm",
        "-m",
        "ansible.builtin.ping",
    )


def test_check_ansible_ssh_propagates_failed_ping(
    fake_commands: _FakeCommands,
) -> None:
    """A nonzero Ansible ping exit status fails the connection preflight."""
    fake_commands.ansible_returncode = 4

    with pytest.raises(
        sut.TailscaleAnsibleError,
        match="exit status 4",
    ):
        sut.check_ansible_ssh(host="mxm-security", user="mxm")
