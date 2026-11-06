"""Unit tests for estate-driven Ansible planning and application.

All external commands are replaced with fakes. No tailnet or remote host is used.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from mxm.control import ansible as sut
from mxm.control.tailscale_ansible import (
    TailscaleAnsibleConnection,
    TailscaleAnsibleError,
)

_CANONICAL_HOST = "mxm-security.tail.example.ts.net."


def _single_host_inventory() -> dict[str, object]:
    """Return a resolved native Ansible inventory with one managed host."""
    return {
        "_meta": {
            "hostvars": {
                "security": {
                    "ansible_host": "mxm-security",
                    "ansible_user": "mxm",
                    "ansible_python_interpreter": "/usr/bin/python3",
                }
            }
        },
        "all": {"children": ["ungrouped"]},
        "ungrouped": {"hosts": ["security"]},
    }


class _FakeExternal:
    """Record simulated inventory, Tailscale, and Ansible calls."""

    def __init__(self, known_hosts: Path) -> None:
        """Establish independent, explicitly typed fake state for each test."""
        self.known_hosts = known_hosts
        self.inventory_data: dict[str, object] = _single_host_inventory()
        self.inventory_output: str | None = None
        self.inventory_returncode = 0
        self.inventory_exception: OSError | subprocess.TimeoutExpired | None = None
        self.playbook_returncode = 0
        self.connection_failure = False
        self.execution_failure = False
        self.inventory_calls: list[tuple[str, ...]] = []
        self.inventory_cwd: Path | None = None
        self.prepare_calls: list[tuple[str, str]] = []
        self.playbook_calls: list[tuple[str, ...]] = []
        self.playbook_cwd: Path | None = None

    def inventory_run(
        self,
        command: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        """Simulate ansible-inventory --list without executing a subprocess."""
        self.inventory_calls.append(tuple(command))
        cwd = kwargs.get("cwd")
        if isinstance(cwd, Path):
            self.inventory_cwd = cwd

        if self.inventory_exception is not None:
            raise self.inventory_exception

        if Path(command[0]).name != "ansible-inventory":
            pytest.fail(f"Unexpected inventory command: {command!r}")

        output = (
            json.dumps(self.inventory_data)
            if self.inventory_output is None
            else self.inventory_output
        )
        return subprocess.CompletedProcess(
            args=list(command),
            returncode=self.inventory_returncode,
            stdout=output,
            stderr="",
        )

    def prepare(
        self,
        *,
        host: str,
        user: str,
    ) -> TailscaleAnsibleConnection:
        """Simulate Tailscale SSH preflight and record its machine identity."""
        self.prepare_calls.append((host, user))
        if self.connection_failure:
            raise TailscaleAnsibleError("Tailscale SSH denied access")
        return TailscaleAnsibleConnection(
            host=_CANONICAL_HOST.rstrip("."),
            user=user,
            host_key_alias=_CANONICAL_HOST,
            known_hosts=self.known_hosts,
        )

    def run_playbook(
        self,
        command: Sequence[str],
        *,
        connection: TailscaleAnsibleConnection,
        cwd: Path | None = None,
    ) -> int:
        """Simulate a playbook run using the estate execution directory."""
        assert connection.known_hosts == self.known_hosts
        self.playbook_cwd = cwd
        self.playbook_calls.append(tuple(command))

        if self.execution_failure:
            raise TailscaleAnsibleError("Unable to launch Ansible")

        return self.playbook_returncode


@pytest.fixture
def deployment_root(tmp_path: Path) -> Path:
    """Create an estate deployment with a native inventory and playbook."""
    root = tmp_path / "l2"
    root.mkdir()
    (root / "inventory.yml").write_text(
        "all:\n  hosts:\n    security:\n"
        "      ansible_host: mxm-security\n"
        "      ansible_user: mxm\n"
        "      ansible_python_interpreter: /usr/bin/python3\n"
    )
    (root / "playbook.yml").write_text(
        "---\n- hosts: all\n  gather_facts: false\n  tasks: []\n"
    )
    return root


@pytest.fixture
def fake_external(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> _FakeExternal:
    """Replace all external execution boundaries with recorded fakes."""
    fake = _FakeExternal(known_hosts=tmp_path / "ssh_known_hosts")
    monkeypatch.setattr(sut.subprocess, "run", fake.inventory_run)
    monkeypatch.setattr(sut, "prepare_tailscale_ansible", fake.prepare)
    monkeypatch.setattr(sut, "run_ansible", fake.run_playbook)
    return fake


def test_plan_uses_target_and_user_from_inventory(
    deployment_root: Path,
    fake_external: _FakeExternal,
) -> None:
    """Resolve estate-owned identity and run only the selected host in check mode."""
    deployment = sut.plan_ansible(root=deployment_root)

    assert deployment.root == deployment_root.resolve()
    assert deployment.inventory == (deployment_root / "inventory.yml").resolve()
    assert deployment.playbook == (deployment_root / "playbook.yml").resolve()
    assert fake_external.inventory_calls == [
        (
            "ansible-inventory",
            "--inventory",
            str(deployment.inventory),
            "--list",
        )
    ]

    assert fake_external.playbook_cwd == deployment_root.resolve()
    assert fake_external.inventory_cwd == deployment_root
    assert fake_external.prepare_calls == [("mxm-security", "mxm")]
    assert fake_external.playbook_calls == [
        (
            "ansible-playbook",
            "--inventory",
            str(deployment.inventory),
            "--limit",
            "security",
            "--user",
            "mxm",
            str(deployment.playbook),
            "--check",
            "--diff",
        )
    ]


def test_apply_uses_estate_target_without_check_mode(
    deployment_root: Path,
    fake_external: _FakeExternal,
) -> None:
    """Apply to the inventory host without predictive check-mode flags."""
    deployment = sut.apply_ansible(root=deployment_root)

    assert fake_external.prepare_calls == [("mxm-security", "mxm")]
    assert fake_external.playbook_calls == [
        (
            "ansible-playbook",
            "--inventory",
            str(deployment.inventory),
            "--limit",
            "security",
            "--user",
            "mxm",
            str(deployment.playbook),
        )
    ]


def test_inventory_alias_can_differ_from_tailscale_name(
    deployment_root: Path,
    fake_external: _FakeExternal,
) -> None:
    """Use ansible_host for Tailscale and the inventory key for --limit."""
    fake_external.inventory_data = {
        "_meta": {
            "hostvars": {
                "security-node": {
                    "ansible_host": "security.tail.example.ts.net",
                    "ansible_user": "operator",
                }
            }
        }
    }

    sut.plan_ansible(root=deployment_root)

    assert fake_external.prepare_calls == [("security.tail.example.ts.net", "operator")]
    assert "security-node" in fake_external.playbook_calls[0]
    assert "operator" in fake_external.playbook_calls[0]


@pytest.mark.parametrize("name", ["inventory.yml", "playbook.yml"])
def test_missing_deployment_file_fails_before_remote_access(
    deployment_root: Path,
    fake_external: _FakeExternal,
    name: str,
) -> None:
    """Reject an incomplete estate root without launching inventory or SSH."""
    (deployment_root / name).unlink()

    with pytest.raises(sut.AnsibleError, match=name):
        sut.plan_ansible(root=deployment_root)

    assert fake_external.inventory_calls == []
    assert fake_external.prepare_calls == []


def test_missing_root_is_rejected(tmp_path: Path) -> None:
    """Require an existing estate deployment directory."""
    with pytest.raises(sut.AnsibleError, match="root"):
        sut.plan_ansible(root=tmp_path / "missing")


def test_symlinked_root_is_rejected(
    deployment_root: Path,
    tmp_path: Path,
) -> None:
    """Refuse deployment-root symlinks instead of following them."""
    link = tmp_path / "l2-link"
    link.symlink_to(deployment_root, target_is_directory=True)

    with pytest.raises(sut.AnsibleError, match="symbolic link"):
        sut.plan_ansible(root=link)


def test_symlinked_playbook_is_rejected(
    deployment_root: Path,
    fake_external: _FakeExternal,
) -> None:
    """Reject a symlinked playbook before any remote operation."""
    playbook = deployment_root / "playbook.yml"
    real_playbook = deployment_root / "real-playbook.yml"
    playbook.rename(real_playbook)
    playbook.symlink_to(real_playbook)

    with pytest.raises(sut.AnsibleError, match="symbolic link"):
        sut.plan_ansible(root=deployment_root)

    assert fake_external.inventory_calls == []


@pytest.mark.parametrize(
    "hostvars",
    [
        {},
        {
            "security-a": {"ansible_host": "security-a", "ansible_user": "mxm"},
            "security-b": {"ansible_host": "security-b", "ansible_user": "mxm"},
        },
    ],
)
def test_requires_exactly_one_inventory_target(
    deployment_root: Path,
    fake_external: _FakeExternal,
    hostvars: dict[str, object],
) -> None:
    """Reject zero or multiple managed machines in this initial adapter."""
    fake_external.inventory_data = {"_meta": {"hostvars": hostvars}}

    with pytest.raises(sut.AnsibleError, match="exactly one"):
        sut.plan_ansible(root=deployment_root)

    assert fake_external.prepare_calls == []
    assert fake_external.playbook_calls == []


@pytest.mark.parametrize(
    "hostvars",
    [
        {"ansible_user": "mxm"},
        {"ansible_host": ""},
        {"ansible_host": 1},
        {"ansible_host": "mxm-security"},
        {"ansible_host": "mxm-security", "ansible_user": ""},
        {"ansible_host": "mxm-security", "ansible_user": 1},
    ],
)
def test_requires_explicit_valid_host_and_user(
    deployment_root: Path,
    fake_external: _FakeExternal,
    hostvars: dict[str, object],
) -> None:
    """Never substitute an implicit remote user or SSH destination."""
    fake_external.inventory_data = {"_meta": {"hostvars": {"security": hostvars}}}

    with pytest.raises(sut.AnsibleError, match=r"ansible_host|ansible_user"):
        sut.plan_ansible(root=deployment_root)

    assert fake_external.prepare_calls == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"ansible_connection": "local"},
        {"ansible_connection": "paramiko"},
        {"ansible_connection": 42},
        {"ansible_ssh_common_args": "-o StrictHostKeyChecking=no"},
        {"ansible_ssh_executable": "/tmp/ssh"},
        {"ansible_ssh_private_key_file": "/tmp/key"},
        {"ansible_password": "not-allowed"},
        {"ansible_port": 2222},
    ],
)
def test_inventory_cannot_override_verified_transport(
    deployment_root: Path,
    fake_external: _FakeExternal,
    overrides: dict[str, object],
) -> None:
    """Reject inventory declarations that can replace the SSH transport."""
    variables: dict[str, object] = {
        "ansible_host": "mxm-security",
        "ansible_user": "mxm",
        **overrides,
    }
    fake_external.inventory_data = {"_meta": {"hostvars": {"security": variables}}}

    with pytest.raises(sut.AnsibleError, match=r"SSH|transport|connection"):
        sut.plan_ansible(root=deployment_root)

    assert fake_external.prepare_calls == []


@pytest.mark.parametrize("connection", ["ssh", "ansible.builtin.ssh"])
def test_explicit_builtin_ssh_plugin_is_allowed(
    deployment_root: Path,
    fake_external: _FakeExternal,
    connection: str,
) -> None:
    """Accept only the standard SSH connection plugin when explicitly set."""
    fake_external.inventory_data = {
        "_meta": {
            "hostvars": {
                "security": {
                    "ansible_host": "mxm-security",
                    "ansible_user": "mxm",
                    "ansible_connection": connection,
                }
            }
        }
    }

    sut.plan_ansible(root=deployment_root)

    assert fake_external.prepare_calls == [("mxm-security", "mxm")]


@pytest.mark.parametrize(
    ("inventory_json", "returncode", "message"),
    [
        ("{}", 1, "inventory failed"),
        ("not-json", 0, "Invalid Ansible inventory JSON"),
        ("[]", 0, "not a JSON object"),
        ("{}", 0, "host-variable metadata"),
        ('{"_meta": {}}', 0, "host-variable mapping"),
    ],
)
def test_bad_inventory_output_fails_before_ssh(
    deployment_root: Path,
    fake_external: _FakeExternal,
    inventory_json: str,
    returncode: int,
    message: str,
) -> None:
    """Reject inventory parser failure, malformed JSON, or invalid schema."""
    fake_external.inventory_output = inventory_json
    fake_external.inventory_returncode = returncode

    with pytest.raises(sut.AnsibleError, match=message):
        sut.plan_ansible(root=deployment_root)

    assert fake_external.prepare_calls == []


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("ansible-inventory not found"),
        subprocess.TimeoutExpired(cmd="ansible-inventory", timeout=30),
    ],
)
def test_inventory_launch_errors_are_reported(
    deployment_root: Path,
    fake_external: _FakeExternal,
    error: OSError | subprocess.TimeoutExpired,
) -> None:
    """Translate a missing or timed-out inventory executable to AnsibleError."""
    fake_external.inventory_exception = error

    with pytest.raises(sut.AnsibleError, match="Unable to run Ansible inventory"):
        sut.plan_ansible(root=deployment_root)

    assert fake_external.prepare_calls == []


def test_tailscale_preflight_failure_blocks_playbook(
    deployment_root: Path,
    fake_external: _FakeExternal,
) -> None:
    """Never execute a playbook when Tailscale SSH preflight fails."""
    fake_external.connection_failure = True

    with pytest.raises(sut.AnsibleError, match="Tailscale SSH denied access"):
        sut.apply_ansible(root=deployment_root)

    assert fake_external.playbook_calls == []


@pytest.mark.parametrize("mode", ["plan", "apply"])
def test_nonzero_playbook_status_is_reported(
    deployment_root: Path,
    fake_external: _FakeExternal,
    mode: str,
) -> None:
    """Report the failing Ansible exit status for both control operations."""
    fake_external.playbook_returncode = 4

    with pytest.raises(sut.AnsibleError, match="exit status 4"):
        if mode == "plan":
            sut.plan_ansible(root=deployment_root)
        else:
            sut.apply_ansible(root=deployment_root)


def test_playbook_launch_error_is_reported(
    deployment_root: Path,
    fake_external: _FakeExternal,
) -> None:
    """Translate a Tailscale adapter execution failure to AnsibleError."""
    fake_external.execution_failure = True

    with pytest.raises(sut.AnsibleError, match="Unable to launch Ansible"):
        sut.apply_ansible(root=deployment_root)
