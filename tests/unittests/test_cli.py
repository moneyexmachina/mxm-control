"""Unit tests for the MXM estate-control command-line interface.

Verify command registration, argument forwarding, result reporting, and error
handling for infrastructure provisioning, machine bootstrap, GitHub policy,
and operator authentication.

External operations are replaced with controlled test implementations.
"""

from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mxm.control import cli, operator
from mxm.control.ansible import AnsibleDeployment, AnsibleError
from mxm.control.cli import app
from mxm.control.github.actions_policy import (
    ActionsPolicyError,
    ActionsPolicyPlan,
    PlanAction,
)
from mxm.control.github.api import JsonObject
from mxm.control.machine_bootstrap import MachineBootstrapError
from mxm.control.openbao.api import OpenBaoError
from mxm.control.openbao.restore import (
    OpenBaoRecoveryInterruptedError,
    OpenBaoRecoveryResult,
    OpenBaoRestorePlan,
    OpenBaoRestoreResult,
)
from mxm.control.openbao.status import OpenBaoStatus
from mxm.control.openbao.unseal import OpenBaoUnsealResult
from mxm.control.opentofu import OpenTofuCheckResult, OpenTofuError
from mxm.control.service import RegisteredService, ServiceError, ServiceTarget
from mxm.control.snapshot import SnapshotError

runner = CliRunner()


# ---------------------------------------------------------------------------
# Command registration
# ---------------------------------------------------------------------------


def test_help_exposes_control_operations() -> None:
    """Expose planning, preflight, application, and checking commands."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "plan" in result.stdout
    assert "preflight" in result.stdout
    assert "apply" in result.stdout
    assert "check" in result.stdout


def test_plan_help_exposes_opentofu_and_machine_bootstrap() -> None:
    """Expose OpenTofu and machine-bootstrap planning capabilities."""
    result = runner.invoke(app, ["plan", "--help"])

    assert result.exit_code == 0
    assert "opentofu" in result.stdout
    assert "machine-bootstrap" in result.stdout


def test_preflight_help_exposes_commands() -> None:
    """Expose machine-bootstrap and Ansible SSH preflight capabilities."""
    result = runner.invoke(app, ["preflight", "--help"])

    assert result.exit_code == 0
    assert "machine-bootstrap" in result.stdout
    assert "ansible-ssh" in result.stdout


def test_check_help_exposes_ansible() -> None:
    """Expose the Ansible configuration preview command."""
    result = runner.invoke(app, ["check", "--help"])

    assert result.exit_code == 0
    assert "ansible" in result.stdout


def test_apply_help_exposes_ansible() -> None:
    """Expose the Ansible configuration application command."""
    result = runner.invoke(app, ["apply", "--help"])

    assert result.exit_code == 0
    assert "ansible" in result.stdout


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


def test_plan_opentofu_reports_saved_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Forward OpenTofu root and policy arguments and report the saved plan."""
    root = tmp_path / "root"
    root.mkdir()
    plan = tmp_path / "reviewed.plan"
    observed: dict[str, Path] = {}

    def fake_plan_opentofu(
        root: Path,
        environment_policy: Path,
        plan: Path,
    ) -> Path:
        """Record the arguments supplied to OpenTofu planning."""
        observed["root"] = root
        observed["environment_policy"] = environment_policy
        observed["plan"] = plan
        return plan.resolve()

    monkeypatch.setattr(
        "mxm.control.cli.plan_opentofu",
        fake_plan_opentofu,
    )

    result = runner.invoke(
        app,
        [
            "plan",
            "opentofu",
            "--root",
            str(root),
            "--out",
            str(plan),
            "--environment-policy",
            str(environment_policy),
        ],
    )

    assert result.exit_code == 0
    assert observed == {
        "root": root,
        "environment_policy": environment_policy,
        "plan": plan,
    }
    assert "OK" in result.stdout
    assert str(plan.resolve()) in result.stdout


def test_plan_machine_bootstrap_reports_saved_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Forward machine-bootstrap arguments and report the saved plan."""
    root = tmp_path / "root"
    root.mkdir()
    plan = tmp_path / "machine-bootstrap.plan"
    observed: dict[str, Path] = {}

    def fake_plan_machine_bootstrap(
        root: Path,
        environment_policy: Path,
        plan: Path,
    ) -> Path:
        """Record the arguments supplied to machine-bootstrap planning."""
        observed["root"] = root
        observed["environment_policy"] = environment_policy
        observed["plan"] = plan
        return plan.resolve()

    monkeypatch.setattr(
        "mxm.control.cli.plan_machine_bootstrap",
        fake_plan_machine_bootstrap,
    )

    result = runner.invoke(
        app,
        [
            "plan",
            "machine-bootstrap",
            "--root",
            str(root),
            "--out",
            str(plan),
            "--environment-policy",
            str(environment_policy),
        ],
    )

    assert result.exit_code == 0
    assert observed == {
        "root": root,
        "environment_policy": environment_policy,
        "plan": plan,
    }
    assert "OK" in result.stdout
    assert str(plan.resolve()) in result.stdout


def test_plan_machine_bootstrap_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Report machine-bootstrap planning failures without claiming success."""
    root = tmp_path / "root"
    root.mkdir()
    plan = tmp_path / "machine-bootstrap.plan"

    def fail(
        root: Path,
        environment_policy: Path,
        plan: Path,
    ) -> Path:
        """Represent an unsuccessful machine-bootstrap planning operation."""
        raise MachineBootstrapError("Machine-bootstrap plan failed")

    monkeypatch.setattr(
        "mxm.control.cli.plan_machine_bootstrap",
        fail,
    )

    result = runner.invoke(
        app,
        [
            "plan",
            "machine-bootstrap",
            "--root",
            str(root),
            "--out",
            str(plan),
            "--environment-policy",
            str(environment_policy),
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: Machine-bootstrap plan failed" in result.output
    assert "OK" not in result.output


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
def test_preflight_ansible_ssh_forwards_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forward the selected Tailscale host and user to the SSH preflight."""
    observed: dict[str, str] = {}

    def fake_preflight(
        *,
        host: str,
        user: str,
    ) -> None:
        """Record preflight arguments without contacting Tailscale."""
        observed["host"] = host
        observed["user"] = user

    monkeypatch.setattr(
        cli,
        "check_ansible_ssh",
        fake_preflight,
    )

    result = runner.invoke(
        app,
        [
            "preflight",
            "ansible-ssh",
            "--host",
            "mxm-security",
            "--user",
            "operator",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == {
        "host": "mxm-security",
        "user": "operator",
    }
    assert "OK" in result.output
    assert "Ansible Tailscale SSH: operator@mxm-security" in result.output


def test_preflight_ansible_ssh_defaults_to_mxm_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the default MXM operator account when no user is specified."""
    observed: dict[str, str] = {}

    def fake_preflight(
        *,
        host: str,
        user: str,
    ) -> None:
        """Record the effective Tailscale SSH identity."""
        observed["host"] = host
        observed["user"] = user

    monkeypatch.setattr(
        cli,
        "check_ansible_ssh",
        fake_preflight,
    )

    result = runner.invoke(
        app,
        [
            "preflight",
            "ansible-ssh",
            "--host",
            "mxm-security",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == {
        "host": "mxm-security",
        "user": "mxm",
    }
    assert "Ansible Tailscale SSH: mxm@mxm-security" in result.output


def test_preflight_ansible_ssh_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report Tailscale SSH failures without claiming successful access."""

    def fake_preflight(
        *,
        host: str,
        user: str,
    ) -> None:
        """Simulate an unsuccessful Tailscale SSH preflight."""
        raise cli.TailscaleAnsibleError("No verified SSH host key found")

    monkeypatch.setattr(
        cli,
        "check_ansible_ssh",
        fake_preflight,
    )

    result = runner.invoke(
        app,
        [
            "preflight",
            "ansible-ssh",
            "--host",
            "mxm-security",
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: No verified SSH host key found" in result.output
    assert "OK" not in result.output


def test_preflight_machine_bootstrap_forwards_arguments(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Forward the saved plan to the read-only bootstrap preflight."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "machine-bootstrap.plan"
    plan.write_bytes(b"saved plan")

    observed: dict[str, Path] = {}

    def fake_preflight(
        root: Path,
        environment_policy: Path,
        plan: Path,
    ) -> Path:
        """Record preflight parameters without contacting external services."""
        observed["root"] = root
        observed["environment_policy"] = environment_policy
        observed["plan"] = plan
        return plan

    monkeypatch.setattr(
        cli,
        "preflight_machine_bootstrap_credentials",
        fake_preflight,
    )

    result = runner.invoke(
        app,
        [
            "preflight",
            "machine-bootstrap",
            "--root",
            str(root),
            "--environment-policy",
            str(environment_policy),
            "--plan",
            str(plan),
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == {
        "root": root,
        "environment_policy": environment_policy,
        "plan": plan,
    }


def test_preflight_machine_bootstrap_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Report a failed preflight without claiming success."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "machine-bootstrap.plan"
    plan.write_bytes(b"saved plan")

    def fake_preflight(
        root: Path,
        environment_policy: Path,
        plan: Path,
    ) -> Path:
        """Simulate unsuccessful Tailscale device discovery."""
        raise MachineBootstrapError("Tailscale device discovery failed")

    monkeypatch.setattr(
        cli,
        "preflight_machine_bootstrap_credentials",
        fake_preflight,
    )

    result = runner.invoke(
        app,
        [
            "preflight",
            "machine-bootstrap",
            "--root",
            str(root),
            "--environment-policy",
            str(environment_policy),
            "--plan",
            str(plan),
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: Tailscale device discovery failed" in result.output
    assert "OK" not in result.output


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def test_apply_opentofu_routes_existing_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Forward a reviewed saved plan to the OpenTofu application capability."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")

    observed: dict[str, Path] = {}

    def fake_apply(
        root: Path,
        environment_policy: Path,
        plan: Path,
    ) -> Path:
        """Record the arguments supplied to OpenTofu application."""
        observed["root"] = root
        observed["environment_policy"] = environment_policy
        observed["plan"] = plan
        return plan.resolve()

    monkeypatch.setattr(
        "mxm.control.cli.apply_opentofu",
        fake_apply,
    )

    result = runner.invoke(
        app,
        [
            "apply",
            "opentofu",
            "--root",
            str(root),
            "--plan",
            str(plan),
            "--environment-policy",
            str(environment_policy),
        ],
    )

    assert result.exit_code == 0
    assert observed == {
        "root": root,
        "environment_policy": environment_policy,
        "plan": plan,
    }
    assert "OK" in result.stdout


def test_apply_machine_bootstrap_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Forward the authoritative machine-bootstrap inputs to the mechanism."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "machine-bootstrap.tfplan"
    plan.write_bytes(b"saved plan")

    observed: dict[str, Path] = {}

    def fake_apply_machine_bootstrap(
        root: Path,
        environment_policy: Path,
        plan: Path,
    ) -> Path:
        """Record the request without modifying infrastructure."""
        observed["root"] = root
        observed["environment_policy"] = environment_policy
        observed["plan"] = plan
        return plan

    monkeypatch.setattr(
        cli,
        "apply_machine_bootstrap",
        fake_apply_machine_bootstrap,
    )

    result = runner.invoke(
        app,
        [
            "apply",
            "machine-bootstrap",
            "--root",
            str(root),
            "--environment-policy",
            str(environment_policy),
            "--plan",
            str(plan),
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == {
        "root": root,
        "environment_policy": environment_policy,
        "plan": plan,
    }
    assert "OK" in result.output
    assert str(plan) in result.output


def test_apply_machine_bootstrap_command_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Report a machine-bootstrap failure with exit status one."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "machine-bootstrap.tfplan"
    plan.write_bytes(b"saved plan")

    def fake_apply_machine_bootstrap(
        root: Path,
        environment_policy: Path,
        plan: Path,
    ) -> Path:
        """Simulate a failed machine replacement."""
        raise MachineBootstrapError("Tailscale retirement failed")

    monkeypatch.setattr(
        cli,
        "apply_machine_bootstrap",
        fake_apply_machine_bootstrap,
    )

    result = runner.invoke(
        app,
        [
            "apply",
            "machine-bootstrap",
            "--root",
            str(root),
            "--environment-policy",
            str(environment_policy),
            "--plan",
            str(plan),
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: Tailscale retirement failed" in result.output
    assert "Machine bootstrap completed" not in result.output


def test_apply_github_actions_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Report successful GitHub Actions policy reconciliation."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{}")

    desired: JsonObject = {
        "name": "mxm-actions",
        "enforcement": "active",
        "rules": [],
    }

    def fake_apply(
        api: object,
        organization: str,
        policy_path: Path,
    ) -> ActionsPolicyPlan:
        """Return a successfully reconciled GitHub Actions policy."""
        return ActionsPolicyPlan(
            action=PlanAction.NO_CHANGE,
            name="mxm-actions",
            policy_id=42,
            desired=desired,
            actual=desired,
        )

    monkeypatch.setattr(
        "mxm.control.cli.apply_actions_policy",
        fake_apply,
    )

    result = runner.invoke(
        app,
        [
            "apply",
            "github-actions",
            "--organization",
            "moneyexmachina",
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 0
    assert "OK" in result.stdout
    assert "mxm-actions" in result.stdout


def test_apply_github_actions_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Report GitHub Actions reconciliation errors without claiming success."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{}")

    def fake_apply(
        api: object,
        organization: str,
        policy_path: Path,
    ) -> ActionsPolicyPlan:
        """Represent an unsuccessful GitHub Actions policy reconciliation."""
        raise ActionsPolicyError("policy did not converge")

    monkeypatch.setattr(
        "mxm.control.cli.apply_actions_policy",
        fake_apply,
    )

    result = runner.invoke(
        app,
        [
            "apply",
            "github-actions",
            "--organization",
            "moneyexmachina",
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: policy did not converge" in result.output


def test_apply_ansible_forwards_deployment_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Forward the estate root and report successful Ansible application."""
    root = tmp_path / "l2"
    root.mkdir()
    observed: list[Path] = []

    def fake_apply_ansible(*, root: Path) -> AnsibleDeployment:
        """Record the deployment root without executing Ansible."""
        observed.append(root)
        return AnsibleDeployment(
            root=root.resolve(),
            inventory=root / "inventory.yml",
            playbook=root / "playbook.yml",
        )

    monkeypatch.setattr(cli, "apply_ansible", fake_apply_ansible)

    result = runner.invoke(
        app,
        [
            "apply",
            "ansible",
            "--root",
            str(root),
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == [root]
    assert f"OK        Ansible applied: {root.resolve()}" in result.output


def test_apply_ansible_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Report failed Ansible application without claiming success."""
    root = tmp_path / "l2"
    root.mkdir()

    def fake_apply_ansible(*, root: Path) -> AnsibleDeployment:
        """Simulate an unsuccessful Ansible reconciliation."""
        raise AnsibleError("Ansible apply failed with exit status 2")

    monkeypatch.setattr(cli, "apply_ansible", fake_apply_ansible)

    result = runner.invoke(
        app,
        [
            "apply",
            "ansible",
            "--root",
            str(root),
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: Ansible apply failed with exit status 2" in result.output
    assert "Ansible applied" not in result.output


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------


def test_check_ansible_forwards_deployment_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Forward the estate root and report a completed Ansible preview."""
    root = tmp_path / "l2"
    root.mkdir()
    observed: list[Path] = []

    def fake_plan_ansible(*, root: Path) -> AnsibleDeployment:
        """Record the deployment root without executing Ansible."""
        observed.append(root)
        return AnsibleDeployment(
            root=root.resolve(),
            inventory=root / "inventory.yml",
            playbook=root / "playbook.yml",
        )

    monkeypatch.setattr(cli, "plan_ansible", fake_plan_ansible)

    result = runner.invoke(
        app,
        [
            "check",
            "ansible",
            "--root",
            str(root),
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == [root]
    assert f"PREVIEW   Ansible check completed: {root.resolve()}" in result.output


def test_check_ansible_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Report a failed Ansible preview without claiming completion."""
    root = tmp_path / "l2"
    root.mkdir()

    def fake_plan_ansible(*, root: Path) -> AnsibleDeployment:
        """Simulate an unsuccessful Ansible check-mode execution."""
        raise AnsibleError("Ansible preview failed with exit status 4")

    monkeypatch.setattr(cli, "plan_ansible", fake_plan_ansible)

    result = runner.invoke(
        app,
        [
            "check",
            "ansible",
            "--root",
            str(root),
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: Ansible preview failed with exit status 4" in result.output
    assert "PREVIEW" not in result.output
    assert "Ansible check completed" not in result.output


def test_check_opentofu_reports_drift_with_distinct_exit_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Return exit status two when OpenTofu identifies configuration drift."""
    root = tmp_path / "root"
    root.mkdir()

    def fake_check_opentofu(
        root: Path,
        environment_policy: Path,
    ) -> OpenTofuCheckResult:
        """Return a detected infrastructure difference."""
        _ = (root, environment_policy)
        return OpenTofuCheckResult.DRIFT

    monkeypatch.setattr(
        "mxm.control.cli.check_opentofu",
        fake_check_opentofu,
    )

    result = runner.invoke(
        app,
        [
            "check",
            "opentofu",
            "--root",
            str(root),
            "--environment-policy",
            str(environment_policy),
        ],
    )

    assert result.exit_code == 2
    assert "DRIFT" in result.output


def test_check_opentofu_reports_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Distinguish OpenTofu execution failures from detected drift."""
    root = tmp_path / "root"
    root.mkdir()

    def fail(
        root: Path,
        environment_policy: Path,
    ) -> OpenTofuCheckResult:
        """Represent an unsuccessful OpenTofu check."""
        raise OpenTofuError("OpenTofu check failed with exit status 1")

    monkeypatch.setattr(
        "mxm.control.cli.check_opentofu",
        fail,
    )

    result = runner.invoke(
        app,
        [
            "check",
            "opentofu",
            "--root",
            str(root),
            "--environment-policy",
            str(environment_policy),
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: OpenTofu check failed with exit status 1" in result.output


def test_check_github_actions_succeeds_when_policy_matches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Report success when the GitHub Actions policy matches its declaration."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{}")

    desired: JsonObject = {
        "name": "mxm-actions",
        "enforcement": "active",
        "rules": [],
    }

    def fake_plan(
        api: object,
        organization: str,
        policy_path: Path,
    ) -> ActionsPolicyPlan:
        """Return a matching GitHub Actions policy."""
        return ActionsPolicyPlan(
            action=PlanAction.NO_CHANGE,
            name="mxm-actions",
            policy_id=42,
            desired=desired,
            actual=desired,
        )

    monkeypatch.setattr(
        "mxm.control.cli.plan_actions_policy",
        fake_plan,
    )

    result = runner.invoke(
        app,
        [
            "check",
            "github-actions",
            "--organization",
            "moneyexmachina",
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 0
    assert "OK" in result.stdout
    assert "mxm-actions" in result.stdout


def test_check_github_actions_fails_when_policy_has_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Report drift when the GitHub Actions policy differs from its declaration."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{}")

    desired: JsonObject = {
        "name": "mxm-actions",
        "enforcement": "active",
        "rules": [],
    }

    actual: JsonObject = {
        "name": "mxm-actions",
        "enforcement": "disabled",
        "rules": [],
    }

    def fake_plan(
        api: object,
        organization: str,
        policy_path: Path,
    ) -> ActionsPolicyPlan:
        """Return a GitHub Actions policy requiring reconciliation."""
        return ActionsPolicyPlan(
            action=PlanAction.UPDATE,
            name="mxm-actions",
            policy_id=42,
            desired=desired,
            actual=actual,
        )

    monkeypatch.setattr(
        "mxm.control.cli.plan_actions_policy",
        fake_plan,
    )

    result = runner.invoke(
        app,
        [
            "check",
            "github-actions",
            "--organization",
            "moneyexmachina",
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 1
    assert "DRIFT" in result.output
    assert "UPDATE" in result.output
    assert "mxm-actions" in result.output


# ---------------------------------------------------------------------------
# Operator authentication
# ---------------------------------------------------------------------------


def test_login_reuses_or_establishes_operator_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delegate operator authentication to the operator module."""
    calls: list[str] = []

    def fake_login() -> None:
        """Record a request to establish operator authentication."""
        calls.append("login")

    monkeypatch.setattr(
        "mxm.control.cli.operator.login",
        fake_login,
    )

    result = runner.invoke(app, ["login"])

    assert result.exit_code == 0
    assert calls == ["login"]
    assert "Proton Pass session available" in result.stdout


def test_login_reports_authentication_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report unsuccessful operator authentication."""

    def fake_login() -> None:
        """Represent an unsuccessful Proton Pass login."""
        raise operator.OperatorError("Proton Pass login failed")

    monkeypatch.setattr(
        "mxm.control.cli.operator.login",
        fake_login,
    )

    result = runner.invoke(app, ["login"])

    assert result.exit_code == 1
    assert "ERROR: Proton Pass login failed" in result.output


def test_status_reports_both_authenticated_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report available Proton Pass and GitHub operator sessions."""

    def fake_status() -> operator.OperatorStatus:
        """Return two authenticated operator backends."""
        return operator.OperatorStatus(proton_pass=True, github=True)

    monkeypatch.setattr(
        operator,
        "operator_status",
        fake_status,
    )

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0
    assert "OK                Proton Pass" in result.stdout
    assert "OK                GitHub CLI" in result.stdout


def test_status_reports_partial_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identify unavailable operator backends and return a failure status."""

    def fake_status() -> operator.OperatorStatus:
        """Return a partially authenticated operator environment."""
        return operator.OperatorStatus(proton_pass=True, github=False)

    monkeypatch.setattr(
        operator,
        "operator_status",
        fake_status,
    )

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 1
    assert "OK                Proton Pass" in result.output
    assert "UNAUTHENTICATED" in result.output
    assert "GitHub CLI" in result.output


def test_logout_terminates_operator_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delegate operator session termination to the operator module."""
    calls: list[str] = []

    def fake_logout() -> None:
        """Record a request to terminate the operator session."""
        calls.append("logout")

    monkeypatch.setattr(
        "mxm.control.cli.operator.logout",
        fake_logout,
    )

    result = runner.invoke(app, ["logout"])

    assert result.exit_code == 0
    assert calls == ["logout"]
    assert "Proton Pass session terminated" in result.stdout


def test_logout_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report unsuccessful operator session termination."""

    def fake_logout() -> None:
        """Represent an unsuccessful Proton Pass logout."""
        raise operator.OperatorError("Proton Pass logout failed")

    monkeypatch.setattr(
        "mxm.control.cli.operator.logout",
        fake_logout,
    )

    result = runner.invoke(app, ["logout"])

    assert result.exit_code == 1
    assert "ERROR: Proton Pass logout failed" in result.output


# ---------------------------------------------------------------------------
# OpenBao operator operations
# ---------------------------------------------------------------------------


OPENBAO_ADDRESS = "https://openbao.tail546174.ts.net"
OPENBAO_MACHINE = "mxm-security.tail546174.ts.net"


def _openbao_target() -> ServiceTarget:
    """Return a synthetic resolved OpenBao service."""
    return ServiceTarget(
        name="openbao",
        address=OPENBAO_ADDRESS,
        machine=OPENBAO_MACHINE,
        user="mxm",
        unit="openbao.service",
    )


def _mock_estate_root(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
) -> None:
    """Replace the workstation estate-checkout convention."""

    def fake_estate_root() -> Path:
        return root

    monkeypatch.setattr(cli, "_estate_root", fake_estate_root)


def _mock_openbao_resolution(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
) -> list[tuple[Path, str]]:
    """Replace estate service resolution and record its arguments."""
    calls: list[tuple[Path, str]] = []
    _mock_estate_root(monkeypatch, root)

    def fake_resolve(
        *,
        estate_root: Path,
        name: str,
    ) -> RegisteredService:
        calls.append((estate_root, name))
        return RegisteredService(target=_openbao_target(), credentials=None)

    monkeypatch.setattr(cli, "resolve_service", fake_resolve)
    return calls


def _openbao_status(
    *,
    initialized: bool = True,
    sealed: bool = True,
    shares: int = 3,
    threshold: int = 2,
    progress: int = 0,
) -> OpenBaoStatus:
    """Construct a representative OpenBao seal-status response."""
    return OpenBaoStatus(
        initialized=initialized,
        sealed=sealed,
        version="2.6.5",
        seal_type="shamir",
        shares=shares,
        threshold=threshold,
        progress=progress,
    )


def _openbao_command(command: str) -> list[str]:
    """Build an estate-backed OpenBao CLI invocation."""
    return ["openbao", command]


# ---------------------------------------------------------------------------
# Command registration
# ---------------------------------------------------------------------------


def test_openbao_help_exposes_status_and_unseal() -> None:
    """Expose OpenBao lifecycle operations as a separate command group."""
    result = runner.invoke(app, ["openbao", "--help"])

    assert result.exit_code == 0, result.output
    assert "status" in result.output
    assert "unseal" in result.output
    assert "restore" in result.output


@pytest.mark.parametrize("command", ["status", "unseal", "restore"])
def test_openbao_command_help_uses_automatic_estate_resolution(
    command: str,
) -> None:
    """Operator commands neither require deployment roots nor raw addresses."""
    result = runner.invoke(app, ["openbao", command, "--help"])

    assert result.exit_code == 0, result.output
    assert "--root" not in result.output
    assert "--address" not in result.output


# ---------------------------------------------------------------------------
# OpenBao status
# ---------------------------------------------------------------------------


def test_openbao_status_reports_initialized_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Resolve the service and display its current Shamir state."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    resolution_calls = _mock_openbao_resolution(
        monkeypatch,
        root,
    )
    status_calls: list[str] = []

    def fake_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> OpenBaoStatus:
        status_calls.append(address)
        return _openbao_status(progress=1)

    monkeypatch.setattr(cli, "status_openbao", fake_status)

    result = runner.invoke(
        app,
        _openbao_command("status"),
    )

    assert result.exit_code == 0, result.output
    assert resolution_calls == [(root, "openbao")]
    assert status_calls == [OPENBAO_ADDRESS]

    assert "Service" in result.output
    assert "openbao" in result.output
    assert OPENBAO_ADDRESS in result.output
    assert OPENBAO_MACHINE in result.output
    assert "2.6.5" in result.output
    assert "Initialized  True" in result.output
    assert "Sealed       True" in result.output
    assert "Seal type    shamir" in result.output
    assert "Shares       3" in result.output
    assert "Threshold    2" in result.output
    assert "Progress     1/2" in result.output


def test_openbao_status_reports_uninitialized_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not display Shamir share requirements before initialization."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    _mock_openbao_resolution(monkeypatch, root)

    def fake_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> OpenBaoStatus:
        return _openbao_status(
            initialized=False,
            sealed=True,
            shares=0,
            threshold=0,
        )

    monkeypatch.setattr(cli, "status_openbao", fake_status)

    result = runner.invoke(
        app,
        _openbao_command("status"),
    )

    assert result.exit_code == 0, result.output
    assert "Initialized  False" in result.output
    assert "Sealed       True" in result.output
    assert "Shares" not in result.output
    assert "Threshold" not in result.output
    assert "Progress" not in result.output


def test_openbao_status_reports_service_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A failed estate lookup must not contact OpenBao."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    _mock_estate_root(monkeypatch, root)

    def failing_resolve(
        *,
        estate_root: Path,
        name: str,
    ) -> RegisteredService:
        raise ServiceError("OpenBao service not found")

    def forbidden_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> OpenBaoStatus:
        pytest.fail("OpenBao API must not be called")

    monkeypatch.setattr(cli, "resolve_service", failing_resolve)
    monkeypatch.setattr(cli, "status_openbao", forbidden_status)

    result = runner.invoke(
        app,
        _openbao_command("status"),
    )

    assert result.exit_code == 1
    assert "ERROR: OpenBao service not found" in result.output


def test_openbao_status_reports_api_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Report API failures without claiming successful inspection."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    _mock_openbao_resolution(monkeypatch, root)

    def failing_status(
        address: str,
        *,
        timeout: float = 10.0,
    ) -> OpenBaoStatus:
        raise OpenBaoError("OpenBao status unavailable")

    monkeypatch.setattr(cli, "status_openbao", failing_status)

    result = runner.invoke(
        app,
        _openbao_command("status"),
    )

    assert result.exit_code == 1
    assert "ERROR: OpenBao status unavailable" in result.output
    assert "Initialized" not in result.output


# ---------------------------------------------------------------------------
# OpenBao unseal
# ---------------------------------------------------------------------------


def test_openbao_unseal_submits_physical_shares(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Delegate share collection and unsealing to existing capabilities."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    resolution_calls = _mock_openbao_resolution(
        monkeypatch,
        root,
    )

    shares = {
        1: "synthetic-share-one",
        2: "synthetic-share-two",
    }

    prompts: list[str] = []
    submissions: list[str] = []
    addresses: list[str] = []

    def fake_prompt(
        label: str,
        expected_length: int | None = None,
    ) -> str:
        prompts.append(label)
        number = len(prompts)
        return shares[number]

    def fake_unseal(
        address: str,
        *,
        get_share: Callable[[int, int], str],
        timeout: float = 10.0,
    ) -> OpenBaoUnsealResult:
        addresses.append(address)

        submissions.append(get_share(1, 2))
        submissions.append(get_share(2, 2))

        return OpenBaoUnsealResult(
            sealed=False,
            progress=0,
            threshold=2,
            shares=3,
        )

    monkeypatch.setattr(cli, "prompt_secret", fake_prompt)
    monkeypatch.setattr(cli, "unseal_openbao", fake_unseal)

    result = runner.invoke(
        app,
        _openbao_command("unseal"),
    )

    assert result.exit_code == 0, result.output
    assert resolution_calls == [(root, "openbao")]
    assert addresses == [OPENBAO_ADDRESS]

    assert prompts == [
        "Unseal share 1 of 2",
        "Unseal share 2 of 2",
    ]
    assert submissions == [
        "synthetic-share-one",
        "synthetic-share-two",
    ]

    assert "OK" in result.output
    assert "OpenBao unsealed" in result.output

    for share in shares.values():
        assert share not in result.output


def test_openbao_unseal_already_unsealed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not request shares if the underlying capability needs none."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    _mock_openbao_resolution(monkeypatch, root)

    def forbidden_prompt(
        label: str,
        expected_length: int | None = None,
    ) -> str:
        pytest.fail("No physical share should be requested")

    def fake_unseal(
        address: str,
        *,
        get_share: Callable[[int, int], str],
        timeout: float = 10.0,
    ) -> OpenBaoUnsealResult:
        return OpenBaoUnsealResult(
            sealed=False,
            progress=0,
            threshold=2,
            shares=3,
        )

    monkeypatch.setattr(cli, "prompt_secret", forbidden_prompt)
    monkeypatch.setattr(cli, "unseal_openbao", fake_unseal)

    result = runner.invoke(
        app,
        _openbao_command("unseal"),
    )

    assert result.exit_code == 0, result.output
    assert "OpenBao unsealed" in result.output


def test_openbao_unseal_reports_incomplete_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A still-sealed authority must not produce a success result."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    _mock_openbao_resolution(monkeypatch, root)

    def fake_unseal(
        address: str,
        *,
        get_share: Callable[[int, int], str],
        timeout: float = 10.0,
    ) -> OpenBaoUnsealResult:
        return OpenBaoUnsealResult(
            sealed=True,
            progress=1,
            threshold=2,
            shares=3,
        )

    monkeypatch.setattr(cli, "unseal_openbao", fake_unseal)

    result = runner.invoke(
        app,
        _openbao_command("unseal"),
    )

    assert result.exit_code == 1
    assert "INCOMPLETE" in result.output
    assert "1/2" in result.output
    assert "OpenBao unsealed" not in result.output


def test_openbao_unseal_handles_operator_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Cancellation stops unsealing with the conventional exit code 130."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    _mock_openbao_resolution(monkeypatch, root)

    def cancelled_prompt(
        label: str,
        expected_length: int | None = None,
    ) -> str:
        raise cli.SecretEntryCancelled()

    def fake_unseal(
        address: str,
        *,
        get_share: Callable[[int, int], str],
        timeout: float = 10.0,
    ) -> OpenBaoUnsealResult:
        get_share(1, 2)
        pytest.fail("Cancelled share entry must stop unsealing")

    monkeypatch.setattr(cli, "prompt_secret", cancelled_prompt)
    monkeypatch.setattr(cli, "unseal_openbao", fake_unseal)

    result = runner.invoke(
        app,
        _openbao_command("unseal"),
    )

    assert result.exit_code == 130
    assert "CANCELLED" in result.output
    assert "OpenBao unsealed" not in result.output


def test_openbao_unseal_reports_api_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An OpenBao submission failure must not claim successful unseal."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    _mock_openbao_resolution(monkeypatch, root)

    def failing_unseal(
        address: str,
        *,
        get_share: Callable[[int, int], str],
        timeout: float = 10.0,
    ) -> OpenBaoUnsealResult:
        raise OpenBaoError("Unseal submission outcome uncertain")

    monkeypatch.setattr(cli, "unseal_openbao", failing_unseal)

    result = runner.invoke(
        app,
        _openbao_command("unseal"),
    )

    assert result.exit_code == 1
    assert "ERROR: Unseal submission outcome uncertain" in result.output
    assert "OpenBao unsealed" not in result.output


def test_openbao_unseal_reports_service_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Do not request shares when the service cannot be resolved."""
    root = tmp_path / "mxm-estate"
    root.mkdir()

    _mock_estate_root(monkeypatch, root)

    def failing_resolve(
        *,
        estate_root: Path,
        name: str,
    ) -> RegisteredService:
        raise ServiceError("Unable to resolve estate service openbao")

    def forbidden_unseal(
        address: str,
        *,
        get_share: Callable[[int, int], str],
        timeout: float = 10.0,
    ) -> OpenBaoUnsealResult:
        pytest.fail("Unseal must not start without service resolution")

    monkeypatch.setattr(cli, "resolve_service", failing_resolve)
    monkeypatch.setattr(cli, "unseal_openbao", forbidden_unseal)

    result = runner.invoke(
        app,
        _openbao_command("unseal"),
    )

    assert result.exit_code == 1
    assert "ERROR: Unable to resolve estate service openbao" in result.output
    assert "OpenBao unsealed" not in result.output


@pytest.mark.parametrize("command", ["status", "unseal"])
def test_openbao_commands_report_missing_estate_checkout(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    tmp_path: Path,
) -> None:
    """A missing estate checkout is a resolution error, not a CLI argument error."""
    _mock_estate_root(monkeypatch, tmp_path / "missing-estate")

    result = runner.invoke(app, _openbao_command(command))

    assert result.exit_code == 1
    assert "ERROR: Estate root not found" in result.output


# ---------------------------------------------------------------------------
# OpenBao restore
# ---------------------------------------------------------------------------


RESTORE_SHA256 = "a" * 64
RESTORE_SNAPSHOT = "ssh://mxm@monolith/recovery/openbao.snap"


def _openbao_restore_plan() -> OpenBaoRestorePlan:
    """Return a synthetic, fully staged restoration plan."""
    return OpenBaoRestorePlan(
        address=OPENBAO_ADDRESS,
        machine=OPENBAO_MACHINE,
        snapshot_source=RESTORE_SNAPSHOT,
        snapshot_size=51200,
        snapshot_sha256=RESTORE_SHA256,
        expected_shares=3,
        expected_threshold=2,
    )


def _openbao_restore_result() -> OpenBaoRecoveryResult:
    """Return a successful synthetic restoration result."""
    return OpenBaoRecoveryResult(
        restore=OpenBaoRestoreResult(
            sha256=RESTORE_SHA256,
            size=51200,
            forced=True,
        ),
        shares=3,
        threshold=2,
    )


def _openbao_restore_command() -> list[str]:
    """Build a restore command with the operator-selected snapshot URI."""
    return [*_openbao_command("restore"), "--snapshot", RESTORE_SNAPSHOT]


def test_openbao_restore_help_exposes_required_inputs() -> None:
    """Expose snapshot URI without a root or internal checksum arguments."""
    result = runner.invoke(app, ["openbao", "restore", "--help"])

    assert result.exit_code == 0, result.output
    assert "--root" not in result.output
    assert "--snapshot" in result.output
    assert "--sha256" not in result.output
    assert "--address" not in result.output


def test_openbao_restore_authorizes_exact_plan_and_reports_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Forward inputs, display the plan, and require explicit approval."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    _mock_estate_root(monkeypatch, root)
    calls: list[tuple[Path, str]] = []
    approvals: list[bool] = []

    def fake_restore(
        *,
        estate_root: Path,
        snapshot_uri: str,
        authorize: Callable[[OpenBaoRestorePlan], bool],
        expected_shares: int = 3,
        expected_threshold: int = 2,
        timeout: float = 120.0,
    ) -> OpenBaoRecoveryResult:
        calls.append((estate_root, snapshot_uri))
        assert (expected_shares, expected_threshold, timeout) == (3, 2, 120.0)

        approvals.append(authorize(_openbao_restore_plan()))
        if approvals[-1] is not True:
            raise PermissionError("OpenBao restoration was not authorized")
        return _openbao_restore_result()

    monkeypatch.setattr(cli, "restore_openbao", fake_restore)

    result = runner.invoke(
        app,
        _openbao_restore_command(),
        input="RESTORE\n",
    )

    assert result.exit_code == 0, result.output
    assert calls == [(root, RESTORE_SNAPSHOT)]
    assert approvals == [True]
    assert OPENBAO_ADDRESS in result.output
    assert OPENBAO_MACHINE in result.output
    assert RESTORE_SNAPSHOT in result.output
    assert RESTORE_SHA256 in result.output
    assert "51200 bytes" in result.output
    assert "threshold 2" in result.output
    assert "OpenBao authority restored" in result.output
    assert "Initialized and sealed" in result.output
    assert "original physical Shamir shares" in result.output


@pytest.mark.parametrize("answer", ["NO\n", "restore\n", "\n"])
def test_openbao_restore_refuses_without_exact_authorization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    answer: str,
) -> None:
    """Reject any response other than the exact uppercase RESTORE token."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    _mock_estate_root(monkeypatch, root)
    calls: list[str] = []

    def fake_restore(
        *,
        estate_root: Path,
        snapshot_uri: str,
        authorize: Callable[[OpenBaoRestorePlan], bool],
        expected_shares: int = 3,
        expected_threshold: int = 2,
        timeout: float = 120.0,
    ) -> OpenBaoRecoveryResult:
        calls.append("restore")

        if authorize(_openbao_restore_plan()):
            pytest.fail("unauthorized restoration must not proceed")
        raise PermissionError("OpenBao restoration was not authorized")

    monkeypatch.setattr(cli, "restore_openbao", fake_restore)

    result = runner.invoke(
        app,
        _openbao_restore_command(),
        input=answer,
    )

    assert result.exit_code == 1
    assert calls == ["restore"]
    assert "CANCELLED   OpenBao restoration" in result.output
    assert "OpenBao authority restored" not in result.output


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (
            ServiceError("estate service unavailable"),
            "estate service unavailable",
        ),
        (
            SnapshotError("snapshot cannot be read"),
            "snapshot cannot be read",
        ),
        (
            OpenBaoError("destination already initialized"),
            "destination already initialized",
        ),
    ],
)
def test_openbao_restore_reports_capability_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error: Exception,
    message: str,
) -> None:
    """Report delegated capability failures without claiming restoration."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    _mock_estate_root(monkeypatch, root)

    def failing_restore(
        *,
        estate_root: Path,
        snapshot_uri: str,
        authorize: Callable[[OpenBaoRestorePlan], bool],
        expected_shares: int = 3,
        expected_threshold: int = 2,
        timeout: float = 120.0,
    ) -> OpenBaoRecoveryResult:
        raise error

    monkeypatch.setattr(cli, "restore_openbao", failing_restore)

    result = runner.invoke(app, _openbao_restore_command())

    assert result.exit_code == 1
    assert f"ERROR: {message}" in result.output
    assert "OpenBao authority restored" not in result.output


def test_openbao_restore_reports_interruption_and_requires_inspection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Report uncertain recovery state and require inspection before retry."""
    root = tmp_path / "mxm-estate"
    root.mkdir()
    _mock_estate_root(monkeypatch, root)

    def interrupted_restore(
        *,
        estate_root: Path,
        snapshot_uri: str,
        authorize: Callable[[OpenBaoRestorePlan], bool],
        expected_shares: int = 3,
        expected_threshold: int = 2,
        timeout: float = 120.0,
    ) -> OpenBaoRecoveryResult:
        assert authorize(_openbao_restore_plan()) is True
        raise OpenBaoRecoveryInterruptedError("snapshot restoration")

    monkeypatch.setattr(cli, "restore_openbao", interrupted_restore)

    result = runner.invoke(
        app,
        _openbao_restore_command(),
        input="RESTORE\n",
    )

    assert result.exit_code == 1
    assert "INTERRUPTED OpenBao recovery: snapshot restoration" in result.output
    assert "Do not retry without inspecting its state" in result.output
    assert "custody" not in result.output.lower()
    assert "OpenBao authority restored" not in result.output


def test_openbao_restore_reports_missing_estate_checkout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reject a nonexistent estate checkout before staging a snapshot."""
    _mock_estate_root(monkeypatch, tmp_path / "missing-estate")

    result = runner.invoke(app, _openbao_restore_command())

    assert result.exit_code == 1
    assert "ERROR: Estate root not found" in result.output
