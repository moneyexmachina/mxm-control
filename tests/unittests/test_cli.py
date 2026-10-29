"""Unit tests for the MXM estate-control command-line interface.

Tests verify command registration, argument forwarding, result reporting,
and error handling across OpenTofu reconciliation, machine bootstrap,
GitHub policy management, and operator authentication.

External operations are replaced with controlled test implementations.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from mxm.control import cli, operator
from mxm.control.cli import app
from mxm.control.github.actions_policy import (
    ActionsPolicyError,
    ActionsPolicyPlan,
    PlanAction,
)
from mxm.control.github.api import JsonObject
from mxm.control.machine_bootstrap import MachineBootstrapError
from mxm.control.opentofu import OpenTofuCheckResult, OpenTofuError

runner = CliRunner()


def test_apply_machine_bootstrap_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Forward approved machine-bootstrap arguments to the mechanism."""
    stack = tmp_path / "stack"
    stack.mkdir()

    policy = tmp_path / "environment.toml"
    policy.write_text("")

    plan = tmp_path / "machine-bootstrap.tfplan"
    plan.write_bytes(b"saved plan")

    observed: dict[str, object] = {}

    def fake_apply_machine_bootstrap(
        root: Path,
        environment_policy: Path,
        plan: Path,
        *,
        expected_hostname: str,
        recovery_verified: bool,
        confirmation: str,
    ) -> Path:
        """Capture the arguments without executing infrastructure operations."""
        observed.update(
            root=root,
            environment_policy=environment_policy,
            plan=plan,
            expected_hostname=expected_hostname,
            recovery_verified=recovery_verified,
            confirmation=confirmation,
        )
        return plan

    monkeypatch.setattr(
        cli,
        "apply_machine_bootstrap",
        fake_apply_machine_bootstrap,
    )

    result = runner.invoke(
        cli.app,
        [
            "apply",
            "machine-bootstrap",
            "--stack",
            str(stack),
            "--environment-policy",
            str(policy),
            "--plan",
            str(plan),
            "--expected-hostname",
            "mxm-security",
            "--recovery-verified",
            "--confirmation",
            "REBUILD hcloud_server.security",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == {
        "root": stack,
        "environment_policy": policy,
        "plan": plan,
        "expected_hostname": "mxm-security",
        "recovery_verified": True,
        "confirmation": "REBUILD hcloud_server.security",
    }
    assert "OK" in result.output
    assert str(plan) in result.output


def test_apply_machine_bootstrap_command_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Return exit status 1 when the bootstrap mechanism fails."""
    stack = tmp_path / "stack"
    stack.mkdir()

    policy = tmp_path / "environment.toml"
    policy.write_text("")

    plan = tmp_path / "machine-bootstrap.tfplan"
    plan.write_bytes(b"saved plan")

    def fake_apply_machine_bootstrap(
        root: Path,
        environment_policy: Path,
        plan: Path,
        *,
        expected_hostname: str,
        recovery_verified: bool,
        confirmation: str,
    ) -> Path:
        """Simulate a failed machine replacement."""
        raise MachineBootstrapError("Tailscale retirement failed")

    monkeypatch.setattr(
        cli,
        "apply_machine_bootstrap",
        fake_apply_machine_bootstrap,
    )

    result = runner.invoke(
        cli.app,
        [
            "apply",
            "machine-bootstrap",
            "--stack",
            str(stack),
            "--environment-policy",
            str(policy),
            "--plan",
            str(plan),
            "--expected-hostname",
            "mxm-security",
            "--recovery-verified",
            "--confirmation",
            "REBUILD hcloud_server.security",
        ],
    )

    assert result.exit_code == 1
    assert "ERROR: Tailscale retirement failed" in result.output
    assert "Machine bootstrap completed" not in result.output


runner = CliRunner()


def test_help_exposes_control_operations() -> None:
    """Expose the planning, application, and checking command groups."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "plan" in result.stdout
    assert "apply" in result.stdout
    assert "check" in result.stdout


def test_plan_help_exposes_opentofu_and_machine_bootstrap() -> None:
    """Expose OpenTofu and machine-bootstrap planning capabilities."""
    result = runner.invoke(app, ["plan", "--help"])

    assert result.exit_code == 0
    assert "opentofu" in result.stdout
    assert "machine-bootstrap" in result.stdout


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

    monkeypatch.setattr("mxm.control.cli.plan_opentofu", fake_plan_opentofu)

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

    monkeypatch.setattr("mxm.control.cli.check_opentofu", fail)

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

    monkeypatch.setattr("mxm.control.cli.apply_opentofu", fake_apply)

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


def test_login_reuses_or_establishes_operator_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delegate operator authentication to the operator module."""
    calls: list[str] = []

    def fake_login() -> None:
        """Record a request to establish operator authentication."""
        calls.append("login")

    monkeypatch.setattr("mxm.control.cli.operator.login", fake_login)

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

    monkeypatch.setattr("mxm.control.cli.operator.login", fake_login)

    result = runner.invoke(app, ["login"])

    assert result.exit_code == 1
    assert "ERROR: Proton Pass login failed" in result.output


def test_status_reports_both_authenticated_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report available Proton Pass and GitHub operator sessions."""
    monkeypatch.setattr(
        operator,
        "operator_status",
        lambda: operator.OperatorStatus(proton_pass=True, github=True),
    )

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0
    assert "OK                Proton Pass" in result.stdout
    assert "OK                GitHub CLI" in result.stdout


def test_status_reports_partial_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identify unavailable operator backends and return a failure status."""
    monkeypatch.setattr(
        operator,
        "operator_status",
        lambda: operator.OperatorStatus(proton_pass=True, github=False),
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

    monkeypatch.setattr("mxm.control.cli.operator.logout", fake_logout)

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

    monkeypatch.setattr("mxm.control.cli.operator.logout", fake_logout)

    result = runner.invoke(app, ["logout"])

    assert result.exit_code == 1
    assert "ERROR: Proton Pass logout failed" in result.output
