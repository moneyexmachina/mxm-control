from pathlib import Path

import pytest
from typer.testing import CliRunner

from mxm.control import operator
from mxm.control.cli import app
from mxm.control.github.actions_policy import (
    ActionsPolicyError,
    ActionsPolicyPlan,
    PlanAction,
)
from mxm.control.github.api import JsonObject
from mxm.control.opentofu import OpenTofuCheckResult, OpenTofuError

runner = CliRunner()


def test_help_exposes_control_operations() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "plan" in result.stdout
    assert "apply" in result.stdout
    assert "check" in result.stdout


def test_plan_help_exposes_opentofu() -> None:
    result = runner.invoke(app, ["plan", "--help"])

    assert result.exit_code == 0
    assert "opentofu" in result.stdout


def test_plan_opentofu_reports_saved_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"

    def fake_plan_opentofu(stack: Path, plan: Path) -> Path:
        return plan.resolve()

    monkeypatch.setattr("mxm.control.cli.plan_opentofu", fake_plan_opentofu)

    result = runner.invoke(
        app,
        [
            "plan",
            "opentofu",
            "--stack",
            str(stack),
            "--out",
            str(plan),
        ],
    )

    assert result.exit_code == 0
    assert "OK" in result.stdout
    assert str(plan) in result.stdout


def test_check_opentofu_reports_drift_with_distinct_exit_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()

    def fake_check_opentofu(stack: Path) -> OpenTofuCheckResult:
        return OpenTofuCheckResult.DRIFT

    monkeypatch.setattr("mxm.control.cli.check_opentofu", fake_check_opentofu)

    result = runner.invoke(
        app,
        ["check", "opentofu", "--stack", str(stack)],
    )

    assert result.exit_code == 2
    assert "DRIFT" in result.output


def test_check_opentofu_reports_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()

    def fail(stack: Path) -> OpenTofuCheckResult:
        raise OpenTofuError("OpenTofu check failed with exit status 1")

    monkeypatch.setattr("mxm.control.cli.check_opentofu", fail)

    result = runner.invoke(
        app,
        ["check", "opentofu", "--stack", str(stack)],
    )

    assert result.exit_code == 1
    assert "ERROR: OpenTofu check failed with exit status 1" in result.output


def test_apply_opentofu_routes_existing_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    observed: dict[str, Path] = {}

    def fake_apply(stack: Path, plan: Path) -> Path:
        observed["stack"] = stack
        observed["plan"] = plan
        return plan.resolve()

    monkeypatch.setattr("mxm.control.cli.apply_opentofu", fake_apply)

    result = runner.invoke(
        app,
        [
            "apply",
            "opentofu",
            "--stack",
            str(stack),
            "--plan",
            str(plan),
        ],
    )

    assert result.exit_code == 0
    assert observed == {"stack": stack, "plan": plan}
    assert "OK" in result.stdout


def test_check_github_actions_succeeds_when_policy_matches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
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
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{}")

    def fake_apply(
        api: object,
        organization: str,
        policy_path: Path,
    ) -> ActionsPolicyPlan:
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
    """Login delegates authentication to the operator module."""
    calls: list[str] = []

    def fake_login() -> None:
        calls.append("login")

    monkeypatch.setattr("mxm.control.cli.operator.login", fake_login)

    result = runner.invoke(app, ["login"])

    assert result.exit_code == 0
    assert calls == ["login"]
    assert "Proton Pass session available" in result.stdout


def test_login_reports_authentication_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Login reports an operator authentication failure."""

    def fake_login() -> None:
        raise operator.OperatorError("Proton Pass login failed")

    monkeypatch.setattr("mxm.control.cli.operator.login", fake_login)

    result = runner.invoke(app, ["login"])

    assert result.exit_code == 1
    assert "ERROR: Proton Pass login failed" in result.output


def test_status_reports_available_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Status succeeds when an operator session exists."""
    monkeypatch.setattr("mxm.control.cli.operator.status", lambda: True)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0
    assert "Proton Pass session available" in result.stdout


def test_status_reports_unavailable_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Status fails when no operator session is available."""
    monkeypatch.setattr("mxm.control.cli.operator.status", lambda: False)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 1
    assert "UNAUTHENTICATED" in result.output


def test_status_reports_operator_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Status reports execution failures without exposing credentials."""

    def fake_status() -> bool:
        raise operator.OperatorError("Proton Pass CLI is not installed")

    monkeypatch.setattr("mxm.control.cli.operator.status", fake_status)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 1
    assert "ERROR: Proton Pass CLI is not installed" in result.output


def test_logout_terminates_operator_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logout delegates session termination to the operator module."""
    calls: list[str] = []

    def fake_logout() -> None:
        calls.append("logout")

    monkeypatch.setattr("mxm.control.cli.operator.logout", fake_logout)

    result = runner.invoke(app, ["logout"])

    assert result.exit_code == 0
    assert calls == ["logout"]
    assert "Proton Pass session terminated" in result.stdout


def test_logout_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logout reports failures without claiming session termination."""

    def fake_logout() -> None:
        raise operator.OperatorError("Proton Pass logout failed")

    monkeypatch.setattr("mxm.control.cli.operator.logout", fake_logout)

    result = runner.invoke(app, ["logout"])

    assert result.exit_code == 1
    assert "ERROR: Proton Pass logout failed" in result.output
