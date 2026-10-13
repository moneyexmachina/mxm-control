from pathlib import Path

import pytest
from typer.testing import CliRunner

from mxm.control.cli import app
from mxm.control.github.actions_policy import (
    ActionsPolicyPlan,
    PlanAction,
)
from mxm.control.github.api import JsonObject

runner = CliRunner()


def test_help_exposes_control_operations() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "plan" in result.stdout
    assert "apply" in result.stdout
    assert "check" in result.stdout


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
