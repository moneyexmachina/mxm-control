import json
from pathlib import Path

import pytest

from mxm.control.github.actions_policy import (
    ActionsPolicyError,
    PlanAction,
    plan_actions_policy,
)
from mxm.control.github.api import JsonObject


def policy_definition(
    enforcement: str = "active",
) -> JsonObject:
    return {
        "name": "mxm-actions",
        "enforcement": enforcement,
        "conditions": {
            "repository_name": {
                "include": ["~ALL"],
                "exclude": [],
            }
        },
        "rules": [],
    }


class FakeGitHubApi:
    def __init__(self, responses: dict[str, JsonObject]) -> None:
        self.responses = responses

    def get_object(self, endpoint: str) -> JsonObject:
        return self.responses[endpoint]


def write_policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy_definition()))
    return path


def test_plan_create_when_policy_is_absent(tmp_path: Path) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            "orgs/moneyexmachina/actions/policies"
            "?has_parents=false&per_page=100&page=1": {
                "total_count": 0,
                "policies": [],
            }
        }
    )

    plan = plan_actions_policy(api, "moneyexmachina", policy)

    assert plan.action is PlanAction.CREATE
    assert plan.policy_id is None


def test_plan_no_change_when_policy_matches(tmp_path: Path) -> None:
    policy = write_policy(tmp_path)

    actual: JsonObject = policy_definition()
    api = FakeGitHubApi(
        {
            "orgs/moneyexmachina/actions/policies"
            "?has_parents=false&per_page=100&page=1": {
                "total_count": 1,
                "policies": [{"id": 42, "name": "mxm-actions"}],
            },
            "orgs/moneyexmachina/actions/policies/42": actual,
        }
    )

    plan = plan_actions_policy(api, "moneyexmachina", policy)

    assert plan.action is PlanAction.NO_CHANGE
    assert plan.policy_id == 42


def test_plan_update_when_policy_differs(tmp_path: Path) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            "orgs/moneyexmachina/actions/policies"
            "?has_parents=false&per_page=100&page=1": {
                "total_count": 1,
                "policies": [{"id": 42, "name": "mxm-actions"}],
            },
            "orgs/moneyexmachina/actions/policies/42": {
                "name": "mxm-actions",
                "enforcement": "disabled",
                "conditions": {
                    "repository_name": {
                        "include": ["~ALL"],
                        "exclude": [],
                    }
                },
                "rules": [],
            },
        }
    )

    plan = plan_actions_policy(api, "moneyexmachina", policy)

    assert plan.action is PlanAction.UPDATE
    assert plan.policy_id == 42


def test_plan_rejects_duplicate_policy_names(tmp_path: Path) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            "orgs/moneyexmachina/actions/policies"
            "?has_parents=false&per_page=100&page=1": {
                "total_count": 2,
                "policies": [
                    {"id": 41, "name": "mxm-actions"},
                    {"id": 42, "name": "mxm-actions"},
                ],
            }
        }
    )

    with pytest.raises(
        ActionsPolicyError,
        match="Multiple organization Actions policies",
    ):
        plan_actions_policy(api, "moneyexmachina", policy)
