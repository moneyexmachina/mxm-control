import json
from pathlib import Path

import pytest

from mxm.control.github.actions_policy import (
    ActionsPolicyError,
    PlanAction,
    apply_actions_policy,
    plan_actions_policy,
)
from mxm.control.github.api import JsonObject

COLLECTION_ENDPOINT = (
    "orgs/moneyexmachina/actions/policies?has_parents=false&per_page=100&page=1"
)
POLICY_ENDPOINT = "orgs/moneyexmachina/actions/policies/42"


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
    def __init__(
        self,
        responses: dict[str, JsonObject],
        *,
        converge_writes: bool = True,
    ) -> None:
        self.responses = responses
        self.converge_writes = converge_writes
        self.writes: list[tuple[str, str, JsonObject]] = []

    def get_object(self, endpoint: str) -> JsonObject:
        return self.responses[endpoint]

    def send_object(
        self,
        method: str,
        endpoint: str,
        payload: JsonObject,
    ) -> JsonObject:
        self.writes.append(
            (
                method,
                endpoint,
                dict(payload),
            )
        )

        if not self.converge_writes:
            return {}

        if method == "POST":
            name = payload.get("name")

            if not isinstance(name, str):
                raise AssertionError("Test policy requires string name")

            self.responses[f"{endpoint}?has_parents=false&per_page=100&page=1"] = {
                "total_count": 1,
                "policies": [
                    {
                        "id": 42,
                        "name": name,
                    }
                ],
            }
            self.responses[f"{endpoint}/42"] = dict(payload)

            return {"id": 42}

        if method == "PUT":
            self.responses[endpoint] = dict(payload)
            return dict(payload)

        raise AssertionError(f"Unexpected test method: {method}")


def write_policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy_definition()))
    return path


def test_plan_create_when_policy_is_absent(tmp_path: Path) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            COLLECTION_ENDPOINT: {
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
            COLLECTION_ENDPOINT: {
                "total_count": 1,
                "policies": [
                    {
                        "id": 42,
                        "name": "mxm-actions",
                    }
                ],
            },
            POLICY_ENDPOINT: actual,
        }
    )

    plan = plan_actions_policy(api, "moneyexmachina", policy)

    assert plan.action is PlanAction.NO_CHANGE
    assert plan.policy_id == 42


def test_plan_update_when_policy_differs(tmp_path: Path) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            COLLECTION_ENDPOINT: {
                "total_count": 1,
                "policies": [
                    {
                        "id": 42,
                        "name": "mxm-actions",
                    }
                ],
            },
            POLICY_ENDPOINT: policy_definition(
                enforcement="disabled",
            ),
        }
    )

    plan = plan_actions_policy(api, "moneyexmachina", policy)

    assert plan.action is PlanAction.UPDATE
    assert plan.policy_id == 42


def test_plan_rejects_duplicate_policy_names(
    tmp_path: Path,
) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            COLLECTION_ENDPOINT: {
                "total_count": 2,
                "policies": [
                    {
                        "id": 41,
                        "name": "mxm-actions",
                    },
                    {
                        "id": 42,
                        "name": "mxm-actions",
                    },
                ],
            }
        }
    )

    with pytest.raises(
        ActionsPolicyError,
        match="Multiple organization Actions policies",
    ):
        plan_actions_policy(
            api,
            "moneyexmachina",
            policy,
        )


def test_apply_does_not_write_when_policy_matches(
    tmp_path: Path,
) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            COLLECTION_ENDPOINT: {
                "total_count": 1,
                "policies": [
                    {
                        "id": 42,
                        "name": "mxm-actions",
                    }
                ],
            },
            POLICY_ENDPOINT: policy_definition(),
        }
    )

    result = apply_actions_policy(
        api,
        "moneyexmachina",
        policy,
    )

    assert result.action is PlanAction.NO_CHANGE
    assert result.policy_id == 42
    assert api.writes == []


def test_apply_creates_absent_policy_and_verifies_convergence(
    tmp_path: Path,
) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            COLLECTION_ENDPOINT: {
                "total_count": 0,
                "policies": [],
            }
        }
    )

    result = apply_actions_policy(
        api,
        "moneyexmachina",
        policy,
    )

    assert api.writes == [
        (
            "POST",
            "orgs/moneyexmachina/actions/policies",
            policy_definition(),
        )
    ]

    assert result.action is PlanAction.NO_CHANGE
    assert result.policy_id == 42
    assert result.actual == policy_definition()


def test_apply_updates_drifted_policy_and_verifies_convergence(
    tmp_path: Path,
) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            COLLECTION_ENDPOINT: {
                "total_count": 1,
                "policies": [
                    {
                        "id": 42,
                        "name": "mxm-actions",
                    }
                ],
            },
            POLICY_ENDPOINT: policy_definition(
                enforcement="disabled",
            ),
        }
    )

    result = apply_actions_policy(
        api,
        "moneyexmachina",
        policy,
    )

    assert api.writes == [
        (
            "PUT",
            POLICY_ENDPOINT,
            policy_definition(),
        )
    ]

    assert result.action is PlanAction.NO_CHANGE
    assert result.policy_id == 42
    assert result.actual == policy_definition()


def test_apply_fails_when_policy_does_not_converge(
    tmp_path: Path,
) -> None:
    policy = write_policy(tmp_path)

    api = FakeGitHubApi(
        {
            COLLECTION_ENDPOINT: {
                "total_count": 0,
                "policies": [],
            }
        },
        converge_writes=False,
    )

    with pytest.raises(
        ActionsPolicyError,
        match="did not converge after apply",
    ):
        apply_actions_policy(
            api,
            "moneyexmachina",
            policy,
        )

    assert api.writes == [
        (
            "POST",
            "orgs/moneyexmachina/actions/policies",
            policy_definition(),
        )
    ]
