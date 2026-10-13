import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import quote

from mxm.control.github.api import JsonObject, JsonValue


class ActionsPolicyError(RuntimeError):
    """Invalid policy definition or unexpected GitHub policy state."""


class PlanAction(StrEnum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    NO_CHANGE = "NO CHANGE"


@dataclass(frozen=True)
class ActionsPolicyPlan:
    action: PlanAction
    name: str
    policy_id: int | None
    desired: JsonObject
    actual: JsonObject | None


class GitHubApiReader(Protocol):
    def get_object(self, endpoint: str) -> JsonObject: ...


def load_policy(path: Path) -> JsonObject:
    try:
        payload = cast(JsonValue, json.loads(path.read_text()))
    except json.JSONDecodeError as exc:
        raise ActionsPolicyError(f"Invalid JSON in policy file: {path}") from exc

    if not isinstance(payload, dict):
        raise ActionsPolicyError("Actions policy must be a JSON object")

    return cast(JsonObject, payload)


def normalize_policy(policy: JsonObject) -> JsonObject:
    name = policy.get("name")
    enforcement = policy.get("enforcement")
    rules = policy.get("rules")

    if not isinstance(name, str) or not name:
        raise ActionsPolicyError("Actions policy requires a non-empty 'name'")

    if not isinstance(enforcement, str):
        raise ActionsPolicyError("Actions policy requires string 'enforcement'")

    if not isinstance(rules, list):
        raise ActionsPolicyError("Actions policy requires array 'rules'")

    normalized: JsonObject = {
        "name": name,
        "enforcement": enforcement,
        "rules": rules,
    }

    if "conditions" in policy:
        conditions = policy["conditions"]

        if not isinstance(conditions, dict):
            raise ActionsPolicyError("Actions policy 'conditions' must be an object")

        normalized["conditions"] = conditions

    return normalized


def _find_policy_by_name(
    api: GitHubApiReader,
    organization_path: str,
    name: str,
) -> JsonObject | None:
    matches: list[JsonObject] = []
    page = 1

    while True:
        response = api.get_object(
            f"orgs/{organization_path}/actions/policies"
            f"?has_parents=false&per_page=100&page={page}"
        )

        total_count = response.get("total_count")
        policies = response.get("policies")

        if not isinstance(total_count, int) or isinstance(total_count, bool):
            raise ActionsPolicyError(
                "GitHub Actions policy list has invalid 'total_count'"
            )

        if not isinstance(policies, list):
            raise ActionsPolicyError(
                "GitHub Actions policy list has invalid 'policies'"
            )

        for policy in policies:
            if not isinstance(policy, dict):
                raise ActionsPolicyError(
                    "GitHub Actions policy list contains a non-object"
                )

            policy_object = cast(JsonObject, policy)

            if policy_object.get("name") == name:
                matches.append(policy_object)

        if page * 100 >= total_count:
            break

        if not policies:
            raise ActionsPolicyError(
                "GitHub Actions policy pagination ended unexpectedly"
            )

        page += 1

    if len(matches) > 1:
        raise ActionsPolicyError(
            f"Multiple organization Actions policies named '{name}'"
        )

    return matches[0] if matches else None


def plan_actions_policy(
    api: GitHubApiReader,
    organization: str,
    policy_path: Path,
) -> ActionsPolicyPlan:
    desired = normalize_policy(load_policy(policy_path))
    name = cast(str, desired["name"])
    organization_path = quote(organization, safe="")

    existing = _find_policy_by_name(
        api,
        organization_path,
        name,
    )

    if existing is None:
        return ActionsPolicyPlan(
            action=PlanAction.CREATE,
            name=name,
            policy_id=None,
            desired=desired,
            actual=None,
        )

    policy_id = existing.get("id")

    if not isinstance(policy_id, int) or isinstance(policy_id, bool):
        raise ActionsPolicyError(f"GitHub Actions policy '{name}' has invalid id")

    actual = normalize_policy(
        api.get_object(f"orgs/{organization_path}/actions/policies/{policy_id}")
    )

    action = PlanAction.NO_CHANGE if actual == desired else PlanAction.UPDATE

    return ActionsPolicyPlan(
        action=action,
        name=name,
        policy_id=policy_id,
        desired=desired,
        actual=actual,
    )
