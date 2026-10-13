from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Action(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    NO_CHANGE = "no-change"


@dataclass(frozen=True)
class ActionsPolicyPlan:
    action: Action
    name: str
    policy_id: int | None
    desired: dict[str, Any]
    actual: dict[str, Any] | None
