import json
import subprocess

import pytest

from mxm.control.github.api import (
    GITHUB_API_VERSION,
    GitHubApi,
    GitHubApiError,
    JsonObject,
)


class RunStub:
    def __init__(
        self,
        *,
        stdout: str = "{}",
        stderr: str = "",
        returncode: int = 0,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

        self.commands: list[list[str]] = []
        self.inputs: list[str | None] = []

    def __call__(
        self,
        command: list[str],
        *,
        input: str | None = None,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        self.inputs.append(input)

        return subprocess.CompletedProcess(
            args=command,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


def test_get_object_calls_github_api_and_returns_json_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = RunStub(
        stdout=json.dumps(
            {
                "total_count": 0,
                "policies": [],
            }
        )
    )

    monkeypatch.setattr(
        "mxm.control.github.api.subprocess.run",
        stub,
    )

    api = GitHubApi()

    result = api.get_object("orgs/moneyexmachina/actions/policies?has_parents=false")

    expected: JsonObject = {
        "total_count": 0,
        "policies": [],
    }

    assert result == expected
    assert stub.inputs == [None]
    assert stub.commands == [
        [
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            "orgs/moneyexmachina/actions/policies?has_parents=false",
        ]
    ]


def test_send_object_calls_github_api_with_method_and_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response: JsonObject = {
        "id": 42,
        "name": "mxm-actions",
    }

    stub = RunStub(stdout=json.dumps(response))

    monkeypatch.setattr(
        "mxm.control.github.api.subprocess.run",
        stub,
    )

    api = GitHubApi()

    payload: JsonObject = {
        "name": "mxm-actions",
        "enforcement": "active",
        "rules": [],
    }

    result = api.send_object(
        "POST",
        "orgs/moneyexmachina/actions/policies",
        payload,
    )

    assert result == response
    assert stub.inputs == [json.dumps(payload)]
    assert stub.commands == [
        [
            "gh",
            "api",
            "--method",
            "POST",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            "orgs/moneyexmachina/actions/policies",
            "--input",
            "-",
        ]
    ]


def test_get_object_raises_on_github_api_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = RunStub(
        returncode=1,
        stderr="gh: forbidden",
    )

    monkeypatch.setattr(
        "mxm.control.github.api.subprocess.run",
        stub,
    )

    api = GitHubApi()

    with pytest.raises(
        GitHubApiError,
        match="gh: forbidden",
    ):
        api.get_object("orgs/moneyexmachina/actions/policies")


def test_send_object_raises_on_github_api_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = RunStub(
        returncode=1,
        stderr="gh: forbidden",
    )

    monkeypatch.setattr(
        "mxm.control.github.api.subprocess.run",
        stub,
    )

    api = GitHubApi()

    payload: JsonObject = {
        "name": "mxm-actions",
        "enforcement": "active",
        "rules": [],
    }

    with pytest.raises(
        GitHubApiError,
        match="gh: forbidden",
    ):
        api.send_object(
            "POST",
            "orgs/moneyexmachina/actions/policies",
            payload,
        )


@pytest.mark.parametrize(
    "method",
    ["get", "send"],
)
def test_api_rejects_non_object_json(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    stub = RunStub(stdout="[]")

    monkeypatch.setattr(
        "mxm.control.github.api.subprocess.run",
        stub,
    )

    api = GitHubApi()

    with pytest.raises(
        GitHubApiError,
        match="did not return a JSON object",
    ):
        if method == "get":
            api.get_object("example")
        else:
            api.send_object(
                "POST",
                "example",
                {},
            )


@pytest.mark.parametrize(
    "method",
    ["get", "send"],
)
def test_api_rejects_invalid_json(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    stub = RunStub(stdout="not json")

    monkeypatch.setattr(
        "mxm.control.github.api.subprocess.run",
        stub,
    )

    api = GitHubApi()

    with pytest.raises(
        GitHubApiError,
        match="returned invalid JSON",
    ):
        if method == "get":
            api.get_object("example")
        else:
            api.send_object(
                "POST",
                "example",
                {},
            )
