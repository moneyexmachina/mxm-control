import json
import subprocess
from dataclasses import dataclass
from typing import cast

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]


GITHUB_API_VERSION = "2026-03-10"


class GitHubApiError(RuntimeError):
    """Failure while calling the GitHub API."""


@dataclass(frozen=True)
class GitHubApi:
    """Thin transport around the authenticated GitHub CLI."""

    executable: str = "gh"

    def get_object(self, endpoint: str) -> JsonObject:
        command = [
            self.executable,
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            endpoint,
        ]

        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise GitHubApiError(
                f"GitHub CLI executable not found: {self.executable}"
            ) from exc

        if result.returncode != 0:
            message = result.stderr.strip() or "unknown GitHub API failure"
            raise GitHubApiError(message)

        try:
            payload = cast(JsonValue, json.loads(result.stdout))
        except json.JSONDecodeError as exc:
            raise GitHubApiError("GitHub API returned invalid JSON") from exc

        if not isinstance(payload, dict):
            raise GitHubApiError("GitHub API did not return a JSON object")

        return cast(JsonObject, payload)

    def send_object(
        self,
        method: str,
        endpoint: str,
        payload: JsonObject,
    ) -> JsonObject:
        command = [
            self.executable,
            "api",
            "--method",
            method,
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            endpoint,
            "--input",
            "-",
        ]

        try:
            result = subprocess.run(
                command,
                input=json.dumps(payload),
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise GitHubApiError(
                f"GitHub CLI executable not found: {self.executable}"
            ) from exc

        if result.returncode != 0:
            message = result.stderr.strip() or "unknown GitHub API failure"
            raise GitHubApiError(message)

        try:
            response = cast(JsonValue, json.loads(result.stdout))
        except json.JSONDecodeError as exc:
            raise GitHubApiError("GitHub API returned invalid JSON") from exc

        if not isinstance(response, dict):
            raise GitHubApiError("GitHub API did not return a JSON object")

        return cast(JsonObject, response)
