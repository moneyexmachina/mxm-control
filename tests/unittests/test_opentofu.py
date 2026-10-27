import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from mxm.control.opentofu import (
    OpenTofuCheckResult,
    OpenTofuError,
    apply_opentofu,
    check_opentofu,
    plan_opentofu,
)


def completed(returncode: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode)


def test_plan_writes_explicit_saved_plan_with_restrictive_permissions(
    monkeypatch: pytest.MonkeyPatch,
    environment_policy: Path,
    tmp_path: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"
    observed: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        _ = env
        observed["command"] = command
        observed["check"] = check
        observed["umask"] = umask
        plan.write_bytes(b"saved plan")
        plan.chmod(0o666)
        return completed(0)

    monkeypatch.setattr("mxm.control.credentials.subprocess.run", fake_run)

    result = plan_opentofu(stack, environment_policy, plan)

    assert result == plan
    assert observed["command"] == [
        "tofu",
        f"-chdir={stack}",
        "plan",
        "-input=false",
        f"-out={plan}",
    ]
    assert observed["check"] is False
    assert observed["umask"] == 0o077
    assert stat_mode(plan) == 0o600


def test_plan_refuses_to_overwrite_an_existing_file(
    monkeypatch: pytest.MonkeyPatch,
    environment_policy: Path,
    tmp_path: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"
    plan.write_text("existing")

    def must_not_run(
        command: list[str],
        *,
        check: bool,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        pytest.fail("OpenTofu must not run")

    monkeypatch.setattr("mxm.control.credentials.subprocess.run", must_not_run)

    with pytest.raises(OpenTofuError, match="already exists"):
        plan_opentofu(stack, environment_policy, plan)


def test_plan_removes_partial_output_after_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        plan.write_bytes(b"partial")
        return completed(1)

    monkeypatch.setattr("mxm.control.credentials.subprocess.run", fake_run)

    with pytest.raises(OpenTofuError, match="plan failed with exit status 1"):
        plan_opentofu(stack, environment_policy, plan)

    assert not plan.exists()


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [
        (0, OpenTofuCheckResult.NO_CHANGE),
        (2, OpenTofuCheckResult.DRIFT),
    ],
)
def test_check_interprets_detailed_exit_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
    returncode: int,
    expected: OpenTofuCheckResult,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        return completed(returncode)

    monkeypatch.setattr("mxm.control.credentials.subprocess.run", fake_run)

    assert check_opentofu(stack, environment_policy=environment_policy) is expected
    assert observed["command"] == [
        "tofu",
        f"-chdir={stack}",
        "plan",
        "-input=false",
        "-detailed-exitcode",
    ]


def test_check_distinguishes_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        return completed(1)

    monkeypatch.setattr("mxm.control.credentials.subprocess.run", fake_run)

    with pytest.raises(OpenTofuError, match="check failed with exit status 1"):
        check_opentofu(stack, environment_policy=environment_policy)


def test_apply_uses_exact_existing_plan_without_replanning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        return completed(0)

    monkeypatch.setattr("mxm.control.credentials.subprocess.run", fake_run)

    assert apply_opentofu(stack, environment_policy, plan) == plan
    assert observed["command"] == [
        "tofu",
        f"-chdir={stack}",
        "apply",
        "-input=false",
        str(plan),
    ]


def test_apply_rejects_a_group_or_other_readable_plan(
    tmp_path: Path, environment_policy: Path
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o644)

    with pytest.raises(OpenTofuError, match="permissions must be owner-only"):
        apply_opentofu(stack, environment_policy, plan)


def test_apply_rejects_a_symbolic_link_plan(
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    target = tmp_path / "target.plan"
    target.write_bytes(b"saved plan")
    plan = tmp_path / "reviewed.plan"
    plan.symlink_to(target)

    with pytest.raises(OpenTofuError, match="must not be a symbolic link"):
        apply_opentofu(stack, environment_policy, plan)


def test_operations_reject_a_non_directory_stack(
    tmp_path: Path, environment_policy: Path
) -> None:
    stack = tmp_path / "stack.tf"
    stack.write_text("")

    with pytest.raises(OpenTofuError, match="stack is not a directory"):
        check_opentofu(stack, environment_policy=environment_policy)


def test_missing_executable_is_reported_clearly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()

    def missing_executable(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(
        "mxm.control.credentials.subprocess.run",
        missing_executable,
    )

    with pytest.raises(OpenTofuError, match="executable not found"):
        check_opentofu(stack, environment_policy=environment_policy)


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


def test_plan_uses_stack_credential_bindings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """OpenTofu planning delegates credential resolution to the runner."""
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"

    observed: dict[str, object] = {}

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        observed["command"] = command
        observed["stack"] = stack
        observed["environment_policy"] = environment_policy
        observed["restrictive_umask"] = restrictive_umask

        plan.write_bytes(b"saved plan")
        return 0

    monkeypatch.setattr(
        "mxm.control.opentofu.run_with_credentials",
        fake_run_with_credentials,
    )

    result = plan_opentofu(stack, environment_policy, plan)

    assert result == plan
    assert observed == {
        "command": [
            "tofu",
            f"-chdir={stack}",
            "plan",
            "-input=false",
            f"-out={plan}",
        ],
        "stack": stack,
        "environment_policy": environment_policy,
        "restrictive_umask": True,
    }

    assert stat_mode(plan) == 0o600
    assert observed["environment_policy"] == environment_policy


def test_credential_failure_is_reported_as_opentofu_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Credential failures must prevent OpenTofu execution."""
    from mxm.control.credentials import CredentialError

    stack = tmp_path / "stack"
    stack.mkdir()

    def fail_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        raise CredentialError("Credential resolution failed")

    monkeypatch.setattr(
        "mxm.control.opentofu.run_with_credentials",
        fail_credentials,
    )

    with pytest.raises(
        OpenTofuError,
        match="Credential resolution failed",
    ):
        check_opentofu(stack, environment_policy=environment_policy)
