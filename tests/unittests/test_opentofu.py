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
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["check"] = check
        observed["umask"] = umask
        plan.write_bytes(b"saved plan")
        plan.chmod(0o666)
        return completed(0)

    monkeypatch.setattr("mxm.control.opentofu.subprocess.run", fake_run)

    result = plan_opentofu(stack, plan)

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

    monkeypatch.setattr("mxm.control.opentofu.subprocess.run", must_not_run)

    with pytest.raises(OpenTofuError, match="already exists"):
        plan_opentofu(stack, plan)


def test_plan_removes_partial_output_after_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"

    def fake_run(
        command: list[str],
        *,
        check: bool,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        plan.write_bytes(b"partial")
        return completed(1)

    monkeypatch.setattr("mxm.control.opentofu.subprocess.run", fake_run)

    with pytest.raises(OpenTofuError, match="plan failed with exit status 1"):
        plan_opentofu(stack, plan)

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
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        return completed(returncode)

    monkeypatch.setattr("mxm.control.opentofu.subprocess.run", fake_run)

    assert check_opentofu(stack) is expected
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
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()

    def fake_run(
        command: list[str],
        *,
        check: bool,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        return completed(1)

    monkeypatch.setattr("mxm.control.opentofu.subprocess.run", fake_run)

    with pytest.raises(OpenTofuError, match="check failed with exit status 1"):
        check_opentofu(stack)


def test_apply_uses_exact_existing_plan_without_replanning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
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
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        return completed(0)

    monkeypatch.setattr("mxm.control.opentofu.subprocess.run", fake_run)

    assert apply_opentofu(stack, plan) == plan
    assert observed["command"] == [
        "tofu",
        f"-chdir={stack}",
        "apply",
        "-input=false",
        str(plan),
    ]


def test_apply_rejects_a_group_or_other_readable_plan(tmp_path: Path) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o644)

    with pytest.raises(OpenTofuError, match="permissions must be owner-only"):
        apply_opentofu(stack, plan)


def test_apply_rejects_a_symbolic_link_plan(tmp_path: Path) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()
    target = tmp_path / "target.plan"
    target.write_bytes(b"saved plan")
    plan = tmp_path / "reviewed.plan"
    plan.symlink_to(target)

    with pytest.raises(OpenTofuError, match="must not be a symbolic link"):
        apply_opentofu(stack, plan)


def test_operations_reject_a_non_directory_stack(tmp_path: Path) -> None:
    stack = tmp_path / "stack.tf"
    stack.write_text("")

    with pytest.raises(OpenTofuError, match="stack is not a directory"):
        check_opentofu(stack)


def test_missing_executable_is_reported_clearly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stack = tmp_path / "stack"
    stack.mkdir()

    def missing_executable(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(
        "mxm.control.opentofu.subprocess.run",
        missing_executable,
    )

    with pytest.raises(OpenTofuError, match="executable not found"):
        check_opentofu(stack)


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777
