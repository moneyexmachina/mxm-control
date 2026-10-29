"""Unit tests for MXM OpenTofu infrastructure reconciliation.

OpenTofu operations target a root module and support three workflows:

- Plan infrastructure changes into a protected saved plan.
- Check declared infrastructure against realised state.
- Apply exactly one existing, reviewed saved plan.

Tests verify command construction, result interpretation, credential
delegation, plan-file validation, and failure handling.

External execution is replaced with controlled test implementations.
"""

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from mxm.control.credentials import CredentialError
from mxm.control.opentofu import (
    OpenTofuCheckResult,
    OpenTofuError,
    apply_opentofu,
    apply_opentofu_inherited,
    check_opentofu,
    plan_opentofu,
)


def completed(returncode: int) -> subprocess.CompletedProcess[str]:
    """Build a subprocess result with the requested exit status."""
    return subprocess.CompletedProcess(args=[], returncode=returncode)


def stat_mode(path: Path) -> int:
    """Return the permission bits of a filesystem entry."""
    return os.stat(path).st_mode & 0o777


def test_plan_writes_explicit_saved_plan_with_restrictive_permissions(
    monkeypatch: pytest.MonkeyPatch,
    environment_policy: Path,
    tmp_path: Path,
) -> None:
    """Create a saved plan with owner-only permissions."""
    root = tmp_path / "root"
    root.mkdir()
    plan = tmp_path / "reviewed.plan"
    observed: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        """Record execution arguments and create a representative plan."""
        _ = env
        observed["command"] = command
        observed["check"] = check
        observed["umask"] = umask

        plan.write_bytes(b"saved plan")
        plan.chmod(0o666)

        return completed(0)

    monkeypatch.setattr(
        "mxm.control.credentials.subprocess.run",
        fake_run,
    )

    result = plan_opentofu(root, environment_policy, plan)

    assert result == plan
    assert observed["command"] == [
        "tofu",
        f"-chdir={root}",
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
    """Preserve existing plan files and reject duplicate destinations."""
    root = tmp_path / "root"
    root.mkdir()
    plan = tmp_path / "reviewed.plan"
    plan.write_text("existing")

    def must_not_run(
        command: list[str],
        *,
        check: bool,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        """Fail if planning attempts external execution."""
        pytest.fail("OpenTofu must not run")

    monkeypatch.setattr(
        "mxm.control.credentials.subprocess.run",
        must_not_run,
    )

    with pytest.raises(OpenTofuError, match="already exists"):
        plan_opentofu(root, environment_policy, plan)


def test_plan_removes_partial_output_after_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Remove an incomplete saved plan when planning fails."""
    root = tmp_path / "root"
    root.mkdir()
    plan = tmp_path / "reviewed.plan"

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        """Create a partial plan and return an execution failure."""
        plan.write_bytes(b"partial")
        return completed(1)

    monkeypatch.setattr(
        "mxm.control.credentials.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        OpenTofuError,
        match="plan failed with exit status 1",
    ):
        plan_opentofu(root, environment_policy, plan)

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
    """Interpret OpenTofu detailed exit statuses as reconciliation results."""
    root = tmp_path / "root"
    root.mkdir()
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        """Record the drift-check command and return its requested status."""
        observed["command"] = command
        return completed(returncode)

    monkeypatch.setattr(
        "mxm.control.credentials.subprocess.run",
        fake_run,
    )

    result = check_opentofu(
        root,
        environment_policy=environment_policy,
    )

    assert result is expected
    assert observed["command"] == [
        "tofu",
        f"-chdir={root}",
        "plan",
        "-input=false",
        "-detailed-exitcode",
    ]


def test_check_distinguishes_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Report OpenTofu execution errors separately from infrastructure drift."""
    root = tmp_path / "root"
    root.mkdir()

    def fake_run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str] | None,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        """Return an OpenTofu execution failure."""
        return completed(1)

    monkeypatch.setattr(
        "mxm.control.credentials.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        OpenTofuError,
        match="check failed with exit status 1",
    ):
        check_opentofu(
            root,
            environment_policy=environment_policy,
        )


def test_apply_uses_exact_existing_plan_without_replanning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Apply the supplied saved plan directly against its OpenTofu root."""
    root = tmp_path / "root"
    root.mkdir()
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
        """Record the OpenTofu apply command."""
        observed["command"] = command
        return completed(0)

    monkeypatch.setattr(
        "mxm.control.credentials.subprocess.run",
        fake_run,
    )

    result = apply_opentofu(root, environment_policy, plan)

    assert result == plan
    assert observed["command"] == [
        "tofu",
        f"-chdir={root}",
        "apply",
        "-input=false",
        str(plan),
    ]


def test_apply_rejects_a_group_or_other_readable_plan(
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Require owner-only permissions for saved OpenTofu plans."""
    root = tmp_path / "root"
    root.mkdir()
    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o644)

    with pytest.raises(
        OpenTofuError,
        match="permissions must be owner-only",
    ):
        apply_opentofu(root, environment_policy, plan)


def test_apply_rejects_a_symbolic_link_plan(
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Require the supplied saved plan to be a regular file, not a symlink."""
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "target.plan"
    target.write_bytes(b"saved plan")
    plan = tmp_path / "reviewed.plan"
    plan.symlink_to(target)

    with pytest.raises(
        OpenTofuError,
        match="must not be a symbolic link",
    ):
        apply_opentofu(root, environment_policy, plan)


def test_operations_reject_a_non_directory_root(
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Require the OpenTofu root to identify a directory."""
    root = tmp_path / "root.tf"
    root.write_text("")

    with pytest.raises(
        OpenTofuError,
        match="root is not a directory",
    ):
        check_opentofu(
            root,
            environment_policy=environment_policy,
        )


def test_missing_executable_is_reported_clearly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Report an unavailable OpenTofu executable as an execution error."""
    root = tmp_path / "root"
    root.mkdir()

    def missing_executable(
        *args: object,
        **kwargs: object,
    ) -> None:
        """Represent an unavailable external executable."""
        raise FileNotFoundError

    monkeypatch.setattr(
        "mxm.control.credentials.subprocess.run",
        missing_executable,
    )

    with pytest.raises(
        OpenTofuError,
        match="executable not found",
    ):
        check_opentofu(
            root,
            environment_policy=environment_policy,
        )


def test_plan_uses_root_credential_bindings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Delegate OpenTofu root credential bindings to the credential runner."""
    root = tmp_path / "root"
    root.mkdir()
    plan = tmp_path / "reviewed.plan"
    observed: dict[str, object] = {}

    def fake_run_with_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        """Record credential execution arguments and produce a saved plan."""
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

    result = plan_opentofu(root, environment_policy, plan)

    assert result == plan
    assert observed == {
        "command": [
            "tofu",
            f"-chdir={root}",
            "plan",
            "-input=false",
            f"-out={plan}",
        ],
        "stack": root,
        "environment_policy": environment_policy,
        "restrictive_umask": True,
    }
    assert stat_mode(plan) == 0o600


def test_credential_failure_is_reported_as_opentofu_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Propagate credential execution failures through the OpenTofu interface."""
    root = tmp_path / "root"
    root.mkdir()

    def fail_credentials(
        command: list[str],
        *,
        stack: Path,
        environment_policy: Path,
        restrictive_umask: bool = False,
    ) -> int:
        """Represent an unsuccessful credential resolution operation."""
        raise CredentialError("Credential resolution failed")

    monkeypatch.setattr(
        "mxm.control.opentofu.run_with_credentials",
        fail_credentials,
    )

    with pytest.raises(
        OpenTofuError,
        match="Credential resolution failed",
    ):
        check_opentofu(
            root,
            environment_policy=environment_policy,
        )


def test_apply_inherited_uses_exact_saved_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Apply the reviewed plan using the existing process environment."""
    root = tmp_path / "root"
    root.mkdir()

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
        observed["check"] = check
        observed["umask"] = umask
        return completed(0)

    def unexpected_credentials(*args: object, **kwargs: object) -> None:
        pytest.fail("Inherited apply must not resolve credentials again")

    monkeypatch.setattr(
        "mxm.control.opentofu.subprocess.run",
        fake_run,
    )
    monkeypatch.setattr(
        "mxm.control.opentofu.run_with_credentials",
        unexpected_credentials,
    )

    result = apply_opentofu_inherited(root, plan)

    assert result == plan
    assert observed == {
        "command": [
            "tofu",
            f"-chdir={root}",
            "apply",
            "-input=false",
            str(plan),
        ],
        "check": False,
        "umask": 0o077,
    }


@pytest.mark.parametrize("returncode", [1, 2, 127])
def test_apply_inherited_reports_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    returncode: int,
) -> None:
    """Propagate unsuccessful OpenTofu execution as OpenTofuError."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    def fake_run(
        command: list[str],
        *,
        check: bool,
        umask: int,
    ) -> subprocess.CompletedProcess[str]:
        return completed(returncode)

    monkeypatch.setattr(
        "mxm.control.opentofu.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        OpenTofuError,
        match=f"apply failed with exit status {returncode}",
    ):
        apply_opentofu_inherited(root, plan)


def test_apply_inherited_rejects_insecure_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reject a plan readable by users other than its owner."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o644)

    def unexpected_run(*args: object, **kwargs: object) -> None:
        pytest.fail("OpenTofu must not execute with an insecure plan")

    monkeypatch.setattr(
        "mxm.control.opentofu.subprocess.run",
        unexpected_run,
    )

    with pytest.raises(
        OpenTofuError,
        match="permissions must be owner-only",
    ):
        apply_opentofu_inherited(root, plan)


def test_apply_inherited_rejects_symlink_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Refuse symbolic links to saved plans."""
    root = tmp_path / "root"
    root.mkdir()

    target = tmp_path / "target.plan"
    target.write_bytes(b"saved plan")
    target.chmod(0o600)

    plan = tmp_path / "reviewed.plan"
    plan.symlink_to(target)

    def unexpected_run(*args: object, **kwargs: object) -> None:
        pytest.fail("OpenTofu must not execute with a symlink plan")

    monkeypatch.setattr(
        "mxm.control.opentofu.subprocess.run",
        unexpected_run,
    )

    with pytest.raises(
        OpenTofuError,
        match="must not be a symbolic link",
    ):
        apply_opentofu_inherited(root, plan)


def test_apply_inherited_rejects_invalid_root(
    tmp_path: Path,
) -> None:
    """Require an existing OpenTofu root directory."""
    root = tmp_path / "invalid.tf"
    root.write_text("")

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    with pytest.raises(
        OpenTofuError,
        match="not a directory",
    ):
        apply_opentofu_inherited(root, plan)


def test_apply_inherited_reports_missing_executable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Translate a missing OpenTofu executable into OpenTofuError."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    def missing_executable(
        *args: object,
        **kwargs: object,
    ) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(
        "mxm.control.opentofu.subprocess.run",
        missing_executable,
    )

    with pytest.raises(
        OpenTofuError,
        match="OpenTofu executable not found",
    ):
        apply_opentofu_inherited(root, plan)


def test_apply_inherited_reports_process_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Translate operating-system execution errors into OpenTofuError."""
    root = tmp_path / "root"
    root.mkdir()

    plan = tmp_path / "reviewed.plan"
    plan.write_bytes(b"saved plan")
    plan.chmod(0o600)

    def failed_execution(
        *args: object,
        **kwargs: object,
    ) -> None:
        raise OSError("Process unavailable")

    monkeypatch.setattr(
        "mxm.control.opentofu.subprocess.run",
        failed_execution,
    )

    with pytest.raises(
        OpenTofuError,
        match="Unable to execute OpenTofu apply",
    ):
        apply_opentofu_inherited(root, plan)
