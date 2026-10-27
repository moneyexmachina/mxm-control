"""Unit tests for MXM estate-control credential bindings.

All subprocess execution is mocked. Tests use synthetic Proton Pass
references and must never access real credentials, operator sessions,
or external infrastructure.
"""

import subprocess
from pathlib import Path
from typing import Any

import pytest

from mxm.control import credentials

SHARE_ID = "syntheticShareId123=="
ITEM_ID = "syntheticItemId456=="

HCLOUD_REFERENCE = f"pass://{SHARE_ID}/{ITEM_ID}/API key"
CLIENT_ID_REFERENCE = f"pass://{SHARE_ID}/{ITEM_ID}/client-id"
CLIENT_SECRET_REFERENCE = f"pass://{SHARE_ID}/{ITEM_ID}/client-secret"


def completed(returncode: int) -> subprocess.CompletedProcess[str]:
    """Create a subprocess result with the requested exit status."""
    return subprocess.CompletedProcess(args=[], returncode=returncode)


def write_manifest(stack: Path, content: str) -> Path:
    """Write a synthetic stack-local credential manifest."""
    manifest = stack / credentials.CREDENTIALS_FILENAME
    manifest.write_text(content, encoding="utf-8")
    return manifest


def valid_manifest() -> str:
    """Return a valid manifest containing three provider bindings."""
    return f"""
[environment]
HCLOUD_TOKEN = "{HCLOUD_REFERENCE}"
TAILSCALE_OAUTH_CLIENT_ID = "{CLIENT_ID_REFERENCE}"
TAILSCALE_OAUTH_CLIENT_SECRET = "{CLIENT_SECRET_REFERENCE}"
"""


def test_missing_manifest_returns_empty_bindings(tmp_path: Path) -> None:
    """A stack without credential declarations requires no injection."""
    assert credentials.load_credentials(tmp_path) == {}


def test_valid_manifest_loads_bindings(tmp_path: Path) -> None:
    """Valid declarations are returned without resolving secrets."""
    write_manifest(tmp_path, valid_manifest())

    assert credentials.load_credentials(tmp_path) == {
        "HCLOUD_TOKEN": HCLOUD_REFERENCE,
        "TAILSCALE_OAUTH_CLIENT_ID": CLIENT_ID_REFERENCE,
        "TAILSCALE_OAUTH_CLIENT_SECRET": CLIENT_SECRET_REFERENCE,
    }


def test_nonexistent_stack_is_rejected(tmp_path: Path) -> None:
    """Credential declarations require an existing stack directory."""
    stack = tmp_path / "missing"

    with pytest.raises(
        credentials.CredentialError,
        match="Credential stack directory does not exist",
    ):
        credentials.load_credentials(stack)


def test_manifest_symlink_is_rejected(tmp_path: Path) -> None:
    """A manifest must not redirect resolution through a symbolic link."""
    source = tmp_path / "source.toml"
    source.write_text(valid_manifest(), encoding="utf-8")

    stack = tmp_path / "stack"
    stack.mkdir()
    (stack / credentials.CREDENTIALS_FILENAME).symlink_to(source)

    with pytest.raises(
        credentials.CredentialError,
        match="must not be a symbolic link",
    ):
        credentials.load_credentials(stack)


def test_non_regular_manifest_is_rejected(tmp_path: Path) -> None:
    """A directory cannot masquerade as a credential manifest."""
    (tmp_path / credentials.CREDENTIALS_FILENAME).mkdir()

    with pytest.raises(
        credentials.CredentialError,
        match="not a regular file",
    ):
        credentials.load_credentials(tmp_path)


def test_invalid_toml_is_rejected(tmp_path: Path) -> None:
    """Malformed TOML must fail before any operation is executed."""
    write_manifest(tmp_path, "[environment\nHCLOUD_TOKEN = 123")

    with pytest.raises(
        credentials.CredentialError,
        match="Unable to read credential manifest",
    ):
        credentials.load_credentials(tmp_path)


@pytest.mark.parametrize(
    "manifest",
    [
        "",
        '[credentials]\nHCLOUD_TOKEN = "value"\n',
        "[environment]\n",
        valid_manifest() + "\n[additional]\nvalue = 1\n",
    ],
)
def test_invalid_manifest_structure_is_rejected(
    tmp_path: Path,
    manifest: str,
) -> None:
    """Only a non-empty environment binding table is supported."""
    write_manifest(tmp_path, manifest)

    with pytest.raises(credentials.CredentialError):
        credentials.load_credentials(tmp_path)


@pytest.mark.parametrize(
    "name",
    [
        "INVALID-NAME",
        "INVALID NAME",
        "123_INVALID",
        "INVALID.NAME",
        "",
    ],
)
def test_invalid_environment_variable_names_are_rejected(
    tmp_path: Path,
    name: str,
) -> None:
    """Bindings must use valid environment variable identifiers."""
    write_manifest(
        tmp_path,
        f'[environment]\n"{name}" = "{HCLOUD_REFERENCE}"\n',
    )

    with pytest.raises(
        credentials.CredentialError,
        match="Invalid credential environment variable name",
    ):
        credentials.load_credentials(tmp_path)


@pytest.mark.parametrize(
    "reference",
    [
        "plaintext-secret",
        "https://example.com/credential",
        "pass://share-id/item-id",
        "pass://share-id/item-id/field/extra",
        "pass:///item-id/field",
        "pass://share-id//field",
        "pass://share-id/item-id/",
        "pass://share-id/item-id/ field",
        "pass://share-id/item-id/field ",
        "pass://share-id/item-id/field\nname",
    ],
)
def test_invalid_secret_references_are_rejected(
    tmp_path: Path,
    reference: str,
) -> None:
    """Malformed or noncanonical references must never be accepted."""
    import json

    write_manifest(
        tmp_path,
        f"[environment]\nHCLOUD_TOKEN = {json.dumps(reference)}\n",
    )

    with pytest.raises(credentials.CredentialError):
        credentials.load_credentials(tmp_path)


def test_reference_validation_does_not_verify_identifier_existence(
    tmp_path: Path,
) -> None:
    """Syntactically valid IDs are accepted without querying Proton Pass."""
    reference = "pass://synthetic-share/synthetic-item/client-id"

    write_manifest(
        tmp_path,
        f'[environment]\nCLIENT_ID = "{reference}"\n',
    )

    assert credentials.load_credentials(tmp_path) == {
        "CLIENT_ID": reference,
    }


def test_non_string_binding_is_rejected(tmp_path: Path) -> None:
    """Environment bindings must contain string references."""
    write_manifest(tmp_path, "[environment]\nHCLOUD_TOKEN = 123\n")

    with pytest.raises(
        credentials.CredentialError,
        match="must be a string",
    ):
        credentials.load_credentials(tmp_path)


def test_empty_command_is_rejected(
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """The execution mechanism must reject an empty command."""
    with pytest.raises(
        credentials.CredentialError,
        match="Cannot execute an empty command",
    ):
        credentials.run_with_credentials(
            [], stack=tmp_path, environment_policy=environment_policy
        )


def test_command_without_manifest_runs_directly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """A credential-free operation must not require Proton Pass."""
    observed: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["kwargs"] = kwargs
        return completed(0)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)
    monkeypatch.setenv("GITHUB_TOKEN", "unwanted")
    monkeypatch.setenv("HCLOUD_TOKEN", "unwanted")
    monkeypatch.setenv("TF_VAR_unwanted", "unwanted")
    monkeypatch.setenv("MXM_TEST_PRESERVED", "preserved")
    result = credentials.run_with_credentials(
        ["tofu", "version"],
        stack=tmp_path,
        environment_policy=environment_policy,
    )

    assert result == 0
    assert observed["command"] == ["tofu", "version"]
    environment = observed["kwargs"]["env"]

    assert isinstance(environment, dict)

    assert observed["kwargs"]["check"] is False
    assert "GITHUB_TOKEN" not in environment
    assert "HCLOUD_TOKEN" not in environment
    assert "TF_VAR_unwanted" not in environment
    assert environment["MXM_TEST_PRESERVED"] == "preserved"


def test_command_with_bindings_uses_pass_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Declared references are passed to Proton Pass for resolution."""
    write_manifest(tmp_path, valid_manifest())

    observed: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["kwargs"] = kwargs
        return completed(0)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    result = credentials.run_with_credentials(
        ["tofu", "plan", "-input=false"],
        stack=tmp_path,
        environment_policy=environment_policy,
    )

    assert result == 0
    assert observed["command"] == [
        "pass-cli",
        "run",
        "--",
        "tofu",
        "plan",
        "-input=false",
    ]

    environment = observed["kwargs"]["env"]

    assert environment["HCLOUD_TOKEN"] == HCLOUD_REFERENCE
    assert environment["TAILSCALE_OAUTH_CLIENT_ID"] == CLIENT_ID_REFERENCE
    assert environment["TAILSCALE_OAUTH_CLIENT_SECRET"] == CLIENT_SECRET_REFERENCE
    assert observed["kwargs"]["check"] is False


def test_declared_binding_overrides_inherited_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Stack declarations override matching inherited variable names."""
    write_manifest(
        tmp_path,
        f'[environment]\nHCLOUD_TOKEN = "{HCLOUD_REFERENCE}"\n',
    )

    monkeypatch.setenv("HCLOUD_TOKEN", "inherited-placeholder")

    observed: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed["environment"] = kwargs["env"]
        return completed(0)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    credentials.run_with_credentials(
        ["tofu", "plan"],
        stack=tmp_path,
        environment_policy=environment_policy,
    )

    assert observed["environment"]["HCLOUD_TOKEN"] == HCLOUD_REFERENCE


def test_unrelated_environment_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """The initial implementation preserves unrelated shell variables."""
    write_manifest(
        tmp_path,
        f'[environment]\nHCLOUD_TOKEN = "{HCLOUD_REFERENCE}"\n',
    )

    monkeypatch.setenv("MXM_SYNTHETIC_TEST_VARIABLE", "test-value")

    observed: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed["environment"] = kwargs["env"]
        return completed(0)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    credentials.run_with_credentials(
        ["tofu", "plan"],
        stack=tmp_path,
        environment_policy=environment_policy,
    )

    assert observed["environment"]["MXM_SYNTHETIC_TEST_VARIABLE"] == "test-value"


@pytest.mark.parametrize("returncode", [0, 1, 2, 17])
def test_subprocess_exit_status_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
    returncode: int,
) -> None:
    """Execution returns the subprocess status without reinterpretation."""
    write_manifest(tmp_path, valid_manifest())

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        return completed(returncode)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    assert (
        credentials.run_with_credentials(
            ["tofu", "plan"],
            stack=tmp_path,
            environment_policy=environment_policy,
        )
        == returncode
    )


def test_restrictive_umask_is_forwarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Credential-bound operations preserve owner-only file creation."""
    write_manifest(tmp_path, valid_manifest())

    observed: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed["umask"] = kwargs["umask"]
        return completed(0)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    credentials.run_with_credentials(
        ["tofu", "plan"],
        stack=tmp_path,
        environment_policy=environment_policy,
        restrictive_umask=True,
    )

    assert observed["umask"] == 0o077


def test_default_umask_is_inherited(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Normal operations retain the caller's existing file creation mask."""
    observed: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed["umask"] = kwargs["umask"]
        return completed(0)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    credentials.run_with_credentials(
        ["tofu", "version"],
        stack=tmp_path,
        environment_policy=environment_policy,
    )

    assert observed["umask"] == -1


def test_missing_pass_cli_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """A missing credential resolver produces a controlled failure."""
    write_manifest(tmp_path, valid_manifest())

    def fake_run(*args: Any, **kwargs: Any) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    with pytest.raises(
        credentials.CredentialError,
        match="Required executable not found: pass-cli",
    ):
        credentials.run_with_credentials(
            ["tofu", "plan"],
            stack=tmp_path,
            environment_policy=environment_policy,
        )


def test_subprocess_os_error_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """OS-level execution failures raise CredentialError."""
    write_manifest(tmp_path, valid_manifest())

    def fake_run(*args: Any, **kwargs: Any) -> None:
        raise OSError("Permission denied")

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    with pytest.raises(
        credentials.CredentialError,
        match="Unable to execute credential-bound command",
    ):
        credentials.run_with_credentials(
            ["tofu", "plan"],
            stack=tmp_path,
            environment_policy=environment_policy,
        )


def test_invalid_manifest_prevents_command_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Invalid credentials must fail before any subprocess is started."""
    write_manifest(
        tmp_path,
        '[environment]\nHCLOUD_TOKEN = "plaintext-secret"\n',
    )

    def must_not_run(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Subprocess must not execute with invalid credentials")

    monkeypatch.setattr(credentials.subprocess, "run", must_not_run)

    with pytest.raises(credentials.CredentialError):
        credentials.run_with_credentials(
            ["tofu", "plan"],
            stack=tmp_path,
            environment_policy=environment_policy,
        )


@pytest.mark.parametrize(
    "contents",
    [
        "",
        "[other]\nstrip = []\n",
        "[inheritance]\nstrip = []\n",
        '[inheritance]\nstrip = "HCLOUD_TOKEN"\nstrip_prefixes = []\n',
        "[inheritance]\nstrip = [123]\nstrip_prefixes = []\n",
        '[inheritance]\nstrip = ["INVALID-NAME"]\nstrip_prefixes = []\n',
        '[inheritance]\nstrip = ["HCLOUD_TOKEN", "HCLOUD_TOKEN"]\nstrip_prefixes = []\n',
        '[inheritance]\nstrip = []\nstrip_prefixes = [""]\n',
        '[inheritance]\nstrip = []\nstrip_prefixes = ["TF_VAR_", "TF_VAR_"]\n',
        '[inheritance]\nstrip = ["TF_VAR_secret"]\nstrip_prefixes = ["TF_VAR_"]\n',
        '[inheritance]\nstrip = []\nstrip_prefixes = ["TF_", "TF_VAR_"]\n',
        "[inheritance\n",
    ],
)
def test_environment_policy_rejects_invalid_declarations(
    tmp_path: Path,
    contents: str,
) -> None:
    """Reject malformed or ambiguous environment policies."""
    policy_path = tmp_path / "environment.toml"
    policy_path.write_text(contents, encoding="utf-8")

    with pytest.raises(credentials.CredentialError):
        credentials.load_environment_policy(policy_path)


def test_environment_policy_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """A missing policy must not silently enable unrestricted inheritance."""
    with pytest.raises(credentials.CredentialError):
        credentials.load_environment_policy(tmp_path / "missing-environment.toml")


def test_environment_policy_rejects_symlink(
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Reject a symbolic link supplied as the policy file."""
    link = tmp_path / "environment-link.toml"
    link.symlink_to(environment_policy)

    with pytest.raises(
        credentials.CredentialError,
        match="symbolic link",
    ):
        credentials.load_environment_policy(link)


def test_filter_environment_removes_prohibited_inheritance(
    environment_policy: Path,
) -> None:
    """Remove prohibited names and prefixes while preserving other variables."""
    policy = credentials.load_environment_policy(environment_policy)

    inherited = {
        "PATH": "/usr/bin",
        "HOME": "/home/operator",
        "HCLOUD_TOKEN": "inherited-hetzner",
        "GITHUB_TOKEN": "inherited-github",
        "GH_TOKEN": "inherited-gh",
        "TF_VAR_secret": "inherited-input",
        "TF_CLI_ARGS_plan": "-lock=false",
        "MXM_TEST_PRESERVED": "preserved",
    }

    result = credentials.filter_environment(inherited, policy)

    assert result == {
        "PATH": "/usr/bin",
        "HOME": "/home/operator",
        "MXM_TEST_PRESERVED": "preserved",
    }

    # Filtering must not mutate the operator's original environment.
    assert inherited["HCLOUD_TOKEN"] == "inherited-hetzner"
    assert inherited["TF_VAR_secret"] == "inherited-input"


def test_declared_credentials_replace_inherited_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_policy: Path,
) -> None:
    """Explicit bindings replace inherited provider credentials."""
    stack = tmp_path / "stack"
    stack.mkdir()

    reference = "pass://test-share/test-item/API-key"

    (stack / "credentials.toml").write_text(
        f'[environment]\nHCLOUD_TOKEN = "{reference}"\n',
        encoding="utf-8",
    )

    monkeypatch.setenv("HCLOUD_TOKEN", "inherited-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "unrelated-inherited-secret")
    monkeypatch.setenv("MXM_TEST_PRESERVED", "preserved")

    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        return completed(0)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    result = credentials.run_with_credentials(
        ["tofu", "version"],
        stack=stack,
        environment_policy=environment_policy,
    )

    assert result == 0
    assert observed["command"] == [
        "pass-cli",
        "run",
        "--",
        "tofu",
        "version",
    ]

    environment = observed["environment"]
    assert isinstance(environment, dict)

    assert environment["HCLOUD_TOKEN"] == reference
    assert "GITHUB_TOKEN" not in environment
    assert environment["MXM_TEST_PRESERVED"] == "preserved"


@pytest.mark.parametrize(
    "contents",
    [
        None,
        "",
        "[inheritance]\nstrip = []\n",
        '[inheritance]\nstrip = ["HCLOUD_TOKEN", "HCLOUD_TOKEN"]\nstrip_prefixes = []\n',
    ],
)
def test_invalid_environment_policy_prevents_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    contents: str | None,
) -> None:
    """Invalid or missing policy must stop execution before subprocess creation."""
    stack = tmp_path / "stack"
    stack.mkdir()

    policy_path = tmp_path / "environment.toml"

    if contents is not None:
        policy_path.write_text(contents, encoding="utf-8")

    observed: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return completed(0)

    monkeypatch.setattr(credentials.subprocess, "run", fake_run)

    with pytest.raises(credentials.CredentialError):
        credentials.run_with_credentials(
            ["tofu", "version"],
            stack=stack,
            environment_policy=policy_path,
        )

    assert observed == []
