"""Shared pytest fixtures for MXM Control tests."""

from pathlib import Path

import pytest


@pytest.fixture
def environment_policy(tmp_path: Path) -> Path:
    """Create a valid synthetic operator environment policy."""
    path = tmp_path / "environment.toml"
    path.write_text(
        "[inheritance]\n"
        'strip = ["HCLOUD_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"]\n'
        'strip_prefixes = ["TF_VAR_", "TF_CLI_ARGS"]\n',
        encoding="utf-8",
    )
    return path
