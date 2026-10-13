from typer.testing import CliRunner

from mxm.control.cli import app

runner = CliRunner()


def test_help_exposes_control_operations() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "plan" in result.stdout
    assert "apply" in result.stdout
    assert "check" in result.stdout
