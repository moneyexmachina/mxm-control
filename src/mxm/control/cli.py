from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(help="Reusable control mechanisms for the MXM computational estate.")

plan_app = typer.Typer(help="Plan changes without modifying realised state.")
apply_app = typer.Typer(help="Reconcile realised state with desired state.")
check_app = typer.Typer(help="Check realised state against desired state.")

app.add_typer(plan_app, name="plan")
app.add_typer(apply_app, name="apply")
app.add_typer(check_app, name="check")


@plan_app.command("github-actions")
def plan_github_actions(
    organization: Annotated[
        str,
        typer.Option("--organization"),
    ],
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Plan reconciliation of a GitHub organization Actions policy."""
    raise NotImplementedError


@check_app.command("github-actions")
def check_github_actions(
    organization: Annotated[
        str,
        typer.Option("--organization"),
    ],
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Check a GitHub organization Actions policy for drift."""
    raise NotImplementedError


@apply_app.command("github-actions")
def apply_github_actions(
    organization: Annotated[
        str,
        typer.Option("--organization"),
    ],
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Reconcile a GitHub organization Actions policy."""
    raise NotImplementedError
