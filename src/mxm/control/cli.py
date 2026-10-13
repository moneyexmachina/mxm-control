from pathlib import Path
from typing import Annotated

import typer

from mxm.control.github.actions_policy import (
    ActionsPolicyError,
    PlanAction,
    apply_actions_policy,
    plan_actions_policy,
)
from mxm.control.github.api import GitHubApi, GitHubApiError

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
    try:
        plan = plan_actions_policy(
            GitHubApi(),
            organization,
            policy,
        )
    except (ActionsPolicyError, GitHubApiError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"{plan.action.value:<10} {plan.name}")


@check_app.command("github-actions")
def check_github_actions(
    organization: Annotated[str, typer.Option("--organization")],
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
    try:
        plan = plan_actions_policy(
            GitHubApi(),
            organization,
            policy,
        )
    except (ActionsPolicyError, GitHubApiError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if plan.action is PlanAction.NO_CHANGE:
        typer.echo(f"OK        {plan.name}")
        return

    typer.echo(
        f"DRIFT     {plan.name} ({plan.action.value})",
        err=True,
    )
    raise typer.Exit(1)


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
    try:
        result = apply_actions_policy(
            GitHubApi(),
            organization,
            policy,
        )
    except (ActionsPolicyError, GitHubApiError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        {result.name}")
