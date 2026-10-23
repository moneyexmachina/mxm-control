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
from mxm.control.opentofu import (
    OpenTofuCheckResult,
    OpenTofuError,
    apply_opentofu,
    check_opentofu,
    plan_opentofu,
)

app = typer.Typer(help="Reusable control mechanisms for the MXM computational estate.")

plan_app = typer.Typer(help="Plan changes without modifying realised state.")
apply_app = typer.Typer(help="Reconcile realised state with desired state.")
check_app = typer.Typer(help="Check realised state against desired state.")

app.add_typer(plan_app, name="plan")
app.add_typer(apply_app, name="apply")
app.add_typer(check_app, name="check")


@plan_app.command("opentofu")
def plan_opentofu_command(
    stack: Annotated[
        Path,
        typer.Option(
            "--stack",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ],
    out: Annotated[Path, typer.Option("--out")],
) -> None:
    """Create a saved OpenTofu plan without modifying realised state."""
    try:
        plan = plan_opentofu(stack, out)
    except OpenTofuError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        {plan}")


@check_app.command("opentofu")
def check_opentofu_command(
    stack: Annotated[
        Path,
        typer.Option(
            "--stack",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ],
) -> None:
    """Check an OpenTofu stack for drift."""
    try:
        result = check_opentofu(stack)
    except OpenTofuError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if result is OpenTofuCheckResult.NO_CHANGE:
        typer.echo(f"OK        {stack.resolve()}")
        return

    typer.echo(f"DRIFT     {stack.resolve()}", err=True)
    raise typer.Exit(2)


@apply_app.command("opentofu")
def apply_opentofu_command(
    stack: Annotated[
        Path,
        typer.Option(
            "--stack",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ],
    plan: Annotated[
        Path,
        typer.Option(
            "--plan",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Apply exactly one existing, reviewed OpenTofu plan."""
    try:
        applied_plan = apply_opentofu(stack, plan)
    except OpenTofuError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        {applied_plan}")


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
