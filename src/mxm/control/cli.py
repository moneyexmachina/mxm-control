"""Human-operated CLI for MXM computational estate control.

The CLI exposes infrastructure reconciliation, machine-bootstrap planning,
GitHub policy management, and operator authentication.

OpenTofu commands operate on individual root modules. Machine-bootstrap
planning coordinates infrastructure creation with the enrollment authority
needed to establish a machine's initial trusted management identity.
"""

from pathlib import Path
from typing import Annotated

import typer

from mxm.control import operator
from mxm.control.github.actions_policy import (
    ActionsPolicyError,
    PlanAction,
    apply_actions_policy,
    plan_actions_policy,
)
from mxm.control.github.api import GitHubApi, GitHubApiError
from mxm.control.machine_bootstrap import (
    MachineBootstrapError,
    apply_machine_bootstrap,
    plan_machine_bootstrap,
)
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
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ],
    out: Annotated[Path, typer.Option("--out")],
    environment_policy: Annotated[
        Path,
        typer.Option(
            "--environment-policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Authoritative operator environment policy.",
        ),
    ],
) -> None:
    """Create a saved OpenTofu plan without modifying realised state."""
    try:
        plan = plan_opentofu(root, environment_policy, out)
    except OpenTofuError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        {plan}")


@plan_app.command("machine-bootstrap")
def plan_machine_bootstrap_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ],
    out: Annotated[Path, typer.Option("--out")],
    environment_policy: Annotated[
        Path,
        typer.Option(
            "--environment-policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Authoritative operator environment policy.",
        ),
    ],
) -> None:
    """Plan machine creation with the required Tailscale enrollment authority."""
    try:
        plan = plan_machine_bootstrap(root, environment_policy, out)
    except MachineBootstrapError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        {plan}")


@check_app.command("opentofu")
def check_opentofu_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ],
    environment_policy: Annotated[
        Path,
        typer.Option(
            "--environment-policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Authoritative operator environment policy.",
        ),
    ],
) -> None:
    """Check an OpenTofu root module for drift."""
    try:
        result = check_opentofu(root, environment_policy=environment_policy)
    except OpenTofuError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if result is OpenTofuCheckResult.NO_CHANGE:
        typer.echo(f"OK        {root.resolve()}")
        return

    typer.echo(f"DRIFT     {root.resolve()}", err=True)
    raise typer.Exit(2)


@apply_app.command("opentofu")
def apply_opentofu_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ],
    environment_policy: Annotated[
        Path,
        typer.Option(
            "--environment-policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Authoritative operator environment policy.",
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
        applied_plan = apply_opentofu(root, environment_policy, plan)
    except OpenTofuError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        {applied_plan}")


@apply_app.command("machine-bootstrap")
def apply_machine_bootstrap_command(
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
    environment_policy: Annotated[
        Path,
        typer.Option(
            "--environment-policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Authoritative operator environment policy.",
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
            help="Existing reviewed machine-bootstrap OpenTofu plan.",
        ),
    ],
    expected_hostname: Annotated[
        str,
        typer.Option(
            "--expected-hostname",
            help="Expected hostname of the replacement Tailscale device.",
        ),
    ],
    recovery_verified: Annotated[
        bool,
        typer.Option(
            "--recovery-verified",
            help="Acknowledge verified recovery material for the existing machine.",
        ),
    ] = False,
    confirmation: Annotated[
        str,
        typer.Option(
            "--confirmation",
            help="Explicit machine replacement confirmation.",
        ),
    ] = "",
) -> None:
    """Apply a reviewed L1 machine replacement and verify Tailscale SSH."""
    try:
        applied_plan = apply_machine_bootstrap(
            root=stack,
            environment_policy=environment_policy,
            plan=plan,
            expected_hostname=expected_hostname,
            recovery_verified=recovery_verified,
            confirmation=confirmation,
        )
    except MachineBootstrapError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        Machine bootstrap completed: {applied_plan}")


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


@app.command("login")
def login_command() -> None:
    """Establish or reuse the authenticated operator session."""
    try:
        operator.login()
    except operator.OperatorError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo("OK        Proton Pass session available")


@app.command("status")
def status_command() -> None:
    """Report authentication status for all operator backends."""
    try:
        result = operator.operator_status()
    except operator.OperatorError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"{'OK' if result.proton_pass else 'UNAUTHENTICATED':<17} Proton Pass")
    typer.echo(f"{'OK' if result.github else 'UNAUTHENTICATED':<17} GitHub CLI")

    if not result.authenticated:
        raise typer.Exit(1)


@app.command("logout")
def logout_command() -> None:
    """Terminate the authenticated operator session."""
    try:
        operator.logout()
    except operator.OperatorError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo("OK        Proton Pass session terminated")
