"""Human-operated CLI for MXM computational estate control.

Expose planning, preflight verification, application, drift checking, and
operator authentication through reusable control-plane mechanisms.

OpenTofu commands operate on individual root modules. Machine bootstrap
coordinates provisioning and Tailscale enrollment for named singleton
machines, without managing application or service restoration.
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
    preflight_machine_bootstrap_credentials,
)
from mxm.control.opentofu import (
    OpenTofuCheckResult,
    OpenTofuError,
    apply_opentofu,
    check_opentofu,
    plan_opentofu,
)

app = typer.Typer(
    help="Human-operated control mechanisms for the MXM computational estate.",
)

plan_app = typer.Typer(
    help="Produce plans without modifying realised state.",
)
preflight_app = typer.Typer(
    help="Verify prerequisites before applying planned changes.",
)
apply_app = typer.Typer(
    help="Apply reviewed plans to realised state.",
)
check_app = typer.Typer(
    help="Check realised state against declared intent.",
)

app.add_typer(plan_app, name="plan")
app.add_typer(preflight_app, name="preflight")
app.add_typer(apply_app, name="apply")
app.add_typer(check_app, name="check")


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


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
            help="OpenTofu root module.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            help="Destination for the saved OpenTofu plan.",
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
            help="OpenTofu root module for the singleton machine.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            help="Destination for the saved machine-bootstrap plan.",
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
    """Plan machine provisioning with fresh Tailscale enrollment authority."""
    try:
        plan = plan_machine_bootstrap(root, environment_policy, out)
    except MachineBootstrapError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        {plan}")


@plan_app.command("github-actions")
def plan_github_actions(
    organization: Annotated[
        str,
        typer.Option(
            "--organization",
            help="GitHub organization whose Actions policy is being planned.",
        ),
    ],
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Declared GitHub Actions policy.",
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


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


@preflight_app.command("machine-bootstrap")
def preflight_machine_bootstrap_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="OpenTofu root module for the singleton machine.",
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
            help="Existing saved machine-bootstrap OpenTofu plan.",
        ),
    ],
) -> None:
    """Validate a bootstrap plan and discover Tailscale registrations.

    Inspect the saved plan and the live Tailscale inventory without
    modifying device registrations or infrastructure resources.
    """
    try:
        preflight_machine_bootstrap_credentials(
            root,
            environment_policy,
            plan,
        )
    except MachineBootstrapError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


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
            help="OpenTofu root module.",
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
            help="Existing reviewed OpenTofu plan.",
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
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="OpenTofu root module for the singleton machine.",
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
) -> None:
    """Apply a saved singleton-machine plan and verify Tailscale SSH.

    Retire previous registrations matching the planned service tag,
    apply the saved OpenTofu plan, and verify the replacement machine.

    This operation does not install or restore application services.
    """
    try:
        applied_plan = apply_machine_bootstrap(
            root=root,
            environment_policy=environment_policy,
            plan=plan,
        )
    except MachineBootstrapError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        Machine bootstrap completed: {applied_plan}")


@apply_app.command("github-actions")
def apply_github_actions(
    organization: Annotated[
        str,
        typer.Option(
            "--organization",
            help="GitHub organization whose Actions policy is being applied.",
        ),
    ],
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Declared GitHub Actions policy.",
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


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------


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
            help="OpenTofu root module.",
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


@check_app.command("github-actions")
def check_github_actions(
    organization: Annotated[
        str,
        typer.Option(
            "--organization",
            help="GitHub organization whose Actions policy is being checked.",
        ),
    ],
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Declared GitHub Actions policy.",
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


# ---------------------------------------------------------------------------
# Operator authentication
# ---------------------------------------------------------------------------


@app.command("login")
def login_command() -> None:
    """Establish or reuse the authenticated Proton Pass operator session."""
    try:
        operator.login()
    except operator.OperatorError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo("OK        Proton Pass session available")


@app.command("status")
def status_command() -> None:
    """Report authentication status for the operator backends."""
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
    """Terminate the authenticated Proton Pass operator session."""
    try:
        operator.logout()
    except operator.OperatorError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo("OK        Proton Pass session terminated")
