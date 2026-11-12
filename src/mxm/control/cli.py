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
from mxm.control.ansible import (
    AnsibleError,
    apply_ansible,
    plan_ansible,
)
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
from mxm.control.openbao.api import OpenBaoError
from mxm.control.openbao.restore import (
    OpenBaoRecoveryInterruptedError,
    OpenBaoRestorePlan,
    restore_openbao,
)
from mxm.control.openbao.status import status_openbao
from mxm.control.openbao.unseal import unseal_openbao
from mxm.control.opentofu import (
    OpenTofuCheckResult,
    OpenTofuError,
    apply_opentofu,
    check_opentofu,
    plan_opentofu,
)
from mxm.control.secret_entry import (
    SecretEntryCancelled,
    SecretEntryError,
    prompt_secret,
)
from mxm.control.service import ServiceError, resolve_service
from mxm.control.snapshot import SnapshotError
from mxm.control.tailscale_ansible import (
    TailscaleAnsibleError,
    check_ansible_ssh,
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
openbao_app = typer.Typer(
    help="Operate estate-managed OpenBao authorities.",
)
app.add_typer(plan_app, name="plan")
app.add_typer(preflight_app, name="preflight")
app.add_typer(apply_app, name="apply")
app.add_typer(check_app, name="check")
app.add_typer(openbao_app, name="openbao")


def _estate_root() -> Path:
    """Locate the operator workstation's mxm-estate checkout."""
    return Path.home() / "mxm-estate"


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
@preflight_app.command("ansible-ssh")
def preflight_ansible_ssh_command(
    host: Annotated[
        str,
        typer.Option(
            "--host",
            help="Short or fully qualified Tailscale machine hostname.",
        ),
    ],
    user: Annotated[
        str,
        typer.Option(
            "--user",
            help="Remote Unix account used for Tailscale SSH.",
        ),
    ] = "mxm",
) -> None:
    """Verify Ansible connectivity through authenticated Tailscale SSH.

    Resolve the target's canonical Tailscale identity, verify SSH access
    and host keys, then execute a read-only Ansible ping.

    This command does not modify remote machine configuration.
    """
    try:
        check_ansible_ssh(
            host=host,
            user=user,
        )
    except TailscaleAnsibleError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        Ansible Tailscale SSH: {user}@{host}")


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


@apply_app.command("ansible")
def apply_ansible_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Estate Ansible deployment root.",
        ),
    ],
) -> None:
    """Reconcile a machine using its estate-defined Ansible playbook.

    Resolve the target and remote user from the estate inventory,
    establish verified Tailscale SSH access, and execute the playbook.

    Ansible evaluates the current machine state during application.
    """
    try:
        deployment = apply_ansible(root=root)
    except AnsibleError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"OK        Ansible applied: {deployment.root}")


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


@check_app.command("ansible")
def check_ansible_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Estate Ansible deployment root.",
        ),
    ],
) -> None:
    """Preview estate configuration using Ansible check and diff modes.

    Resolve the target from the estate inventory and execute the
    playbook with --check --diff.

    The output is predictive, not a saved executable plan.
    A successful check does not imply the absence of changes.
    """
    try:
        deployment = plan_ansible(root=root)
    except AnsibleError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"PREVIEW   Ansible check completed: {deployment.root}")


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


# ---------------------------------------------------------------------------
# OpenBao operator operations
# ---------------------------------------------------------------------------


@openbao_app.command("status")
def openbao_status_command() -> None:
    """Inspect the estate-managed OpenBao authority."""
    try:
        target = resolve_service(
            estate_root=_estate_root(),
            name="openbao",
        ).target

        status = status_openbao(target.address)
    except (ServiceError, OpenBaoError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"Service      {target.name}")
    typer.echo(f"Address      {target.address}")
    typer.echo(f"Machine      {target.machine}")
    typer.echo(f"Version      {status.version}")
    typer.echo(f"Initialized  {status.initialized}")
    typer.echo(f"Sealed       {status.sealed}")
    typer.echo(f"Seal type    {status.seal_type}")

    if status.initialized:
        typer.echo(f"Shares       {status.shares}")
        typer.echo(f"Threshold    {status.threshold}")

        if status.sealed:
            typer.echo(f"Progress     {status.progress}/{status.threshold}")


@openbao_app.command("unseal")
def openbao_unseal_command() -> None:
    """Unseal the estate-managed OpenBao authority interactively.

    Collect physical Shamir shares from the controlling terminal.
    Shares are never supplied through command-line arguments.
    """

    def get_share(number: int, total: int) -> str:
        typer.echo(f"Enter OpenBao share {number} of {total}")
        return prompt_secret(f"Unseal share {number} of {total}")

    try:
        target = resolve_service(
            estate_root=_estate_root(),
            name="openbao",
        ).target

        typer.echo(f"Service     {target.name}")
        typer.echo(f"Address     {target.address}")

        result = unseal_openbao(
            target.address,
            get_share=get_share,
        )

    except SecretEntryCancelled:
        typer.echo("CANCELLED   OpenBao unseal", err=True)
        raise typer.Exit(130) from None

    except (SecretEntryError, ServiceError, OpenBaoError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if result.sealed:
        typer.echo(
            "INCOMPLETE  OpenBao remains sealed "
            f"({result.progress}/{result.threshold})",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo("OK         OpenBao unsealed")


@openbao_app.command("restore")
def openbao_restore_command(
    snapshot: Annotated[
        str,
        typer.Option(
            "--snapshot",
            help="Local or remote OpenBao Raft snapshot URI.",
        ),
    ],
) -> None:
    """Restore an estate-managed OpenBao authority from a snapshot.

    Display the verified restoration plan and require explicit operator
    authorization before invoking the complete recovery capability.

    Snapshot acquisition, integrity verification, temporary bootstrap,
    restoration, restart, and post-restore verification are delegated
    to restore_openbao().
    """

    def authorize(plan: OpenBaoRestorePlan) -> bool:
        """Present the verified plan and request operator approval."""
        typer.echo("")
        typer.echo("OpenBao authority restoration")
        typer.echo(f"Address     {plan.address}")
        typer.echo(f"Machine     {plan.machine}")
        typer.echo(f"Snapshot    {plan.snapshot_source}")
        typer.echo(f"Size        {plan.snapshot_size} bytes")
        typer.echo(f"SHA-256     {plan.snapshot_sha256}")
        typer.echo(
            f"Seal        {plan.expected_shares} shares / "
            f"threshold {plan.expected_threshold}"
        )

        typer.echo("")
        typer.echo(
            "WARNING: This operation replaces the destination OpenBao authority."
        )
        typer.echo(
            "The destination must be uninitialized. "
            "The original Shamir shares will be required afterward."
        )
        typer.echo("")

        confirmation = typer.prompt(
            "Type RESTORE to authorize",
            default="",
            show_default=False,
        )

        return confirmation == "RESTORE"

    try:
        result = restore_openbao(
            estate_root=_estate_root(),
            snapshot_uri=snapshot,
            authorize=authorize,
        )

    except PermissionError:
        typer.echo("CANCELLED   OpenBao restoration")
        raise typer.Exit(1) from None

    except OpenBaoRecoveryInterruptedError as exc:
        typer.echo(f"INTERRUPTED OpenBao recovery: {exc.phase}", err=True)
        typer.echo(
            "The destination may have changed. "
            "Do not retry without inspecting its state.",
            err=True,
        )

        raise typer.Exit(1) from None

    except (ServiceError, SnapshotError, OpenBaoError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo("")
    typer.echo("OK         OpenBao authority restored")
    typer.echo(f"SHA-256     {result.restore.sha256}")
    typer.echo(f"Size        {result.restore.size} bytes")
    typer.echo(f"Seal        {result.shares} shares / threshold {result.threshold}")
    typer.echo("State       Initialized and sealed")
    typer.echo("")
    typer.echo("Next: unseal OpenBao using the original physical Shamir shares.")
