![Version](https://img.shields.io/github/v/release/moneyexmachina/mxm-control)
![License](https://img.shields.io/github/license/moneyexmachina/mxm-control)
![Python](https://img.shields.io/badge/python-3.13%2B-blue)
[![Checked with pyright](https://microsoft.github.io/pyright/img/pyright_badge.svg)](https://microsoft.github.io/pyright/)

**Reusable mechanisms for controlling a computational estate.**

`mxm-control` is the public mechanism component of the **MXM Estate Control System**. It executes infrastructure and administrative operations against the authoritative declarations maintained separately in the private [`mxm-estate`](https://github.com/moneyexmachina/mxm-estate) repository.

The separation is deliberate:

- **`mxm-control` — how:** reusable operator commands, integrations, validation, and execution mechanisms.
- **`mxm-estate` — what:** concrete resources, topology, identities, policies, and estate-specific configuration.
- **Realised estate — actual state:** the infrastructure, systems, and services resulting from those declarations and operations.

`mxm-control` is not an application runtime and does not contain MXM trading or other domain logic.

## Control model

The control system distinguishes three operational layers:

| Layer | Responsibility | Principal mechanisms |
| --- | --- | --- |
| **L1 — Infrastructure** | Provision machines, networks, firewalls, and initial management identities | OpenTofu, first-boot bootstrap, Tailscale |
| **L2 — Systems** | Configure operating systems, packages, appliances, and service processes | Ansible and host-level configuration |
| **L3 — Services** | Establish and evolve service administrative state and persisted data | Service APIs, native CLIs, migrations, and restoration workflows |

These layers describe the architecture, **not a claim that every layer is fully implemented**.

Changes also have distinct semantics:

- **Reconciliation:** converge on declared intent; use established declarative tools such as OpenTofu where appropriate.
- **Migration:** perform an ordered, reviewable transition when history or sequencing matters.
- **Operation:** perform a specific service-native action or transaction.

The objective is to compose existing tools, not reimplement their state engines or collapse these semantics into one custom orchestrator.

## Current capabilities

The Python CLI currently exposes:

| Command | Purpose |
| --- | --- |
| `mxm-control login` / `status` / `logout` | Manage and inspect operator authentication |
| `mxm-control plan opentofu` | Produce a saved OpenTofu plan |
| `mxm-control apply opentofu` | Apply a saved OpenTofu plan |
| `mxm-control check opentofu` | Check an OpenTofu root for drift |
| `mxm-control plan machine-bootstrap` | Plan singleton-machine creation or replacement with fresh Tailscale enrollment authority |
| `mxm-control preflight machine-bootstrap` | Validate a saved bootstrap plan and discover existing Tailscale registrations without changing them |
| `mxm-control apply machine-bootstrap` | Retire previous singleton registrations, apply the saved plan, and verify new Tailscale enrollment and SSH |
| `mxm-control plan github-actions` / `check github-actions` / `apply github-actions` | Inspect and reconcile a GitHub organization's Actions policy |

Machine bootstrap currently targets **named singleton machines**: one service tag identifies one machine role. During replacement, the mechanism retires all existing Tailscale registrations bearing that exact tag. This is **not** a fleet or ephemeral-worker lifecycle manager.

The L1 machine-provisioning and Tailscale-enrollment flow has been exercised against the live estate. Its first replacement completed and the new machine was verified accessible; the initial combined apply command terminated during a transient Tailscale API request, so the automated success-reporting path still needs an end-to-end rerun after the subsequent retry-handling correction. L2/L3 restoration and recovery of the complete agent development environment remain separate work.

## Installation and prerequisites

For development:

```bash
poetry install
```

The package supplies an `mxm-control` console command. Run it from an environment in which the package is installed and its executable is on `PATH`:

```bash
mxm-control --help
mxm-control status
```

The relevant operations also require the corresponding external tools and access: OpenTofu, the configured operator credential system (currently Proton Pass), and—in the case of machine bootstrap—Tailscale CLI/API access. The selected estate root supplies its provider and environment declarations. `mxm-control` does not embed credentials or estate-specific paths.

## Operator workflow

A machine-bootstrap operation follows **plan → preflight → apply**. It acts on one OpenTofu root module and one saved plan. The following variables are placeholders for paths in your own estate configuration:

```bash
root=/path/to/estate/stacks/example/l1
policy=/path/to/estate/authority/environment.toml
plan=/secure/path/to/machine-bootstrap.tfplan
```

**1. Plan** — create a private saved plan, including fresh Tailscale enrollment authority when a server will be created:

```bash
mxm-control plan machine-bootstrap \
  --root "$root" \
  --environment-policy "$policy" \
  --out "$plan"
```

Review the resource actions before continuing. Saved OpenTofu plans can contain sensitive enrollment material and must remain access-restricted; do not publish their contents or raw JSON.

**2. Preflight** — validate the saved plan, its permitted changes, and the available Tailscale management authority without modifying resources:

```bash
mxm-control preflight machine-bootstrap \
  --root "$root" \
  --environment-policy "$policy" \
  --plan "$plan"
```

**3. Apply** — retire prior registrations with the planned singleton tag, apply the exact saved OpenTofu plan, and verify that a newly enrolled device accepts Tailscale SSH:

```bash
mxm-control apply machine-bootstrap \
  --root "$root" \
  --environment-policy "$policy" \
  --plan "$plan"
```

**This operation can destroy and replace a machine.** Ensure any service data requiring restoration is backed up by the appropriate service-level process before a destructive cutover. A successful L1 bootstrap does not install or restore L2/L3 services.

A saved plan is not a repeatable rebuild command: after a successful or partially successful apply, inspect actual state and produce a fresh plan rather than blindly rerunning it. An explicit `--rebuild` planning option is not yet implemented; deliberate replacement of an otherwise unchanged machine is planned follow-up work.

For ordinary OpenTofu reconciliation, use `plan opentofu`, `apply opentofu`, and `check opentofu`. For GitHub Actions policy operations, use the corresponding `github-actions` commands and their `--organization` and `--policy` options. Run `mxm-control <command> --help` for full option details.

## Security and responsibility boundaries

- **Public mechanism, private intent:** do not commit estate addresses, account identifiers, policy bindings, credentials, or saved plans to this repository.
- **Credential-bound execution:** operator credentials are resolved for authorised child operations; credentials must not appear in CLI arguments or log output.
- **Exact saved-plan application:** preflight and apply inspect planned resource actions. Machine bootstrap permits only the singleton server and its enrollment-key changes; unrelated managed-resource mutations are rejected.
- **Service-tag ownership:** automatic Tailscale retirement is safe only under the stated singleton tag-ownership contract.
- **Layer separation:** L1 success establishes a machine and trusted access, not a working OpenBao, PostgreSQL, Prefect, or other application service.
- **Native state ownership:** OpenTofu owns infrastructure state; each service's own migration, backup, and administration tools remain authoritative for its state.

## Architecture and development

The architectural rationale and design boundaries are documented in [`docs/estate-control-system.md`](docs/estate-control-system.md).

Source lives under `src/mxm/control/`, with unit tests under `tests/unittests/`. The canonical local validation gate is:

```bash
poetry install
make check
```

Development follows the shared `mxm-foundry` package conventions. Contributions should preserve the mechanism/intent boundary, keep orchestration thin, and add tests for resource-validation and failure-path behaviour.

For a record of changes, see [`CHANGELOG.md`](CHANGELOG.md). Outstanding capabilities and improvements should be tracked in repository issues rather than represented as already implemented.

## License

MIT License. See [`LICENSE`](LICENSE).
