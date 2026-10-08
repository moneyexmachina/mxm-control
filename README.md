![Version](https://img.shields.io/github/v/release/moneyexmachina/mxm-control)
![License](https://img.shields.io/github/license/moneyexmachina/mxm-control)
![Python](https://img.shields.io/badge/python-3.13+-blue)
[![Checked with pyright](https://microsoft.github.io/pyright/img/pyright_badge.svg)](https://microsoft.github.io/pyright/)

Reusable control-plane mechanisms for provisioning, configuring, and governing the MXM computational estate.

`mxm-control` provides the mechanisms used to realise the authoritative estate intent defined in [`mxm-estate`](https://github.com/moneyexmachina/mxm-estate).

## Purpose

The **MXM Estate Control System** separates reusable control machinery from the concrete definition of the MXM computational estate.

`mxm-control` is the reusable mechanism side of that system.

It provides control mechanisms across three operational layers:

- **Infrastructure** — provision external resources such as machines, networks, firewalls, volumes, and DNS.
- **Systems** — configure hosts and appliances, including operating systems, packages, services, networking, and local runtime state.
- **Services** — establish and evolve the logical administrative state of services such as OpenBao, PostgreSQL, GitHub, Tailscale, and Prefect.

The package is intended to compose established deterministic tools rather than replace them. Depending on the layer and control semantics, these may include:

- OpenTofu for declarative resource reconciliation;
- Ansible and bootstrap tooling for system configuration;
- service-specific migration mechanisms for ordered state transitions;
- native service APIs and CLIs for transactional operations.

`mxm-control` contains **mechanisms, not concrete MXM estate intent**.

Concrete topology, identities, policy bindings, service configuration, and estate migration history belong in the private `mxm-estate` repository.

Secrets belong in OpenBao and operational controller state belongs in dedicated state backends.

## Installation

Install the package for development with Poetry:

```bash
poetry install
```

## Usage

`mxm-control` is currently being established as the reusable control-plane component of the MXM Estate Control System.

Its principal structure is organised around:

```text
mxm-control/
├── infra/
├── systems/
├── services/
├── operations/
├── src/
│   └── mxm/
│       └── control/
└── tests/
```

The repository will provide reusable mechanisms that can be instantiated by `mxm-estate`.

The governing distinction is:

```text
mxm-control
    how an estate can be controlled

mxm-estate
    how the MXM estate should be constituted

realised estate
    the infrastructure, systems, and services that actually exist
```

`mxm-control` does not contain domain application logic. MXM domain packages such as `mxm-runtime`, `mxm-secrets`, `mxm-config`, `mxm-dataio`, and `mxm-moneymachine` operate within and consume capabilities provided by the realised estate.

## Control Semantics

The Estate Control System distinguishes three forms of change.

### Reconciliation

Reconciliation expresses a desired equilibrium state:

> Make and keep this condition true.

Where a mature provider exists, OpenTofu is the preferred mechanism.

### Migration

Migration expresses an ordered and auditable transition:

> Move the estate from state N to state N+1.

Migration is used where transition order or historical evolution is itself significant.

### Operation

An operation is a transactional action:

> Do this now.

Operations normally use the underlying service API or CLI, with `mxm-control` providing a thin operator surface where useful for safety or consistency.

These semantics remain distinct and should not be collapsed into a single custom orchestration framework.

## Design Principles

- **Mechanism separate from intent**  
  `mxm-control` provides reusable control mechanisms; `mxm-estate` defines the concrete MXM estate.

- **Layered control model**  
  Infrastructure, systems, and services are treated as distinct operational layers.

- **Use established mechanisms first**  
  OpenTofu, Ansible, native migration tooling, and service APIs are preferred over custom orchestration.

- **Deterministic actuation**  
  Estate changes should be inspectable, reproducible, testable, and auditable.

- **Explicit control semantics**  
  Reconciliation, migration, and operation are separate concepts with different mechanisms.

- **Public by construction**  
  `mxm-control` contains no private estate topology, operational state, or secrets.

- **Minimal implicit behaviour**  
  Control behaviour and authority boundaries should be explicit and inspectable.

- **Domain separation**  
  The control plane establishes capabilities; domain systems exercise them.

## Architecture

The canonical architecture is documented in:

```text
docs/estate-control-system.md
```

At a high level:

```text
mxm-estate
    authoritative estate intent
          │
          ▼
mxm-control
    reusable control mechanisms
          │
          ▼
realised estate
    infrastructure
    systems
    services
          │
          ▼
MXM domain systems
```

## Development

Install dependencies and run the canonical MXM validation gate:

```bash
poetry install

make check
```

All development must remain compliant with the `mxm-foundry` package contract.

Changes should preserve the fundamental repository boundary:

> Generic and reusable control machinery belongs in `mxm-control`; concrete MXM estate intent belongs in `mxm-estate`.

## License

MIT License. See [LICENSE](LICENSE).
Policy-driven validation and standardisation tool for Money Ex Machina Python packages.
