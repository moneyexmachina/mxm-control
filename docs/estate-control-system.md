# MXM Estate Control System

**Status:** Architecture baseline  
**Scope:** Operational infrastructure, systems, services, and their control  
**Canonical repositories:** `mxm-control` and `mxm-estate`

## 1. Purpose

The **MXM Estate Control System** is the system by which we define, provision, configure, evolve, and govern the computational estate on which MXM operates.

It separates:

- reusable control mechanisms from estate-specific intent;
- infrastructure, system configuration, and service control from domain applications;
- desired intent from realised operational state;
- reconciliation from migration from operation;
- security policy intent from operational enforcement;
- control-plane state from secrets and domain data.

The Estate Control System consists of two repositories:

- **`mxm-control`** — public, reusable control machinery;
- **`mxm-estate`** — private, authoritative intent and audited history for the concrete MXM estate.

Together, they control the realised estate: Hetzner resources, hosts, routers, OpenBao, PostgreSQL, GitHub, Tailscale, Prefect, Hindsight, and other infrastructure, systems, and services.

Domain repositories such as `mxm-runtime`, `mxm-secrets`, `mxm-config`, `mxm-dataio`, `mxm-refdata`, and `mxm-moneymachine` run within and use that estate. They are not part of the Estate Control System.

---

## 2. Architectural overview

The architecture has three major regions:

```text
                    ESTATE CONTROL SYSTEM

             ┌─────────────────────────┐
             │       mxm-estate        │
             │ authoritative intent    │
             │ topology + policy       │
             │ migration history       │
             └────────────┬────────────┘
                          │
                          ▼
             ┌─────────────────────────┐
             │       mxm-control       │
             │ provision              │
             │ configure              │
             │ reconcile              │
             │ migrate                │
             │ operate                │
             └────────────┬────────────┘
                          │
                          ▼

                    REALISED ESTATE

             L1  Infrastructure
             L2  Systems
             L3  Services

                          │
                          ▼

                    DOMAIN SYSTEMS

              mxm-runtime
              mxm-secrets
              mxm-config
              mxm-dataio
              mxm-refdata
              mxm-moneymachine
              ...
```

The control plane does not contain domain logic. It establishes and governs the environment in which domain systems operate.

---

## 3. Layer model

### 3.1 L1 — Infrastructure

L1 consists of externally provisioned resources and topology:

- virtual machines;
- networks;
- firewalls;
- volumes;
- IP addresses;
- DNS records;
- cloud resources;
- physical or virtual network resources.

The default mechanism is **OpenTofu**.

Typical examples:

```text
Hetzner VM
Hetzner network
Hetzner firewall
DNS record
cloud volume
```

L1 answers:

> What computational and network resources exist?

---

### 3.2 L2 — Systems

L2 turns provisioned resources into functioning nodes or appliances.

It includes:

- operating-system configuration;
- packages;
- users;
- filesystems;
- network interfaces;
- SSH configuration;
- systemd units;
- OpenWrt configuration;
- service installation;
- host-local runtime configuration.

The default mechanism is **configuration management**, currently expected to be primarily Ansible where appropriate, with bootstrap mechanisms such as cloud-init where useful.

Typical examples:

```text
Ubuntu host configuration
OpenWrt router configuration
OpenBao installation
PostgreSQL installation
systemd service definitions
WireGuard configuration
```

L2 answers:

> What is this machine or node, and how is it configured to run?

---

### 3.3 L3 — Services

L3 concerns the logical administrative state of running services, whether self-hosted or external.

Examples include:

- OpenBao auth methods, mounts, policies, and AppRoles;
- GitHub repositories, rulesets, organisation settings, and access controls;
- PostgreSQL databases, roles, grants, and extensions;
- Tailscale policy and service-level configuration;
- Prefect control state;
- other external or self-hosted service APIs.

L3 answers:

> How is this service constituted and governed?

Where mature providers exist, **OpenTofu is the default reconciliation engine for L3 desired state**.

Where state changes are intrinsically ordered and historical, **migrations** are used.

Where an action is transactional or imperative, the service's **native API or CLI** is used through a thin operator surface where needed.

---

### 3.4 L4 — Domain systems

L4 is outside the Estate Control System.

It contains application and domain behaviour, including:

- market data;
- trading strategies;
- portfolio state;
- orders and trades;
- runtime configuration semantics;
- secret references;
- business records;
- application-level database schemas;
- domain-specific workflows.

Examples include:

```text
mxm-runtime
mxm-secrets
mxm-config
mxm-dataio
mxm-refdata
mxm-moneymachine
```

L4 answers:

> What does the application or domain system do?

The Estate Control System establishes the capabilities on which these systems depend. Domain systems then exercise those capabilities.

---

## 4. Appliances are vertical compositions, not layers

An appliance is not a separate architectural layer.

An appliance is a composition that crosses L1, L2, and often L3.

For example:

```text
mxm-security

L1  Hetzner VM, network, firewall
L2  Ubuntu, OpenBao process, systemd, proxy/TLS
L3  OpenBao mounts, auth methods, policies, AppRoles
```

Likewise, a future `gatehouse` appliance may comprise:

```text
L1  physical or cloud network resources
L2  OpenWrt and host configuration
L3  service-level networking policy
```

This distinction prevents appliance-specific implementation structure from replacing the more general estate model.

---

## 5. Repository responsibilities

## 5.1 `mxm-control`

`mxm-control` is the **public control mechanism repository**.

It contains reusable machinery for controlling an estate:

```text
mxm-control/
    infra/
    systems/
    services/
    migrations/
    operations/
    cli/
    docs/
    tests/
```

Its contents may include:

- OpenTofu modules;
- provider configuration patterns;
- Ansible roles and playbooks;
- generic service-control modules;
- migration runner machinery;
- validation and schemas;
- operator commands;
- planning and checking tools;
- reusable bootstrap logic;
- examples using fictitious or sample estates;
- tests and architectural documentation.

It must not contain the concrete topology, identities, access relationships, migration history, or secrets of the MXM estate.

A clean checkout of `mxm-control` should contain enough machinery to build and operate an equivalent estate, but should reveal no material facts about the actual MXM estate.

---

## 5.2 `mxm-estate`

`mxm-estate` is the **private authoritative intent repository** for the concrete MXM estate.

It contains:

- actual estate topology;
- appliance inventory;
- service identities;
- security intent;
- access relationships;
- concrete desired service configuration;
- environment composition;
- L1-L3 migration history;
- bindings between domain systems and estate capabilities.

Illustratively:

```text
mxm-estate/
    infra/
    systems/
    services/
        openbao/
        github/
        postgres/
        tailscale/
        prefect/
    migrations/
    docs/
```

`mxm-estate` is private, but its contents are not assumed to be secrets.

Security must not depend on concealment of the repository.

Instead, privacy limits unnecessary exposure of topology, principal names, trust relationships, operational history, and attack surface.

---

## 5.3 Domain repositories

Domain repositories remain separate.

Examples:

```text
mxm-secrets
mxm-runtime
mxm-config
mxm-dataio
mxm-refdata
mxm-moneymachine
```

They consume capabilities provided by the realised estate.

They do not establish the estate itself.

A useful rule is:

> `mxm-control` establishes capabilities; `mxm-estate` decides how they are instantiated and granted; domain systems exercise them.

---

## 6. Authority model

The architecture distinguishes **authoritative intent** from **operational authority**.

### 6.1 Authoritative intent

`mxm-estate` is the authoritative statement of how the estate is intended to be constituted.

It answers questions such as:

- which appliances should exist;
- which services should exist;
- which identities should exist;
- what access relationships should be established;
- what the intended topology is;
- which ordered transitions have been approved and applied.

It is the normative source of estate intent and audited change history.

---

### 6.2 Operational authority

The realised services remain authoritative for current operational enforcement.

For example, OpenBao is the operational security authority for secret access.

If the question is:

> Can `factory-agent` read this secret right now?

the authoritative answer comes from OpenBao.

OpenBao evaluates the actual identity, token, policy, path, and request and allows or rejects access.

The relationship is therefore:

```text
mxm-estate
    authoritative intent
          │
          │ control / migration
          ▼
OpenBao
    realised logical state
    operational enforcement authority
```

A divergence between these two is **drift**.

The control system should detect and, where appropriate, reconcile or explicitly migrate that drift.

---

## 7. Reconciliation, migration, and operation

These are distinct control semantics and must not be collapsed into one generic mechanism.

### 7.1 Reconciliation

Reconciliation expresses an equilibrium condition:

> I want X to be true.

Examples:

```text
this VM exists
this GitHub ruleset exists
this PostgreSQL role exists
this Tailscale policy has this form
```

The normal mechanism is OpenTofu or another mature idempotent desired-state controller.

Reconciliation is appropriate when the important property is the resulting steady state, not the sequence of transitions used to reach it.

---

### 7.2 Migration

Migration expresses an audited ordered transition:

> Move the estate from state version N to state version N+1.

Examples:

```text
replace an OpenBao policy model
move roles between auth structures
remove a legacy trust relationship
transform an application database schema
```

Migration is appropriate when:

- ordering matters;
- historical transitions matter;
- an in-place transformation is required;
- the transition itself must be audited.

Estate migrations belong in `mxm-estate`.

Application/domain migrations remain with the domain repository that owns the data model.

For example:

```text
OpenBao policy transition        -> mxm-estate
GitHub administrative migration -> mxm-estate
PostgreSQL role/grant migration  -> mxm-estate

mxm-dataio schema migration      -> mxm-dataio
mxm-refdata schema migration     -> mxm-refdata
```

The layer being migrated determines ownership.

---

### 7.3 Operation

An operation is a transactional or imperative action:

> Do X now.

Examples:

```text
rotate a credential
take a backup
restore a snapshot
unseal a service
trigger a run
restart a process
diagnose a service
```

Operations are not desired-state declarations and not historical migrations.

They should normally use the underlying service API or CLI, optionally exposed through a thin `mxm-control` operator verb where that adds coherence or safety.

---

## 8. Tooling principle

The Estate Control System should **compose established deterministic mechanisms before inventing new ones**.

Default tool choices are:

| Layer / semantic | Default mechanism |
| --- | --- |
| L1 infrastructure reconciliation | OpenTofu |
| L2 system configuration | Ansible / bootstrap tooling |
| L3 service reconciliation | OpenTofu provider where mature |
| Ordered estate transition | migration mechanism |
| Transactional operation | native API / CLI |
| Secrets | OpenBao |
| Domain behaviour | domain package |

`mxm-control` should not become a homemade general-purpose orchestration framework.

Its purpose is to make these mechanisms coherent within one estate-control model and expose a consistent operator surface.

The Kubernetes controller model is useful conceptually — observed state is driven toward desired state — but MXM should not introduce Kubernetes merely to obtain that abstraction.

---

## 9. Secrets and `mxm-secrets`

OpenBao is the secret service and operational authority.

`mxm-secrets` is a domain-facing facade for exercising authority already granted by OpenBao.

The ownership split is:

### `mxm-control`

Knows how to configure OpenBao generically:

- enable mounts;
- configure auth mechanisms;
- create policy resources;
- create AppRoles;
- perform generic bootstrap and administrative operations.

### `mxm-estate`

Defines concrete MXM security intent:

- which AppRoles exist;
- which policies exist;
- which identities receive which capabilities;
- which paths and namespaces exist;
- how security topology evolves.

### OpenBao

Contains and enforces realised operational state:

- policies;
- AppRoles;
- tokens;
- auth configuration;
- secret values.

### `mxm-secrets`

Provides application and operator semantics such as:

```text
authenticate a RuntimeIdentity
resolve a SecretRef
read a secret
write a permitted secret
rotate or replace a secret
```

`mxm-secrets` does not decide what an identity is allowed to do.

It asks OpenBao to perform an action; OpenBao decides whether the granted authority permits it.

A useful principle is:

> A domain application may declare what capability it requires; the estate decides what capability it receives.

---

## 10. Information classification

Every control artefact belongs to one of four classes.

| Class | Meaning | Location | Visibility |
| --- | --- | --- | --- |
| Mechanism | how control is performed | `mxm-control` | public |
| Intent | what this estate should be | `mxm-estate` | private, not secret |
| Operational state | controller record of realised estate | state backend / runtime systems | private, not Git |
| Secret | possession grants authority | OpenBao | secret |

Examples:

```text
Reusable Hetzner OpenTofu module
    -> public mechanism

"mxm-security exists in this region with this role"
    -> private estate intent

Hetzner resource IDs in tofu state
    -> operational state

Hetzner API token
    -> secret
```

The classification tests are:

1. **Could this be reused unchanged to control another equivalent estate?**  
   If yes, it probably belongs in `mxm-control`.

2. **Does this describe what the concrete MXM estate owns, wants, trusts, or permits?**  
   If yes, it belongs in `mxm-estate`.

3. **Was this produced by a controller as a record of realised state?**  
   If yes, it belongs in an operational state backend, not Git.

4. **Does possession of this material grant authority?**  
   If yes, it belongs in OpenBao or another dedicated secret mechanism.

---

## 11. Open-source boundary

`mxm-control` should be public **by construction**.

The intended invariant is:

> There is nothing private in `mxm-control`.

It should not rely on contributor discipline to avoid accidentally exposing production estate details.

Conversely, `mxm-estate` is intentionally private because it records:

- concrete topology;
- service identities;
- security relationships;
- operational history;
- migration history;
- estate-specific bindings.

These are not secrets, but there is no benefit in publishing them.

Secrets themselves belong in neither repository.

---

## 12. Realised state and derivation

The realised estate is derived from:

```text
mxm-control
    reusable mechanisms
        +
mxm-estate
    authoritative intent and history
        +
external authority
    credentials / bootstrap trust
        ↓
realised estate
```

Examples of realised state include:

- actual Hetzner resources;
- actual host configuration;
- actual OpenBao logical state;
- actual GitHub organisation/repository configuration;
- actual PostgreSQL service administration state;
- actual Tailscale configuration;
- actual Prefect deployment/control state.

These systems remain operationally authoritative for what exists and what is currently enforced.

The Estate Control System provides the means to reconstruct, validate, evolve, and govern that realised state.

---

## 13. Relationship to the former `mxm-infra`

The existing `mxm-infra` repository is subsumed into the Estate Control System and split by responsibility.

Material moves according to semantics, not filename or historical location.

### Move to `mxm-control`

- reusable OpenTofu modules;
- generic provisioning logic;
- generic configuration logic;
- reusable Ansible roles;
- generic service adapters;
- CLI/operator machinery;
- generic tests and validation.

### Move to `mxm-estate`

- actual host inventory;
- concrete Hetzner resources and topology;
- MXM appliance definitions;
- OpenBao policy/AppRole intent;
- GitHub estate policy;
- PostgreSQL administrative intent;
- Tailscale estate policy;
- L1-L3 migration history.

### Move elsewhere or remove

- secrets -> OpenBao;
- generated OpenTofu state -> state backend;
- domain application infrastructure/schema logic -> owning domain package where appropriate;
- duplicated or obsolete ad-hoc scripts -> remove after replacement.

The same classification should be applied to infrastructure material currently embedded in `mxm-moneymachine` or other domain repositories.

---

## 14. Architectural invariants

The following invariants define the architecture.

1. **`mxm-control` contains mechanisms, not concrete MXM estate facts.**
2. **`mxm-estate` contains authoritative intent and estate history, not secrets.**
3. **Secrets are never stored in either Git repository.**
4. **Generated controller state is not committed to source control.**
5. **L1, L2, and L3 belong to the Estate Control System; L4 domain behaviour does not.**
6. **Appliances are compositions across layers, not architectural layers themselves.**
7. **Reconciliation, migration, and operation remain distinct semantics.**
8. **OpenTofu is preferred for stable declarative reconciliation where a mature provider exists.**
9. **Existing deterministic tools are preferred over custom agentic or orchestration machinery.**
10. **Operational services remain authoritative for current realised enforcement.**
11. **`mxm-estate` is authoritative for intended estate constitution and approved history.**
12. **Domain systems exercise granted capabilities; they do not grant themselves authority.**
13. **A domain package may declare requirements; only the estate may bind those requirements to actual authority.**
14. **The control system must remain reconstructable, inspectable, testable, and auditable.**

---

## 15. First implementation slice

The first vertical implementation should be `mxm-security`, because it exercises the full architecture.

```text
mxm-estate
    declares mxm-security

        ↓

mxm-control / infra
    provisions Hetzner resources

        ↓

mxm-control / systems
    configures the host

        ↓

mxm-control / services / openbao
    establishes and evolves OpenBao logical state

        ↓

OpenBao
    becomes the realised operational security authority

        ↓

mxm-secrets
    exercises granted authority for domain applications
```

This slice should be completed before introducing broad generic abstractions.

Interfaces should be derived from real repeated needs rather than designed speculatively.

---

## 16. Implementation sequence

The refounding should proceed in this order:

1. Create `mxm-control` as the public control-mechanism repository.
2. Create `mxm-estate` as the private estate-intent repository.
3. Establish the L1/L2/L3 directory and documentation structure.
4. Classify all existing `mxm-infra` material into mechanism, intent, operational state, secret, or domain material.
5. Move generic mechanisms into `mxm-control`.
6. Move concrete estate intent and history into `mxm-estate`.
7. Remove secrets and generated state from Git-backed material.
8. Refound `mxm-security` as the first complete vertical slice.
9. Migrate infrastructure/control fragments currently embedded in `mxm-moneymachine` and other domain repositories.
10. Add GitHub, Tailscale, PostgreSQL, Prefect, gatehouse/OpenWrt, and later `mxm-memory` using the same model.
11. Generalise only after repeated patterns are demonstrated.

---

## 17. Definition

The canonical definition is:

> **The MXM Estate Control System is the system by which we define, provision, configure, evolve, and govern the infrastructure, systems, and services on which MXM operates. It consists of `mxm-control`, which provides reusable mechanisms of control, and `mxm-estate`, which records the authoritative intent and audited history of the MXM estate. The resulting realised estate remains the operational locus of service state and enforcement, while MXM domain systems operate within and consume the capabilities established by that estate.**

This document is the architectural contract for the refounding of `mxm-infra`, the consolidation of estate-control logic currently distributed across MXM repositories, and the subsequent refounding of `mxm-security`.
