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
- systemd and other host service-management facilities;
- OpenWrt configuration;
- Tailscale installation and node enrollment;
- container engines and Compose support;
- host storage preparation and mounts;
- host-local runtime configuration.

L2 supplies the execution environment for services. The deployed application/service instance and its own configuration and data belong to L3, even when running on a local host.

The default mechanism is **configuration management**, currently expected to be primarily Ansible where appropriate, with bootstrap mechanisms such as cloud-init where useful.

Typical examples:

```text
Ubuntu host configuration
OpenWrt router configuration
Tailscale node enrollment
Docker or Podman runtime
host filesystem mounts
systemd host facilities
WireGuard configuration
```

L2 answers:

> What is this machine or node, and how is it configured to run?

---

### 3.3 L3 — Services

L3 concerns deployed services and their desired configuration, lifecycle, persistent service data, and logical administrative state, whether self-hosted or external. A hosted service has no MXM-managed L1/L2 merely because MXM manages its L3 resources.

Examples include:

- OpenBao container deployment, listener, Raft data, auth methods, mounts, policies, and AppRoles;
- PostgreSQL service deployment, databases, roles, grants, and extensions;
- GitHub repositories, rulesets, organisation settings, and access controls;
- Tailscale policy and service-level configuration;
- Prefect control state;
- other external or self-hosted service APIs.

L3 answers:

> How is this service constituted and governed?

Where mature providers exist, **OpenTofu is the default reconciliation engine for L3 desired state**. For container-hosted services, established container tooling (such as Compose) manages deployment; host configuration tools remain responsible for the L2 runtime prerequisites.

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

## 4. Stacks and appliances are vertical compositions, not layers

A **stack** is a bounded unit of estate ownership and intent, providing a coherent capability. It may span L1–L3, or manage only those layers for which MXM has authority. Stacks are the primary organisational units of `mxm-estate`; layers are secondary divisions within a stack where useful.

A self-hosted appliance is a typical vertical stack. For example:

```text
stacks/mxm-security/
    l1/  Hetzner VM, network, firewall, volumes
    l2/  Ubuntu, Tailscale node, container runtime, host facilities
    l3/  OpenBao deployment, persistent Raft storage, service policy
```

A hosted service can also be a stack. For example, `stacks/github/` manages GitHub organisation and ruleset intent at L3. GitHub's own machines and operating systems are not part of the MXM estate. `stacks/tailscale/` similarly owns tailnet-wide policy and service configuration; a Tailscale node installed on `mxm-security` belongs to that appliance's L2.

The following distinctions are important:

- A stack is **not** an OpenTofu root directory. An OpenTofu root is a mechanism-specific unit of reconciliation that may be contained within a stack.
- A stack need not contain every layer, and empty layer directories are unnecessary.
- A stack is **not** automatically an atomic deployment, transaction, or unit of `plan/check/apply` execution.
- Each managed resource must have exactly one authoritative owner, even when stacks depend on one another.
- Cross-stack dependencies do not transfer resource ownership.

A future `gatehouse` appliance might span a physical network resource (L1), OpenWrt configuration (L2), and service-level networking policy (L3). Appliances are therefore compositions across layers, not architectural layers themselves.

Stack-first layout is an ownership and navigation convention. It does **not** mandate a custom stack orchestrator or universal stack-level reconciliation verbs. Those would require separate justification based on demonstrated repeated needs.

---

## 5. Repository responsibilities

## 5.1 `mxm-control`

`mxm-control` is the **public control mechanism repository**.

It contains reusable machinery for controlling an estate:

```text
mxm-control/
    src/mxm/control/    # operator CLI and reusable capabilities
    tests/              # mechanism and contract tests
    docs/               # public usage and design
    ...                 # reusable modules, roles, and adapters as needed
```

The organisation of `mxm-control` is **capability-first**, not stack-first or necessarily layer-first. A mechanism such as OpenTofu can serve both L1 machine declarations and L3 externally hosted service declarations.

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
    authority/
        environment.toml
    stacks/
        github/              # externally hosted L3
        tailscale/           # externally hosted L3
        mxm-security/
            l1/             # OpenTofu root: machine resources
            l2/             # host-system configuration
            l3/             # OpenBao service deployment and intent
        ...
    migrations/              # estate-wide transitions where required
    docs/
```

Stack-local ordered transitions and operator materials may live alongside the stack they affect. The illustrative layout is not a requirement to introduce manifests or a general stack execution engine. Existing `github` and `tailscale` OpenTofu roots remain valid without artificial layer directories.

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

### 8.1 Human operator control surface

**`mxm-control` is the single privileged, human-operated administrative entry point for the estate. It is not an agent runtime, and autonomous agents must never be given direct or indirect authority to invoke it.** This boundary is enforced through credential custody, operating-system identities, and permissions, not merely by usage conventions. See [authority-model.md](authority-model.md) for the complementary authority hierarchy.

The CLI is **capability-oriented**: it preserves the genuine semantics of the underlying technology while supplying common operator authentication, declared credential bindings, environment-inheritance policy, safety checks, and explicit operation boundaries.

For example:

```text
mxm-control plan opentofu --root ...
mxm-control check opentofu --root ...
mxm-control apply opentofu --root ...
mxm-control openbao snapshot ...
mxm-control openbao restore ...
mxm-control authorize ...
```

The OpenTofu `--root` spelling and the OpenBao/authorization commands above are **target interfaces**, not a claim that every command is currently implemented. The existing OpenTofu `--stack` argument denotes an OpenTofu root and should be renamed or aliased to `--root` as a separate CLI compatibility change.

Technology-level reconciliation commands are suitable for OpenTofu, Ansible, and Compose when appropriate. Service-specific administration (snapshot, restore, unseal, authorization lease) deserves typed, bounded operator commands rather than an unrestricted script executor. Concrete targets and policy belong in `mxm-estate`; reusable execution and safety mechanisms belong in `mxm-control`.

There is **no initial promise of universal `mxm-control stack plan/check/apply` verbs**. `stacks/` establishes the estate's units of intent and ownership, not an invented common reconciliation semantics across heterogeneous tools. Stack-wide orchestration may be considered later only when repeated practical requirements justify it.

### 8.2 Bootstrap authority and environment inheritance

Human operator access uses the authority model described in [authority-model.md](authority-model.md). `mxm-estate/authority/environment.toml` declares which inherited environment variables may not implicitly affect control operations; stack-local credential bindings declare explicitly required Proton Pass references. `mxm-control` validates and enforces those declarations without embedding MXM-specific provider policy in its public mechanism code.

Missing or invalid required environment policy must fail before execution. This controls declared environment inheritance; it is not a general process sandbox or a substitute for provider-specific authorization checks.

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
6. **Stacks are bounded units of intent and ownership; appliances are vertical compositions across layers, not architectural layers themselves.**
7. **Reconciliation, migration, and operation remain distinct semantics.**
8. **OpenTofu is preferred for stable declarative reconciliation where a mature provider exists.**
9. **Existing deterministic tools are preferred over custom agentic or orchestration machinery.**
10. **Operational services remain authoritative for current realised enforcement.**
11. **`mxm-estate` is authoritative for intended estate constitution and approved history.**
12. **Domain systems exercise granted capabilities; they do not grant themselves authority.**
13. **A domain package may declare requirements; only the estate may bind those requirements to actual authority.**
14. **The control system must remain reconstructable, inspectable, testable, and auditable.**
15. **`mxm-estate` is organised stack-first, with L1–L3 subdivisions only where useful; one managed resource has one authoritative owner.**
16. **A stack is not an OpenTofu root and does not imply a universal or atomic stack-level reconciliation operation.**
17. **`mxm-control` is exclusively a privileged human-operated administrative interface, inaccessible to autonomous agents.**
18. **`mxm-control` is capability-oriented and delegates to mature native tools instead of duplicating their orchestration engines.**
19. **Declared operator-environment policy is enforced before credentials are injected or managed operations execute.**

---

## 15. First implementation slice

The first complete self-hosted vertical implementation is `mxm-security`. This stack tests L1–L3 separately without rebuilding the former all-in-one cloud-init installer:

```text
mxm-estate/stacks/mxm-security/
    l1/  declare new generation Hetzner resources
    l2/  declare Ubuntu, Tailscale node, container-host configuration
    l3/  declare OpenBao container, plugin, persistence and policy

mxm-control
    reconcile L1 via OpenTofu
    configure L2 through established host-management tooling
    deploy and operate L3 through established service mechanisms

realised OpenBao
    provides operational authority consumed by mxm-secrets and other workloads
```

Stages have independent execution and verification boundaries. Cloud-init is minimal bootstrap, not the installation or migration of OpenBao. The old OpenBao authority remains intact until a separately approved Raft restore, Shamir unseal, verification and service cutover. Ordinary reconciliation must not implicitly initialise or restore OpenBao or remove the sole persistent state copy.

The existing `stacks/github` and `stacks/tailscale` are already functioning externally hosted L3 stacks and provide working examples of OpenTofu reconciliation under declared human-operator authority. The operator login, credential bindings and environment-policy enforcement have been implemented and checked against both stacks with no observed drift.

This slice should be completed before introducing broad generic abstractions. Interfaces should be derived from real repeated needs rather than designed speculatively.

---

## 16. Implementation sequence

The refounding proceeds incrementally, preserving the distinction between implemented capabilities and planned work.

1. **Established:** Create `mxm-control` (public) and `mxm-estate` (private) and establish the authority boundary.
2. **Established:** Reconcile the GitHub and Tailscale hosted-service stacks using OpenTofu and the human operator authentication, credential binding, and environment-policy mechanisms.
3. **Current:** Organise `mxm-estate` by stacks, with layer-local declarations for composite appliances. Preserve existing simple OpenTofu roots without unnecessary restructuring.
4. **Next:** Rebuild `mxm-security` in independently verified L1 (Hetzner), L2 (host and container runtime), and L3 (OpenBao) stages. Adopt generic mechanisms only to the extent demonstrated by this working vertical slice.
5. **Controlled transition:** Perform snapshot verification, Raft restoration, original Shamir unseal, service verification and authority cutover as separately authorised procedures, keeping the legacy service available until safe cutover.
6. **Continue migration:** Classify and move the remaining `mxm-infra` and domain-repository infrastructure fragments by mechanism, intent, operational state, secret, and domain ownership. Retire legacy repositories only after verifying their functions and recovery requirements are replaced.
7. **Expand:** Deploy subsequent service stacks (PostgreSQL, Prefect, S3 and others) using proven host and service mechanisms. Generalise cross-stack orchestration only if repeatable practical needs warrant it.

---

## 17. Definition

The canonical definition is:

> **The MXM Estate Control System is the system by which we define, provision, configure, evolve, and govern the infrastructure, systems, and services on which MXM operates. It consists of `mxm-control`, which provides reusable mechanisms of control, and `mxm-estate`, which records the authoritative intent and audited history of the MXM estate. The resulting realised estate remains the operational locus of service state and enforcement, while MXM domain systems operate within and consume the capabilities established by that estate.**

This document is the architectural contract for the refounding of `mxm-infra`, the consolidation of estate-control logic currently distributed across MXM repositories, and the subsequent refounding of `mxm-security`.
