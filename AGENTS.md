# Agent operating guide

This file contains durable instructions for engineering agents working in
`mxm-control`. Task-specific goals and temporary implementation decisions belong
in the task or Mission plan, not here.

## MXM engineering policy

### Configuration and secrets

MXM does not use environment variables or `.env` files for application
configuration or secrets unless explicitly required by an external tool that
cannot be integrated otherwise.

Do not introduce environment-variable configuration, `.env` files, or
`.env.example` files as an application configuration mechanism.

Application configuration is provided through the MXM configuration and runtime
composition system. Secrets and credentials are supplied through the MXM
secrets and workload-identity mechanisms.

If configuration or credentials required by a change are not available through
those mechanisms, treat that as an architectural or integration issue rather
than adding an environment-variable fallback.

### Python environment

MXM Python repositories use Poetry with a project-local `.venv/`.

Before running project Python, tests, validation, or other project tooling,
ensure the project and its dependencies are installed:

    poetry install

Do not assume that an existing `.venv/` is present or usable.

Do not use or depend on Python packages installed in the host environment.
Run Python and project Python tooling through Poetry or through repository
`make` targets.

### Validation

The repository Makefile defines the canonical local engineering interface.

Before considering a change complete, run:

```bash
make check
```

`make check` is the authoritative full local validation gate. During
development, use narrower checks or tests where useful, but they do not replace
the final `make check`.

Do not weaken, bypass, or remove validation in order to make a change pass.

Report any validation that could not be run or did not pass.

### Authority boundaries

Treat source code, tests, and documentation as proposal-capable state: modify
them when required by the assigned work.

Do not assume authority to change repository governance or other
authority-bearing state. In particular, do not modify:

- CI or release workflows;
- branch or repository protection;
- credentials, identities, or secrets;
- release or publication configuration; or
- this `AGENTS.md`

unless the task explicitly authorizes that class of change.

Do not publish packages, create release tags, merge changes, or otherwise
promote a proposal into authoritative state unless explicitly authorized.

Never commit credentials, tokens, secrets, private data, or development
artifacts containing them.

Do not discard or overwrite existing work merely to obtain a clean working
state.

## `mxm-control` contract

`mxm-control` provides reusable mechanisms for controlling infrastructure,
systems, and services in the MXM Estate Control System.

It is a public mechanism repository. It must not contain concrete MXM estate
intent or authority-bearing material.

Preserve these boundaries when changing the package:

- reusable control mechanisms belong in `mxm-control`;
- concrete MXM topology, identities, grants, bindings, policy, and migration
  history belong in `mxm-estate`;
- generated controller state belongs in its operational state backend, not Git;
- credentials, tokens, private keys, and other authority-bearing material do
  not belong in this repository;
- prefer established deterministic control tools and providers over custom
  orchestration when they already express the required semantics; and
- reconciliation, migration, and imperative operation are distinct control
  semantics and should not be silently conflated.

`mxm-control` may wrap or compose established tools such as OpenTofu where doing
so provides a stable operator interface, validation, or safety boundary. It
should not reimplement provider or controller functionality merely to
centralize it in Python.

The package should remain independent of concrete MXM estate topology. Mechanism
code must not embed specific MXM machines, services, identities, grants, secret
paths, provider accounts, or environment topology.

Concrete estate declarations used while developing or testing mechanisms should
be synthetic fixtures rather than real MXM topology unless the task explicitly
requires otherwise.

For detailed architecture and rationale, consult the repository documentation.

## Testing

Use the narrowest relevant tests while developing, then run the full validation
gate before completion.

Tests must be deterministic and isolated. Do not make uncontrolled real
external requests or depend on mutable external state when an isolated test can
exercise the behaviour.

Changes to behaviour should be accompanied by tests that demonstrate the
intended behaviour and protect relevant invariants.

Tests of control mechanisms must not mutate live MXM infrastructure or service
state unless the task explicitly authorizes an integration test against a
designated target.

Use temporary or otherwise isolated state for test persistence and filesystem
operations. Do not modify or delete operator or production data while testing.

## Completion

Before declaring engineering work complete:

1. Run focused validation appropriate to the changed behaviour.
2. Run `make check`.
3. Update durable documentation when public behaviour or architectural
   contracts have changed.
4. Report the validation performed and any checks that could not be completed.

If completing a change reveals that this operating guide is inaccurate or
incomplete, report the required update rather than silently changing the guide.
