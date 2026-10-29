# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Initial implementation of the MXM Estate Control System's
  reusable control-plane mechanisms.
- OpenTofu integration for declarative infrastructure planning,
  reconciliation, and application of saved plans.
- Credential-bound operator execution with explicit environment
  policies and separation of operational credentials from
  estate configuration.
- Tailscale management API client supporting OAuth authentication,
  device discovery, exact tag matching, and device retirement.
- Singleton machine-bootstrap workflow with three explicit
  operator stages:
  - `plan machine-bootstrap` — generate a reviewable OpenTofu
    execution plan.
  - `preflight machine-bootstrap` — validate the saved plan,
    operational credentials, and existing machine registrations.
  - `apply machine-bootstrap` — retire previous registrations,
    execute the approved plan, and verify replacement enrollment.
- Automated machine-bootstrap verification requiring a new
  Tailscale registration, control-plane connectivity, and
  successful Tailscale SSH.
- Automatic replacement of Tailscale enrollment credentials
  when a new machine is provisioned.
- Safety checks for saved-plan integrity, restricted file
  permissions, singleton identity, and registration ambiguity.
- Unit tests covering machine-bootstrap planning, preflight,
  application, failure handling, and safety invariants.

### Changed

- Established the separation between reusable control mechanisms
  in public `mxm-control` and authoritative estate intent in
  private `mxm-estate`.
- Formalised the three-layer estate control architecture:
  - L1 — Infrastructure provisioning and bootstrap.
  - L2 — System and appliance commissioning.
  - L3 — Service configuration and state management.
- Adopted explicit reconciliation, migration, and operation
  semantics rather than a single general-purpose orchestration
  mechanism.
- Simplified the machine-bootstrap operator interface to use
  the estate root, environment policy, and saved plan without
  redundant confirmation parameters.
- Updated the README to document implemented capabilities,
  operator workflows, architecture, and current limitations.

### Fixed

- Improved Tailscale API error classification to distinguish
  transient transport and service failures from permanent
  authentication and permission failures.
- Updated machine-bootstrap enrollment verification to retry
  transient API failures within the existing timeout rather
  than terminating immediately.
- Increased the enrollment polling interval from 10 to
  20 seconds.

### Validation

- Successfully executed the first live L1 replacement of
  `mxm-security` using the new `mxm-control` and `mxm-estate`
  architecture.
- Verified creation of the replacement Hetzner VM, retirement
  of the previous Tailscale registration, enrollment of the
  replacement machine, and successful Tailscale SSH access.
- Identified a transient Tailscale API failure that prematurely
  terminated the original post-apply verification worker.
- Implemented the corresponding retry and error-classification
  corrections; a subsequent end-to-end rebuild remains pending.

### Notes

- This milestone consolidates and restores previously existing
  infrastructure capabilities under the new control-plane
  architecture. It does not represent completion of the MXM
  estate migration.
- Full restoration of `mxm-security`, `mxm-factory-agent`,
  and the Droid-based development workflow remains outstanding.
- Explicit machine replacement through a proposed
  `plan machine-bootstrap --rebuild` option is deferred
  to a separate issue.
- L2 appliance commissioning and L3 service-state restoration
  are the next implementation priorities.

## [0.0.1] — 2026-10-08

### Added

- Initial `mxm-control` repository scaffold.
- `src/mxm/control/` namespace package layout.
- Initial Poetry package metadata for `mxm-control`.
- Canonical MXM development and validation configuration.
- Initial pytest smoke test under `tests/unittests/`.
- Initial `README.md` describing the purpose, architectural boundary, and design principles of `mxm-control`.
- `CHANGELOG.md` following the MXM package documentation convention.

### Notes

- This release establishes the initial package structure only.
- `mxm-control` is intended to provide reusable control-plane mechanisms for the MXM Estate Control System.
- Infrastructure, system, and service control implementations have not yet been migrated into this repository.
