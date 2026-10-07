# Changelog
All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.1.1] - 2026-05-06

### Fixed

- Corrected MXM namespace package policy for Poetry package declarations.
- Changed canonical Poetry package inclusion from leaf package form:

  ```toml
  packages = [{ include = "mxm/<package>", from = "src" }]
  ```

  to namespace root form:

  ```toml
  packages = [{ include = "mxm", from = "src" }]
  ```

- Added validation that `src/mxm` is a PEP 420 namespace package root and does not contain `__init__.py`.
- Added validation that `src/mxm/<package>` matches the Poetry distribution name suffix.
- Updated pyproject policy coverage to include MXM namespace package structure checks.
- Removed reliance on the obsolete “Other checks” policy grouping from CLI tests.

### Changed

- Clarified the separation between filesystem-derived checks and Python project/package setup policy.
- Updated canonical `pyproject.toml` expectations for all MXM packages.
- Updated test coverage for namespace package layout, Poetry package declarations, and CLI policy output.

### Notes

- This release fixes a policy error discovered during Session 42 while applying `mxm-foundry` to `mxm-types`.
- The previous policy incorrectly required Poetry to include the leaf package path, which conflicted with the intended MXM namespace package model.
## [0.1.0] — 2026-05-04

### Added

#### Core CLI
- `mxm-foundry` CLI with `check` command for validating MXM Python packages against canonical standards.
- Deterministic check runner producing structured output across checks and policies.
- Exit code semantics suitable for CI/CD integration (non-zero on failure).

#### Check System
- Typed `Check`, `CheckResult`, and `Policy` models for composable validation logic.
- Central registry for all checks with code-based lookup and duplicate detection.
- Deterministic execution order and grouping of checks into policies and misc categories.

#### Filesystem Checks (FS)
- Validation of required project structure:
  - `README.md`, `LICENSE`, `pyproject.toml`, `pyrightconfig.json`, `Makefile`
  - `tests/`, `src/mxm/`, single package directory, `py.typed`
  - `CHANGELOG.md`

#### Pyproject Checks (PY)
- Structural validation of `pyproject.toml`:
  - `[tool.poetry]` presence and naming conventions (`mxm-*`)
  - `src/mxm` package layout enforcement
  - Required sections:
    - `[tool.poetry.dependencies]`
    - `[tool.poetry.group.dev.dependencies]`
    - `[build-system]`
    - `[tool.pytest.ini_options]`
  - Enforcement of `py.typed` inclusion in packaging metadata
- Explicit prohibition of `[tool.pyright]` in favour of `pyrightconfig.json`

#### Canonical Configuration Checks
- Exact-match validation against canonical MXM configuration:
  - `[tool.black]`
  - `[tool.ruff]`
  - `[tool.ruff.lint]`
  - `[tool.ruff.lint.isort]`
  - `[tool.isort]`
  - `pyrightconfig.json`

#### Makefile Checks (MK)
- Parsing-based validation of Makefile targets and commands
- Canonical enforcement of:
  - `type`, `lint`, `fmt`, `test`, `check`, `ci` targets
  - Correct invocation of `pyright`, `ruff`, `black`, `isort`, `pytest`
- Structural validation of `check` and `ci` orchestration targets

#### Policies
- **License policy**
  - Requires presence and canonical match of `LICENSE`
- **Typing policy**
  - Enforces `pyrightconfig.json`, absence of `[tool.pyright]`, and typing markers
- **Formatting policy**
  - Enforces canonical tool configuration and Makefile integration
- **Pyproject policy**
  - Enforces structural correctness and packaging semantics
- **Testing policy**
  - Enforces pytest usage and correct invocation via Makefile
- **Check-gate policy**
  - Formalises `make check` as the required integration point for all validation
- **Documentation policy**
  - Requires `README.md` structure and `CHANGELOG.md` with minimal format
- **Misc policy**
  - Covers remaining structural checks not part of explicit policies

#### Documentation Validation (DOC)
- `README.md` must contain required sections:
  - Purpose, Installation, Usage, Development
- `CHANGELOG.md` must follow minimal *Keep a Changelog* structure:
  - `# Changelog`, `## Unreleased`

#### Canonical Configuration
- Introduced canonical reference files:
  - `canonical/pyproject.toml`
  - `canonical/pyrightconfig.json`
  - `canonical/Makefile`
- All configuration checks derive from canonical definitions to prevent drift.

#### Test Suite
- Comprehensive pytest suite covering:
  - Individual predicates
  - Policy aggregation
  - CLI output and exit codes
  - Registry integrity and documentation synchronisation
- Strict coupling between:
  - `docs/check-codes.md`
  - expected test codes
  - implemented checks

### Changed
- Refactored Makefile validation to derive expectations from canonical Makefile rather than hardcoded command sets.
- Generalised TOML comparison logic to support arbitrary `[tool.*]` blocks.
- Reorganised policy structure to reflect semantic domains (typing, formatting, testing, etc.).
- Improved CLI output clarity and grouping by policy.

### Fixed
- Eliminated drift between canonical configuration and predicate logic by enforcing canonical-based comparisons.
- Resolved inconsistencies in minimal project fixtures used for testing.
- Stabilised CLI tests by removing brittle global count assertions.

### Notes
- This release establishes the first **MXM package standardisation contract**.
- A package passing `mxm-foundry check` satisfies all structural, typing, formatting, testing, and documentation requirements for publication.
- `make check` is now the canonical integration point for validation and CI.

### Upgrade Guidance
- Ensure your package includes:
  - Canonical `pyproject.toml`, `pyrightconfig.json`, and `Makefile`
  - Required filesystem structure and documentation files
- Run:
  ```bash
  mxm-foundry check <project-root>


## [0.0.1] — 2025-10-31
### Added
- Initial repository scaffold with `src/mxm/foundry/` namespace layout.
- `pyproject.toml` with Poetry, dev toolchain (Ruff, Black, Isort, Pyright, Pytest).
- `pyrightconfig.json` (Python 3.13, strict mode).
- `Makefile` with standard targets (`fmt`, `lint`, `type`, `test`, `check`, etc.).
- `README.md` and `LICENSE` (MIT).
- `.gitignore` for Python, Poetry, and tool caches.
- `py.typed` marker and inclusion in packaging.
- Minimal CLI stub (`mxm-foundry`) with `new` and `check` placeholders.
- `tests/test_smoke.py` covering version import and CLI basics.
