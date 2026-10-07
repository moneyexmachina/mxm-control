![Version](https://img.shields.io/github/v/release/moneyexmachina/mxm-foundry)
![License](https://img.shields.io/github/license/moneyexmachina/mxm-foundry)
![Python](https://img.shields.io/badge/python-3.13+-blue)
[![Checked with pyright](https://microsoft.github.io/pyright/img/pyright_badge.svg)](https://microsoft.github.io/pyright/)

Policy-driven validation and standardisation tool for Money Ex Machina Python packages.

`mxm-foundry` defines what constitutes a *valid MXM package* and provides a single interface (`mxm-foundry check`) to enforce that contract.

## Purpose

MXM packages are designed to be:

- structurally consistent  
- fully typed  
- reproducibly configured  
- CI-ready by construction  
- easy to reason about across repositories  

`mxm-foundry` enforces this through a set of **checks** and **policies** covering:

- filesystem structure  
- `pyproject.toml` semantics  
- typing configuration (Pyright)  
- formatting configuration (Black, Ruff, Isort)  
- Makefile orchestration (`lint`, `type`, `test`, `check`)  
- testing conventions (pytest)  
- documentation structure (`README.md`, `CHANGELOG.md`)  
- license compliance  

A package that passes all checks satisfies the MXM **publish contract**.

## Installation

```bash
pip install mxm-foundry
```

## Usage

Run the validation tool against a project:

```bash
mxm-foundry check <project-root>
```

Example:

```bash
mxm-foundry check .
```

Output is grouped by **policy** and reports:

- individual check results  
- policy-level pass/fail status  
- summary counts  
- non-zero exit code on failure (CI-compatible)  

## Policy Model

`mxm-foundry` organises validation into policies:

- **License policy** — LICENSE presence and canonical content  
- **Typing policy** — Pyright configuration, absence of `[tool.pyright]`, typing markers  
- **Formatting policy** — canonical Black, Ruff, Isort configuration and Makefile integration  
- **Pyproject policy** — structural correctness of `pyproject.toml`  
- **Testing policy** — pytest usage and Makefile integration  
- **Check-gate policy** — enforcement of `make check` as integration point  
- **Documentation policy** — README structure and CHANGELOG presence/format  
- **Misc policy** — remaining structural checks  

Each policy aggregates multiple checks and fails atomically if any check fails.

## Canonical Configuration

MXM packages are standardised against canonical definitions shipped with `mxm-foundry`:

- `canonical/pyproject.toml`  
- `canonical/pyrightconfig.json`  
- `canonical/Makefile`  

Checks compare project configuration **exactly** against these canonical sources.

This ensures:

- zero configuration drift across packages  
- predictable tooling behaviour  
- uniform developer experience  

## Makefile Contract

The Makefile is a first-class interface in MXM packages.

Required targets:

- `fmt` — formatting (ruff --fix, black, isort)  
- `lint` — static checks (ruff, black --check, isort --check)  
- `type` — type checking (pyright)  
- `test` — pytest execution  
- `check` — aggregate of `lint`, `type`, `test`  
- `ci` — alias for `check`  

`make check` is the **canonical publish gate**.

## Design Principles

- **Single validation interface**  
  One command (`mxm-foundry check`) defines package validity.  

- **Policy-driven architecture**  
  Checks are grouped into semantic domains rather than treated independently.  

- **Canonical configuration**  
  Tooling configuration is not inferred or approximated; it is enforced.  

- **Deterministic results**  
  Checks run in a fixed order with stable output.  

- **Strict typing**  
  Fully Pyright-clean and PEP 561 compliant.  

- **Minimal implicit behaviour**  
  All structure and configuration is explicit and inspectable.  

## Development

```bash
poetry install

make check

poetry run mxm-foundry --help
```

## License

MIT License. See [LICENSE](LICENSE).
