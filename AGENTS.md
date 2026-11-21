# Repository guide

## Purpose

Robinshood is a deterministic, evidence-first OSINT toolkit. It runs small Python
modules against an explicitly supplied target and records structured findings.
There is no LLM at runtime. Pivot suggestions come from static input/output type
matching; keep that behavior inspectable and reproducible.

The command line is the primary interface. The Textual TUI is an optional,
focused front end for selecting and running modules; do not duplicate core run,
case, export, or network logic in the TUI.

## Development

Use a project-local virtual environment. Do not install dependencies into the
host Python environment.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/robinshood list
.venv/bin/robinshood tui
```

Tests must not access the network or require optional OSINT binaries. Mock HTTP
at the shared client boundary and replace `RunContext.exec` for CLI wrappers.

## Architecture

- `src/robinshood/cli.py`: argument parsing and command orchestration.
- `src/robinshood/core/`: shared execution, case, network, export, and safety logic.
- `src/robinshood/modules/`: independently discovered lookup modules.
- `src/robinshood/tui/`: optional presentation layer only.
- `tests/`: offline behavioral and determinism tests.
- `cases/`: runtime output; only `.gitkeep` is versioned.

## Invariants

- Modules use `ctx.http` and `ctx.exec`; they do not create clients or subprocesses
  directly. This keeps proxying, caching, egress logging, and tests centralized.
- A module raises operational errors. `core/runner.py` converts them into recorded
  failures. A legitimate no-result response returns an empty list.
- Active modules (`passive=False`) require explicit approval. Never weaken or hide
  that gate.
- Requested Tor rotation fails closed. Do not continue a run when rotation fails.
- Sweep results are recorded in module-name order, regardless of completion order,
  so generated evidence and exports stay deterministic.
- API keys come from `ctx.env`. Never persist or print secrets.
- Generated exports may only overwrite files marked as Robinshood-generated unless
  the operator explicitly uses the destructive override.
- The core install stays lightweight. TUI dependencies belong in the `tui` extra.

## Adding a module

Create one file under `src/robinshood/modules/<category>/` with:

```python
MODULE = ModuleSpec(
    name="example_lookup",
    category="example",
    description="What the source returns",
    consumes="domain",
    produces=("ip",),
    requires_key=(),
    requires_bin=(),
    passive=True,
    source_url="https://example.invalid/",
)

def run(target: str, ctx: RunContext) -> list[Finding]:
    ...
```

Reuse established finding type names because those names form the pivot graph.
Declare required environment variables and binaries in `ModuleSpec`. Validate
flag-shaped CLI targets with `safe_target`, pass argv as a list, and never use
`shell=True`.

Add offline tests and update the module tables in `README.md` and the operator
documentation. Run the complete test suite and `robinshood list` before handoff.

## Scope and public hygiene

Keep personal filesystem paths, credentials, investigation data, generated
metadata, virtual environments, and container-specific assumptions out of the
repository. Preserve the existing public license and organization attribution.
Do not commit or push unless the user explicitly asks.
