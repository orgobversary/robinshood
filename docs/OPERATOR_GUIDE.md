# Robinshood operator guide

This guide explains how Robinshood chooses work, records evidence, and protects
operator intent. The command line is authoritative; use `robinshood --help` and
subcommand help for the exact current options.

## Operating model

Robinshood does not decide what to investigate. The operator supplies a target
and either selects one module or requests a sweep. Target shape determines the
input type (`domain`, `ip`, `email`, `username`, `url`, or `phone`), and only
compatible modules are considered.

Each module declares:

- the input type it accepts;
- the finding types it can produce;
- whether it may contact the target directly;
- required environment variables or local binaries;
- the external source it uses.

Finding types form a static pivot graph. A module that produces `ip`, for
example, can lead to modules that consume `ip`. Suggestions are descriptive;
Robinshood never follows them automatically.

## Passive and active work

Most modules query third-party datasets. A module with `passive=False` may send
traffic to the target and requires explicit confirmation. A sweep presents one
confirmation for the active modules in its batch. Non-interactive use must pass
`--yes`; otherwise Robinshood refuses instead of hanging or assuming consent.

Treat "passive" as a description of network behavior, not legal authorization or
guaranteed invisibility. Third-party services still receive the query, source IP,
and user agent.

## Runs, sweeps, and failures

```bash
robinshood run dns_doh example.com
robinshood sweep example.com
```

A run records both success and failure. An empty result means the source returned
no matching data; an exception or unusable response becomes a failed evidence
record. Those states are intentionally different.

A sweep runs compatible modules concurrently. Unavailable modules are skipped by
default so missing binaries or keys do not bury real observations in predictable
failures. Use `--include-unavailable` when the failure record itself is useful.

Completion messages can arrive in any order, but persistence happens in sorted
module-name order. This is what makes repeated exports reproducible.

## Case evidence

Robinshood appends JSON Lines records rather than maintaining an opaque database.
The files can be inspected with any text editor or tools such as `jq`.

- `evidence.jsonl` records module, target, duration, status, errors, and cache use.
- `findings.jsonl` records normalized values, confidence, module, and source.
- `egress.jsonl` records outbound HTTP requests and wrapped command executions.
- `labels.jsonl` records operator-supplied labels.

Use `--case` to group multiple targets under an engagement name. Use
`--cases-dir` or `ROBINSHOOD_CASES_DIR` to keep real case data outside the source
checkout.

## Caching

Caching is opt-in:

```bash
robinshood --cache-ttl 3600 run crtsh_subdomains example.com
```

Only successful GET responses are cached. Evidence records the number and age of
cached responses. `--no-cache` forces a live request without deleting cache data.
Do not describe a cached observation as current.

## Proxy and Tor behavior

HTTP modules share one configured HTTPX client, and CLI wrappers receive proxy
environment variables through one command boundary. Modules do not implement
their own proxy behavior.

```bash
robinshood --proxy socks5h://127.0.0.1:9050 whoami
```

Run `whoami` before trusting a route. A proxy can change apparent network origin;
it does not grant authorization, guarantee anonymity, or ensure that every
third-party binary implements proxy variables correctly.

When `--tor-rotate` is requested, failure to reach or authenticate to the Tor
control port blocks the operation. For a sweep, rotation occurs once before any
worker starts.

## Markdown export

Preview before writing:

```bash
robinshood export --all --vault /path/to/vault --dry-run
```

The exporter groups findings by type and limits inlined values per type. Set
`--limit 0` to inline all findings, but large cases can produce unwieldy files.
Generated notes carry a marker; Robinshood will not overwrite an unrelated file
unless the operator explicitly supplies `--force`.

Analyst notes live in a companion file and are not overwritten by regeneration:

```bash
robinshood note example.com --title "review" --body "Verify ownership."
```

## Optional TUI

Install the `tui` extra and launch it explicitly:

```bash
python -m pip install "robinshood[tui]"
robinshood tui
```

The TUI provides target entry, compatible-module filtering, optional Tor
rotation, single-module execution, sweep (`F3`), result rows, and pivot hints.
Export, note, label, configuration, and diagnostics remain CLI workflows so the
interactive screen stays focused.

## Extending Robinshood

Module discovery is automatic. A module exposes one `MODULE` specification and
one `run(target, ctx)` function under `src/robinshood/modules/<category>/`.

Use `ctx.http` for APIs and `ctx.exec` for local programs. Never construct an
independent network client or invoke `subprocess` directly inside a module. The
shared boundaries provide test replacement, proxying, retry, caching, egress
logging, timeouts, and consistent error handling.

For a CLI wrapper:

- pass arguments as a list and never use `shell=True`;
- reject empty or flag-shaped targets with `safe_target`;
- declare the required binary;
- use a temporary working directory if the tool creates files;
- assign `Unverified` confidence when the upstream tool has known false positives.

For an HTTP module:

- declare environment key names and read them from `ctx.env`;
- let operational exceptions reach the shared runner;
- return an empty list for a valid no-result response;
- reuse existing finding type names so pivots remain connected.

Every new behavior needs offline tests. Run the full suite and verify module
discovery before handoff:

```bash
.venv/bin/pytest -q
.venv/bin/robinshood list
```
