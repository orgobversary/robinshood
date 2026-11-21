# Robinshood

Robinshood is a deterministic, evidence-first OSINT toolkit for explicit,
operator-supplied targets. Each module performs one understandable lookup and
returns structured findings. There is no LLM at runtime, and suggested pivots
come from static type matching rather than autonomous decisions.

Use Robinshood only on targets you own or are authorized to investigate. Some
modules contact third-party sources; modules marked active may contact the target
itself and always require explicit confirmation.

## Why this version is leaner

- The command line is the primary interface and the default install is small.
- The optional TUI focuses on choosing modules, running them, and reviewing results.
- Export and note workflows live in the CLI instead of a second GUI wizard.
- Runtime data, generated metadata, and virtual environments stay outside Git.
- Plain Markdown documentation replaces the old themed HTML manual.

## Install

Robinshood requires Python 3.10 or newer.

```bash
git clone https://github.com/orgobversary/robinshood.git
cd robinshood
python3 -m venv .venv

# Core CLI
.venv/bin/python -m pip install -e .

# Optional terminal interface
.venv/bin/python -m pip install -e ".[tui]"
```

For development, install the test tools and optional TUI together:

```bash
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pytest -q
```

See [INSTALL.md](INSTALL.md) for optional local tools, API keys, and proxy/Tor
setup.

## Start here

```bash
robinshood --help
robinshood list
robinshood run dns_doh example.com
robinshood run rdap_ip 8.8.8.8 --json
robinshood sweep example.com
robinshood tui                       # requires the `tui` extra
```

The CLI returns `0` on success, `1` when a lookup ran but failed, and `2` for a
usage or safety precondition error. JSON output is suitable for scripts.

## Common workflows

Run one module and optionally file the evidence under a named case:

```bash
robinshood run crtsh_subdomains example.com
robinshood run rdap_ip 8.8.8.8 --case client-acme --json
```

Run every available module that accepts a target type:

```bash
robinshood sweep example.com
robinshood sweep example.com --max-workers 4
robinshood sweep example.com --yes                 # approve active modules
robinshood sweep example.com --include-unavailable # record missing tools/keys
```

Sweep workers run concurrently, but Robinshood records results in module-name
order. That keeps evidence and exports deterministic even when network completion
order changes.

Inspect and export recorded cases:

```bash
robinshood export example.com --vault ~/vault/Recon --dry-run
robinshood export example.com --vault ~/vault/Recon
robinshood export --all --vault ~/vault/Recon --limit 50
robinshood note example.com --title "next steps" --vault ~/vault/Recon
robinshood label example.com authorized-scope
```

Robinshood refuses to overwrite a non-generated note unless `--force` is supplied.
Personal analysis goes into a companion `<case>-notes.md` file so regenerated
evidence does not erase it.

Cache slow or rate-limited HTTP sources explicitly:

```bash
robinshood --cache-ttl 3600 run crtsh_subdomains example.com
robinshood --cache-ttl 3600 --no-cache run crtsh_subdomains example.com
```

Caching is off by default. Evidence marks cached responses so a replay is never
presented as a fresh observation.

## Proxy and Tor

Both HTTP modules and wrapped command-line tools receive proxy settings through
shared execution boundaries:

```bash
robinshood --proxy socks5h://127.0.0.1:9050 whoami
robinshood --proxy socks5h://127.0.0.1:9050 run subfinder example.com
robinshood --proxy socks5h://127.0.0.1:9050 --tor-rotate run dns_doh example.com
```

`whoami` verifies Robinshood's apparent egress. Requested Tor rotation fails
closed: if Robinshood cannot request a new circuit, it blocks the run instead of
quietly continuing with the old identity. A sweep rotates once before the batch,
so all modules in that sweep share the resulting exit.

## Evidence layout

By default, cases are written beneath `./cases/<slug>/`:

```text
cases/<slug>/
├── evidence.jsonl   # one receipt per attempted module run
├── findings.jsonl   # normalized findings
├── egress.jsonl     # outbound request/command receipts
└── labels.jsonl     # operator-added labels
```

Set `ROBINSHOOD_CASES_DIR` or use `--cases-dir` to keep investigation data in a
separate location. Case contents are ignored by Git.

## Modules

HTTP modules use Robinshood's shared client. CLI wrappers require the named local
binary. Keyed modules read credentials from the environment and never write them
to case files.

| Module | Input | Output | Requirement |
|---|---|---|---|
| `gau` | domain | archived URL | `gau` binary |
| `wayback_available` | URL | archived URL | none |
| `wayback_cdx` | domain | archived URL | none |
| `hibp_breach_check` | email | breach status | `HIBP_API_KEY` |
| `crtsh_subdomains` | domain | domain | none |
| `photon` | domain | email, URL | `photon` binary |
| `dns_doh` | domain | IP, MX, NS, TXT | none |
| `ipinfo_geo` | IP | geography, ASN | none |
| `hackertarget_hostsearch` | IP | domain | none |
| `httpx_probe` | domain | URL | `httpx` binary |
| `shodan_internetdb` | IP | port, CPE, vulnerability | none |
| `numlookup_phone` | phone | carrier, line type, geography | `NUMLOOKUP_API_KEY` |
| `ripestat_abuse` | IP | abuse contact | none |
| `ripestat_routing` | IP | ASN, prefix | none |
| `amass` | domain | domain | `amass` binary |
| `subfinder` | domain | domain | `subfinder` binary |
| `alienvault_otx` | domain | threat pulse | none |
| `github_user_lookup` | username | profile | none |
| `maigret` | username | profile | `maigret` binary |
| `sherlock` | username | profile | `sherlock` binary |
| `rdap_domain` | domain | registrar, nameserver | none |
| `rdap_ip` | IP | ASN, network name | none |

The live source of truth is always:

```bash
robinshood list
```

## Project structure

```text
src/robinshood/core/      shared execution and evidence logic
src/robinshood/modules/   auto-discovered lookup modules
src/robinshood/tui/       optional Textual interface
tests/                    offline test suite
docs/OPERATOR_GUIDE.md    behavior, safety, and extension guide
```

Read [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) for operational details and
[AGENTS.md](AGENTS.md) for development invariants and the module contract.

## License

Robinshood is released under the [MIT License](LICENSE).
