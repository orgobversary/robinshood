# Installing Robinshood

Robinshood supports Python 3.10 and newer. Use a virtual environment so the
project does not alter the host Python installation.

## Core CLI

```bash
git clone https://github.com/orgobversary/robinshood.git
cd robinshood
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/robinshood list
```

The core install includes HTTP and SOCKS proxy support. It does not install the
terminal interface or third-party OSINT binaries.

## Optional terminal interface

```bash
.venv/bin/python -m pip install -e ".[tui]"
.venv/bin/robinshood tui
```

Without the extra, `robinshood tui` exits with an installation hint; every CLI
workflow remains available.

## Development setup

```bash
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pytest -q
```

The test suite is offline and does not require API keys or external binaries.

## Optional local tools

Seven modules wrap local programs: `sherlock`, `maigret`, `subfinder`, `amass`,
`gau`, ProjectDiscovery `httpx`, and `photon`. Install only the tools needed for
your authorized workflow:

```bash
./scripts/install-cli-tools.sh             # all supported tools
./scripts/install-cli-tools.sh subfinder   # one tool
command -v sherlock maigret subfinder amass gau httpx photon
```

The installer targets the user environment, not system directories. Review the
script before running it. Missing tools remain visible in `robinshood list` and
are skipped by a normal sweep.

## Optional API keys

```bash
export HIBP_API_KEY="..."
export NUMLOOKUP_API_KEY="..."
```

Keys are read from the process environment. Do not add them to repository files,
shell history, case data, or bug reports.

## Runtime data

Cases default to `./cases`. Keep real investigation data outside the checkout:

```bash
export ROBINSHOOD_CASES_DIR="/path/to/authorized-cases"
robinshood run dns_doh example.com
```

For Markdown export, name an explicit destination:

```bash
export ROBINSHOOD_VAULT_DIR="/path/to/vault/Recon"
robinshood export --all --dry-run
robinshood export --all
```

Use a path visible from the environment where Robinshood runs. In a container,
that may differ from the path used by a host application.

## Proxy and Tor

Any HTTP, HTTPS, or SOCKS5 proxy accepted by HTTPX can be supplied with
`--proxy` or `ROBINSHOOD_PROXY`:

```bash
export ROBINSHOOD_PROXY="socks5h://127.0.0.1:9050"
robinshood whoami
```

Confirm `whoami` before relying on the route. CLI-wrapper tools receive standard
proxy environment variables, but support varies by upstream tool.

Tor identity rotation additionally requires a reachable control port:

```bash
robinshood \
  --proxy socks5h://127.0.0.1:9050 \
  --tor-rotate \
  run dns_doh example.com
```

The default control address is `127.0.0.1:9051`. Override it with
`--tor-control` and, when configured, `--tor-control-password`. Rotation failure
blocks the run.

## Troubleshooting

```bash
.venv/bin/python --version
.venv/bin/python -m pip show robinshood httpx
.venv/bin/robinshood --help
.venv/bin/robinshood list
```

If a moved or copied virtual environment reports a bad interpreter, delete that
generated `.venv` directory and recreate it in the current checkout. Virtual
environments are not portable project artifacts.
