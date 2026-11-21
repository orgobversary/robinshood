#!/usr/bin/env bash
#
# Installs the optional local CLI tools that back the seven CLI-wrapper modules
# (sherlock, maigret, subfinder, amass, gau, httpx_probe, photon). None are
# required — the other modules work without them.
#
# Installs to ~/.local/bin. Never needs root, never touches the host OS.
#
#   ./scripts/install-cli-tools.sh            # all seven
#   ./scripts/install-cli-tools.sh sherlock   # just one
#   SUBFINDER_VERSION=2.15.0 ./scripts/install-cli-tools.sh
#
set -euo pipefail

SUBFINDER_VERSION="${SUBFINDER_VERSION:-2.15.0}"
AMASS_VERSION="${AMASS_VERSION:-4.2.0}"
GAU_VERSION="${GAU_VERSION:-2.2.4}"
HTTPX_VERSION="${HTTPX_VERSION:-1.6.10}"
PHOTON_DIR="${PHOTON_DIR:-$HOME/.local/share/robinshood-tools/Photon}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"; }

install_sherlock() {
  if command -v sherlock >/dev/null 2>&1; then
    say "sherlock already installed: $(command -v sherlock)"
    return
  fi
  need pipx
  say "installing sherlock via pipx"
  pipx install sherlock-project
}

install_maigret() {
  if command -v maigret >/dev/null 2>&1; then
    say "maigret already installed: $(command -v maigret)"
    return
  fi
  need pipx
  say "installing maigret via pipx"
  pipx install maigret
}

install_subfinder() {
  if command -v subfinder >/dev/null 2>&1; then
    say "subfinder already installed: $(command -v subfinder)"
    return
  fi

  # Prefer a Go toolchain when present; otherwise fall back to a verified
  # release binary, which is the only option on a container without Go.
  if command -v go >/dev/null 2>&1; then
    say "installing subfinder via go install"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    return
  fi

  need curl
  need unzip
  need sha256sum

  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m) — install subfinder manually" ;;
  esac

  local base="https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}"
  local zip="subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip"
  local sums="subfinder_${SUBFINDER_VERSION}_checksums.txt"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  say "downloading subfinder v${SUBFINDER_VERSION} (linux/${arch})"
  curl -fsSL -o "$tmp/$zip"  "$base/$zip"  || die "download failed: $base/$zip"
  curl -fsSL -o "$tmp/$sums" "$base/$sums" || die "download failed: $base/$sums"

  say "verifying checksum"
  ( cd "$tmp" && grep " ${zip}\$" "$sums" | sha256sum -c - ) \
    || die "checksum verification FAILED — do not use this download"

  mkdir -p "$BIN_DIR"
  unzip -o -q "$tmp/$zip" -d "$tmp/x"
  install -m 0755 "$tmp/x/subfinder" "$BIN_DIR/subfinder"
  say "installed $BIN_DIR/subfinder"
}

install_amass() {
  if command -v amass >/dev/null 2>&1; then
    say "amass already installed: $(command -v amass)"
    return
  fi
  need go
  say "installing amass via go install"
  go install -v "github.com/owasp-amass/amass/v4/...@v${AMASS_VERSION}"
}

install_gau() {
  if command -v gau >/dev/null 2>&1; then
    say "gau already installed: $(command -v gau)"
    return
  fi
  need go
  say "installing gau via go install"
  go install "github.com/lc/gau/v2/cmd/gau@v${GAU_VERSION}"
}

install_httpx() {
  if command -v httpx >/dev/null 2>&1; then
    say "httpx already installed: $(command -v httpx)"
    return
  fi
  need go
  say "installing httpx (ProjectDiscovery) via go install — NOT the Python httpx library"
  go install "github.com/projectdiscovery/httpx/cmd/httpx@v${HTTPX_VERSION}"
}

install_photon() {
  if command -v photon >/dev/null 2>&1; then
    say "photon already installed: $(command -v photon)"
    return
  fi
  need git
  need python3

  if [ ! -d "$PHOTON_DIR" ]; then
    say "cloning Photon to $PHOTON_DIR"
    git clone --depth 1 https://github.com/s0md3v/Photon "$PHOTON_DIR"
  fi

  # A plain `pip install --user` fails on modern Debian ("externally-managed-
  # environment", PEP 668) — use an isolated venv instead, same idea as
  # sherlock's pipx install, rather than reaching for --break-system-packages.
  local venv="$PHOTON_DIR/.venv"
  if [ ! -d "$venv" ]; then
    say "creating an isolated venv for Photon's dependencies"
    python3 -m venv "$venv"
  fi
  "$venv/bin/pip" install --quiet -r "$PHOTON_DIR/requirements.txt"

  mkdir -p "$BIN_DIR"
  cat > "$BIN_DIR/photon" <<SHIM
#!/usr/bin/env bash
exec "$venv/bin/python" "$PHOTON_DIR/photon.py" "\$@"
SHIM
  chmod +x "$BIN_DIR/photon"
  say "installed shim $BIN_DIR/photon -> $PHOTON_DIR/photon.py (venv: $venv)"
}

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(sherlock maigret subfinder amass gau httpx photon)
fi

for t in "${targets[@]}"; do
  case "$t" in
    sherlock)  install_sherlock ;;
    maigret)   install_maigret ;;
    subfinder) install_subfinder ;;
    amass)     install_amass ;;
    gau)       install_gau ;;
    httpx)     install_httpx ;;
    photon)    install_photon ;;
    *) die "unknown tool '$t' (expected: sherlock, maigret, subfinder, amass, gau, httpx, photon)" ;;
  esac
done

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH — add it, or robinshood will report the tools as missing" ;;
esac

say "done. verify with: robinshood list"
