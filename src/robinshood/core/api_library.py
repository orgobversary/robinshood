from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from robinshood.core.export import _yaml_str
from robinshood.core.registry import Registry

GENERATOR = "robinshood"

_SECTION_RE = re.compile(r"^### (.+)$")
_ROW_RE = re.compile(
    r"^\|\s*\[(?P<name>[^\]]+)\]\((?P<url>[^)]+)\)\s*\|(?P<desc>[^|]*)\|"
    r"(?P<auth>[^|]*)\|(?P<https>[^|]*)\|(?P<cors>[^|]*)\|\s*$"
)


@dataclass(frozen=True)
class ApiEntry:
    """One external service, grouped from every module that talks to it —
    wayback_cdx and gau both hit archive.org and collapse into one entry with
    two used_by_modules, rather than one entry per module."""

    service: str
    slug: str
    used_by_modules: tuple[str, ...]
    access: str  # "http-api" | "cli-binary"
    requires_key: tuple[str, ...]
    requires_bin: tuple[str, ...]
    passive: bool
    source_url: str
    category: str
    configured: bool  # live env/PATH check — not part of any determinism guarantee


def _registrable_domain(netloc: str) -> str:
    """Last two labels of a hostname — a simplification (no public-suffix-list
    handling for multi-part TLDs like co.uk), good enough for matching a
    handful of well-known services."""
    labels = netloc.lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else netloc.lower()


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _group_key_and_service(spec) -> tuple[str, str]:
    """Returns (slug, display service name).

    CLI-wrapper modules' source_url is their project homepage (often a bare
    github.com repo link), not an API host — several unrelated tools share
    that literal netloc, so grouping those by netloc would wrongly merge e.g.
    sherlock and subfinder into one "github.com" entry. Group those by the
    binary they wrap instead: the tool itself is the distinct "service" for a
    CLI wrapper. Pure HTTP modules keep the netloc-based grouping, since their
    source_url genuinely is the API host being called — this is also what
    correctly merges rdap_domain and rdap_ip (both rdap.org) into one entry.
    """
    if spec.requires_bin:
        tool = spec.requires_bin[0]
        return _slugify(tool) or spec.name, tool
    netloc = urlparse(spec.source_url).netloc or spec.name
    return _slugify(netloc) or spec.name, netloc


def build_api_index(registry: Registry, env: dict | None = None) -> list[ApiEntry]:
    env = env if env is not None else os.environ
    grouped: dict[str, list] = {}
    services: dict[str, str] = {}
    for entry in registry:
        spec = entry.spec
        slug, service = _group_key_and_service(spec)
        grouped.setdefault(slug, []).append(spec)
        services.setdefault(slug, service)

    entries: list[ApiEntry] = []
    for slug, specs in grouped.items():
        keys = tuple(sorted({k for s in specs for k in s.requires_key}))
        bins = tuple(sorted({b for s in specs for b in s.requires_bin}))
        configured = all(env.get(k) for k in keys) and all(shutil.which(b) for b in bins)
        entries.append(
            ApiEntry(
                service=services[slug],
                slug=slug,
                used_by_modules=tuple(sorted(s.name for s in specs)),
                access="cli-binary" if bins else "http-api",
                requires_key=keys,
                requires_bin=bins,
                passive=all(s.passive for s in specs),
                source_url=specs[0].source_url,
                category=specs[0].category,
                configured=configured,
            )
        )
    return sorted(entries, key=lambda e: e.slug)


def load_public_apis_enrichment(repo_dir: Path) -> dict[str, dict]:
    """Parses a public-apis-style README.md's per-category Markdown tables
    (`### <Category>` heading, then `| [Name](url) | Description | Auth |
    HTTPS | CORS |` rows) into {registrable_domain: {category, auth, https,
    cors}}, plus the same data indexed by a slugified display name for a
    substring-match fallback (some entries link to a docs/marketing domain
    that differs from the API's actual host, e.g. archive.org's entry linking
    to a readme.io docs site).

    Never a hard requirement: a missing directory or unparseable file returns
    {} and callers fall back to registry-derived values — this only enriches
    notes, it never blocks writing them."""
    readme = repo_dir / "README.md"
    if not readme.is_file():
        return {}

    try:
        text = readme.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    by_domain: dict[str, dict] = {}
    by_name: dict[str, dict] = {}
    category = "Uncategorized"
    for line in text.splitlines():
        section = _SECTION_RE.match(line)
        if section:
            category = section.group(1).strip()
            continue
        row = _ROW_RE.match(line)
        if not row:
            continue
        data = {
            "category": category,
            "auth": row.group("auth").strip().strip("`") or "Unknown",
            "https": row.group("https").strip(),
            "cors": row.group("cors").strip(),
        }
        domain = _registrable_domain(urlparse(row.group("url")).netloc)
        by_domain.setdefault(domain, data)
        name_key = re.sub(r"[^a-z0-9]+", "", row.group("name").lower())
        if name_key:
            by_name.setdefault(name_key, data)

    return {"__by_domain__": by_domain, "__by_name__": by_name}


def match_enrichment(entry: ApiEntry, enrichment: dict) -> dict | None:
    by_domain = enrichment.get("__by_domain__", {})
    by_name = enrichment.get("__by_name__", {})
    if not by_domain and not by_name:
        return None

    # public-apis catalogs HTTP APIs, not local CLI recon tools — a CLI
    # wrapper's "service" is just its own binary name (e.g. "photon",
    # "sherlock"), which is short and generic enough to spuriously
    # name-match an unrelated catalog entry ("photon" inside "photography").
    # There's nothing meaningful to enrich here, so skip matching entirely.
    if entry.access == "cli-binary":
        return None

    domain = _registrable_domain(urlparse(entry.source_url).netloc)
    if domain in by_domain:
        return by_domain[domain]

    # Fallback for HTTP entries whose linked URL isn't the API's own host
    # (e.g. a docs subdomain): require the public-apis name to cover most of
    # our service name, not just share a short/generic fragment.
    haystack = re.sub(r"[^a-z0-9]+", "", entry.service.lower())
    best_key, best_data = "", None
    for name_key, data in by_name.items():
        if len(name_key) < 5:
            continue
        if name_key in haystack and len(name_key) > len(best_key):
            best_key, best_data = name_key, data
    return best_data


def _https_from_url(url: str) -> bool:
    return urlparse(url).scheme == "https"


def render_api_note(entry: ApiEntry, enrichment: dict | None = None) -> str:
    """Deterministic given the same (entry, enrichment) — but NOT stable across
    machines or time, since `configured` reflects live env/PATH state. That's
    intentional: this note answers "what's set up right now", not "what did
    this case find", so it doesn't carry render_note's byte-identical-across-
    runs guarantee."""
    enrichment = enrichment or {}
    auth = "apiKey" if entry.requires_key else enrichment.get("auth", "None")
    https = enrichment.get("https") or ("Yes" if _https_from_url(entry.source_url) else "Unknown")
    cors = enrichment.get("cors", "Unknown")
    category = enrichment.get("category", entry.category)

    out = [
        "---",
        f"service: {_yaml_str(entry.service)}",
        "record_type: api",
        f"category: {_yaml_str(category)}",
        f"access: {entry.access}",
        f"auth: {_yaml_str(auth)}",
        f"https: {_yaml_str(https)}",
        f"cors: {_yaml_str(cors)}",
        f"used_by_modules: [{', '.join(entry.used_by_modules)}]",
        f"requires_key: [{', '.join(entry.requires_key)}]",
        f"requires_bin: [{', '.join(entry.requires_bin)}]",
        f"passive: {'true' if entry.passive else 'false'}",
        f"configured: {'true' if entry.configured else 'false'}",
        "tags: [recon/api]",
        f"generator: {GENERATOR}",
        "---",
        "",
        f"# {entry.service}",
        "",
        f"Used by: {', '.join(f'`{m}`' for m in entry.used_by_modules)}",
        "",
        f"Source: {entry.source_url}",
        "",
    ]
    return "\n".join(out)
