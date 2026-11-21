from __future__ import annotations

from pathlib import Path

from robinshood.core.api_library import (
    ApiEntry,
    build_api_index,
    load_public_apis_enrichment,
    match_enrichment,
    render_api_note,
)
from robinshood.core.registry import load_registry


def test_build_api_index_groups_http_modules_sharing_a_host():
    """rdap_domain and rdap_ip both hit rdap.org and must collapse into one
    entry, not two."""
    index = build_api_index(load_registry(), env={})
    rdap = next(e for e in index if "rdap.org" in e.source_url)
    assert set(rdap.used_by_modules) >= {"rdap_domain", "rdap_ip"}


def test_build_api_index_does_not_merge_cli_tools_sharing_github_as_a_host():
    """subfinder's and sherlock's source_url both happen to point at GitHub
    repo pages — that must not merge two unrelated CLI tools into one entry."""
    index = build_api_index(load_registry(), env={})
    subfinder_entry = next(e for e in index if "subfinder" in e.used_by_modules)
    sherlock_entry = next(e for e in index if "sherlock" in e.used_by_modules)
    assert subfinder_entry.slug != sherlock_entry.slug
    assert "sherlock" not in subfinder_entry.used_by_modules


def test_build_api_index_access_is_cli_binary_when_requires_bin():
    index = build_api_index(load_registry(), env={})
    subfinder_entry = next(e for e in index if "subfinder" in e.used_by_modules)
    assert subfinder_entry.access == "cli-binary"


def test_build_api_index_access_is_http_api_when_no_requires_bin():
    index = build_api_index(load_registry(), env={})
    dns_entry = next(e for e in index if "dns_doh" in e.used_by_modules)
    assert dns_entry.access == "http-api"


def test_build_api_index_configured_reflects_env_and_path():
    index = build_api_index(load_registry(), env={})
    hibp_entry = next(e for e in index if "hibp_breach_check" in e.used_by_modules)
    assert hibp_entry.requires_key == ("HIBP_API_KEY",)
    assert hibp_entry.configured is False  # no key in env

    index_with_key = build_api_index(load_registry(), env={"HIBP_API_KEY": "x"})
    hibp_entry = next(e for e in index_with_key if "hibp_breach_check" in e.used_by_modules)
    assert hibp_entry.configured is True  # hibp needs no binary, only its key


def test_render_api_note_without_enrichment():
    entry = ApiEntry(
        service="internetdb.shodan.io",
        slug="internetdb-shodan-io",
        used_by_modules=("shodan_internetdb",),
        access="http-api",
        requires_key=(),
        requires_bin=(),
        passive=True,
        source_url="https://internetdb.shodan.io/",
        category="infra",
        configured=True,
    )
    note = render_api_note(entry)
    assert "service: \"internetdb.shodan.io\"" in note
    assert "record_type: api" in note
    assert "category: \"infra\"" in note
    assert "used_by_modules: [shodan_internetdb]" in note
    assert "configured: true" in note
    assert "generator: robinshood" in note


def test_render_api_note_with_enrichment_overrides_category_and_auth():
    entry = ApiEntry(
        service="haveibeenpwned.com",
        slug="haveibeenpwned-com",
        used_by_modules=("hibp_breach_check",),
        access="http-api",
        requires_key=("HIBP_API_KEY",),
        requires_bin=(),
        passive=True,
        source_url="https://haveibeenpwned.com/api/v3/breachedaccount/",
        category="breach",
        configured=False,
    )
    note = render_api_note(entry, enrichment={"category": "Security", "https": "Yes", "cors": "Unknown"})
    assert "category: \"Security\"" in note
    assert "auth: \"apiKey\"" in note  # requires_key wins over any enrichment auth value


def test_load_public_apis_enrichment_missing_dir_returns_empty(tmp_path):
    assert load_public_apis_enrichment(tmp_path / "does-not-exist") == {}


def test_load_public_apis_enrichment_parses_readme_table(tmp_path):
    repo = tmp_path / "public-apis"
    repo.mkdir()
    (repo / "README.md").write_text(
        "### Security\n"
        "API | Description | Auth | HTTPS | CORS |\n"
        "|:---|:---|:---|:---|:---|\n"
        "| [Shodan](https://developer.shodan.io/) | Search engine for devices | `apiKey` | Yes | Unknown |\n",
        encoding="utf-8",
    )
    enrichment = load_public_apis_enrichment(repo)
    assert "shodan.io" in enrichment["__by_domain__"]
    row = enrichment["__by_domain__"]["shodan.io"]
    assert row["category"] == "Security"
    assert row["auth"] == "apiKey"
    assert row["https"] == "Yes"


def test_match_enrichment_falls_back_to_name_substring(tmp_path):
    repo = tmp_path / "public-apis"
    repo.mkdir()
    (repo / "README.md").write_text(
        "### Anti-Malware\n"
        "API | Description | Auth | HTTPS | CORS |\n"
        "|:---|:---|:---|:---|:---|\n"
        "| [Archive.org](https://archive.readme.io/docs) | The Internet Archive | No | Yes | No |\n",
        encoding="utf-8",
    )
    enrichment = load_public_apis_enrichment(repo)
    entry = ApiEntry(
        service="web.archive.org",
        slug="web-archive-org",
        used_by_modules=("wayback_cdx",),
        access="http-api",
        requires_key=(),
        requires_bin=(),
        passive=True,
        source_url="http://web.archive.org/cdx/search/cdx",
        category="archive",
        configured=True,
    )
    match = match_enrichment(entry, enrichment)
    assert match is not None
    assert match["category"] == "Anti-Malware"


def test_match_enrichment_returns_none_when_nothing_matches():
    entry = ApiEntry(
        service="totally-unrelated.example",
        slug="totally-unrelated-example",
        used_by_modules=("nonexistent",),
        access="http-api",
        requires_key=(),
        requires_bin=(),
        passive=True,
        source_url="https://totally-unrelated.example/",
        category="infra",
        configured=True,
    )
    assert match_enrichment(entry, {}) is None
