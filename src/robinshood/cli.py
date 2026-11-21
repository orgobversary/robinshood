from __future__ import annotations

import argparse
import contextlib
import functools
import json
import os
import sys
from pathlib import Path

from robinshood.banner import BANNER
from robinshood.core.api_library import (
    build_api_index,
    load_public_apis_enrichment,
    match_enrichment,
    render_api_note,
)
from robinshood.core.cache import CacheStats
from robinshood.core.egress import EgressLog, logged_exec
from robinshood.core.case import Case, list_cases, slugify
from robinshood.core.export import (
    ExportError,
    attach_note,
    default_limit,
    export_case,
    human_bytes,
    is_generated,
    preview_export,
)
from robinshood.core.http import build_client
from robinshood.core.options import (
    ModuleOptionError,
    option_default_text,
    parse_module_options,
    validate_module_options,
)
from robinshood.core.registry import Registry, load_registry
from robinshood.core.runner import run_module
from robinshood.core.shell import proxy_env, run_command
from robinshood.core.sweep import SweepError, run_sweep, select_modules
from robinshood.core.tor import DEFAULT_CONTROL_ADDR, TorControlError, new_identity
from robinshood.core.types import RunContext


def _cases_root(args_cases_dir: str | None) -> Path:
    return Path(args_cases_dir or os.environ.get("ROBINSHOOD_CASES_DIR", "cases"))


def _module_info(registry: Registry) -> dict[str, tuple[str, bool]]:
    return {e.spec.name: (e.spec.category, e.spec.passive) for e in registry}


def _proxy(args: argparse.Namespace) -> str | None:
    return args.proxy or os.environ.get("ROBINSHOOD_PROXY") or None


def _user_agent(args: argparse.Namespace) -> str | None:
    return args.user_agent or os.environ.get("ROBINSHOOD_USER_AGENT") or None


def _tor_rotate(args: argparse.Namespace) -> bool:
    return bool(args.tor_rotate or os.environ.get("ROBINSHOOD_TOR_ROTATE"))


def _tor_control_addr(args: argparse.Namespace) -> tuple[str, int]:
    raw = args.tor_control or os.environ.get("ROBINSHOOD_TOR_CONTROL")
    if not raw:
        return DEFAULT_CONTROL_ADDR
    host, _, port = raw.rpartition(":")
    return (host or "127.0.0.1", int(port))


def _tor_control_password(args: argparse.Namespace) -> str | None:
    return args.tor_control_password or os.environ.get("ROBINSHOOD_TOR_CONTROL_PASSWORD") or None


def _cache_ttl(args: argparse.Namespace) -> float:
    """Opt-in: 0 disables the cache, which is the default everywhere."""
    if getattr(args, "no_cache", False):
        return 0.0
    raw = args.cache_ttl if args.cache_ttl is not None else os.environ.get("ROBINSHOOD_CACHE_TTL")
    if raw is None or not str(raw).strip():
        return 0.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.0


def _cache_dir(args: argparse.Namespace) -> Path:
    raw = args.cache_dir or os.environ.get("ROBINSHOOD_CACHE_DIR")
    return Path(raw) if raw else _cases_root(args.cases_dir) / ".cache"


def _exec_for(proxy: str | None):
    """The ctx.exec every CLI-wrapper module gets. Wrapping happens once,
    here, at RunContext-construction time — no module ever sees proxy
    config, matching how ctx.http/ctx.exec are already the sole approved
    network entry points (AGENTS.md)."""
    if not proxy:
        return run_command
    return functools.partial(run_command, env=proxy_env(proxy))


def cmd_run(args: argparse.Namespace) -> int:
    registry = load_registry()
    if args.module not in registry:
        available = ", ".join(sorted(e.spec.name for e in registry))
        print(f"error: unknown module {args.module!r}. Available: {available}", file=sys.stderr)
        return 2

    entry = registry[args.module]
    try:
        module_options = parse_module_options(entry.spec, args.option)
        validate_module_options(entry.spec, module_options, entry.validate_options)
    except ModuleOptionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not _confirm_active([entry], args.yes):
        print("run cancelled.", file=sys.stderr)
        return 2

    case = Case.open(_cases_root(args.cases_dir), args.case or args.target)

    proxy = _proxy(args)
    user_agent = _user_agent(args)
    tor_rotated = _tor_rotate(args)

    if tor_rotated:
        if not proxy:
            print(
                "warning: --tor-rotate requested but no --proxy is set — a fresh Tor "
                "circuit was requested, but this run isn't routed through Tor to use it",
                file=sys.stderr,
            )
        try:
            new_identity(_tor_control_addr(args), _tor_control_password(args))
            print("new tor circuit requested", file=sys.stderr)
        except TorControlError as exc:
            # Blocked, not degraded: proceeding silently would let the run
            # happen looking "protected" when the rotation the user asked
            # for never took effect.
            print(f"error: {exc}", file=sys.stderr)
            return 2

    # Per-module timeout is honored here, at client-construction time — a module
    # still calls ctx.http.get(...) with no timeout of its own.
    timeout = entry.spec.http_timeout or args.timeout
    cache_ttl = _cache_ttl(args)
    stats = CacheStats() if cache_ttl > 0 else None
    egress_log = EgressLog()
    egress_log.current_tor_rotated = tor_rotated
    exec_fn = _exec_for(proxy)
    with build_client(
        timeout=timeout,
        proxy=proxy,
        user_agent=user_agent,
        cache_dir=_cache_dir(args) if cache_ttl > 0 else None,
        cache_ttl=cache_ttl,
        cache_stats=stats,
        egress_log=egress_log,
    ) as client:
        ctx = RunContext(
            http=client,
            env=dict(os.environ),
            options=module_options,
            timeout=timeout,
            exec=logged_exec(exec_fn, egress_log, proxy),
            cache_stats=stats,
            egress_log=egress_log,
        )
        result = run_module(entry, args.target, ctx)

    if proxy:
        print(f"via proxy: {proxy}", file=sys.stderr)

    case.record_result(result)

    if args.json:
        print(
            json.dumps(
                {
                    "module": result.module,
                    "target": result.target,
                    "ok": result.ok,
                    "duration_ms": round(result.duration_ms, 1),
                    "error": result.error,
                    "options": result.options,
                    "cached_responses": result.cached_responses,
                    "findings": [
                        {"type": f.type, "value": f.value, "source_url": f.source_url}
                        for f in result.findings
                    ],
                },
                indent=2,
            )
        )
    else:
        status = "OK" if result.ok else "FAILED"
        cached = f", {result.cached_responses} cached" if result.cached_responses else ""
        print(
            f"[{status}] {result.module} -> {result.target} "
            f"({result.duration_ms:.0f}ms{cached})"
        )
        if result.options:
            print(f"  options: {json.dumps(result.options, sort_keys=True)}")
        if result.error:
            print(f"  error: {result.error}")
        for finding in result.findings:
            print(f"  {finding.type}: {finding.value}")
        print(f"case: {case.dir}")

    return 0 if result.ok else 1


def _confirm_active(entries, assume_yes: bool) -> bool:
    """One prompt for all non-passive modules in an operation.

    A non-TTY without --yes refuses outright instead of blocking on a read that
    will never be answered — a script should fail loudly, not hang."""
    active = [e for e in entries if not e.spec.passive]
    if not active or assume_yes:
        return True
    print("These modules are NOT passive-only and may send traffic to the target itself:", file=sys.stderr)
    for entry in active:
        print(f"  {entry.spec.name} — {entry.spec.description}", file=sys.stderr)
    if not sys.stdin.isatty():
        print(
            "error: refusing to run active modules without confirmation. "
            "Pass --yes to accept, or omit the active module(s).",
            file=sys.stderr,
        )
        return False
    try:
        answer = input("Run them anyway? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def cmd_sweep(args: argparse.Namespace) -> int:
    """Runs every applicable module against one target concurrently. Shares the
    registry/runner/case code with `run` — no duplicated run logic."""
    registry = load_registry()
    env = dict(os.environ)

    try:
        entries, skipped = select_modules(
            registry, args.target, env, include_unavailable=args.include_unavailable
        )
    except SweepError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for entry, missing in skipped:
        print(f"skipping {entry.spec.name}: needs {', '.join(missing)}", file=sys.stderr)
    if not entries:
        print(f"error: no runnable modules for target {args.target!r}", file=sys.stderr)
        return 2

    try:
        sweep_options = _parse_sweep_options(entries, args.option)
    except ModuleOptionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not _confirm_active(entries, args.yes):
        print("sweep cancelled.", file=sys.stderr)
        return 2

    proxy = _proxy(args)
    user_agent = _user_agent(args)
    cache_ttl = _cache_ttl(args)
    cache_dir = _cache_dir(args) if cache_ttl > 0 else None
    tor_rotated = _tor_rotate(args)

    if tor_rotated:
        if not proxy:
            print(
                "warning: --tor-rotate requested but no --proxy is set — a fresh Tor "
                "circuit was requested, but this run isn't routed through Tor to use it",
                file=sys.stderr,
            )
        try:
            # Once, before any module starts. Every module in the sweep shares
            # this exit IP — a sweep is one identity, not one per module.
            new_identity(_tor_control_addr(args), _tor_control_password(args))
            print("new tor circuit requested (shared by every module in this sweep)", file=sys.stderr)
        except TorControlError as exc:
            # Blocked, not degraded — same rule as cmd_run.
            print(f"error: {exc}", file=sys.stderr)
            return 2

    exec_fn = _exec_for(proxy)

    @contextlib.contextmanager
    def ctx_factory(entry):
        """One client per module, so a slow source's http_timeout applies to it
        alone and each module gets its own CacheStats/EgressLog instead of racing."""
        stats = CacheStats() if cache_ttl > 0 else None
        egress_log = EgressLog()
        egress_log.current_tor_rotated = tor_rotated
        timeout = entry.spec.http_timeout or args.timeout
        with build_client(
            timeout=timeout,
            proxy=proxy,
            user_agent=user_agent,
            cache_dir=cache_dir,
            cache_ttl=cache_ttl,
            cache_stats=stats,
            egress_log=egress_log,
        ) as client:
            yield RunContext(
                http=client, env=env, options=sweep_options.get(entry.spec.name, {}),
                timeout=timeout,
                exec=logged_exec(exec_fn, egress_log, proxy),
                cache_stats=stats, egress_log=egress_log,
            )

    def progress(result):
        status = "OK" if result.ok else "FAILED"
        detail = result.error if result.error else f"{len(result.findings)} finding(s)"
        print(f"[{status}] {result.module} ({result.duration_ms:.0f}ms) — {detail}", file=sys.stderr)

    print(f"sweeping {args.target} with {len(entries)} module(s)...", file=sys.stderr)
    results = run_sweep(
        entries,
        args.target,
        ctx_factory,
        max_workers=args.max_workers,
        on_result=None if args.json else progress,
    )

    # Serial, on the sorted results — recording order must not depend on which
    # module happened to finish first, or the exported note stops being
    # byte-identical across sweeps.
    case = Case.open(_cases_root(args.cases_dir), args.case or args.target)
    for result in results:
        case.record_result(result)

    if proxy:
        print(f"via proxy: {proxy}", file=sys.stderr)

    if args.json:
        print(
            json.dumps(
                {
                    "target": args.target,
                    "modules": len(results),
                    "results": [
                        {
                            "module": r.module,
                            "ok": r.ok,
                            "duration_ms": round(r.duration_ms, 1),
                            "error": r.error,
                            "options": r.options,
                            "cached_responses": r.cached_responses,
                            "findings": [
                                {"type": f.type, "value": f.value, "source_url": f.source_url}
                                for f in r.findings
                            ],
                        }
                        for r in results
                    ],
                },
                indent=2,
            )
        )
    else:
        ok = sum(1 for r in results if r.ok)
        total_findings = sum(len(r.findings) for r in results)
        slowest = max(results, key=lambda r: r.duration_ms)
        print(
            f"\n{ok}/{len(results)} module(s) ok · {total_findings:,} finding(s) · "
            f"slowest: {slowest.module} ({slowest.duration_ms:.0f}ms)"
        )
        print(f"case: {case.dir}")

    return 0 if all(r.ok for r in results) else 1


def cmd_list(args: argparse.Namespace) -> int:
    registry = load_registry()
    for category, entries in sorted(registry.by_category().items()):
        print(f"[{category}]")
        for entry in sorted(entries, key=lambda e: e.spec.name):
            needs = [*entry.spec.requires_key, *entry.spec.requires_bin]
            note = f" (requires: {', '.join(needs)})" if needs else ""
            if entry.spec.options:
                note += f" (options: {len(entry.spec.options)})"
            print(f"  {entry.spec.name:<22} {entry.spec.consumes:<9} -> {', '.join(entry.spec.produces):<30}{note}")
    return 0


def cmd_options(args: argparse.Namespace) -> int:
    registry = load_registry()
    if args.module is None:
        for entry in sorted(registry, key=lambda item: item.spec.name):
            names = ", ".join(option.name for option in entry.spec.options) or "(none)"
            print(f"{entry.spec.name:<24} {names}")
        print("\nUse `robinshood options MODULE` for types, defaults, and choices.")
        return 0
    if args.module not in registry:
        print(f"error: unknown module {args.module!r}", file=sys.stderr)
        return 2
    spec = registry[args.module].spec
    print(f"{spec.name}: {spec.description}")
    if not spec.options:
        print("  no configurable module options")
        return 0
    for option in spec.options:
        details = [option.kind, f"default={option_default_text(option)}"]
        if option.choices:
            details.append(f"choices={','.join(option.choices)}")
        if option.minimum is not None:
            details.append(f"min={option.minimum}")
        if option.maximum is not None:
            details.append(f"max={option.maximum}")
        print(f"  {option.name:<20} {'; '.join(details)}")
        print(f"    {option.description}")
    print(f"\nUse: robinshood run {spec.name} TARGET --option NAME=VALUE")
    return 0


def _parse_sweep_options(entries, raw_options: list[str]) -> dict[str, dict]:
    """Parse MODULE.NAME=VALUE overrides for a multi-module sweep."""
    selected = {entry.spec.name: entry for entry in entries}
    grouped: dict[str, list[str]] = {}
    for raw_option in raw_options:
        key, separator, value = raw_option.partition("=")
        module_name, dot, option_name = key.rpartition(".")
        if not separator or not dot or not module_name or not option_name:
            raise ModuleOptionError(
                f"invalid sweep option {raw_option!r}; expected MODULE.NAME=VALUE"
            )
        if module_name not in selected:
            available = ", ".join(sorted(selected))
            raise ModuleOptionError(
                f"module {module_name!r} is not selected for this sweep; selected: {available}"
            )
        grouped.setdefault(module_name, []).append(f"{option_name}={value}")
    parsed = {
        module_name: parse_module_options(selected[module_name].spec, values)
        for module_name, values in grouped.items()
    }
    for module_name, entry in selected.items():
        validate_module_options(
            entry.spec,
            parsed.get(module_name, {}),
            entry.validate_options,
        )
    return parsed


def cmd_whoami(args: argparse.Namespace) -> int:
    """Not a registry module — it takes no target and doesn't fit the
    consumes/produces contract. A diagnostic: confirms what any HTTP module
    would actually be seen as right now, so 'is the proxy working' is a
    one-command check rather than an assumption."""
    proxy = _proxy(args)
    user_agent = _user_agent(args)

    if _tor_rotate(args):
        try:
            new_identity(_tor_control_addr(args), _tor_control_password(args))
        except TorControlError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    # ipinfo.io gives richer org/geo data but actively blocks known Tor exit
    # nodes with a 403 (confirmed live) — check.torproject.org's own API is
    # built to be reachable *through* Tor and reports whether Tor was
    # actually detected, which is the more relevant question once a proxy
    # is in play. Split by whether one is set, rather than guessing from
    # the proxy URL whether it happens to be Tor specifically.
    source = "check.torproject.org" if proxy else "ipinfo.io"
    url = "https://check.torproject.org/api/ip" if proxy else "https://ipinfo.io/json"

    with build_client(timeout=args.timeout, proxy=proxy, user_agent=user_agent) as client:
        try:
            resp = client.get(url)
        except Exception as exc:  # noqa: BLE001 - report, don't crash a diagnostic command
            print(f"error: could not reach {source}: {exc}", file=sys.stderr)
            return 1
        if resp.status_code != 200:
            print(
                f"error: {source} returned HTTP {resp.status_code} — it may be blocking "
                f"this exit node/proxy rather than robinshood being misconfigured",
                file=sys.stderr,
            )
            return 1
        data = resp.json()

    if args.json:
        print(json.dumps({"proxy": proxy, "source": source, **data}, indent=2))
    elif proxy:
        print(f"proxy:  {proxy}")
        print(f"ip:     {data.get('IP', '?')}")
        print(f"is_tor: {data.get('IsTor', '?')}")
    else:
        print("proxy:  (none — direct connection)")
        print(f"ip:     {data.get('ip', '?')}")
        print(f"org:    {data.get('org', '?')}")
        print(f"city:   {data.get('city', '?')}, {data.get('country', '?')}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    cases_root = _cases_root(args.cases_dir)
    vault_dir = args.vault or os.environ.get("ROBINSHOOD_VAULT_DIR")
    if not vault_dir:
        print(
            "error: no vault directory. Pass --vault PATH or set $ROBINSHOOD_VAULT_DIR.\n"
            "Use the host-absolute path if Obsidian runs outside this container.",
            file=sys.stderr,
        )
        return 2
    vault_path = Path(vault_dir)

    available = list_cases(cases_root)
    if not available:
        print(f"error: no cases found under {cases_root}", file=sys.stderr)
        return 2

    if args.all:
        selected = available
    elif args.case:
        selected = [c for c in available if c == args.case or c == slugify(args.case)]
        if not selected:
            print(
                f"error: no case named {args.case!r}. Available: {', '.join(available)}",
                file=sys.stderr,
            )
            return 2
    else:
        print("error: name a case, or pass --all", file=sys.stderr)
        return 2

    try:
        limit = args.limit if args.limit is not None else default_limit()
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    module_info = _module_info(load_registry())

    if args.dry_run:
        previews = preview_export(
            cases_root, vault_path, selected, limit=limit, force=args.force, module_info=module_info
        )
        total = sum(p.note_bytes for p in previews if p.ok)
        print(f"vault: {vault_path}")
        print(f"limit: {'unlimited' if limit <= 0 else limit} findings per type\n")
        print(f"{'case':<34}{'findings':>10}{'inlined':>10}{'note':>11}  status")
        for p in previews:
            print(
                f"{p.slug:<34}{p.finding_count:>10,}{p.shown_count:>10,}"
                f"{human_bytes(p.note_bytes):>11}  {p.status}"
            )
        writable = [p for p in previews if p.ok]
        print(f"\n{len(writable)} note(s), {human_bytes(total)} total. Nothing written (--dry-run).")
        return 0

    # Every case on disk is link-able, not just the ones exported this run, so a
    # single-case export still resolves wiki links to its siblings.
    known = set(available)

    failures = 0
    for slug in selected:
        case = Case(cases_root, slug)
        try:
            path = export_case(
                case, vault_path, limit=limit, force=args.force, known_slugs=known,
                module_info=module_info,
            )
        except ExportError as exc:
            print(f"skipped {slug}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"wrote {path}")

    # Partial success is still success; only a total failure is an error exit.
    return 1 if failures == len(selected) else 0


def cmd_note(args: argparse.Namespace) -> int:
    vault_dir = args.vault or os.environ.get("ROBINSHOOD_VAULT_DIR")
    if not vault_dir:
        print(
            "error: no vault directory. Pass --vault PATH or set $ROBINSHOOD_VAULT_DIR.",
            file=sys.stderr,
        )
        return 2

    cases_root = _cases_root(args.cases_dir)
    available = list_cases(cases_root)
    slug = next((c for c in available if c in (args.case, slugify(args.case))), None)
    if slug is None:
        print(
            f"error: no case named {args.case!r}. Available: {', '.join(available) or 'none'}",
            file=sys.stderr,
        )
        return 2

    body = args.body
    if body is None and not sys.stdin.isatty():
        body = sys.stdin.read()

    try:
        path = attach_note(Path(vault_dir), slug, args.title or "", body or "")
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {path}")
    return 0


def cmd_label(args: argparse.Namespace) -> int:
    cases_root = _cases_root(args.cases_dir)
    available = list_cases(cases_root)
    slug = next((c for c in available if c in (args.case, slugify(args.case))), None)
    if slug is None:
        print(
            f"error: no case named {args.case!r}. Available: {', '.join(available) or 'none'}",
            file=sys.stderr,
        )
        return 2
    case = Case(cases_root, slug)
    for raw in args.label:
        case.record_label(raw)
        print(f"labeled {slug}: {slugify(raw)}")
    return 0


def cmd_api_library(args: argparse.Namespace) -> int:
    vault_dir = args.vault or os.environ.get("ROBINSHOOD_VAULT_DIR")
    if not vault_dir:
        print(
            "error: no vault directory. Pass --vault PATH or set $ROBINSHOOD_VAULT_DIR.",
            file=sys.stderr,
        )
        return 2

    registry = load_registry()
    repo_dir_raw = args.public_apis_dir or os.environ.get("ROBINSHOOD_PUBLIC_APIS_DIR", "")
    enrichment = load_public_apis_enrichment(Path(repo_dir_raw)) if repo_dir_raw else {}

    vault_path = Path(vault_dir)
    vault_path.mkdir(parents=True, exist_ok=True)
    written = skipped = 0
    for entry in build_api_index(registry):
        note_path = vault_path / f"api-{entry.slug}.md"
        if note_path.exists() and not is_generated(note_path) and not args.force:
            print(f"skipped api-{entry.slug}: not ours", file=sys.stderr)
            skipped += 1
            continue
        note_path.write_text(render_api_note(entry, match_enrichment(entry, enrichment)), encoding="utf-8")
        written += 1
        print(f"wrote {note_path}")
    summary = f"{written} service note(s) written to {vault_path}"
    if skipped:
        summary += f" · {skipped} skipped"
    print(summary)
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    try:
        import textual  # noqa: F401 - explicit optional-dependency gate
    except ModuleNotFoundError as exc:
        if exc.name != "textual":
            raise
        print(
            "error: the optional TUI is not installed; install it with "
            "`python -m pip install 'robinshood[tui]'`",
            file=sys.stderr,
        )
        return 2

    from robinshood.tui.app import RobinshoodApp

    RobinshoodApp(
        cases_root=_cases_root(args.cases_dir),
        proxy=_proxy(args),
        user_agent=_user_agent(args),
        tor_rotate=_tor_rotate(args),
        tor_control_addr=_tor_control_addr(args),
        tor_control_password=_tor_control_password(args),
    ).run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="robinshood",
        description="Deterministic, evidence-first OSINT toolkit.",
    )
    parser.add_argument("--cases-dir", help="Root directory for case storage (default: ./cases or $ROBINSHOOD_CASES_DIR)")
    parser.add_argument(
        "--proxy",
        help="Route robinshood's own traffic through this SOCKS5/HTTP proxy "
        "(default: $ROBINSHOOD_PROXY). Applies to every module — see `robinshood whoami`.",
    )
    parser.add_argument(
        "--user-agent",
        help="Override the User-Agent sent by HTTP modules (default: $ROBINSHOOD_USER_AGENT, else robinshood/0.1)",
    )
    parser.add_argument(
        "--tor-rotate",
        action="store_true",
        help="Request a fresh Tor circuit (new exit IP) before each run, via Tor's control port "
        "(default: $ROBINSHOOD_TOR_ROTATE). Requires --proxy pointed at Tor's SOCKS port to matter.",
    )
    parser.add_argument(
        "--tor-control",
        help="Tor control port address, host:port (default: $ROBINSHOOD_TOR_CONTROL, else 127.0.0.1:9051)",
    )
    parser.add_argument(
        "--tor-control-password",
        help="Tor control port password, if torrc sets HashedControlPassword "
        "(default: $ROBINSHOOD_TOR_CONTROL_PASSWORD, else no auth)",
    )
    parser.add_argument(
        "--cache-ttl",
        type=float,
        default=None,
        help="Seconds to replay cached HTTP responses for; 0 disables "
        "(default: $ROBINSHOOD_CACHE_TTL, else 0). Cached runs are marked in evidence.jsonl.",
    )
    parser.add_argument(
        "--cache-dir",
        help="Where cached responses live (default: $ROBINSHOOD_CACHE_DIR, else <cases-dir>/.cache)",
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Force live requests, ignoring --cache-ttl"
    )
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="Run a single module against a target")
    p_run.add_argument("module", help="Module name (see `robinshood list`)")
    p_run.add_argument("target", help="Target value (domain, IP, email, username, url, phone, ...)")
    p_run.add_argument("--case", help="Case name to file this run under (default: the target)")
    p_run.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    p_run.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds")
    p_run.add_argument(
        "--option",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Set a typed module option; repeat as needed (see `robinshood options MODULE`)",
    )
    p_run.add_argument(
        "--yes", action="store_true", help="Approve a module marked as active without prompting"
    )
    p_run.set_defaults(func=cmd_run)

    p_sweep = sub.add_parser(
        "sweep", help="Run every applicable module against a target, concurrently"
    )
    p_sweep.add_argument("target", help="Target value (domain, IP, email, username, url, phone, ...)")
    p_sweep.add_argument("--case", help="Case name to file this sweep under (default: the target)")
    p_sweep.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    p_sweep.add_argument("--timeout", type=float, default=15.0, help="Default HTTP timeout in seconds")
    p_sweep.add_argument(
        "--max-workers", type=int, default=None, help="Concurrent modules (default: min(8, module count))"
    )
    p_sweep.add_argument(
        "--yes", action="store_true", help="Skip the confirmation prompt for non-passive modules"
    )
    p_sweep.add_argument(
        "--include-unavailable",
        action="store_true",
        help="Run modules whose API key or CLI tool is missing, recording the failure",
    )
    p_sweep.add_argument(
        "--option",
        action="append",
        default=[],
        metavar="MODULE.NAME=VALUE",
        help="Set a typed option for one module in the sweep; repeat as needed",
    )
    p_sweep.set_defaults(func=cmd_sweep)

    p_list = sub.add_parser("list", help="List all registered modules")
    p_list.set_defaults(func=cmd_list)

    p_options = sub.add_parser("options", help="Describe the configurable options for a module")
    p_options.add_argument("module", nargs="?", help="Module name; omit to summarize every module")
    p_options.set_defaults(func=cmd_options)

    p_whoami = sub.add_parser(
        "whoami", help="Show the IP/org robinshood's own traffic would be seen as right now"
    )
    p_whoami.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    p_whoami.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds")
    p_whoami.set_defaults(func=cmd_whoami)

    p_export = sub.add_parser("export", help="Export cases as Obsidian-ready Markdown notes")
    p_export.add_argument("case", nargs="?", help="Case name or slug (omit with --all)")
    p_export.add_argument("--all", action="store_true", help="Export every case")
    p_export.add_argument(
        "--vault", help="Directory to write notes into (default: $ROBINSHOOD_VAULT_DIR)"
    )
    p_export.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max values inlined per finding type; 0 for all "
        "(default: $ROBINSHOOD_EXPORT_LIMIT, else 50)",
    )
    p_export.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what each note would weigh, without writing anything",
    )
    p_export.add_argument(
        "--force",
        action="store_true",
        help="Overwrite notes robinshood did not write (destroys hand-written content)",
    )
    p_export.set_defaults(func=cmd_export)

    p_note = sub.add_parser(
        "note", help="Attach an analyst note to a case (companion note; never overwritten)"
    )
    p_note.add_argument("case", help="Case name or slug")
    p_note.add_argument("--title", help="Note heading")
    p_note.add_argument("--body", help="Note text (or pipe it on stdin)")
    p_note.add_argument("--vault", help="Vault directory (default: $ROBINSHOOD_VAULT_DIR)")
    p_note.set_defaults(func=cmd_note)

    p_label = sub.add_parser("label", help="Attach one or more custom labels to a case")
    p_label.add_argument("case", help="Case name or slug")
    p_label.add_argument("label", nargs="+", help="Label(s) to attach (slugified on write)")
    p_label.set_defaults(func=cmd_label)

    p_api_library = sub.add_parser(
        "api-library", help="Write one flat note per external service robinshood modules use"
    )
    p_api_library.add_argument("--vault", help="Vault directory (default: $ROBINSHOOD_VAULT_DIR)")
    p_api_library.add_argument(
        "--public-apis-dir",
        help="Path to a cloned public-apis-style repo for enrichment "
        "(default: $ROBINSHOOD_PUBLIC_APIS_DIR, else no enrichment)",
    )
    p_api_library.add_argument(
        "--force",
        action="store_true",
        help="Overwrite notes robinshood did not write (destroys hand-written content)",
    )
    p_api_library.set_defaults(func=cmd_api_library)

    p_tui = sub.add_parser("tui", help="Launch the optional terminal interface")
    p_tui.set_defaults(func=cmd_tui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        # The artwork is an interactive welcome, not protocol output.  Keeping
        # it off redirected stdout means bare-command help remains scriptable.
        if sys.stdout.isatty() and not os.environ.get("ROBINSHOOD_NO_BANNER"):
            print(BANNER)
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
