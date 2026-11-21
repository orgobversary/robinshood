from __future__ import annotations

import contextlib
import functools
import os
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Checkbox, DataTable, Footer, Input, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from robinshood.core.case import Case, slugify
from robinshood.core.detect import detect_target_type
from robinshood.core.egress import EgressLog, logged_exec
from robinshood.core.http import build_client
from robinshood.core.pivot import suggest_next
from robinshood.core.registry import Registry, load_registry
from robinshood.core.runner import run_module
from robinshood.core.shell import proxy_env, run_command
from robinshood.core.sweep import SweepError, run_sweep, select_modules
from robinshood.core.tor import DEFAULT_CONTROL_ADDR, TorControlError, new_identity
from robinshood.core.types import ModuleResult, RunContext
from robinshood.tui.widgets import ConfirmModal


# Display cap for the results table. Findings are recorded to disk uncapped;
# this only bounds how many rows the UI renders in one go.
MAX_DISPLAYED_ROWS = 500


class RobinshoodApp(App):
    TITLE = "robinshood"
    CSS = """
    #left { width: 42%; border-right: solid $border; padding: 1; }
    #right { width: 58%; padding: 1; }
    #target-input { margin-bottom: 1; }
    #tor-rotate-checkbox { margin-bottom: 1; }
    #module-list { height: 1fr; }
    #run-log { height: 12; border: solid $border; margin-bottom: 1; }
    #results-table { height: 1fr; }
    #pivot-strip { height: auto; border: solid $border; padding: 0 1; margin-top: 1; }
    """
    # Function keys avoid conflicts with the focused target Input, which binds
    # printable letters and common line-editing shortcuts.
    BINDINGS = [
        ("f3", "sweep", "Sweep all modules"),
        ("q", "quit", "Quit"),
    ]

    def __init__(
        self,
        cases_root: Path,
        proxy: str | None = None,
        user_agent: str | None = None,
        tor_rotate: bool = False,
        tor_control_addr: tuple[str, int] = DEFAULT_CONTROL_ADDR,
        tor_control_password: str | None = None,
    ):
        super().__init__()
        self.cases_root = cases_root
        self.proxy = proxy
        self.tor_rotate = tor_rotate
        self.tor_control_addr = tor_control_addr
        self.tor_control_password = tor_control_password
        self.registry: Registry = load_registry()
        self.user_agent = user_agent
        # One EgressLog for the app's lifetime, shared by every single-run module
        # call — its current_module/current_tor_rotated fields are set fresh
        # immediately before each run_module() call, since this client (and this
        # log) outlives any one of them.
        self.egress_log = EgressLog()
        self.http_client = build_client(proxy=proxy, user_agent=user_agent, egress_log=self.egress_log)
        # Kept unwrapped too: sweep builds a fresh EgressLog per module (like
        # its CacheStats), so it needs to wrap this itself rather than reuse
        # the single app-wide self.exec_fn.
        self.base_exec_fn = run_command if not proxy else functools.partial(run_command, env=proxy_env(proxy))
        self.exec_fn = logged_exec(self.base_exec_fn, self.egress_log, proxy)

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="left"):
                yield Input(
                    placeholder="target: domain / ip / email / username / url / phone",
                    id="target-input",
                )
                yield Checkbox(
                    "Tor: new circuit before each run",
                    value=self.tor_rotate,
                    id="tor-rotate-checkbox",
                )
                yield OptionList(id="module-list")
            with Vertical(id="right"):
                yield RichLog(id="run-log", wrap=True, markup=True)
                yield DataTable(id="results-table")
                yield Static("Run a module to see suggested pivots here.", id="pivot-strip")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.add_columns("type", "value", "module", "confidence")
        self._refresh_module_list()

    def on_unmount(self) -> None:
        self.http_client.close()

    def _refresh_module_list(self, filter_type: str | None = None) -> None:
        option_list = self.query_one("#module-list", OptionList)
        option_list.clear_options()
        for category, entries in sorted(self.registry.by_category().items()):
            visible = [
                e for e in sorted(entries, key=lambda e: e.spec.name)
                if not filter_type or e.spec.consumes == filter_type
            ]
            if not visible:
                continue
            option_list.add_option(
                Option(Text(category.upper(), style="bold"), id=f"__cat_{category}", disabled=True)
            )
            for entry in visible:
                needs = [*entry.spec.requires_key, *entry.spec.requires_bin]
                needs_badge = f"[requires {'/'.join(needs)}]" if needs else "[free]"
                label = Text(
                    f"{entry.spec.name}  ({entry.spec.consumes} -> {', '.join(entry.spec.produces)})  "
                )
                if not entry.spec.passive:
                    label.append("[active] ", style="bold")
                label.append(needs_badge)
                option_list.add_option(Option(label, id=entry.spec.name))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "target-input":
            return
        self._refresh_module_list(filter_type=detect_target_type(event.value))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        module_name = event.option_id
        target = self.query_one("#target-input", Input).value.strip()
        log = self.query_one("#run-log", RichLog)

        if not target:
            log.write("Enter a target above before selecting a module.")
            return
        if module_name not in self.registry:
            return
        self._confirm_and_run(module_name, target)

    # push_screen_wait only works inside a worker, so anything that opens a modal
    # and waits on its result has to run as one.
    @work
    async def _confirm_and_run(self, module_name: str, target: str) -> None:
        log = self.query_one("#run-log", RichLog)
        entry = self.registry[module_name]
        if not entry.spec.passive:
            proceed = await self.push_screen_wait(
                ConfirmModal(
                    f"{entry.spec.name} is flagged as NOT passive-only.\n"
                    f"It may send traffic to the target itself. Run anyway?"
                )
            )
            if not proceed:
                log.write(f"Skipped {entry.spec.name} (not confirmed).")
                return

        tor_rotate = self.query_one("#tor-rotate-checkbox", Checkbox).value
        log.write(f"running [bold]{entry.spec.name}[/bold] -> {target} ...")
        self._execute(entry.spec.name, target, tor_rotate)

    # push_screen_wait needs a worker, and the confirm must resolve on the main
    # thread before the blocking sweep starts — same split as _confirm_and_run.
    @work
    async def action_sweep(self) -> None:
        log = self.query_one("#run-log", RichLog)
        target = self.query_one("#target-input", Input).value.strip()
        if not target:
            log.write("Enter a target above before sweeping.")
            return

        try:
            entries, skipped = select_modules(self.registry, target, dict(os.environ))
        except SweepError as exc:
            log.write(str(exc))
            return

        for entry, missing in skipped:
            log.write(f"[dim]skipping {entry.spec.name}: needs {', '.join(missing)}[/dim]")
        if not entries:
            log.write(f"No runnable modules for {target}.")
            return

        # One batched confirm for the whole sweep, not one modal per module.
        active = [e for e in entries if not e.spec.passive]
        if active:
            listing = "\n".join(f"  · {e.spec.name}" for e in active)
            proceed = await self.push_screen_wait(
                ConfirmModal(
                    f"{len(active)} module(s) in this sweep are NOT passive-only and\n"
                    f"may send traffic to the target itself:\n\n{listing}\n\nRun the sweep anyway?"
                )
            )
            if not proceed:
                log.write("Sweep cancelled (not confirmed).")
                return

        tor_rotate = self.query_one("#tor-rotate-checkbox", Checkbox).value
        log.write(f"sweeping [bold]{target}[/bold] with {len(entries)} module(s) ...")
        self._execute_sweep([e.spec.name for e in entries], target, tor_rotate)

    @work(thread=True, exclusive=False)
    def _execute_sweep(self, module_names: list[str], target: str, tor_rotate: bool) -> None:
        if tor_rotate:
            if not self._rotate_or_block():
                return
            self.call_from_thread(
                self._log, "[dim](one circuit, shared by every module in this sweep)[/dim]"
            )

        entries = [self.registry[name] for name in module_names]

        @contextlib.contextmanager
        def ctx_factory(entry):
            """One client per module: a slow source's http_timeout applies to it
            alone, and each module gets its own CacheStats/EgressLog instead of
            racing — this sweep's Tor state is fixed for its whole run, so it's
            set once here rather than mutated per-module like _execute does."""
            egress_log = EgressLog()
            egress_log.current_tor_rotated = tor_rotate
            with build_client(
                timeout=entry.spec.http_timeout or 15.0,
                proxy=self.proxy,
                user_agent=self.user_agent,
                egress_log=egress_log,
            ) as client:
                yield RunContext(
                    http=client, env=dict(os.environ),
                    exec=logged_exec(self.base_exec_fn, egress_log, self.proxy),
                    egress_log=egress_log,
                )

        def progress(result: ModuleResult) -> None:
            mark = "OK" if result.ok else "FAILED"
            detail = result.error if result.error else f"{len(result.findings)} finding(s)"
            self.call_from_thread(
                self._log, f"{mark} {result.module} ({result.duration_ms:.0f}ms) — {detail}"
            )

        results = run_sweep(entries, target, ctx_factory, on_result=progress)

        # Sorted order in, serial recording — so findings.jsonl doesn't depend
        # on which module finished first.
        case = Case.open(self.cases_root, target)
        for result in results:
            case.record_result(result)

        self.call_from_thread(self._on_sweep_done, results)

    def _on_sweep_done(self, results: list[ModuleResult]) -> None:
        for result in results:
            self._add_result_rows(result)
        ok = sum(1 for r in results if r.ok)
        total = sum(len(r.findings) for r in results)
        self._log(f"[bold]sweep complete: {ok}/{len(results)} ok · {total:,} finding(s)[/bold]")

        all_findings = [f for r in results for f in r.findings]
        self._update_pivots(all_findings)

    def _rotate_or_block(self) -> bool:
        """Blocked, not degraded: running without the rotation the user asked
        for would look protected when it wasn't."""
        if not self.proxy:
            self.call_from_thread(
                self._log,
                "Tor checkbox is on but no --proxy is set — this run isn't "
                "routed through Tor to use the new circuit",
            )
        try:
            new_identity(self.tor_control_addr, self.tor_control_password)
            self.call_from_thread(self._log, "new tor circuit requested")
            return True
        except TorControlError as exc:
            self.call_from_thread(self._log, f"{exc} — run blocked")
            return False

    def _log(self, message: str) -> None:
        self.query_one("#run-log", RichLog).write(message)

    @work(thread=True, exclusive=False)
    def _execute(self, module_name: str, target: str, tor_rotate: bool) -> None:
        if tor_rotate and not self._rotate_or_block():
            return

        # Set fresh before this specific run: self.http_client/self.egress_log
        # persist across every module the user runs in this session.
        self.egress_log.current_tor_rotated = tor_rotate

        entry = self.registry[module_name]
        ctx = RunContext(
            http=self.http_client, env=dict(os.environ), exec=self.exec_fn,
            egress_log=self.egress_log,
        )
        result = run_module(entry, target, ctx)

        case = Case.open(self.cases_root, target)
        case.record_result(result)

        self.call_from_thread(self._on_result, result)

    def _on_result(self, result: ModuleResult) -> None:
        log = self.query_one("#run-log", RichLog)

        if result.ok:
            log.write(
                f"OK {result.module} -> {result.target} "
                f"({result.duration_ms:.0f}ms, {len(result.findings)} finding(s))"
            )
        else:
            log.write(f"FAILED {result.module} -> {result.target}: {result.error}")

        self._add_result_rows(result)
        self._update_pivots(result.findings)

    def _add_result_rows(self, result: ModuleResult) -> None:
        log = self.query_one("#run-log", RichLog)
        table = self.query_one("#results-table", DataTable)
        # Batched, and capped for display only: add_row per finding on the main
        # thread locks the UI on a 25k-result subdomain sweep. Every finding is
        # still recorded to disk in full — this caps rendering, the same way
        # export's --limit caps inlining.
        shown = result.findings[:MAX_DISPLAYED_ROWS]
        table.add_rows(
            (
                finding.type,
                finding.value,
                finding.module,
                Text(
                    finding.confidence,
                    style="bold" if finding.confidence == "Unverified" else "dim",
                ),
            )
            for finding in shown
        )
        hidden = len(result.findings) - len(shown)
        if hidden > 0:
            log.write(
                f"[dim]showing first {MAX_DISPLAYED_ROWS:,} of {len(result.findings):,} — "
                f"all of them are in cases/{slugify(result.target)}/findings.jsonl[/dim]"
            )

    def _update_pivots(self, findings: list) -> None:
        pivots = suggest_next(self.registry, findings)
        strip = self.query_one("#pivot-strip", Static)
        if pivots:
            text = "Suggested pivots: " + "  ".join(s.describe() for s in pivots)
        else:
            text = "No further pivots suggested from this result."
        strip.update(text)
