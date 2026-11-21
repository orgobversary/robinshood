from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="hackertarget_hostsearch",
    category="infra",
    description="Reverse-IP lookup — other hostnames resolving to the same server (shared hosting).",
    consumes="ip",
    produces=("domain",),
    passive=True,
    source_url="https://api.hackertarget.com/hostsearch/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = "https://api.hackertarget.com/hostsearch/"
    resp = ctx.http.get(url, params={"q": target})
    resp.raise_for_status()
    text = resp.text.strip()

    # The free tier answers a 200 with a plain-text error body once the 50
    # requests/day cap is hit — never mistake that for "no hostnames found".
    if not text or "API count exceeded" in text:
        if "API count exceeded" in text:
            raise RuntimeError("hackertarget.com free-tier rate limit hit (50 requests/day) — try later")
        return []

    findings: list[Finding] = []
    seen: set[str] = set()
    for line in text.splitlines():
        hostname, _, ip = line.partition(",")
        hostname = hostname.strip()
        if not hostname or hostname in seen or hostname == target:
            continue
        seen.add(hostname)
        findings.append(
            Finding(
                type="domain", value=hostname, module=MODULE.name, target=target,
                source_url=f"{url}?q={target}", raw={"ip": ip.strip()},
            )
        )
    return findings
