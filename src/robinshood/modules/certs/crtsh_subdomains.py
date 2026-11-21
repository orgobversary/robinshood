from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="crtsh_subdomains",
    category="certs",
    description="Enumerate subdomains observed in Certificate Transparency logs via crt.sh.",
    consumes="domain",
    produces=("domain",),
    passive=True,
    source_url="https://crt.sh/",
    # crt.sh routinely takes well over the 15s default on a busy domain; at the
    # default it was recorded as a failure rather than a slow success.
    http_timeout=60.0,
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = "https://crt.sh/"
    resp = ctx.http.get(url, params={"q": f"%.{target}", "output": "json"})
    resp.raise_for_status()
    entries = resp.json()

    seen: set[str] = set()
    findings: list[Finding] = []
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if not name or name in seen or name == target:
                continue
            seen.add(name)
            findings.append(
                Finding(
                    type="domain",
                    value=name,
                    module=MODULE.name,
                    target=target,
                    source_url=f"https://crt.sh/?q=%.{target}&output=json",
                    raw={"cert_id": entry.get("id"), "issuer": entry.get("issuer_name")},
                )
            )
    return findings
