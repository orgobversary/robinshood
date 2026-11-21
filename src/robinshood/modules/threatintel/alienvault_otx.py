from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="alienvault_otx",
    category="threatintel",
    description="Community threat-intel pulses referencing a domain, via AlienVault OTX.",
    consumes="domain",
    produces=("threat_pulse",),
    passive=True,
    source_url="https://otx.alienvault.com/api/v1/indicators/domain/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"
    resp = ctx.http.get(url)
    resp.raise_for_status()
    data = resp.json()
    pulses = data.get("pulse_info", {}).get("pulses", [])
    if not pulses:
        return []
    return [
        Finding(
            type="threat_pulse",
            # Pulse names occasionally embed literal newlines/runs of whitespace,
            # which renders ugly in findings.jsonl and the exported note.
            value=" ".join(pulse.get("name", "unnamed pulse").split()),
            module=MODULE.name,
            target=target,
            source_url=url,
            raw={"tags": pulse.get("tags"), "created": pulse.get("created")},
        )
        for pulse in pulses
    ]
