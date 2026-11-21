from __future__ import annotations

from dataclasses import dataclass

from robinshood.core.registry import RegisteredModule, Registry
from robinshood.core.types import Finding


@dataclass(frozen=True)
class PivotSuggestion:
    module: RegisteredModule
    finding_type: str
    sample_value: str
    count: int

    def describe(self) -> str:
        if self.count == 1:
            return f"{self.module.spec.name}({self.sample_value})"
        return f"{self.module.spec.name}({self.count} {self.finding_type}s, e.g. {self.sample_value})"


def suggest_next(registry: Registry, findings: list[Finding]) -> list[PivotSuggestion]:
    """For each produced finding type, return modules that consume it — the
    deterministic, code-driven equivalent of a pivot playbook's next step.

    A module is never suggested against findings it produced itself: subfinder
    finding 25k subdomains must not propose re-running subfinder on each one.
    """
    # finding type -> (ordered distinct values, set of modules that produced them)
    by_type: dict[str, list[str]] = {}
    producers: dict[str, set[str]] = {}
    for finding in findings:
        values = by_type.setdefault(finding.type, [])
        if finding.value not in values:
            values.append(finding.value)
        producers.setdefault(finding.type, set()).add(finding.module)

    suggestions: dict[str, PivotSuggestion] = {}
    for finding_type, values in by_type.items():
        for candidate in registry.consuming(finding_type):
            name = candidate.spec.name
            if name in producers[finding_type] or name in suggestions:
                continue
            suggestions[name] = PivotSuggestion(
                module=candidate,
                finding_type=finding_type,
                sample_value=values[0],
                count=len(values),
            )
    return list(suggestions.values())
