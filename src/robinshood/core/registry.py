from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from types import ModuleType

from robinshood import modules as modules_pkg
from robinshood.core.types import ModuleSpec


@dataclass(frozen=True)
class RegisteredModule:
    spec: ModuleSpec
    run: callable


class Registry:
    def __init__(self, entries: dict[str, RegisteredModule]):
        self._entries = entries

    def __getitem__(self, name: str) -> RegisteredModule:
        return self._entries[name]

    def __contains__(self, name: str) -> bool:
        return name in self._entries

    def __iter__(self):
        return iter(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def by_category(self) -> dict[str, list[RegisteredModule]]:
        grouped: dict[str, list[RegisteredModule]] = {}
        for entry in self._entries.values():
            grouped.setdefault(entry.spec.category, []).append(entry)
        return grouped

    def consuming(self, input_type: str) -> list[RegisteredModule]:
        return [e for e in self._entries.values() if e.spec.consumes == input_type]

    def producing(self, output_type: str) -> list[RegisteredModule]:
        return [e for e in self._entries.values() if output_type in e.spec.produces]


def _iter_module_files(pkg: ModuleType):
    for finder, name, is_pkg in pkgutil.walk_packages(pkg.__path__, prefix=f"{pkg.__name__}."):
        if is_pkg:
            continue
        yield name


def load_registry() -> Registry:
    entries: dict[str, RegisteredModule] = {}
    for dotted_name in _iter_module_files(modules_pkg):
        mod = importlib.import_module(dotted_name)
        if not hasattr(mod, "MODULE"):
            raise ValueError(f"{dotted_name}: missing required MODULE spec")
        if not hasattr(mod, "run"):
            raise ValueError(f"{dotted_name}: missing required run() function")
        spec = mod.MODULE
        if not isinstance(spec, ModuleSpec):
            raise TypeError(f"{dotted_name}: MODULE must be a ModuleSpec, got {type(spec)!r}")
        if spec.name in entries:
            raise ValueError(
                f"{dotted_name}: duplicate module name {spec.name!r} "
                f"(already registered by another module file)"
            )
        entries[spec.name] = RegisteredModule(spec=spec, run=mod.run)
    return Registry(entries)
