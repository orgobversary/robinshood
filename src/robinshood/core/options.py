from __future__ import annotations

from typing import Any

from robinshood.core.types import ModuleOption, ModuleSpec


class ModuleOptionError(ValueError):
    """An invalid module option supplied by an operator."""


def _choice(option: ModuleOption, raw: str) -> str:
    by_casefold = {choice.casefold(): choice for choice in option.choices}
    try:
        return by_casefold[raw.casefold()]
    except KeyError as exc:
        choices = ", ".join(option.choices)
        raise ModuleOptionError(
            f"option {option.name!r} must be one of: {choices}"
        ) from exc


def parse_option_value(option: ModuleOption, raw: str) -> Any:
    if option.kind == "str":
        return raw.strip()
    if option.kind == "bool":
        normalized = raw.strip().casefold()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ModuleOptionError(
            f"option {option.name!r} must be true/false, yes/no, on/off, or 1/0"
        )
    if option.kind == "int":
        try:
            value = int(raw)
        except ValueError as exc:
            raise ModuleOptionError(f"option {option.name!r} must be an integer") from exc
        if option.minimum is not None and value < option.minimum:
            raise ModuleOptionError(
                f"option {option.name!r} must be at least {option.minimum}"
            )
        if option.maximum is not None and value > option.maximum:
            raise ModuleOptionError(
                f"option {option.name!r} must be at most {option.maximum}"
            )
        return value
    if option.kind == "choice":
        return _choice(option, raw.strip())
    if option.kind == "choice_list":
        values = tuple(part.strip() for part in raw.split(",") if part.strip())
        if not values:
            raise ModuleOptionError(f"option {option.name!r} requires at least one value")
        normalized = tuple(_choice(option, value) for value in values)
        return tuple(dict.fromkeys(normalized))
    raise AssertionError(f"unhandled option kind: {option.kind}")


def parse_module_options(spec: ModuleSpec, raw_options: list[str]) -> dict[str, Any]:
    declared = {option.name: option for option in spec.options}
    parsed: dict[str, Any] = {}
    for raw_option in raw_options:
        name, separator, raw_value = raw_option.partition("=")
        name = name.strip()
        if not separator or not name:
            raise ModuleOptionError(
                f"invalid option {raw_option!r}; expected NAME=VALUE"
            )
        if name not in declared:
            available = ", ".join(declared) or "(none)"
            raise ModuleOptionError(
                f"module {spec.name!r} has no option {name!r}; available: {available}"
            )
        if name in parsed:
            raise ModuleOptionError(f"option {name!r} was supplied more than once")
        parsed[name] = parse_option_value(declared[name], raw_value)
    return parsed


def effective_module_options(spec: ModuleSpec, overrides: dict[str, Any]) -> dict[str, Any]:
    effective = {
        option.name: option.default
        for option in spec.options
        if option.default is not None
    }
    effective.update(overrides)
    return effective


def validate_module_options(
    spec: ModuleSpec,
    overrides: dict[str, Any],
    validator=None,
) -> dict[str, Any]:
    """Build the effective option set and apply any cross-option constraints."""
    effective = effective_module_options(spec, overrides)
    if validator is not None:
        validator(effective)
    return effective


def jsonable_options(options: dict[str, Any]) -> dict[str, Any]:
    return {
        name: list(value) if isinstance(value, tuple) else value
        for name, value in options.items()
    }


def option_default_text(option: ModuleOption) -> str:
    if option.default is None:
        return "(unset)"
    if isinstance(option.default, tuple):
        return ",".join(str(value) for value in option.default)
    if isinstance(option.default, bool):
        return str(option.default).lower()
    return str(option.default)
