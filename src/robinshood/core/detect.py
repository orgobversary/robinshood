from __future__ import annotations

import ipaddress
import re

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,39}$")
# E.164-ish: optional leading +, 8-15 digits total (ITU E.164's actual max),
# never bare enough to collide with a plausible domain or username.
_PHONE_RE = re.compile(r"^\+?[1-9]\d{7,14}$")


def detect_target_type(value: str) -> str | None:
    """Best-effort guess of an input's type, used only to filter the module
    list in the TUI — never trusted for validation inside a module."""
    value = value.strip()
    if not value:
        return None
    if value.startswith(("http://", "https://")):
        return "url"
    if "@" in value and _EMAIL_RE.match(value):
        return "email"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    # Checked before domain/username: a bare "+15551234567" or "15551234567"
    # would never match _DOMAIN_RE (no dot) but could pass _USERNAME_RE, so
    # phone has to be resolved first to avoid misrouting it.
    if _PHONE_RE.match(value):
        return "phone"
    if _DOMAIN_RE.match(value):
        return "domain"
    if _USERNAME_RE.match(value):
        return "username"
    return None
