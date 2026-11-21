from __future__ import annotations

import pytest

from robinshood.core.detect import detect_target_type


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", "domain"),
        ("sub.example.co.uk", "domain"),
        ("8.8.8.8", "ip"),
        ("2606:4700::1", "ip"),
        ("user@example.com", "email"),
        ("https://example.com/path", "url"),
        ("torvalds", "username"),
        ("+15551234567", "phone"),
        ("15551234567", "phone"),
        ("5551234567", "phone"),  # 10 digits, no '+' -- still resolves as phone, not username
        ("+1", None),  # too short to be a real E.164 number
        ("123", "username"),  # too short for phone, falls through to the username pattern
        ("", None),
        ("not a target!!", None),
    ],
)
def test_detect_target_type(value, expected):
    assert detect_target_type(value) == expected
