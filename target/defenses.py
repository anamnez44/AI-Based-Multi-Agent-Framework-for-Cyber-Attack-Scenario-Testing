"""Defenses the target can switch on. Names match cyberloop.schemas.DefenseId.

For SQL injection the three defenses are deliberately unequal, as they are in practice:

- waf_rules and input_validation are mitigations. They block known payloads but can be
  bypassed (inline comments, boolean chains without comment markers).
- parameterized_queries removes the vulnerability at its root and cannot be bypassed.

So no single mitigation is enough, and even both together miss an obfuscated payload. Only
parameterized queries fully protect the endpoint. This is what makes the closed loop worth
more than a single pass: one defense is often not the right one.
"""

import re

ALL_DEFENSES = frozenset(
    {
        "input_validation",
        "waf_rules",
        "parameterized_queries",
        "login_delay",
        "account_lockout",
        "rate_limiting",
        "response_caching",
        "security_headers",
        "content_security_policy",
    }
)

# Perimeter signatures. Catches the obvious payloads but not comment-obfuscated ones.
_WAF_SIGNATURE = re.compile(
    r"(--)|(\bunion\b\s+\bselect\b)|(\bor\b\s*\(?\s*['\"]?\d)|(['\"]\s*or\s*['\"])",
    re.IGNORECASE,
)

# Blacklist validation. A common anti-pattern: it forbids comment and keyword tokens but not
# quotes, so a boolean injection that avoids those tokens slips through.
_INPUT_BLACKLIST = ("--", ";", "union", "drop")


def matches_waf_signature(value: str) -> bool:
    return _WAF_SIGNATURE.search(value) is not None


def hits_input_blacklist(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in _INPUT_BLACKLIST)


def blocking_defense(active: frozenset[str], value: str) -> str | None:
    """Return the defense that blocks `value` outright, or None to let the request through."""
    if "waf_rules" in active and matches_waf_signature(value):
        return "waf_rules"
    if "input_validation" in active and hits_input_blacklist(value):
        return "input_validation"
    return None
