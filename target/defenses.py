"""Defenses the target can switch on. Names match cyberloop.schemas.DefenseId."""

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

_SQL_METACHARACTERS = ("'", '"', ";", "--", "/*", "*/")
_SQLI_SIGNATURE = re.compile(
    r"(--)|(\bunion\b\s+\bselect\b)|(\bor\b\s*\(?\s*['\"]?\d)|(['\"]\s*or\s*['\"])",
    re.IGNORECASE,
)


def has_sql_metacharacters(value: str) -> bool:
    return any(token in value for token in _SQL_METACHARACTERS)


def looks_like_sqli(value: str) -> bool:
    return _SQLI_SIGNATURE.search(value) is not None


def blocking_defense(active: frozenset[str], value: str) -> str | None:
    """Return the defense that blocks `value` outright, or None to let the request through."""
    if "input_validation" in active and has_sql_metacharacters(value):
        return "input_validation"
    if "waf_rules" in active and looks_like_sqli(value):
        return "waf_rules"
    return None
