"""Local knowledge base given to the agents: MITRE ATT&CK techniques, defense whitelist, target endpoints."""

from .schemas import AttackType, DefenseId

__all__ = ["MITRE_TECHNIQUES", "DEFENSES", "TARGET_ENDPOINTS", "DEFENSE_DESCRIPTIONS", "defenses_for"]

MITRE_TECHNIQUES: dict[AttackType, dict[str, str]] = {
    AttackType.SQL_INJECTION: {
        "T1190": "Exploit Public-Facing Application",
    },
    AttackType.BRUTE_FORCE: {
        "T1110.001": "Brute Force: Password Guessing",
        "T1110.003": "Brute Force: Password Spraying",
        "T1110.004": "Brute Force: Credential Stuffing",
    },
    AttackType.DDOS: {
        "T1498.001": "Network Denial of Service: Direct Network Flood",
        "T1499.002": "Endpoint Denial of Service: Service Exhaustion Flood",
        "T1499.003": "Endpoint Denial of Service: Application Exhaustion Flood",
    },
    AttackType.PHISHING: {
        "T1566.002": "Phishing: Spearphishing Link",
        "T1189": "Drive-by Compromise",
    },
}

DEFENSES: dict[AttackType, list[DefenseId]] = {
    AttackType.SQL_INJECTION: [
        DefenseId.INPUT_VALIDATION,
        DefenseId.WAF_RULES,
        DefenseId.PARAMETERIZED_QUERIES,
    ],
    AttackType.BRUTE_FORCE: [
        DefenseId.LOGIN_DELAY,
        DefenseId.ACCOUNT_LOCKOUT,
        DefenseId.RATE_LIMITING,
    ],
    AttackType.DDOS: [
        DefenseId.RATE_LIMITING,
        DefenseId.RESPONSE_CACHING,
    ],
    AttackType.PHISHING: [
        DefenseId.SECURITY_HEADERS,
        DefenseId.CONTENT_SECURITY_POLICY,
    ],
}

TARGET_ENDPOINTS: dict[str, str] = {
    "/login": "POST form with username and password fields",
    "/products": "GET product search with query parameter q",
    "/": "HTML home page",
}

# Factual descriptions only. They must not say which defense is best or which can be bypassed:
# the whole point of the experiment is to measure how well the agents judge that themselves.
DEFENSE_DESCRIPTIONS: dict[DefenseId, str] = {
    DefenseId.INPUT_VALIDATION: "Reject requests whose input contains blacklisted SQL keywords or comment tokens.",
    DefenseId.WAF_RULES: "Inspect requests at the perimeter and block those matching SQL-injection signatures.",
    DefenseId.PARAMETERIZED_QUERIES: "Send user input to the database as bound parameters kept separate from the SQL text.",
    DefenseId.LOGIN_DELAY: "Add a growing delay after failed logins to slow down guessing.",
    DefenseId.ACCOUNT_LOCKOUT: "Lock an account after several failed logins.",
    DefenseId.RATE_LIMITING: "Cap the number of requests per client over a time window.",
    DefenseId.RESPONSE_CACHING: "Serve cached responses to absorb floods of identical requests.",
    DefenseId.SECURITY_HEADERS: "Send protective HTTP headers such as X-Frame-Options and X-Content-Type-Options.",
    DefenseId.CONTENT_SECURITY_POLICY: "Restrict where content may load from to limit clickjacking and injection.",
}


def defenses_for(attack_type: AttackType) -> list[DefenseId]:
    return DEFENSES[attack_type]
