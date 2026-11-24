"""Local knowledge base given to the agents: MITRE ATT&CK techniques, defense whitelist, target endpoints."""

from .schemas import AttackType, DefenseId

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
