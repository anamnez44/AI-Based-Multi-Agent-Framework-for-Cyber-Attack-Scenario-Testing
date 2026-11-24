"""Handoff contracts between agents. Agents exchange only these models, serialized as JSON."""

from enum import StrEnum

from pydantic import BaseModel, Field, computed_field, field_validator


class AttackType(StrEnum):
    SQL_INJECTION = "sql_injection"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    PHISHING = "phishing"


class DefenseId(StrEnum):
    INPUT_VALIDATION = "input_validation"
    WAF_RULES = "waf_rules"
    PARAMETERIZED_QUERIES = "parameterized_queries"
    LOGIN_DELAY = "login_delay"
    ACCOUNT_LOCKOUT = "account_lockout"
    RATE_LIMITING = "rate_limiting"
    RESPONSE_CACHING = "response_caching"
    SECURITY_HEADERS = "security_headers"
    CONTENT_SECURITY_POLICY = "content_security_policy"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackPlan(BaseModel):
    """Analyst -> Executor. Produced entirely by the LLM."""

    attack_type: AttackType
    mitre_technique_id: str = Field(
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="Only the MITRE ATT&CK technique ID from the catalog, e.g. T1190 or T1110.001",
    )
    target_endpoint: str = Field(description="Endpoint of the target application to test, e.g. /login")
    test_strategy: str = Field(description="At most two sentences on how to test the target")
    success_criteria: list[str] = Field(description="1-3 observable conditions meaning the attack succeeded")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence of the classification between 0 and 1")

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalize_confidence(cls, value):
        """Accept a percentage too: smaller models often answer 95 or 100 instead of 0.0-1.0."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return value
        if number > 1.0:
            number /= 100.0
        return max(0.0, min(1.0, number))


class AttemptResult(BaseModel):
    """Single request sent by the Executor and what it revealed."""

    payload: str
    status_code: int | None = None
    succeeded: bool
    evidence: str = ""
    latency_ms: float = 0.0


class ExecutionResult(BaseModel):
    """Executor -> Evaluator. Measured by code, no LLM involved."""

    iteration: int
    attack_type: AttackType
    target_endpoint: str
    attempts: list[AttemptResult]
    duration_s: float

    @computed_field
    @property
    def successful_attempts(self) -> int:
        return sum(attempt.succeeded for attempt in self.attempts)

    @computed_field
    @property
    def success_rate(self) -> float:
        return self.successful_attempts / len(self.attempts) if self.attempts else 0.0

    @computed_field
    @property
    def attack_succeeded(self) -> bool:
        return self.successful_attempts > 0


class Assessment(BaseModel):
    """LLM judgement attached to the measured facts of an execution."""

    severity: Severity
    findings: list[str] = Field(description="1-3 short findings based on the evidence")
    recommended_defenses: list[DefenseId] = Field(description="Defenses from the whitelist, best first")
    summary: str = Field(description="At most three sentences for the report")


class EvaluationReport(BaseModel):
    """Evaluator -> Defender, or the final report when the cycle stops."""

    iteration: int
    attack_succeeded: bool
    success_rate: float
    assessment: Assessment


class DefenseDecision(BaseModel):
    """LLM choice of the next defense from the whitelist."""

    defense_id: DefenseId
    rationale: str = Field(description="One or two sentences justifying the choice")


class DefenseAction(BaseModel):
    """Defender -> Executor: the decision and whether it was applied to the target."""

    iteration: int
    decision: DefenseDecision
    applied: bool
    details: str = ""
