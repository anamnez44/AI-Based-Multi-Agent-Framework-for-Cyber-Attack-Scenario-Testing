from cyberloop.agents import EvaluatorAgent
from cyberloop.schemas import (
    Assessment,
    AttackType,
    AttemptResult,
    DefenseId,
    ExecutionResult,
    Severity,
)
from tests.fakes import FakeStructuredLLM, structured_result


def execution(succeeded: bool, iteration: int = 1) -> ExecutionResult:
    return ExecutionResult(
        iteration=iteration,
        attack_type=AttackType.SQL_INJECTION,
        target_endpoint="/login",
        attempts=[AttemptResult(payload="p", succeeded=succeeded, evidence="e")],
        duration_s=0.1,
    )


def assessment(*defenses: DefenseId, severity: Severity = Severity.HIGH) -> Assessment:
    return Assessment(
        severity=severity,
        findings=["login authentication can be bypassed"],
        recommended_defenses=list(defenses),
        summary="The endpoint is vulnerable.",
    )


def test_report_carries_measured_facts_not_the_models_opinion():
    llm = FakeStructuredLLM(structured_result(assessment(DefenseId.PARAMETERIZED_QUERIES)))
    report, _ = EvaluatorAgent(llm).evaluate(execution(succeeded=True), applied_defenses=[])
    assert report.attack_succeeded is True
    assert report.success_rate == 1.0
    assert report.assessment.recommended_defenses == [DefenseId.PARAMETERIZED_QUERIES]


def test_recommendation_outside_the_whitelist_is_rejected_then_retried():
    llm = FakeStructuredLLM(
        structured_result(assessment(DefenseId.RATE_LIMITING)),  # not a SQLi defense
        structured_result(assessment(DefenseId.PARAMETERIZED_QUERIES)),
    )
    report, stats = EvaluatorAgent(llm).evaluate(execution(succeeded=True), applied_defenses=[])
    assert stats.attempts == 2
    assert report.assessment.recommended_defenses == [DefenseId.PARAMETERIZED_QUERIES]
    assert "rate_limiting" in llm.calls[1][-1].content


def test_blocked_attack_can_recommend_no_defenses():
    llm = FakeStructuredLLM(structured_result(assessment(severity=Severity.LOW)))
    report, _ = EvaluatorAgent(llm).evaluate(execution(succeeded=False), applied_defenses=["parameterized_queries"])
    assert report.attack_succeeded is False
    assert report.assessment.recommended_defenses == []
