import pytest

from cyberloop.agents import DefenderAgent
from cyberloop.schemas import (
    Assessment,
    DefenseDecision,
    DefenseId,
    EvaluationReport,
    Severity,
)
from tests.fakes import FakeStructuredLLM, structured_result

SQLI_DEFENSES = [DefenseId.INPUT_VALIDATION, DefenseId.WAF_RULES, DefenseId.PARAMETERIZED_QUERIES]


def report(*recommended: DefenseId) -> EvaluationReport:
    return EvaluationReport(
        iteration=1,
        attack_succeeded=True,
        success_rate=1.0,
        assessment=Assessment(
            severity=Severity.HIGH,
            findings=["bypass possible"],
            recommended_defenses=list(recommended),
            summary="vulnerable",
        ),
    )


def decision(defense: DefenseId) -> DefenseDecision:
    return DefenseDecision(defense_id=defense, rationale="because")


def test_defender_picks_an_allowed_defense():
    llm = FakeStructuredLLM(structured_result(decision(DefenseId.PARAMETERIZED_QUERIES)))
    result, _ = DefenderAgent(llm).decide(report(DefenseId.PARAMETERIZED_QUERIES), SQLI_DEFENSES)
    assert result.defense_id == DefenseId.PARAMETERIZED_QUERIES


def test_defender_retries_when_choosing_an_already_excluded_defense():
    remaining = [DefenseId.PARAMETERIZED_QUERIES]
    llm = FakeStructuredLLM(
        structured_result(decision(DefenseId.WAF_RULES)),  # already applied, not in remaining
        structured_result(decision(DefenseId.PARAMETERIZED_QUERIES)),
    )
    result, stats = DefenderAgent(llm).decide(report(), remaining)
    assert result.defense_id == DefenseId.PARAMETERIZED_QUERIES
    assert stats.attempts == 2


def test_defender_refuses_when_nothing_is_allowed():
    with pytest.raises(ValueError, match="no defenses left"):
        DefenderAgent(FakeStructuredLLM()).decide(report(), [])
