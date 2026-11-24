import pytest
from pydantic import ValidationError

from cyberloop.schemas import AttackPlan, AttackType, AttemptResult, ExecutionResult


def make_execution(*outcomes: bool) -> ExecutionResult:
    attempts = [AttemptResult(payload=f"payload-{i}", succeeded=ok) for i, ok in enumerate(outcomes)]
    return ExecutionResult(
        iteration=1,
        attack_type=AttackType.SQL_INJECTION,
        target_endpoint="/login",
        attempts=attempts,
        duration_s=0.5,
    )


def test_execution_metrics_are_computed_from_attempts():
    result = make_execution(True, False, False, True)
    assert result.successful_attempts == 2
    assert result.success_rate == 0.5
    assert result.attack_succeeded


def test_blocked_execution():
    result = make_execution(False, False)
    assert result.success_rate == 0.0
    assert not result.attack_succeeded


def test_execution_without_attempts():
    assert make_execution().success_rate == 0.0


def test_computed_metrics_are_serialized():
    data = make_execution(True).model_dump(mode="json")
    assert data["attack_succeeded"] is True
    assert data["success_rate"] == 1.0
    assert ExecutionResult.model_validate(data).attack_succeeded


VALID_PLAN = dict(
    attack_type=AttackType.DDOS,
    mitre_technique_id="T1499.002",
    target_endpoint="/products",
    test_strategy="Flood the search endpoint.",
    success_criteria=["Requests time out"],
    confidence=0.8,
)


def test_plan_accepts_sub_technique_id():
    assert AttackPlan(**VALID_PLAN).mitre_technique_id == "T1499.002"


@pytest.mark.parametrize(
    "field, value",
    [
        ("confidence", 1.5),
        ("mitre_technique_id", "T1499.002 Service Exhaustion Flood"),
    ],
)
def test_plan_rejects_invalid_values(field, value):
    with pytest.raises(ValidationError):
        AttackPlan(**{**VALID_PLAN, field: value})
