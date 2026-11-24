import pytest

from cyberloop.agents.analyst import SYSTEM_PROMPT, AnalystAgent, check_plan
from cyberloop.catalog import MITRE_TECHNIQUES, TARGET_ENDPOINTS
from cyberloop.schemas import AttackPlan, AttackType
from tests.fakes import FakeStructuredLLM, structured_result


def make_plan(**overrides) -> AttackPlan:
    data = dict(
        attack_type=AttackType.SQL_INJECTION,
        mitre_technique_id="T1190",
        target_endpoint="/login",
        test_strategy="Send authentication bypass payloads to the login form.",
        success_criteria=["Logged in as admin without a valid password"],
        confidence=0.9,
    )
    data.update(overrides)
    return AttackPlan(**data)


def test_prompt_lists_every_technique_and_endpoint():
    for techniques in MITRE_TECHNIQUES.values():
        for technique_id in techniques:
            assert technique_id in SYSTEM_PROMPT
    for path in TARGET_ENDPOINTS:
        assert path in SYSTEM_PROMPT


def test_check_plan_accepts_endpoint_with_query_string():
    check_plan(make_plan(target_endpoint="/products?q=test"))


def test_check_plan_rejects_technique_of_another_attack_type():
    with pytest.raises(ValueError, match="T1110.001"):
        check_plan(make_plan(mitre_technique_id="T1110.001"))


def test_check_plan_rejects_unknown_endpoint():
    with pytest.raises(ValueError, match="/admin"):
        check_plan(make_plan(target_endpoint="/admin"))


def test_analyze_retries_inconsistent_plan():
    llm = FakeStructuredLLM(
        structured_result(make_plan(mitre_technique_id="T1499.002")),
        structured_result(make_plan()),
    )
    plan, stats = AnalystAgent(llm).analyze("SQL injection in the login form")
    assert plan.mitre_technique_id == "T1190"
    assert stats.attempts == 2
    assert "SQL injection in the login form" in llm.calls[0][-1].content
