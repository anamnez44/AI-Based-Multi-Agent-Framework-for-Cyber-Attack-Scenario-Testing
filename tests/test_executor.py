import pytest

from cyberloop.agents import ExecutorAgent
from cyberloop.schemas import AttackType

from .conftest import set_defenses


def make_plan(endpoint: str):
    from cyberloop.schemas import AttackPlan

    return AttackPlan(
        attack_type=AttackType.SQL_INJECTION,
        mitre_technique_id="T1190",
        target_endpoint=endpoint,
        test_strategy="Send SQL injection payloads.",
        success_criteria=["Authentication bypassed"],
        confidence=0.9,
    )


def test_executor_breaks_into_the_vulnerable_login(target_client):
    result = ExecutorAgent(target_client).run(make_plan("/login"), iteration=1)
    assert result.attack_succeeded
    assert result.successful_attempts == len(result.attempts)
    assert all("admin" in a.evidence for a in result.attempts)


def test_executor_leaks_hidden_product_via_search(target_client):
    result = ExecutorAgent(target_client).run(make_plan("/products"), iteration=1)
    assert result.attack_succeeded
    assert any("FLAG-SECRET-PRODUCT" in a.evidence for a in result.attempts if a.succeeded)


def test_executor_reports_failure_once_parameterized_queries_are_on(target_client):
    set_defenses(target_client, "parameterized_queries")
    result = ExecutorAgent(target_client).run(make_plan("/login"), iteration=2)
    assert not result.attack_succeeded
    assert result.success_rate == 0.0
    assert all(a.status_code == 200 for a in result.attempts)


def test_executor_still_breaks_in_behind_a_single_mitigation(target_client):
    # A WAF is not enough: the obfuscated payload still gets through.
    set_defenses(target_client, "waf_rules")
    result = ExecutorAgent(target_client).run(make_plan("/login"), iteration=2)
    assert result.attack_succeeded
    assert 0 < result.success_rate < 1.0
    assert any("blocked" in a.evidence for a in result.attempts)


def test_executor_rejects_unsupported_attack_types(target_client):
    plan = make_plan("/login").model_copy(update={"attack_type": AttackType.DDOS})
    with pytest.raises(NotImplementedError):
        ExecutorAgent(target_client).run(plan, iteration=1)
