"""End-to-end loop with deterministic (fake) LLM agents and the real Executor against the target.

This pins the core research claim: a closed loop reaches full protection by escalating defenses,
while a single pass that stops after one mitigation leaves the target exploitable.
"""

import httpx

from cyberloop.agents import ExecutorAgent
from cyberloop.llm import LLMCallStats
from cyberloop.orchestrator import LoopDeps, run_scenario
from cyberloop.schemas import (
    Assessment,
    AttackPlan,
    AttackType,
    DefenseDecision,
    DefenseId,
    EvaluationReport,
    Severity,
)
from cyberloop.target_control import TargetControl

NO_COST = LLMCallStats(duration_s=0.0, attempts=1, input_tokens=0, output_tokens=0)


class FixedAnalyst:
    def analyze(self, scenario):
        plan = AttackPlan(
            attack_type=AttackType.SQL_INJECTION,
            mitre_technique_id="T1190",
            target_endpoint="/login",
            test_strategy="Probe the login form.",
            success_criteria=["Authentication bypassed"],
            confidence=0.9,
        )
        return plan, NO_COST


class EchoEvaluator:
    """Reports the measured facts; recommends whatever defenses the test wants, in order."""

    def __init__(self, recommended):
        self.recommended = recommended

    def evaluate(self, execution, applied_defenses):
        report = EvaluationReport(
            iteration=execution.iteration,
            attack_succeeded=execution.attack_succeeded,
            success_rate=execution.success_rate,
            assessment=Assessment(
                severity=Severity.HIGH if execution.attack_succeeded else Severity.LOW,
                findings=["bypass" if execution.attack_succeeded else "blocked"],
                recommended_defenses=self.recommended if execution.attack_succeeded else [],
                summary="assessment",
            ),
        )
        return report, NO_COST


class PreferenceDefender:
    """Deploys defenses following a fixed preference order."""

    def __init__(self, order):
        self.order = order

    def decide(self, evaluation, allowed):
        choice = next(d for d in self.order if d in allowed)
        return DefenseDecision(defense_id=choice, rationale="test"), NO_COST


def make_deps(target_client, defender_order):
    return LoopDeps(
        analyst=FixedAnalyst(),
        executor=ExecutorAgent(target_client),
        evaluator=EchoEvaluator(defender_order),
        defender=PreferenceDefender(defender_order),
        control=TargetControl(target_client),
    )


MITIGATIONS_FIRST = [DefenseId.WAF_RULES, DefenseId.INPUT_VALIDATION, DefenseId.PARAMETERIZED_QUERIES]


def test_closed_loop_escalates_until_the_target_is_protected(target_client):
    deps = make_deps(target_client, MITIGATIONS_FIRST)
    result = run_scenario(deps, "SQL injection in the login form", mode="closed_loop", max_iterations=3)

    assert result.blocked
    assert result.initial_success_rate == 1.0
    assert result.final_success_rate == 0.0
    assert result.defenses_applied == ["waf_rules", "input_validation", "parameterized_queries"]
    assert result.iterations == 4
    assert "blocked" in result.stop_reason


def test_single_pass_stops_after_one_mitigation_and_stays_exploitable(target_client):
    deps = make_deps(target_client, MITIGATIONS_FIRST)
    result = run_scenario(deps, "SQL injection in the login form", mode="single_pass", max_iterations=3)

    assert not result.blocked
    assert result.defenses_applied == ["waf_rules"]
    assert result.iterations == 2
    assert result.final_success_rate > 0.0
    assert "single-pass" in result.stop_reason


def test_closed_loop_stops_early_when_the_right_defense_is_chosen_first(target_client):
    deps = make_deps(target_client, [DefenseId.PARAMETERIZED_QUERIES, DefenseId.WAF_RULES])
    result = run_scenario(deps, "SQL injection in the login form", mode="closed_loop", max_iterations=3)

    assert result.blocked
    assert result.defenses_applied == ["parameterized_queries"]
    assert result.iterations == 2


def test_target_is_reset_after_a_run(target_client):
    run_scenario(make_deps(target_client, MITIGATIONS_FIRST), "x", mode="closed_loop", max_iterations=3)
    assert TargetControl(target_client).active() == []
