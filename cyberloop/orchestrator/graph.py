"""LangGraph closed loop: analyse, test, evaluate, harden, re-test.

The loop stops when the attack no longer gets through (the target is protected) or when the
defense budget is spent. In single-pass mode it stops right after the first defense, without
re-testing, which is the baseline the closed loop is compared against.
"""

from dataclasses import dataclass

from langgraph.graph import END, START, StateGraph

from ..agents.analyst import AnalystAgent
from ..agents.defender import DefenderAgent
from ..agents.evaluator import EvaluatorAgent
from ..agents.executor import ExecutorAgent
from ..catalog import defenses_for
from ..schemas import DefenseAction
from ..target_control import TargetControl
from .state import IterationRecord, LoopState, RunResult


@dataclass
class LoopDeps:
    analyst: AnalystAgent
    executor: ExecutorAgent
    evaluator: EvaluatorAgent
    defender: DefenderAgent
    control: TargetControl


def _remaining(plan, applied: list[str]):
    return [d for d in defenses_for(plan.attack_type) if d.value not in applied]


def build_loop(deps: LoopDeps):
    def analyst_node(state: LoopState) -> dict:
        plan, _ = deps.analyst.analyze(state["scenario"])
        return {"plan": plan}

    def executor_node(state: LoopState) -> dict:
        execution = deps.executor.run(state["plan"], state["iteration"])
        record = IterationRecord(iteration=state["iteration"], execution=execution)
        return {"history": state["history"] + [record]}

    def evaluator_node(state: LoopState) -> dict:
        history = state["history"]
        report, _ = deps.evaluator.evaluate(history[-1].execution, state["applied_defenses"])
        history[-1] = history[-1].model_copy(update={"evaluation": report})
        return {"history": history}

    def defender_node(state: LoopState) -> dict:
        history = state["history"]
        decision, _ = deps.defender.decide(history[-1].evaluation, _remaining(state["plan"], state["applied_defenses"]))
        applied = state["applied_defenses"] + [decision.defense_id.value]
        active = deps.control.set_active(applied)
        action = DefenseAction(
            iteration=state["iteration"],
            decision=decision,
            applied=True,
            details=f"active defenses now: {active}",
        )
        history[-1] = history[-1].model_copy(update={"defense": action})
        return {"history": history, "applied_defenses": applied, "iteration": state["iteration"] + 1}

    def route_after_eval(state: LoopState) -> str:
        if not state["history"][-1].execution.attack_succeeded:
            return "end"
        if state["mode"] == "single_pass" and state["applied_defenses"]:
            return "end"
        if len(state["applied_defenses"]) >= state["max_iterations"]:
            return "end"
        if not _remaining(state["plan"], state["applied_defenses"]):
            return "end"
        return "defender"

    graph = StateGraph(LoopState)
    graph.add_node("analyst", analyst_node)
    graph.add_node("executor", executor_node)
    graph.add_node("evaluator", evaluator_node)
    graph.add_node("defender", defender_node)
    graph.add_edge(START, "analyst")
    graph.add_edge("analyst", "executor")
    graph.add_edge("executor", "evaluator")
    graph.add_conditional_edges("evaluator", route_after_eval, {"defender": "defender", "end": END})
    graph.add_edge("defender", "executor")
    return graph.compile()


def _stop_reason(state: LoopState) -> str:
    applied = state["applied_defenses"]
    if not state["history"][-1].execution.attack_succeeded:
        return f"attack blocked after {len(applied)} defense(s)"
    if state["mode"] == "single_pass" and applied:
        return "single-pass policy: stopped after one defense without re-testing"
    if len(applied) >= state["max_iterations"]:
        return f"iteration limit reached after {len(applied)} defense(s)"
    return "no defenses left to try"


def run_scenario(deps: LoopDeps, scenario: str, mode: str, max_iterations: int = 3) -> RunResult:
    deps.control.reset()
    try:
        graph = build_loop(deps)
        state: LoopState = {
            "scenario": scenario,
            "mode": mode,
            "max_iterations": max_iterations,
            "iteration": 1,
            "plan": None,
            "applied_defenses": [],
            "history": [],
        }
        final = graph.invoke(state, {"recursion_limit": 50})
        return RunResult.from_state(final, _stop_reason(final))
    finally:
        deps.control.reset()
