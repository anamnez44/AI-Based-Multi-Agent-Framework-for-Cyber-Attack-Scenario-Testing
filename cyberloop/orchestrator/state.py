"""State carried through the LangGraph loop and the result assembled from it."""

from typing import Literal, TypedDict

from pydantic import BaseModel

from ..schemas import AttackPlan, DefenseAction, EvaluationReport, ExecutionResult

Mode = Literal["closed_loop", "single_pass"]


class IterationRecord(BaseModel):
    """One pass of the loop: an attack, its evaluation, and the defense deployed afterwards."""

    iteration: int
    execution: ExecutionResult
    evaluation: EvaluationReport | None = None
    defense: DefenseAction | None = None


class LoopState(TypedDict):
    scenario: str
    mode: Mode
    max_iterations: int
    iteration: int
    plan: AttackPlan | None
    applied_defenses: list[str]
    history: list[IterationRecord]


class RunResult(BaseModel):
    """What one run of a scenario tells us, for the trace and for the experiments."""

    mode: Mode
    scenario: str
    plan: AttackPlan
    blocked: bool
    stop_reason: str
    iterations: int
    defenses_applied: list[str]
    initial_success_rate: float
    final_success_rate: float
    records: list[IterationRecord]

    @classmethod
    def from_state(cls, state: LoopState, stop_reason: str) -> "RunResult":
        history = state["history"]
        last = history[-1].execution
        return cls(
            mode=state["mode"],
            scenario=state["scenario"],
            plan=state["plan"],
            blocked=not last.attack_succeeded,
            stop_reason=stop_reason,
            iterations=len(history),
            defenses_applied=list(state["applied_defenses"]),
            initial_success_rate=history[0].execution.success_rate,
            final_success_rate=last.success_rate,
            records=history,
        )
