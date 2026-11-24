"""Evaluator agent: turns a measured execution into a report with an LLM assessment.

The facts (whether the attack succeeded, the success rate) come straight from the execution.
The LLM only adds judgement: severity, findings and which defenses to recommend next.
"""

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from ..catalog import DEFENSE_DESCRIPTIONS, defenses_for
from ..llm import LLMCallStats, invoke_structured
from ..schemas import Assessment, EvaluationReport, ExecutionResult

SYSTEM_PROMPT = """You are the Evaluator agent of a multi-agent system that tests and neutralizes
cyber attacks against a web application in an isolated lab. You receive the measured result of an
attack attempt and must assess it for the report and for the Defender agent.

Rules:
- Base your findings only on the evidence provided.
- recommended_defenses must be chosen only from the list of available defenses.
- Order them best first, by how likely each is to stop this attack.
- If the attack was fully blocked, set severity to low and recommend no further defenses."""


def _defense_catalog(attack_type) -> str:
    lines = []
    for defense in defenses_for(attack_type):
        lines.append(f"- {defense.value}: {DEFENSE_DESCRIPTIONS[defense]}")
    return "\n".join(lines)


def _facts(execution: ExecutionResult, applied_defenses: list[str]) -> str:
    sample = "\n".join(
        f"  - [{'success' if a.succeeded else 'failed'}] {a.payload}: {a.evidence}"
        for a in execution.attempts
    )
    applied = ", ".join(applied_defenses) if applied_defenses else "none"
    return (
        f"Attack type: {execution.attack_type.value}\n"
        f"Target endpoint: {execution.target_endpoint}\n"
        f"Attack succeeded: {execution.attack_succeeded}\n"
        f"Success rate: {execution.success_rate:.2f} "
        f"({execution.successful_attempts}/{len(execution.attempts)} attempts)\n"
        f"Defenses already applied: {applied}\n"
        f"Attempts:\n{sample}\n\n"
        f"Available defenses:\n{_defense_catalog(execution.attack_type)}"
    )


class EvaluatorAgent:
    def __init__(self, llm: BaseChatModel, max_retries: int = 2):
        self.llm = llm
        self.max_retries = max_retries

    def evaluate(
        self, execution: ExecutionResult, applied_defenses: list[str]
    ) -> tuple[EvaluationReport, LLMCallStats]:
        allowed = {d.value for d in defenses_for(execution.attack_type)}

        def check(assessment: Assessment) -> None:
            chosen = {d.value for d in assessment.recommended_defenses}
            unknown = chosen - allowed
            if unknown:
                raise ValueError(
                    f"recommended defenses {sorted(unknown)} are not available for "
                    f"{execution.attack_type.value}; choose from {sorted(allowed)}"
                )

        messages = [SystemMessage(SYSTEM_PROMPT), HumanMessage(_facts(execution, applied_defenses))]
        assessment, stats = invoke_structured(
            self.llm, Assessment, messages, self.max_retries, validate=check
        )
        report = EvaluationReport(
            iteration=execution.iteration,
            attack_succeeded=execution.attack_succeeded,
            success_rate=execution.success_rate,
            assessment=assessment,
        )
        return report, stats
