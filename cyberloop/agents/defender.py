"""Defender agent: chooses the next defense to deploy from the whitelist.

The LLM only picks an id from the allowed set; applying it to the target is done by the
orchestrator through the control plane. The Defender can never invent an arbitrary fix.
"""

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from ..catalog import DEFENSE_DESCRIPTIONS
from ..llm import LLMCallStats, invoke_structured
from ..schemas import DefenseDecision, DefenseId, EvaluationReport

SYSTEM_PROMPT = """You are the Defender agent of a multi-agent system that neutralizes cyber
attacks against a web application in an isolated lab. Choose exactly one defense to deploy next so
that the attack is stopped.

Rules:
- Choose a defense_id only from the list of allowed defenses.
- Take the Evaluator's recommendations into account, but you decide.
- Choose the defense most likely to stop this attack.
- Give a short rationale."""


def _options(allowed: list[DefenseId]) -> str:
    return "\n".join(f"- {d.value}: {DEFENSE_DESCRIPTIONS[d]}" for d in allowed)


class DefenderAgent:
    def __init__(self, llm: BaseChatModel, max_retries: int = 2):
        self.llm = llm
        self.max_retries = max_retries

    def decide(
        self, evaluation: EvaluationReport, allowed: list[DefenseId]
    ) -> tuple[DefenseDecision, LLMCallStats]:
        if not allowed:
            raise ValueError("no defenses left to choose from")
        allowed_values = {d.value for d in allowed}

        def check(decision: DefenseDecision) -> None:
            if decision.defense_id.value not in allowed_values:
                raise ValueError(
                    f"{decision.defense_id.value} is not allowed now; "
                    f"choose from {sorted(allowed_values)}"
                )

        assessment = evaluation.assessment
        recommended = ", ".join(d.value for d in assessment.recommended_defenses) or "none"
        human = (
            f"Attack type: {evaluation.attack_succeeded and 'succeeding' or 'blocked'}\n"
            f"Current success rate: {evaluation.success_rate:.2f}\n"
            f"Evaluator severity: {assessment.severity.value}\n"
            f"Evaluator findings: {'; '.join(assessment.findings)}\n"
            f"Evaluator recommendations (best first): {recommended}\n\n"
            f"Allowed defenses to deploy now:\n{_options(allowed)}"
        )
        messages = [SystemMessage(SYSTEM_PROMPT), HumanMessage(human)]
        return invoke_structured(self.llm, DefenseDecision, messages, self.max_retries, validate=check)
