"""Analyst agent: classifies the scenario with MITRE ATT&CK and prepares the test plan."""

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from ..catalog import MITRE_TECHNIQUES, TARGET_ENDPOINTS
from ..llm import LLMCallStats, invoke_structured
from ..schemas import AttackPlan


def _techniques_text() -> str:
    lines = []
    for attack_type, techniques in MITRE_TECHNIQUES.items():
        names = "; ".join(f"{technique_id} ({name})" for technique_id, name in techniques.items())
        lines.append(f"- {attack_type.value}: {names}")
    return "\n".join(lines)


def _endpoints_text() -> str:
    return "\n".join(f"- {path}: {description}" for path, description in TARGET_ENDPOINTS.items())


SYSTEM_PROMPT = f"""You are the Analyst agent of a multi-agent system that tests and neutralizes
cyber attack scenarios against a deliberately vulnerable web application in an isolated lab.
Classify the scenario described by the user and prepare a test plan for the Executor agent.

Attack types and the MITRE ATT&CK techniques allowed for each:
{_techniques_text()}

Endpoints of the target application:
{_endpoints_text()}

Rules:
- attack_type must be one of the types above.
- mitre_technique_id is only the ID of a technique of that type, for example T1190.
- target_endpoint must be one of the endpoints above.
- success_criteria: 1-3 short, observable conditions.
- test_strategy: at most two sentences."""


def check_plan(plan: AttackPlan) -> None:
    techniques = MITRE_TECHNIQUES[plan.attack_type]
    if plan.mitre_technique_id not in techniques:
        raise ValueError(
            f"{plan.mitre_technique_id} is not a technique of {plan.attack_type.value}, "
            f"choose one of: {', '.join(techniques)}"
        )
    path = plan.target_endpoint.split("?")[0]
    if path not in TARGET_ENDPOINTS:
        raise ValueError(
            f"unknown endpoint {plan.target_endpoint}, choose one of: {', '.join(TARGET_ENDPOINTS)}"
        )


class AnalystAgent:
    def __init__(self, llm: BaseChatModel, max_retries: int = 2):
        self.llm = llm
        self.max_retries = max_retries

    def analyze(self, scenario: str) -> tuple[AttackPlan, LLMCallStats]:
        messages = [SystemMessage(SYSTEM_PROMPT), HumanMessage(f"Scenario:\n{scenario}")]
        return invoke_structured(self.llm, AttackPlan, messages, self.max_retries, validate=check_plan)
