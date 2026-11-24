"""Build the agents, the target client and the loop dependencies from settings."""

import httpx

from .agents import AnalystAgent, DefenderAgent, EvaluatorAgent, ExecutorAgent
from .config import Settings
from .llm import create_chat_model
from .orchestrator import LoopDeps
from .target_control import TargetControl


def target_client(settings: Settings) -> httpx.Client:
    return httpx.Client(base_url=settings.target_url, timeout=30)


def build_deps(settings: Settings, client: httpx.Client) -> LoopDeps:
    llm = create_chat_model(settings)
    return LoopDeps(
        analyst=AnalystAgent(llm, settings.llm_max_retries),
        executor=ExecutorAgent(client),
        evaluator=EvaluatorAgent(llm, settings.llm_max_retries),
        defender=DefenderAgent(llm, settings.llm_max_retries),
        control=TargetControl(client),
    )
