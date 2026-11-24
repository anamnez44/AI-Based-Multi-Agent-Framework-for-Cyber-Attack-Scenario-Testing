"""Provider-independent access to chat models: a factory and structured calls with validation and retry."""

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage
from pydantic import BaseModel

from .config import Settings

T = TypeVar("T", bound=BaseModel)


def create_chat_model(settings: Settings) -> BaseChatModel:
    if settings.llm_provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=settings.llm_model,
            base_url=settings.ollama_base_url,
            temperature=settings.llm_temperature,
            seed=settings.llm_seed,
            num_ctx=settings.llm_num_ctx,
            keep_alive=settings.llm_keep_alive,
            reasoning=False,
        )
    if settings.llm_provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=settings.llm_model,
            temperature=settings.llm_temperature,
            seed=settings.llm_seed,
            api_key=settings.openai_api_key,
        )
    if settings.llm_provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=settings.llm_model,
            temperature=settings.llm_temperature,
            api_key=settings.anthropic_api_key,
        )
    raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")


@dataclass
class LLMCallStats:
    duration_s: float
    attempts: int
    input_tokens: int
    output_tokens: int


class LLMOutputError(RuntimeError):
    """The model did not produce a valid structured answer within the retry budget."""


def invoke_structured(
    llm: BaseChatModel,
    schema: type[T],
    messages: list[BaseMessage],
    max_retries: int = 2,
    validate: Callable[[T], None] | None = None,
) -> tuple[T, LLMCallStats]:
    """Ask for an answer matching `schema`; on an invalid answer, explain the error and ask again."""
    structured = llm.with_structured_output(schema, include_raw=True)
    conversation = list(messages)
    input_tokens = output_tokens = 0
    started = time.perf_counter()
    error: Exception | None = None

    for attempt in range(1, max_retries + 2):
        result = structured.invoke(conversation)
        usage = getattr(result["raw"], "usage_metadata", None) or {}
        input_tokens += usage.get("input_tokens", 0)
        output_tokens += usage.get("output_tokens", 0)

        parsed, error = result["parsed"], result["parsing_error"]
        if error is None and validate is not None:
            try:
                validate(parsed)
            except ValueError as exc:
                error = exc
        if error is None:
            stats = LLMCallStats(time.perf_counter() - started, attempt, input_tokens, output_tokens)
            return parsed, stats

        # Re-sending the same prompt would repeat the same answer at temperature 0.
        conversation.append(
            HumanMessage(f"Your previous answer was rejected: {error}. Answer again following the schema.")
        )

    raise LLMOutputError(f"No valid {schema.__name__} after {max_retries + 1} attempts: {error}")
