import pytest
from pydantic import BaseModel

from cyberloop.config import Settings
from cyberloop.llm import LLMOutputError, create_chat_model, invoke_structured
from tests.fakes import FakeStructuredLLM, structured_result


class Answer(BaseModel):
    value: int


def test_returns_parsed_answer_and_usage():
    llm = FakeStructuredLLM(structured_result(Answer(value=1), input_tokens=12, output_tokens=3))
    answer, stats = invoke_structured(llm, Answer, [])
    assert answer.value == 1
    assert (stats.attempts, stats.input_tokens, stats.output_tokens) == (1, 12, 3)


def test_retries_with_error_feedback_after_invalid_answer():
    llm = FakeStructuredLLM(
        structured_result(error=ValueError("bad json")),
        structured_result(Answer(value=2)),
    )
    answer, stats = invoke_structured(llm, Answer, [])
    assert answer.value == 2
    assert stats.attempts == 2
    assert stats.output_tokens == 10
    assert "bad json" in llm.calls[1][-1].content


def test_failed_validation_triggers_retry():
    def must_be_positive(answer: Answer) -> None:
        if answer.value <= 0:
            raise ValueError("value must be positive")

    llm = FakeStructuredLLM(structured_result(Answer(value=-1)), structured_result(Answer(value=3)))
    answer, stats = invoke_structured(llm, Answer, [], validate=must_be_positive)
    assert answer.value == 3
    assert stats.attempts == 2
    assert "value must be positive" in llm.calls[1][-1].content


def test_gives_up_after_retry_budget():
    llm = FakeStructuredLLM(*[structured_result(error=ValueError("bad json")) for _ in range(3)])
    with pytest.raises(LLMOutputError):
        invoke_structured(llm, Answer, [], max_retries=2)
    assert len(llm.calls) == 3


def test_ollama_model_is_configured_from_settings():
    settings = Settings(_env_file=None, llm_model="qwen3.5:2b", llm_seed=7, llm_num_ctx=2048)
    model = create_chat_model(settings)
    assert model.model == "qwen3.5:2b"
    assert model.seed == 7
    assert model.num_ctx == 2048
    assert model.temperature == 0.0
    assert model.reasoning is False
