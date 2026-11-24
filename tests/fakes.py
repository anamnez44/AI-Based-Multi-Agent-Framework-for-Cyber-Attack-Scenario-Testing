from langchain_core.messages import AIMessage


class FakeStructuredLLM:
    """Replays prepared structured-output results instead of calling a model."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def with_structured_output(self, schema, include_raw=False):
        return self

    def invoke(self, messages):
        self.calls.append(list(messages))
        return self.results.pop(0)


def structured_result(parsed=None, error=None, input_tokens=10, output_tokens=5):
    raw = AIMessage(
        content="",
        usage_metadata={
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
    )
    return {"raw": raw, "parsed": parsed, "parsing_error": error}
