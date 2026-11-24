"""Measure the configured LLM on the Analyst task: latency, tokens, valid answers and accuracy.

Usage: python scripts/benchmark_llm.py [--runs 3] [--model qwen3.5:2b]
"""

import argparse
import statistics
import time

import httpx

from cyberloop.agents import AnalystAgent
from cyberloop.config import Settings
from cyberloop.llm import LLMOutputError, create_chat_model
from cyberloop.schemas import AttackType

SCENARIOS = [
    (
        AttackType.SQL_INJECTION,
        "An attacker types ' OR '1'='1' -- into the login form to get in without a password "
        "and then dumps the users table.",
    ),
    (
        AttackType.BRUTE_FORCE,
        "A script tries thousands of common passwords against the admin account on the login page.",
    ),
    (
        AttackType.DDOS,
        "A botnet floods the product search with HTTP requests until the shop stops responding.",
    ),
    (
        AttackType.PHISHING,
        "A fake page loads our site in an invisible iframe so that victims click buttons they cannot see.",
    ),
]


def gpu_share(settings: Settings) -> str:
    """Size of the loaded model and the share kept in GPU memory, from Ollama's /api/ps."""
    try:
        loaded = httpx.get(f"{settings.ollama_base_url}/api/ps", timeout=5).json().get("models", [])
    except httpx.HTTPError:
        return "unknown"
    for model in loaded:
        if settings.llm_model in (model.get("model"), model.get("name")):
            size, vram = model.get("size", 0), model.get("size_vram", 0)
            return f"{size / 1e9:.1f} GB in memory, {100 * vram / size:.0f}% on GPU" if size else "unknown"
    return "model not loaded"


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the LLM on the Analyst task")
    parser.add_argument("--runs", type=int, default=3, help="repetitions of each scenario")
    parser.add_argument("--model", help="override LLM_MODEL from .env")
    args = parser.parse_args()

    settings = Settings()
    if args.model:
        settings = settings.model_copy(update={"llm_model": args.model})
    agent = AnalystAgent(create_chat_model(settings), settings.llm_max_retries)
    print(f"provider: {settings.llm_provider}, model: {settings.llm_model}")

    started = time.perf_counter()
    agent.analyze(SCENARIOS[0][1])
    print(f"warm-up incl. model loading: {time.perf_counter() - started:.1f} s\n")

    durations, speeds, correct, invalid = [], [], 0, 0
    for expected, text in SCENARIOS:
        for run in range(1, args.runs + 1):
            try:
                plan, stats = agent.analyze(text)
            except LLMOutputError as exc:
                invalid += 1
                print(f"{expected.value:14} #{run}  invalid answer: {exc}")
                continue
            durations.append(stats.duration_s)
            speeds.append(stats.output_tokens / stats.duration_s)
            correct += plan.attack_type == expected
            verdict = "ok" if plan.attack_type == expected else f"WRONG: {plan.attack_type.value}"
            print(
                f"{expected.value:14} #{run}  {verdict:22} {plan.mitre_technique_id:10} "
                f"{stats.duration_s:5.1f} s  {stats.output_tokens:4} tokens  attempts: {stats.attempts}"
            )

    total = len(SCENARIOS) * args.runs
    print(f"\ncorrect attack type: {correct}/{total}, invalid answers: {invalid}/{total}")
    if durations:
        print(f"latency per answer: mean {statistics.mean(durations):.1f} s, max {max(durations):.1f} s")
        print(f"effective output speed: {statistics.mean(speeds):.1f} tokens/s")
    if settings.llm_provider == "ollama":
        print(f"memory: {gpu_share(settings)}")


if __name__ == "__main__":
    main()
