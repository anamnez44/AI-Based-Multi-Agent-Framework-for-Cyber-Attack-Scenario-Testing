"""Run one scenario through the loop and print the trace and outcome.

Needs the target running (docker compose up -d) and the LLM provider from .env reachable.

Usage:
  python scripts/run_scenario.py                       # default scenario, both modes
  python scripts/run_scenario.py --mode closed_loop
  python scripts/run_scenario.py --scenario "..." --model qwen3.5:2b-q4_K_M
"""

import argparse
import time

import httpx

from cyberloop.agents import AnalystAgent, DefenderAgent, EvaluatorAgent, ExecutorAgent
from cyberloop.config import Settings
from cyberloop.llm import create_chat_model
from cyberloop.orchestrator import LoopDeps, RunResult, run_scenario
from cyberloop.target_control import TargetControl

DEFAULT_SCENARIO = (
    "The login form of a web application builds its SQL query from user input, so an attacker "
    "can log in as the administrator without knowing the password."
)


def build_deps(settings: Settings, client: httpx.Client) -> LoopDeps:
    llm = create_chat_model(settings)
    return LoopDeps(
        analyst=AnalystAgent(llm, settings.llm_max_retries),
        executor=ExecutorAgent(client),
        evaluator=EvaluatorAgent(llm, settings.llm_max_retries),
        defender=DefenderAgent(llm, settings.llm_max_retries),
        control=TargetControl(client),
    )


def print_run(result: RunResult, seconds: float) -> None:
    plan = result.plan
    print(f"\n=== {result.mode.upper()} ===")
    print(f"plan: {plan.attack_type.value} / {plan.mitre_technique_id} on {plan.target_endpoint} "
          f"(confidence {plan.confidence:.2f})")
    for record in result.records:
        execution = record.execution
        rate = f"{execution.successful_attempts}/{len(execution.attempts)} ({execution.success_rate:.0%})"
        line = f"  iter {execution.iteration}: attack {rate}"
        if record.defense:
            line += f"  -> deploy {record.defense.decision.defense_id.value}: {record.defense.decision.rationale}"
        print(line)
    verdict = "PROTECTED" if result.blocked else "STILL EXPLOITABLE"
    print(f"outcome: {verdict} | {result.stop_reason}")
    print(f"defenses deployed: {result.defenses_applied or ['none']}")
    print(f"iterations: {result.iterations} | wall time: {seconds:.1f} s")


def run_mode(settings: Settings, scenario: str, mode: str) -> tuple[RunResult, float]:
    with httpx.Client(base_url=settings.target_url, timeout=30) as client:
        client.get("/health").raise_for_status()
        deps = build_deps(settings, client)
        started = time.perf_counter()
        result = run_scenario(deps, scenario, mode, settings.max_iterations)
        return result, time.perf_counter() - started


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a scenario through the closed loop")
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO)
    parser.add_argument("--mode", choices=["closed_loop", "single_pass", "both"], default="both")
    parser.add_argument("--model", help="override LLM_MODEL from .env")
    args = parser.parse_args()

    settings = Settings()
    if args.model:
        settings = settings.model_copy(update={"llm_model": args.model})
    print(f"provider: {settings.llm_provider}  model: {settings.llm_model}")
    print(f"scenario: {args.scenario}")

    modes = ["single_pass", "closed_loop"] if args.mode == "both" else [args.mode]
    results = {mode: run_mode(settings, args.scenario, mode) for mode in modes}
    for mode in modes:
        print_run(*results[mode])

    if len(results) == 2:
        sp, cl = results["single_pass"][0], results["closed_loop"][0]
        print("\n=== COMPARISON ===")
        print(f"single-pass: protected={sp.blocked}, final success={sp.final_success_rate:.0%}, "
              f"defenses={len(sp.defenses_applied)}")
        print(f"closed-loop: protected={cl.blocked}, final success={cl.final_success_rate:.0%}, "
              f"defenses={len(cl.defenses_applied)}")


if __name__ == "__main__":
    main()
