"""Run a matrix of scenarios x modes x models and store the results in the history database.

Repeats use a non-zero temperature and a different seed each time, so they vary yet stay
reproducible (the seed is recorded). A run whose Analyst picked a different attack type than the
scenario intended is counted as a classification error, not as a protection.

Needs the target running (docker compose up -d --build) and the LLM provider reachable.

Usage:
  python scripts/run_experiments.py --models qwen3.5:4b,qwen2.5:0.5b --repeats 3 --temperature 0.4
"""

import argparse
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

from cyberloop import storage
from cyberloop.config import Settings
from cyberloop.factory import build_deps, target_client
from cyberloop.orchestrator import run_scenario

SCENARIOS = {
    "sql_injection": (
        "The login form of a web application builds its SQL query from user input, so an attacker "
        "can log in as the administrator without knowing the password."
    ),
    "brute_force": (
        "An attacker repeatedly submits common passwords for the operator account on the login "
        "form until one is accepted."
    ),
}
MODES = ["single_pass", "closed_loop"]


def classify(result, intended: str) -> str:
    if result.plan.attack_type.value != intended:
        return "misclassified"
    return "protected" if result.blocked else "exploitable"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the closed-loop experiment matrix")
    parser.add_argument("--models", help="comma-separated model list (default: LLM_MODEL from .env)")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--temperature", type=float, default=0.4, help="sampling temperature for repeats")
    parser.add_argument("--seed", type=int, help="base seed (default: LLM_SEED from .env)")
    args = parser.parse_args()

    settings = Settings()
    models = args.models.split(",") if args.models else [settings.llm_model]
    base_seed = args.seed if args.seed is not None else settings.llm_seed
    batch = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    conn = storage.connect(settings.history_db)
    summary: dict[tuple, Counter] = defaultdict(Counter)

    for model in models:
        with target_client(settings) as client:
            client.get("/health").raise_for_status()
            for scenario_name, scenario_text in SCENARIOS.items():
                for mode in MODES:
                    for repeat in range(args.repeats):
                        seed = base_seed + repeat
                        run_settings = settings.model_copy(
                            update={"llm_model": model, "llm_seed": seed,
                                    "llm_temperature": args.temperature}
                        )
                        deps = build_deps(run_settings, client)
                        started = time.perf_counter()
                        try:
                            result = run_scenario(
                                deps, scenario_text, mode, run_settings.max_iterations
                            )
                        except Exception as exc:  # noqa: BLE001 - keep the matrix going
                            duration = time.perf_counter() - started
                            storage.save_failed_run(
                                conn, scenario_text, scenario_name, mode, run_settings.llm_provider,
                                model, duration, str(exc), batch, seed, args.temperature,
                            )
                            summary[(model, scenario_name, mode)]["failed"] += 1
                            print(f"{model:20} {scenario_name:14} {mode:12} seed={seed} FAILED: {exc}")
                            continue
                        duration = time.perf_counter() - started
                        storage.save_run(
                            conn, result, run_settings.llm_provider, model, duration, batch,
                            scenario_name, seed, args.temperature,
                        )
                        outcome = classify(result, scenario_name)
                        summary[(model, scenario_name, mode)][outcome] += 1
                        print(
                            f"{model:20} {scenario_name:14} {mode:12} seed={seed} "
                            f"{outcome:13} defenses={result.defenses_applied} {duration:5.1f}s"
                        )

    print(f"\nbatch {batch} stored in {settings.history_db}")
    print("\neffective protection by model / scenario / mode (misclassified != protected):")
    for key in sorted(summary):
        counts = summary[key]
        total = sum(counts.values())
        rate = counts["protected"] / total if total else 0.0
        extras = ", ".join(f"{k}={v}" for k, v in counts.items() if k != "protected")
        print(f"  {key[0]:20} {key[1]:14} {key[2]:12} protected {rate:.0%} ({counts['protected']}/{total})"
              + (f"  [{extras}]" if extras else ""))


if __name__ == "__main__":
    main()
