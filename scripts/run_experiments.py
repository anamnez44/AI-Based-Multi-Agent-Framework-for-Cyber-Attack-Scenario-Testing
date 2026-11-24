"""Run a matrix of scenarios x modes x models and store the results in the history database.

Needs the target running (docker compose up -d --build) and the LLM provider reachable.

Usage:
  python scripts/run_experiments.py --models qwen3.5:4b,qwen3.5:2b-q4_K_M --repeats 1
"""

import argparse
import time
from collections import defaultdict
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the closed-loop experiment matrix")
    parser.add_argument("--models", help="comma-separated model list (default: LLM_MODEL from .env)")
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args()

    settings = Settings()
    models = args.models.split(",") if args.models else [settings.llm_model]
    batch = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    conn = storage.connect(settings.history_db)
    summary: dict[tuple, list[bool]] = defaultdict(list)

    for model in models:
        run_settings = settings.model_copy(update={"llm_model": model})
        with target_client(run_settings) as client:
            client.get("/health").raise_for_status()
            deps = build_deps(run_settings, client)
            for scenario_name, scenario_text in SCENARIOS.items():
                for mode in MODES:
                    for _ in range(args.repeats):
                        started = time.perf_counter()
                        try:
                            result = run_scenario(
                                deps, scenario_text, mode, run_settings.max_iterations
                            )
                        except Exception as exc:  # noqa: BLE001 - keep the matrix going
                            duration = time.perf_counter() - started
                            storage.save_failed_run(
                                conn, scenario_text, scenario_name, mode,
                                run_settings.llm_provider, model, duration, str(exc), batch,
                            )
                            summary[(model, scenario_name, mode)].append(None)
                            print(f"{model:20} {scenario_name:14} {mode:12} FAILED: {exc}")
                            continue
                        duration = time.perf_counter() - started
                        storage.save_run(
                            conn, result, run_settings.llm_provider, model, duration, batch
                        )
                        summary[(model, scenario_name, mode)].append(result.blocked)
                        print(
                            f"{model:20} {scenario_name:14} {mode:12} "
                            f"protected={result.blocked!s:5} defenses={result.defenses_applied} "
                            f"{duration:5.1f}s"
                        )

    print(f"\nbatch {batch} stored in {settings.history_db}")
    print("\nprotected rate by model / scenario / mode (over completed runs):")
    for key in sorted(summary):
        outcomes = summary[key]
        completed = [o for o in outcomes if o is not None]
        failed = len(outcomes) - len(completed)
        rate = f"{sum(completed) / len(completed):.0%}" if completed else "n/a"
        note = f", {failed} failed" if failed else ""
        print(f"  {key[0]:20} {key[1]:14} {key[2]:12} {rate} ({len(completed)} ok{note})")


if __name__ == "__main__":
    main()
