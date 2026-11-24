"""REST API over the run history, plus an endpoint to launch a run.

Launching needs the target and the LLM provider reachable; the read endpoints only need the
history database. Run with: uvicorn api.app:app
"""

from collections import defaultdict
from contextlib import closing

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cyberloop import storage
from cyberloop.config import Settings
from cyberloop.factory import build_deps, target_client
from cyberloop.orchestrator import RunResult, run_scenario


class RunRequest(BaseModel):
    scenario: str
    mode: str = "closed_loop"
    model: str | None = None


def _aggregate(runs: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for run in runs:
        groups[(run["model"], run["scenario"], run["mode"])].append(run)
    stats = []
    for (model, scenario, mode), items in sorted(groups.items()):
        done = [r for r in items if r["status"] == "completed"]
        n = len(done)
        stats.append(
            {
                "model": model,
                "scenario": scenario,
                "mode": mode,
                "runs": len(items),
                "completed": n,
                "failed": sum(r["status"] != "completed" for r in items),
                "misclassified": sum(r["misclassified"] for r in done),
                "protected_rate": (sum(r["protected_effective"] for r in done) / n) if n else None,
                "misclassified_rate": (sum(r["misclassified"] for r in done) / n) if n else None,
                "avg_iterations": (sum(r["iterations"] for r in done) / n) if n else None,
                "avg_final_success": (sum(r["final_success_rate"] for r in done) / n) if n else None,
                "avg_duration_s": (sum(r["duration_s"] for r in done) / n) if n else None,
            }
        )
    return stats


def create_api(db_path: str | None = None) -> FastAPI:
    settings = Settings()
    db_path = db_path or settings.history_db
    app = FastAPI(title="Cyberloop API", version="0.1.0")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/runs")
    def runs(limit: int = 500):
        with closing(storage.connect(db_path)) as conn:
            return storage.list_runs(conn, limit)

    @app.get("/runs/{run_id}")
    def run_detail(run_id: int):
        with closing(storage.connect(db_path)) as conn:
            run = storage.get_run(conn, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        return run

    @app.get("/stats")
    def stats():
        with closing(storage.connect(db_path)) as conn:
            return _aggregate(storage.list_runs(conn, limit=100000))

    @app.post("/runs", response_model=RunResult)
    def launch(request: RunRequest):
        run_settings = settings
        if request.model:
            run_settings = settings.model_copy(update={"llm_model": request.model})
        try:
            with closing(target_client(run_settings)) as client:
                client.get("/health").raise_for_status()
                deps = build_deps(run_settings, client)
                result = run_scenario(deps, request.scenario, request.mode, run_settings.max_iterations)
        except Exception as exc:  # noqa: BLE001 - surface any wiring/runtime issue to the caller
            raise HTTPException(status_code=502, detail=f"run failed: {exc}") from exc
        with closing(storage.connect(db_path)) as conn:
            storage.save_run(
                conn, result, run_settings.llm_provider, run_settings.llm_model, 0.0,
                seed=run_settings.llm_seed, temperature=run_settings.llm_temperature,
            )
        return result

    return app


app = create_api()
