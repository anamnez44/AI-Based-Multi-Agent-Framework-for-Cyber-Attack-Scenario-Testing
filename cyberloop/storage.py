"""SQLite history of loop runs, shared by the API, the dashboard and the CSV export.

A run is stored as "completed" (a full RunResult) or "failed" (the model never produced a usable
answer). A completed run is also flagged "misclassified" when the Analyst picked a different attack
type than the scenario intended; such a run does not count as a protection even if it ended blocked.
"""

import csv
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .orchestrator import RunResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    batch TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    seed INTEGER,
    temperature REAL,
    scenario TEXT NOT NULL,
    intended_attack_type TEXT,
    attack_type TEXT NOT NULL,
    target_endpoint TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed',
    error TEXT,
    blocked INTEGER NOT NULL,
    stop_reason TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    defenses_applied TEXT NOT NULL,
    initial_success_rate REAL NOT NULL,
    final_success_rate REAL NOT NULL,
    duration_s REAL NOT NULL,
    records_json TEXT NOT NULL
)
"""

_COLUMNS = (
    "created_at", "batch", "provider", "model", "seed", "temperature", "scenario",
    "intended_attack_type", "attack_type", "target_endpoint", "mode", "status", "error",
    "blocked", "stop_reason", "iterations", "defenses_applied", "initial_success_rate",
    "final_success_rate", "duration_s", "records_json",
)

_SUMMARY_COLUMNS = (
    "id, created_at, batch, provider, model, seed, temperature, scenario, intended_attack_type, "
    "attack_type, target_endpoint, mode, status, error, blocked, stop_reason, iterations, "
    "defenses_applied, initial_success_rate, final_success_rate, duration_s"
)

_MIGRATIONS = {
    "status": "ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'",
    "error": "ALTER TABLE runs ADD COLUMN error TEXT",
    "seed": "ALTER TABLE runs ADD COLUMN seed INTEGER",
    "temperature": "ALTER TABLE runs ADD COLUMN temperature REAL",
    "intended_attack_type": "ALTER TABLE runs ADD COLUMN intended_attack_type TEXT",
}

_CSV_FIELDS = (
    "id", "created_at", "batch", "provider", "model", "seed", "temperature", "intended_attack_type",
    "attack_type", "mode", "status", "misclassified", "protected_effective", "blocked",
    "stop_reason", "iterations", "defenses_applied", "initial_success_rate", "final_success_rate",
    "duration_s", "error",
)


def connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
    for name, statement in _MIGRATIONS.items():
        if name not in columns:
            conn.execute(statement)
    conn.commit()


def _insert(conn: sqlite3.Connection, row: dict) -> int:
    placeholders = ", ".join("?" for _ in _COLUMNS)
    cursor = conn.execute(
        f"INSERT INTO runs ({', '.join(_COLUMNS)}) VALUES ({placeholders})",
        [row[column] for column in _COLUMNS],
    )
    conn.commit()
    return cursor.lastrowid


def save_run(
    conn: sqlite3.Connection,
    result: RunResult,
    provider: str,
    model: str,
    duration_s: float,
    batch: str | None = None,
    intended_attack_type: str | None = None,
    seed: int | None = None,
    temperature: float | None = None,
) -> int:
    return _insert(
        conn,
        {
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "batch": batch,
            "provider": provider,
            "model": model,
            "seed": seed,
            "temperature": temperature,
            "scenario": result.scenario,
            "intended_attack_type": intended_attack_type or result.plan.attack_type.value,
            "attack_type": result.plan.attack_type.value,
            "target_endpoint": result.plan.target_endpoint,
            "mode": result.mode,
            "status": "completed",
            "error": None,
            "blocked": int(result.blocked),
            "stop_reason": result.stop_reason,
            "iterations": result.iterations,
            "defenses_applied": json.dumps(result.defenses_applied),
            "initial_success_rate": result.initial_success_rate,
            "final_success_rate": result.final_success_rate,
            "duration_s": duration_s,
            "records_json": json.dumps([r.model_dump(mode="json") for r in result.records]),
        },
    )


def save_failed_run(
    conn: sqlite3.Connection,
    scenario: str,
    attack_type: str,
    mode: str,
    provider: str,
    model: str,
    duration_s: float,
    error: str,
    batch: str | None = None,
    seed: int | None = None,
    temperature: float | None = None,
) -> int:
    """Record a run that could not complete, so the experiment matrix can move on."""
    return _insert(
        conn,
        {
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "batch": batch,
            "provider": provider,
            "model": model,
            "seed": seed,
            "temperature": temperature,
            "scenario": scenario,
            "intended_attack_type": attack_type,
            "attack_type": attack_type,
            "target_endpoint": "",
            "mode": mode,
            "status": "failed",
            "error": error,
            "blocked": 0,
            "stop_reason": "run failed",
            "iterations": 0,
            "defenses_applied": json.dumps([]),
            "initial_success_rate": 0.0,
            "final_success_rate": 0.0,
            "duration_s": duration_s,
            "records_json": json.dumps([]),
        },
    )


def _to_summary(row: sqlite3.Row) -> dict:
    data = dict(row)
    data["blocked"] = bool(data["blocked"])
    data["defenses_applied"] = json.loads(data["defenses_applied"])
    intended = data.get("intended_attack_type")
    data["misclassified"] = bool(
        data["status"] == "completed" and intended and intended != data["attack_type"]
    )
    # A misclassified run defended against the wrong attack, so it is not a real protection.
    data["protected_effective"] = bool(data["blocked"] and not data["misclassified"])
    return data


def list_runs(conn: sqlite3.Connection, limit: int = 500) -> list[dict]:
    rows = conn.execute(
        f"SELECT {_SUMMARY_COLUMNS} FROM runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_to_summary(row) for row in rows]


def get_run(conn: sqlite3.Connection, run_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return None
    data = _to_summary(row)
    data["records"] = json.loads(row["records_json"])
    return data


def export_csv(conn: sqlite3.Connection, path: str, batch: str | None = None) -> int:
    runs = list_runs(conn, limit=1_000_000)
    if batch is not None:
        runs = [run for run in runs if run["batch"] == batch]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for run in runs:
            row = dict(run)
            row["defenses_applied"] = "; ".join(run["defenses_applied"])
            writer.writerow(row)
    return len(runs)
