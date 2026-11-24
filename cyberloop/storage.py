"""SQLite history of loop runs, shared by the API and the dashboard.

A run is stored either as "completed" (a full RunResult) or as "failed" (the model did not produce
a usable answer); failed runs keep the reason so the experiment matrix can carry on.
"""

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
    scenario TEXT NOT NULL,
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
    "created_at", "batch", "provider", "model", "scenario", "attack_type", "target_endpoint",
    "mode", "status", "error", "blocked", "stop_reason", "iterations", "defenses_applied",
    "initial_success_rate", "final_success_rate", "duration_s", "records_json",
)

_SUMMARY_COLUMNS = (
    "id, created_at, batch, provider, model, scenario, attack_type, target_endpoint, mode, "
    "status, error, blocked, stop_reason, iterations, defenses_applied, initial_success_rate, "
    "final_success_rate, duration_s"
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
    if "status" not in columns:
        conn.execute("ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'")
    if "error" not in columns:
        conn.execute("ALTER TABLE runs ADD COLUMN error TEXT")
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
) -> int:
    return _insert(
        conn,
        {
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "batch": batch,
            "provider": provider,
            "model": model,
            "scenario": result.scenario,
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
) -> int:
    """Record a run that could not complete, so the experiment matrix can move on."""
    return _insert(
        conn,
        {
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "batch": batch,
            "provider": provider,
            "model": model,
            "scenario": scenario,
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
