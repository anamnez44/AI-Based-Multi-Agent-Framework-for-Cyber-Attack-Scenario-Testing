"""SQLite history of loop runs, shared by the API and the dashboard."""

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

_SUMMARY_COLUMNS = (
    "id, created_at, batch, provider, model, scenario, attack_type, target_endpoint, mode, "
    "blocked, stop_reason, iterations, defenses_applied, initial_success_rate, "
    "final_success_rate, duration_s"
)


def connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    return conn


def save_run(
    conn: sqlite3.Connection,
    result: RunResult,
    provider: str,
    model: str,
    duration_s: float,
    batch: str | None = None,
) -> int:
    cursor = conn.execute(
        f"INSERT INTO runs (created_at, batch, provider, model, scenario, attack_type, "
        f"target_endpoint, mode, blocked, stop_reason, iterations, defenses_applied, "
        f"initial_success_rate, final_success_rate, duration_s, records_json) "
        f"VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            batch,
            provider,
            model,
            result.scenario,
            result.plan.attack_type.value,
            result.plan.target_endpoint,
            result.mode,
            int(result.blocked),
            result.stop_reason,
            result.iterations,
            json.dumps(result.defenses_applied),
            result.initial_success_rate,
            result.final_success_rate,
            duration_s,
            json.dumps([record.model_dump(mode="json") for record in result.records]),
        ),
    )
    conn.commit()
    return cursor.lastrowid


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
