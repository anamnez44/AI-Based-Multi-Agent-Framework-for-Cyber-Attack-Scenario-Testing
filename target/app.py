"""Flask app factory for the vulnerable target.

Each endpoint has a weak code path and a hardened one; which runs depends on the set of active
defenses. The /admin control plane toggles that set at runtime. Changing the set also clears the
per-run login counters, so each attack is measured from a clean state.
"""

import sqlite3
import tempfile
import time
import uuid
from pathlib import Path

from flask import Flask, current_app, jsonify, request

from . import db
from .defenses import (
    ALL_DEFENSES,
    LOCKOUT_THRESHOLD,
    LOGIN_DELAY_SECONDS,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    blocking_defense,
)


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    if db_path is None:
        db_path = str(Path(tempfile.gettempdir()) / f"target-{uuid.uuid4().hex}.db")
    db.seed(db_path)
    app.config["DB_PATH"] = db_path
    app.config["ACTIVE_DEFENSES"] = frozenset()
    app.config["LOGIN_FAILURES"] = {}
    app.config["LOGIN_REQUESTS"] = {}

    def active() -> frozenset[str]:
        return app.config["ACTIVE_DEFENSES"]

    def clear_counters() -> None:
        app.config["LOGIN_FAILURES"] = {}
        app.config["LOGIN_REQUESTS"] = {}

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/admin/defenses")
    def get_defenses():
        return jsonify(active=sorted(active()))

    @app.post("/admin/defenses")
    def set_defenses():
        requested = set((request.get_json(silent=True) or {}).get("active", []))
        unknown = requested - ALL_DEFENSES
        if unknown:
            return jsonify(error="unknown defenses", unknown=sorted(unknown)), 400
        app.config["ACTIVE_DEFENSES"] = frozenset(requested)
        clear_counters()
        return jsonify(active=sorted(requested))

    @app.post("/admin/reset")
    def reset():
        app.config["ACTIVE_DEFENSES"] = frozenset()
        clear_counters()
        return jsonify(status="reset")

    @app.post("/login")
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        for field in (username, password):
            blocked_by = blocking_defense(active(), field)
            if blocked_by:
                return jsonify(authenticated=False, blocked=blocked_by), 403

        if "rate_limiting" in active() and _rate_limited(request.remote_addr or "client"):
            return jsonify(authenticated=False, blocked="rate_limiting"), 429

        if "account_lockout" in active() and _failures().get(username, 0) >= LOCKOUT_THRESHOLD:
            return jsonify(authenticated=False, blocked="account_lockout"), 423

        row = _lookup_user(username, password, "parameterized_queries" in active())
        if row is None:
            _failures()[username] = _failures().get(username, 0) + 1
            if "login_delay" in active():
                time.sleep(LOGIN_DELAY_SECONDS)
            return jsonify(authenticated=False)
        return jsonify(authenticated=True, user=row["username"])

    @app.get("/products")
    def products():
        query = request.args.get("q", "")
        blocked_by = blocking_defense(active(), query)
        if blocked_by:
            return jsonify(products=[], blocked=blocked_by), 403

        with db.connect(current_app.config["DB_PATH"]) as conn:
            try:
                if "parameterized_queries" in active():
                    rows = conn.execute(
                        "SELECT name FROM products WHERE name LIKE ? AND is_secret = 0",
                        (f"%{query}%",),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT name FROM products "
                        f"WHERE name LIKE '%{query}%' AND is_secret = 0"
                    ).fetchall()
            except sqlite3.Error as exc:
                return jsonify(products=[], error=str(exc))

        return jsonify(products=[row["name"] for row in rows])

    def _failures() -> dict:
        return app.config["LOGIN_FAILURES"]

    def _rate_limited(client_key: str) -> bool:
        now = time.monotonic()
        windows = app.config["LOGIN_REQUESTS"]
        recent = [t for t in windows.get(client_key, []) if now - t < RATE_LIMIT_WINDOW]
        recent.append(now)
        windows[client_key] = recent
        return len(recent) > RATE_LIMIT_MAX

    def _lookup_user(username: str, password: str, parameterized: bool):
        with db.connect(app.config["DB_PATH"]) as conn:
            try:
                if parameterized:
                    return conn.execute(
                        "SELECT username FROM users WHERE username = ? AND password = ?",
                        (username, password),
                    ).fetchone()
                return conn.execute(
                    "SELECT username FROM users "
                    f"WHERE username = '{username}' AND password = '{password}'"
                ).fetchone()
            except sqlite3.Error:
                return None

    return app
