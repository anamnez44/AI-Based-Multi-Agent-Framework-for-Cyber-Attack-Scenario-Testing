"""Flask app factory for the vulnerable target.

Each endpoint has a vulnerable code path and a hardened one; which runs depends on the set of
active defenses. The /admin control plane toggles that set at runtime.
"""

import sqlite3
import tempfile
import uuid
from pathlib import Path

from flask import Flask, current_app, jsonify, request

from . import db
from .defenses import ALL_DEFENSES, blocking_defense


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    if db_path is None:
        db_path = str(Path(tempfile.gettempdir()) / f"target-{uuid.uuid4().hex}.db")
    db.seed(db_path)
    app.config["DB_PATH"] = db_path
    app.config["ACTIVE_DEFENSES"] = frozenset()

    def active() -> frozenset[str]:
        return app.config["ACTIVE_DEFENSES"]

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
        return jsonify(active=sorted(requested))

    @app.post("/admin/reset")
    def reset():
        app.config["ACTIVE_DEFENSES"] = frozenset()
        return jsonify(status="reset")

    @app.post("/login")
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        for field in (username, password):
            blocked_by = blocking_defense(active(), field)
            if blocked_by:
                return jsonify(authenticated=False, blocked=blocked_by), 403

        with db.connect(current_app.config["DB_PATH"]) as conn:
            try:
                if "parameterized_queries" in active():
                    row = conn.execute(
                        "SELECT username FROM users WHERE username = ? AND password = ?",
                        (username, password),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT username FROM users "
                        f"WHERE username = '{username}' AND password = '{password}'"
                    ).fetchone()
            except sqlite3.Error as exc:
                return jsonify(authenticated=False, error=str(exc))

        if row is None:
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

    return app
