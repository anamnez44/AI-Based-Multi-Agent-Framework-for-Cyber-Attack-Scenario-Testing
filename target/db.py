"""Seed database for the target. A fresh SQLite file is created and filled on startup."""

import sqlite3

SECRET_PRODUCT = "FLAG-SECRET-PRODUCT"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "S3cr3t_Admin_Pw!"

# A deliberately weak account for the credential-guessing scenario. Its password appears in the
# Executor's wordlist, so the guessing attack can find it unless a login defense stops it first.
WEAK_USER = "operator"
WEAK_PASSWORD = "Password1"

_USERS = [
    (1, ADMIN_USER, ADMIN_PASSWORD),
    (2, "alice", "alice-pw"),
    (3, "bob", "bob-pw"),
    (4, WEAK_USER, WEAK_PASSWORD),
]

# is_secret rows must never appear in search results unless the query is injected.
_PRODUCTS = [
    (1, "Laptop", 0),
    (2, "Phone", 0),
    (3, "Keyboard", 0),
    (99, SECRET_PRODUCT, 1),
]


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def seed(db_path: str) -> None:
    with connect(db_path) as conn:
        conn.executescript(
            """
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS products;
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
            CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, is_secret INTEGER);
            """
        )
        conn.executemany("INSERT INTO users VALUES (?, ?, ?)", _USERS)
        conn.executemany("INSERT INTO products VALUES (?, ?, ?)", _PRODUCTS)
