"""Local SQLite store (data_dir/finance.db) holding accounts, holdings and transactions from Plaid and CSV imports.

Money is stored as Decimal strings, never floats. Only the last 4 characters of an account number are ever kept.
"""
import sqlite3
from pathlib import Path

from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    mask TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('plaid', 'csv')),
    imported_at TEXT NOT NULL,
    file_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS holdings (
    row_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    as_of TEXT NOT NULL,
    symbol TEXT NOT NULL,
    name TEXT NOT NULL,
    quantity TEXT NOT NULL,
    price TEXT NOT NULL,
    market_value TEXT NOT NULL,
    book_value TEXT NOT NULL,
    currency TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('plaid', 'csv')),
    imported_at TEXT NOT NULL,
    file_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS transactions (
    row_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    date TEXT NOT NULL,
    type TEXT NOT NULL,
    symbol TEXT NOT NULL,
    quantity TEXT NOT NULL,
    price TEXT NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    description TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('plaid', 'csv')),
    imported_at TEXT NOT NULL,
    file_sha256 TEXT
);
"""


def db_path() -> Path:
    return settings.data_dir / "finance.db"


def connect(path: Path | None = None) -> sqlite3.Connection:
    path = path or db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn
