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
    account_id TEXT NOT NULL,
    as_of TEXT NOT NULL,
    as_of_inferred INTEGER NOT NULL DEFAULT 0,
    symbol TEXT NOT NULL,
    name TEXT NOT NULL,
    quantity TEXT NOT NULL,
    price TEXT NOT NULL,
    market_value TEXT NOT NULL,
    book_value TEXT NOT NULL,
    currency TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('plaid', 'csv')),
    imported_at TEXT NOT NULL,
    file_sha256 TEXT,
    PRIMARY KEY (account_id, as_of, symbol)
);
CREATE TABLE IF NOT EXISTS transactions (
    row_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    date TEXT NOT NULL,
    type TEXT NOT NULL,
    raw_type TEXT NOT NULL DEFAULT '',
    symbol TEXT NOT NULL,
    quantity TEXT NOT NULL,
    price TEXT NOT NULL,
    amount TEXT NOT NULL,  -- as exported: the sign is Wealthsimple's, not normalised
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


def latest_holdings(conn: sqlite3.Connection, account_id: str | None = None) -> list[dict]:
    """Newest snapshot per account (all accounts, or just one)."""
    sql = (
        "SELECT * FROM holdings h WHERE as_of = (SELECT max(as_of) FROM holdings WHERE account_id = h.account_id)"
        + (" AND account_id = ?" if account_id else "")
        + " ORDER BY account_id, symbol"
    )
    cur = conn.execute(sql, (account_id,) if account_id else ())
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]
