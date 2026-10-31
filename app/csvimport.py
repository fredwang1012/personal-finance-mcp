"""Importer for Wealthsimple's official CSV exports (fallback for data Plaid does not return).

Supported files (matched by header names, case/spacing-insensitive; unknown columns are ignored):
  * Activities export - one row per transaction. Needs a date, an activity type, an amount and a currency.
  * Holdings report - one row per position. Needs a symbol, a quantity and a currency.
How to get them (Wealthsimple web, per the help centre; menu labels change over time):
  * Activities: Activity tab -> Download activities (or Profile -> Documents -> Request documents ->
    "Activities Export (CSV)"), choose a period and accounts, download the CSV.
  * Holdings: Profile -> Documents -> Request documents -> "Holdings report (CSV)", choose accounts.
  * Monthly statements are available as CSV via Documents -> Custom download -> Bulk download monthly statements;
    files with the same columns as above are imported the same way.
Then run: python -m app.cli import-csv PATH...
Re-importing a file is safe: rows are de-duplicated by a stable hash. Reports never echo row contents.
"""
import csv
import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

from app.store import connect

# canonical field -> accepted normalized header names, in priority order
ALIASES = {
    "date": ["transaction_date", "date", "trade_date", "settlement_date"],
    "as_of": ["as_of_date", "as_of", "date", "statement_date"],
    "account_name": ["account_name", "account_nickname", "account", "nickname"],
    "account_type": ["account_type", "registration_type"],
    "account_number": ["account_number", "account_no", "account_id", "account_num"],
    "type": ["activity_type", "transaction_type", "type", "activity"],
    "sub_type": ["activity_sub_type", "sub_type", "subtype"],
    "symbol": ["symbol", "ticker"],
    "name": ["name", "security_name", "description"],
    "quantity": ["quantity", "qty", "shares"],
    "price": ["share_price", "price", "unit_price", "market_price"],
    "amount": ["net_cash_amount", "amount", "net_amount", "value"],
    "market_value": ["market_value", "market_value_cad", "value"],
    "book_value": ["book_value_market", "book_value", "book_value_cad", "book_cost"],
    "currency": ["currency", "market_price_currency", "amount_currency"],
    "description": ["description", "memo", "details", "name"],
}

# first keyword found wins, so order matters (e.g. a "dividend reinvestment" is a dividend)
TYPE_KEYWORDS = [
    ("dividend", ("div",)),
    ("interest", ("interest",)),
    ("fee", ("fee", "commission")),
    ("buy", ("buy", "purchase", "drip")),
    ("sell", ("sell", "sale")),
    ("transfer", ("transfer", "trf")),
    ("deposit", ("deposit", "contribution")),
    ("withdrawal", ("withdraw",)),
]


class RowError(ValueError):
    """A reason safe to print: never contains cell contents."""


@dataclass
class ImportResult:
    kind: str = ""
    added: int = 0
    duplicates: int = 0
    rejected: list[tuple[int, str]] = field(default_factory=list)


def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", h.strip().lower()).strip("_")


def _pick(row: dict[str, str], key: str) -> str:
    for name in ALIASES[key]:
        value = (row.get(name) or "").strip()
        if value:
            return value
    return ""


def _has(headers: set[str], key: str) -> bool:
    return any(a in headers for a in ALIASES[key])


def detect_kind(headers: set[str]) -> str | None:
    if _has(headers, "type") and _has(headers, "date") and (_has(headers, "amount") or _has(headers, "price")):
        return "activities"
    if _has(headers, "symbol") and _has(headers, "quantity") and not _has(headers, "type"):
        return "holdings"
    return None


def _date(raw: str) -> str:
    if not raw:
        raise RowError("missing date")
    text = raw[:10].replace("/", "-")
    try:
        return datetime.strptime(text, "%Y-%m-%d").date().isoformat()
    except ValueError:
        raise RowError("unrecognised date format (expected YYYY-MM-DD)") from None


def _decimal(raw: str, label: str, required: bool = False) -> str:
    if not raw:
        if required:
            raise RowError(f"missing {label}")
        return ""
    text = raw.replace("$", "").replace(",", "").replace(" ", "")
    if text.startswith("(") and text.endswith(")"):
        text = "-" + text[1:-1]
    try:
        d = Decimal(text)
    except InvalidOperation:
        raise RowError(f"invalid {label}") from None
    if not d.is_finite():
        raise RowError(f"invalid {label}")
    return "0" if d == 0 else format(d.normalize(), "f")


def _activity_type(raw: str, sub: str) -> str:
    text = f"{raw} {sub}".lower()
    for canonical, words in TYPE_KEYWORDS:
        if any(w in text for w in words):
            return canonical
    return "other"


def _last4(number: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", number)[-4:]


def _hash(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _account(row: dict[str, str]) -> tuple[str, str, str, str]:
    name = _pick(row, "account_name")
    type_ = _pick(row, "account_type")
    mask = _last4(_pick(row, "account_number"))
    if not (name or type_ or mask):
        raise RowError("missing account")
    # the id derives from non-secret fields only, so the full number never reaches the store
    return _hash("csv-account", name, type_, mask)[:16], name or type_, type_, mask


def import_file(path: Path, conn, now: datetime | None = None) -> ImportResult:
    raw = Path(path).read_bytes()
    file_sha = hashlib.sha256(raw).hexdigest()
    imported_at = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("file is not UTF-8 text") from None
    reader = csv.DictReader(text.splitlines(), restkey="_extra")
    if reader.fieldnames is None:
        raise ValueError("file is empty")
    reader.fieldnames = [_norm_header(h) for h in reader.fieldnames]
    kind = detect_kind(set(reader.fieldnames))
    if kind is None:
        raise ValueError("unrecognised Wealthsimple export format (see app/csvimport.py docstring)")

    result = ImportResult(kind=kind)
    seen: dict[str, int] = {}  # identical rows inside one file are real repeats (e.g. two equal fills), keep both
    for row in reader:
        line = reader.line_num
        try:
            account = _account(row)
            if kind == "activities":
                date = _date(_pick(row, "date"))
                type_ = _activity_type(_pick(row, "type"), _pick(row, "sub_type"))
                symbol = _pick(row, "symbol").upper()
                qty = _decimal(_pick(row, "quantity"), "quantity")
                price = _decimal(_pick(row, "price"), "price")
                amount = _decimal(_pick(row, "amount"), "amount", required=True)
                currency = _pick(row, "currency").upper()
                desc = _pick(row, "description")
                if not currency:
                    raise RowError("missing currency")
                key = _hash(kind, date, account[3], type_, symbol, qty, amount, currency, desc)
            else:
                symbol = _pick(row, "symbol").upper()
                if not symbol:
                    raise RowError("missing symbol")
                as_of = _date(_pick(row, "as_of")) if _pick(row, "as_of") else ""
                qty = _decimal(_pick(row, "quantity"), "quantity", required=True)
                price = _decimal(_pick(row, "price"), "price")
                mv = _decimal(_pick(row, "market_value"), "market value")
                bv = _decimal(_pick(row, "book_value"), "book value")
                currency = _pick(row, "currency").upper()
                if not currency:
                    raise RowError("missing currency")
                key = _hash(kind, as_of, account[3], "", symbol, qty, mv, currency, "")
        except RowError as exc:
            result.rejected.append((line, str(exc)))
            continue

        seen[key] = seen.get(key, 0) + 1
        row_hash = key if seen[key] == 1 else _hash(key, str(seen[key]))
        conn.execute(
            "INSERT OR IGNORE INTO accounts VALUES (?,?,?,?,'csv',?,?)",
            (account[0], account[1], account[2], account[3], imported_at, file_sha),
        )
        if kind == "activities":
            cur = conn.execute(
                "INSERT OR IGNORE INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,'csv',?,?)",
                (row_hash, account[0], date, type_, symbol, qty, price, amount, currency, desc, imported_at, file_sha),
            )
        else:
            cur = conn.execute(
                "INSERT OR IGNORE INTO holdings VALUES (?,?,?,?,?,?,?,?,?,?,'csv',?,?)",
                (row_hash, account[0], as_of, symbol, _pick(row, "name"), qty, price, mv, bv, currency, imported_at, file_sha),
            )
        if cur.rowcount:
            result.added += 1
        else:
            result.duplicates += 1
    conn.commit()
    return result


def import_paths(paths: list[str]) -> int:
    """CLI entry: print counts per file; exit code 1 if any file could not be imported."""
    conn = connect()
    failed = False
    try:
        for p in paths:
            path = Path(p)
            try:
                res = import_file(path, conn)
            except (OSError, ValueError) as exc:
                reason = exc if isinstance(exc, ValueError) else exc.__class__.__name__
                print(f"{path.name}: not imported ({reason})")
                failed = True
                continue
            print(f"{path.name} [{res.kind}]: added {res.added}, duplicates skipped {res.duplicates}, rejected {len(res.rejected)}")
            for line, reason in res.rejected:
                print(f"  line {line}: {reason}")
    finally:
        conn.close()
    return 1 if failed else 0
