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
Re-importing a file is safe: transactions are de-duplicated by a stable hash; holdings are keyed on
(account, as-of date, symbol) and the latest import wins. Reports never echo row contents.
Privacy: only the last 4 characters of an account number are stored, and any long digit run in a text field is
masked. Transaction `amount` is stored exactly as exported (sign included). Decimal-comma amounts are converted;
ambiguous ones such as "1,234" are rejected rather than guessed.
"""
import csv
import hashlib
import io
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

from app.store import connect

MAX_BYTES = 50 * 1024 * 1024
MAX_TEXT = 300
BULLETS = "•••"

# canonical field -> accepted normalized header names, in priority order
ALIASES = {
    "date": ["transaction_date", "date", "trade_date", "settlement_date"],
    "as_of": ["as_of_date", "as_of", "date", "statement_date", "report_date"],
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

# first match wins, so order matters (e.g. a "dividend reinvestment" is a dividend); prefixes at word starts only,
# so "div" matches "DIV"/"Dividend" but not "Individual"
TYPE_RES = [
    (name, re.compile(pat))
    for name, pat in [
        ("dividend", r"\bdiv"),
        ("interest", r"\binterest"),
        ("fee", r"\b(?:fee|commission)"),
        ("buy", r"\b(?:buy|purchase|drip)"),
        ("sell", r"\b(?:sell|sale)"),
        ("transfer", r"\b(?:transfer|trf)"),
        ("deposit", r"\b(?:deposit|contribution)"),
        ("withdrawal", r"\bwithdraw"),
    ]
]
DIGIT_RUN = re.compile(r"\d(?:[ -]?\d){5,}")
NUMBER_LIKE = re.compile(r"[\d \-]{6,}")
IDENTIFIER_LIKE = re.compile(r"[A-Za-z0-9\-]{6,}")  # no spaces, e.g. "AB-77-XYZ12"
LABEL_LIKE = re.compile(r"[A-Za-z]{3,}-?\d{1,4}(?:-\d{1,4})?")  # e.g. "RRSP-2024-01", "TFSA2024"
NUMERIC = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")


class RowError(ValueError):
    """A reason safe to print: never contains cell contents."""


@dataclass
class ImportResult:
    kind: str = ""
    added: int = 0
    updated: int = 0
    duplicates: int = 0
    merged: int = 0  # holdings rows folded into an earlier row for the same (account, as-of, symbol) in one file
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


def _last4(number: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", number)[-4:]


def _mask(match: re.Match) -> str:
    return BULLETS + re.sub(r"\D", "", match.group())[-4:]


def _text(raw: str, number: str = "") -> str:
    """Free text that may reach model context: drop control chars, mask account numbers, cap the length."""
    out = "".join(ch for ch in raw if not unicodedata.category(ch).startswith("C")).strip()
    if len(number) >= 4:
        out = out.replace(number, BULLETS + _last4(number))
    out = DIGIT_RUN.sub(_mask, out)
    return out[:MAX_TEXT]


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
    text = re.sub(r"[\s  $]", "", raw)
    if text.startswith("(") and text.endswith(")"):
        text = "-" + text[1:-1]
    if text.endswith("-"):
        text = "-" + text[:-1]
    if "," in text:
        if "." in text:
            # "1.234,56" (comma last) is European; "1,234.56" is English
            if text.rfind(",") > text.rfind("."):
                text = text.replace(".", "").replace(",", ".")
            else:
                text = text.replace(",", "")
        else:
            groups = text.split(",")
            if len(groups) == 2 and re.fullmatch(r"\d{1,2}", groups[1]):
                text = groups[0] + "." + groups[1]
            elif len(groups) > 2 and all(re.fullmatch(r"\d{3}", g) for g in groups[1:]):
                text = "".join(groups)
            elif len(groups) == 2 and re.fullmatch(r"\d{3}", groups[1]):
                raise RowError(f"ambiguous {label} (comma could be decimal or thousands)")
            else:
                raise RowError(f"invalid {label}")
    if len(text) > 40 or not NUMERIC.fullmatch(text):
        raise RowError(f"invalid {label}")
    try:
        d = Decimal(text)
    except InvalidOperation:
        raise RowError(f"invalid {label}") from None
    if d != 0 and not (-12 <= d.adjusted() <= 15):
        raise RowError(f"{label} out of range")
    return "0" if d == 0 else format(d.normalize(), "f")


def _activity_type(text: str) -> str:
    text = text.lower().replace("_", " ")
    for canonical, pattern in TYPE_RES:
        if pattern.search(text):
            return canonical
    return "other"


def _hash(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _looks_like_number(text: str) -> bool:
    if NUMBER_LIKE.fullmatch(text):
        return True
    # An alphanumeric identifier needs at least 4 digits, so plain names ("NON-REGISTERED") stay names. A word of 3+
    # letters followed by one or two short digit groups ("RRSP-2024-01") is a label, not a number; account numbers
    # either start with at most 2 letters or carry a digit run longer than 4.
    if not IDENTIFIER_LIKE.fullmatch(text) or sum(ch.isdigit() for ch in text) < 4:
        return False
    return not LABEL_LIKE.fullmatch(text)


def _add(a: str, b: str, label: str = "") -> str:
    if not a and not b:
        return ""
    if label and not (a and b):
        raise RowError(f"cannot combine lots: {label} missing in one of them")
    total = Decimal(a or 0) + Decimal(b or 0)
    return "0" if total == 0 else format(total.normalize(), "f")


def _account(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    """Returns (id, name, type, last4, raw number); the raw number is only used to redact other fields."""
    number = _pick(row, "account_number")
    name_raw = _pick(row, "account_name")
    if not number and _looks_like_number(name_raw):
        number = name_raw  # an "Account" column that holds the number itself
    name = _text(name_raw, number)
    type_ = _text(_pick(row, "account_type"), number)
    mask = _last4(number)
    if not (name or type_ or mask):
        raise RowError("missing account")
    # the id derives from non-secret fields only, so the full number never reaches the store
    return _hash("csv-account", name or type_, type_, mask)[:16], name or type_, type_, mask, number


def _decode(raw: bytes) -> str:
    try:
        if raw.startswith(b"\xef\xbb\xbf"):
            return raw.decode("utf-8-sig")
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("cp1252")
    except UnicodeDecodeError:
        raise ValueError("unsupported text encoding") from None


def _records(text: str):
    """Yield (first line number, row) so reports point at real file lines even with quoted newlines."""
    reader = csv.reader(io.StringIO(text, newline=""))
    prev = 0
    for row in reader:
        start = prev + 1
        prev = reader.line_num
        if row:
            yield start, row


def import_file(path: Path, conn, now: datetime | None = None) -> ImportResult:
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("file is larger than 50 MB")
    raw = path.read_bytes()
    file_sha = hashlib.sha256(raw).hexdigest()
    now = now or datetime.now(UTC)
    imported_at = now.isoformat(timespec="seconds")
    text = _decode(raw)

    records = _records(text)
    try:
        first = next(records, None)
        if first is None:
            raise ValueError("file is empty")
        headers = [_norm_header(h) for h in first[1]]
        if len(set(headers)) != len(headers):
            raise ValueError("duplicate column names after normalisation")
        kind = detect_kind(set(headers))
        if kind is None:
            # header names help fix the alias table; they are masked like any text in case row 1 is data
            found = _text(", ".join(h for h in headers if h))[:200] or "none"
            raise ValueError(f"unrecognised Wealthsimple export format; headers found: {found} (see README)")
        result = ImportResult(kind=kind)
        held: dict[tuple, tuple] = {}  # holdings seen in this file, so split lots can be combined
        seen: dict[str, int] = {}  # identical rows inside one file are real repeats (e.g. two equal fills)
        for line, values in records:
            if len(values) > len(headers):
                result.rejected.append((line, "more cells than header columns"))
                continue
            try:
                _import_row(conn, kind, dict(zip(headers, values)), seen, held, result, file_sha, imported_at, now)
            except RowError as exc:
                result.rejected.append((line, str(exc)))
        _flush_holdings(conn, held, result, file_sha, imported_at)
    except csv.Error:
        conn.rollback()
        raise ValueError("malformed CSV (e.g. a cell larger than the parser limit)") from None
    except ValueError:
        conn.rollback()
        raise
    conn.commit()
    return result


def _import_row(conn, kind, row, seen, held, result, file_sha, imported_at, now) -> None:
    account = _account(row)
    number = account[4]
    currency = _pick(row, "currency").upper()
    if not currency:
        raise RowError("missing currency")
    if not re.fullmatch(r"[A-Z]{3}", currency):
        raise RowError("invalid currency")
    symbol = _text(_pick(row, "symbol"), number).upper()
    if kind == "activities":
        date = _date(_pick(row, "date"))
        raw_type = _text(" / ".join(p for p in (_pick(row, "type"), _pick(row, "sub_type")) if p), number)
        type_ = _activity_type(raw_type)
        qty = _decimal(_pick(row, "quantity"), "quantity")
        price = _decimal(_pick(row, "price"), "price")
        amount = _decimal(_pick(row, "amount"), "amount", required=True)
        desc = _text(_pick(row, "description"), number)
        # the description is left out so a reworded re-export still dedupes; the counter keeps true repeats
        key = _hash(kind, date, account[0], type_, symbol, qty, amount, currency)
        seen[key] = seen.get(key, 0) + 1
        row_hash = key if seen[key] == 1 else _hash(key, str(seen[key]))
        _save_account(conn, account, imported_at, file_sha)
        cur = conn.execute(
            "INSERT OR IGNORE INTO transactions (row_hash, account_id, date, type, raw_type, symbol, quantity, price,"
            " amount, currency, description, source, imported_at, file_sha256)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,'csv',?,?)",
            (row_hash, account[0], date, type_, raw_type, symbol, qty, price, amount, currency, desc, imported_at, file_sha),
        )
        result.added += cur.rowcount
        result.duplicates += 1 - cur.rowcount
        return

    if not symbol:
        raise RowError("missing symbol")
    as_of_raw = _pick(row, "as_of")
    as_of = _date(as_of_raw) if as_of_raw else now.date().isoformat()
    values = (
        _text(_pick(row, "name"), number),
        _decimal(_pick(row, "quantity"), "quantity", required=True),
        _decimal(_pick(row, "price"), "price"),
        _decimal(_pick(row, "market_value"), "market value"),
        _decimal(_pick(row, "book_value"), "book value"),
        currency,
    )
    key = (account[0], as_of, symbol)
    previous = held.get(key)
    if previous:
        # a second lot of the same position in one file: combine rather than overwrite
        prev = previous[2]
        if prev[5] != currency:
            raise RowError("same position listed in different currencies")
        values = (prev[0], _add(prev[1], values[1]), prev[2], _add(prev[3], values[3], "market value"),
                  _add(prev[4], values[4], "book value"), currency)
        result.merged += 1
    _save_account(conn, account, imported_at, file_sha)
    held[key] = (account[0], 0 if as_of_raw else 1, values, as_of, symbol)  # written once, after the whole file


def _flush_holdings(conn, held, result, file_sha: str, imported_at: str) -> None:
    for account_id, inferred, values, as_of, symbol in held.values():
        existing = conn.execute(
            "SELECT name, quantity, price, market_value, book_value, currency FROM holdings"
            " WHERE account_id=? AND as_of=? AND symbol=?",
            (account_id, as_of, symbol),
        ).fetchone()
        if existing == values:
            result.duplicates += 1
            continue
        conn.execute(
            "INSERT INTO holdings (account_id, as_of, as_of_inferred, symbol, name, quantity, price, market_value,"
            " book_value, currency, source, imported_at, file_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,'csv',?,?)"
            " ON CONFLICT (account_id, as_of, symbol) DO UPDATE SET as_of_inferred=excluded.as_of_inferred,"
            " name=excluded.name, quantity=excluded.quantity, price=excluded.price, market_value=excluded.market_value,"
            " book_value=excluded.book_value, currency=excluded.currency, source='csv',"
            " imported_at=excluded.imported_at, file_sha256=excluded.file_sha256",
            (account_id, as_of, inferred, symbol, *values, imported_at, file_sha),
        )
        if existing:
            result.updated += 1
        else:
            result.added += 1


def _save_account(conn, account, imported_at: str, file_sha: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO accounts (account_id, name, type, mask, source, imported_at, file_sha256)"
        " VALUES (?,?,?,?,'csv',?,?)",
        (account[0], account[1], account[2], account[3], imported_at, file_sha),
    )


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
            updated = f", updated {res.updated}" if res.updated else ""
            updated += f", merged {res.merged}" if res.merged else ""
            print(
                f"{path.name} [{res.kind}]: added {res.added}{updated}, duplicates skipped {res.duplicates},"
                f" rejected {len(res.rejected)}"
            )
            for line, reason in res.rejected:
                print(f"  line {line}: {reason}")
    finally:
        conn.close()
    return 1 if failed else 0
