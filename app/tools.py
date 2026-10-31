"""Read-only tool logic: merges Plaid data (every linked item) with the local CSV store.

Rules every tool follows:
  * Rows carry `source` ("plaid" | "csv"); Plaid wins when both cover the same account (and date, for transactions).
  * Only needed fields are returned. Account ids are short local hashes, never Plaid ids, tokens or full numbers.
  * Money values are Decimal strings; currencies are never converted.
  * A Plaid holding or investment transaction whose security trades on a US exchange in USD is shown in USD even when
    the institution labels it otherwise (Wealthsimple labels every holding CAD); see holding_currency.
  * Plaid failures become short notes (code + display message); other sources still answer.
  * Output is compact: money rounded to cents, quantities to 6 decimals, empty fields dropped, free text shortened
    (after it has been sanitised) to CONCISE_TEXT or FULL_TEXT characters.
Amount sign convention for transactions: negative = cash out of the account, positive = cash in. Plaid reports the
opposite for investment transactions, so its sign is flipped to match the CSV exports.

Plaid responses are cached per process (PlaidCache) as raw responses keyed by item, token digest, endpoint and
arguments; every call still runs the full clean-and-merge pipeline on them, so caching changes no output.
"""
import copy
import hashlib
import re
import sqlite3
import threading
import time
import unicodedata
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Callable

from app import store
from app.csvimport import _activity_type
from app.plaid_client import PlaidAPI, PlaidError
from app.redact import clean_text, cut, short_hash

MAX_DAYS = 730
MAX_LIMIT = 200
MAX_HOLDINGS = 500
DEFAULT_HOLDINGS = 50
CONCISE_TEXT = 60
FULL_TEXT = 120
CACHE_TTL = 300  # seconds
MAX_WORKERS = 8
UNCACHED = {"item_get"}  # health should reflect the connection right now
MAX_SYMBOL = 12
MAX_KIND = 24
# Plaid's documented enums; anything else (a hostile or new value) is shown as "other" rather than echoed
SECURITY_TYPES = {"cash", "cryptocurrency", "derivative", "equity", "etf", "fixed income", "loan", "mutual fund",
                  "other"}
PLAID_TX_TYPES = {"cancel", "cash"}  # the documented types _activity_type does not already map
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# Only these fields of each Plaid response are ever read, so only these are kept in the cache
KEEP = {
    "accounts_get": {"accounts": ("account_id", "name", "official_name", "type", "subtype", "mask", "balances")},
    "investments_holdings_get": {
        "holdings": ("account_id", "security_id", "quantity", "institution_price", "institution_value", "cost_basis",
                     "iso_currency_code", "institution_price_as_of"),
        "securities": ("security_id", "ticker_symbol", "name", "type", "iso_currency_code", "market_identifier_code"),
    },
    "investments_transactions_get": {
        "investment_transactions": ("account_id", "security_id", "date", "name", "amount", "type", "subtype",
                                    "iso_currency_code"),
        "securities": ("security_id", "ticker_symbol", "iso_currency_code", "market_identifier_code"),
    },
}
LIABILITY_TYPES = {"credit", "loan"}
# ISO 10383 codes of US exchanges. A security listed on one of these in USD is priced in USD, whatever the holding's
# label says. OTC (OOTC) is left out on purpose: Plaid matches TSX-listed ETFs to US OTC tickers, and those holdings
# really are in the institution's currency.
US_EXCHANGES = {"XNAS", "XNYS", "ARCX", "BATS", "XASE", "XNGS", "XNCM", "IEXG", "EDGX", "BATY"}
US_LISTED_NOTE = ("Some US-listed holdings were reported as CAD by the institution; they are shown in USD based on "
                  "their exchange. Account balances are already in CAD.")
INVESTMENT_TYPES = {"buy", "sell", "dividend"}
LINK_CMD = "python -m app.cli link"
TOKEN_RE = re.compile(r"(?:access|link|public)-[a-z]+-[\w-]+")
# Plaid item and account ids are long letter-digit runs (37 characters); nothing a tool should show looks like that,
# and amounts never do (they have at most a few dozen digits with separators, and digit runs are masked anyway)
PLAID_ID_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{30,}(?![A-Za-z0-9])")
CURRENCY_RE = re.compile(r"[A-Z]{3}")
TIMESTAMP_RE = re.compile(r"[0-9T:+.Z -]{1,40}")
# normalised type keyword -> family; two account types are compatible when one contains the other or they share a family
FAMILIES = {
    "tfsa": "tfsa", "rrsp": "rrsp", "fhsa": "fhsa", "resp": "resp", "rrif": "rrif", "lira": "lira",
    "nonregistered": "taxable", "brokerage": "taxable", "margin": "taxable", "individual": "taxable",
    "cash": "cash", "chequing": "cash", "savings": "cash", "crypto": "crypto",
}


def _enum(value: Any) -> str:
    return str(getattr(value, "value", value) or "")


def _dec(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    return Decimal(str(value))


def _str(d: Decimal | None) -> str | None:
    return None if d is None else format(d, "f")


def _norm(text: str) -> str:
    return "".join(ch for ch in text.lower() if ch.isalnum())


def _reauth_hint(short: str) -> str:
    return (f"Reconnect it with `{LINK_CMD} --update {short}`. A plain `{LINK_CMD}` would create a new Item "
            "and use another Trial slot.")


def _iso(value: Any) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value or "")


def _error_note(short: str, exc: Exception, clean: Callable[[str], str] = clean_text) -> str:
    if isinstance(exc, PlaidError):
        note = f"Plaid item {short} failed: {clean(exc.code)}: {clean(exc.message)}"
        if exc.code == "ITEM_LOGIN_REQUIRED":
            note += " " + _reauth_hint(short)
        return note
    return f"Plaid item {short} failed ({type(exc).__name__})."


def _currency(raw: Any, notes: list[str]) -> str | None:
    """A row's currency code, or "???" (with a note) when it is not three capital letters. The raw value is never echoed."""
    if raw is None or raw == "":
        return None
    if CURRENCY_RE.fullmatch(str(raw)):
        return str(raw)
    notes.append("Some rows had an invalid currency code; it is shown as '???'.")
    return "???"


def holding_currency(holding: dict, security: dict, account_currency: str | None = None) -> tuple[str | None, bool]:
    """(currency, corrected) for a Plaid holding or investment transaction.

    Wealthsimple labels every holding CAD, yet the price and value of a US-listed security are in USD. So when the
    security trades on a US exchange in USD and the row is labelled otherwise, the answer is ("USD", True). The rule is
    the exchange, not a price ratio: Plaid's close prices for OTC matches are often wrong or stale. Otherwise the row's
    own currency is kept, falling back to the security's, then the account's. Values are returned raw (unvalidated).
    """
    label = holding.get("iso_currency_code") or holding.get("unofficial_currency_code")
    mic = str(security.get("market_identifier_code") or "").strip().upper()
    sec_currency = str(security.get("iso_currency_code") or "").strip().upper()
    if mic in US_EXCHANGES and sec_currency == "USD" and label != "USD":
        return "USD", label is not None and label != ""
    return label or security.get("iso_currency_code") or account_currency, False


def _clamp(value: int, high: int, low: int = 1) -> int:
    return max(low, min(int(value), high))


class PlaidCache:
    """Per-process, in-memory cache of raw Plaid responses with a TTL. Thread-safe; never written to disk.

    Keys hold the item id, a digest of its access token (never the token), the endpoint and its arguments, so one
    item's data can never be served for another, and a re-linked item with a new token misses. Failed calls are not
    stored. Callers get deep copies, so nothing a tool does can change a cached response.
    """

    def __init__(self, ttl: float = CACHE_TTL, clock: Callable[[], float] = time.monotonic):
        self.ttl, self.clock = ttl, clock
        self._data: dict[tuple, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def key(item_id: str, token: str, endpoint: str, args: tuple) -> tuple:
        return (item_id, hashlib.sha256(token.encode()).hexdigest(), endpoint, *args)

    def get(self, key: tuple, fetch: Callable[[], Any]) -> Any:
        with self._lock:
            hit = self._data.get(key)
            if hit and self.clock() - hit[0] < self.ttl:
                return copy.deepcopy(hit[1])
        value = fetch()  # an exception propagates and nothing is stored
        with self._lock:
            now = self.clock()
            self._data = {k: v for k, v in self._data.items() if now - v[0] < self.ttl}
            self._data[key] = (now, value)
        return copy.deepcopy(value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


@dataclass
class Backend:
    """The data sources for one tool call: an optional Plaid client with per-item tokens, and the CSV store."""

    conn: sqlite3.Connection
    api: PlaidAPI | None = None
    tokens: dict[str, str] = field(default_factory=dict)  # item_id -> access token (never emitted)
    setup_notes: list[str] = field(default_factory=list)
    today: Callable[[], date] = date.today
    cache: PlaidCache | None = None  # shared across calls by the server; None fetches every time
    secrets: tuple[str, ...] = ()  # Plaid client id and secret, redacted from free text as defence in depth
    _pids: set[str] = field(default_factory=set)  # Plaid account ids seen so far; scrubbed from free text

    def clean(self, raw: Any) -> str:
        """Sanitise free text from Plaid and remove anything that looks like a token or a known id."""
        # order matters: invisible characters go first (a zero-width space could split a secret), then exact secrets on
        # the raw string (clean_text masks digit runs, which would hide a token from exact matching), then token- and
        # id-shaped runs, then text cleaning (links, e-mails, digits, length), then the secret and shape passes again
        out = "".join(ch for ch in str(raw or "") if unicodedata.category(ch) not in ("Cc", "Cf"))
        out = PLAID_ID_RE.sub("[redacted]", TOKEN_RE.sub("[redacted]", self._redact_known(out)))
        out = self._redact_known(clean_text(out))
        return PLAID_ID_RE.sub("[redacted]", TOKEN_RE.sub("[redacted]", out))

    def _redact_known(self, text: str) -> str:
        known = (*self.tokens.values(), *self.tokens, *self.secrets, *self._pids)
        for secret in sorted(known, key=len, reverse=True):
            if len(secret) >= 6:  # real ids, tokens and keys are far longer; a stray short value must not shred text
                text = text.replace(secret, "[redacted]")
        return text

    def close(self) -> None:
        self.conn.close()

    # ---- gathering -------------------------------------------------------------------------------------------

    def _call(self, item_id: str, endpoint: str, args: tuple = ()) -> Any:
        token = self.tokens[item_id]
        fetch = lambda: _minimise(endpoint, getattr(self.api, endpoint)(token, *args))  # noqa: E731
        if self.cache is None or endpoint in UNCACHED:
            return fetch()
        return self.cache.get(PlaidCache.key(item_id, token, endpoint, args), fetch)

    def _fetch_all(self, jobs: list[tuple[str, str, tuple]]) -> dict[tuple[str, str], Any]:
        """Run (item_id, endpoint, args) Plaid calls concurrently. Each result is the response or the exception."""

        def run(job):
            try:
                return self._call(*job)
            except Exception as exc:  # reported per item by the caller
                return exc

        if len(jobs) <= 1:
            results = [run(j) for j in jobs]
        else:
            with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(jobs))) as pool:
                results = list(pool.map(run, jobs))
        return {(item, endpoint): r for (item, endpoint, _), r in zip(jobs, results)}

    def _learn_ids(self, results: dict[tuple[str, str], Any]) -> None:
        # every account id is learned before any text is cleaned, so one item's error message cannot leak an id
        # that only another item's response revealed
        for (_, endpoint), r in results.items():
            if endpoint == "accounts_get" and isinstance(r, dict):
                self._pids.update(a["account_id"] for a in r.get("accounts", []) if a.get("account_id"))

    def _load_plaid(self, notes: list[str], holdings: bool = False, tx_range: tuple[date, date] | None = None):
        accounts: list[dict] = []
        held: list[dict] = []
        txs: list[dict] = []
        if not self.api:
            return accounts, held, txs
        endpoints = [("accounts_get", ())]
        if holdings:
            endpoints.append(("investments_holdings_get", ()))
        if tx_range:
            endpoints.append(("investments_transactions_get", tuple(tx_range)))
        results = self._fetch_all([(item, ep, args) for item in self.tokens for ep, args in endpoints])
        self._learn_ids(results)
        for item_id in self.tokens:
            short = short_hash(item_id)
            try:
                failed = next((r for ep, _ in endpoints if isinstance(r := results[item_id, ep], Exception)), None)
                if failed is not None:
                    raise failed
                item_notes: list[str] = []
                raw_accounts = results[item_id, "accounts_get"].get("accounts", [])
                item_accounts = [_plaid_account(a, short, self.clean, item_notes) for a in raw_accounts]
                by_pid = {a["_pid"]: a for a in item_accounts}
                item_held = (
                    _plaid_holdings(results[item_id, "investments_holdings_get"], by_pid, self.clean, item_notes)
                    if holdings
                    else []
                )
                item_txs = (
                    _plaid_transactions(results[item_id, "investments_transactions_get"], by_pid, self.clean, item_notes)
                    if tx_range
                    else []
                )
            except Exception as exc:  # one failing item must not hide the others; only code/message are surfaced
                notes.append(_error_note(short, exc, self.clean))
                continue
            notes += item_notes
            accounts += item_accounts
            held += item_held
            txs += item_txs
        return accounts, held, txs

    def _csv_accounts(self) -> dict[str, dict]:
        rows = self.conn.execute("SELECT account_id, name, type, mask FROM accounts WHERE source = 'csv'").fetchall()
        return {
            r[0]: {"id": short_hash(r[0]), "name": clean_text(r[1]), "type": r[2].lower(), "subtype": None, "mask": r[3], "source": "csv"}
            for r in rows
        }

    def _csv_values(self, csv_accounts: dict[str, dict], notes: list[str]):
        """Latest holdings market value per CSV account and currency, plus the snapshot date per account."""
        totals: dict[str, dict[str, Decimal]] = defaultdict(lambda: defaultdict(Decimal))
        as_of: dict[str, str] = {}
        for h in store.latest_holdings(self.conn):
            value = _dec(h["market_value"])
            if h["account_id"] in csv_accounts and value is not None:
                totals[h["account_id"]][_currency(h["currency"], notes)] += value
                as_of[h["account_id"]] = h["as_of"]
        return totals, as_of

    def _csv_with_data(self) -> set[str]:
        """CSV account ids that have a holdings market value or at least one transaction."""
        held = {h["account_id"] for h in store.latest_holdings(self.conn) if _dec(h["market_value"]) is not None}
        txs = {r[0] for r in self.conn.execute("SELECT DISTINCT account_id FROM transactions WHERE source = 'csv'")}
        return held | txs

    def _resolve(self, csv_accts: dict, plaid_accts: list[dict], notes: list[str]) -> dict[str, dict]:
        """Map CSV account id -> Plaid account, only where the match is unique in both directions."""
        match, conflicts, conflicted = _match_accounts(csv_accts, plaid_accts)
        notes.extend(conflicts)
        if plaid_accts:
            with_data = self._csv_with_data()  # an empty CSV account adds nothing, so it cannot double count
            for cid, c in csv_accts.items():
                if cid not in match and cid not in conflicted and cid in with_data:
                    notes.append(
                        f"Possible double count: CSV account {c['name']} \u2022\u2022{c['mask']} "
                        "wasn't matched to a Plaid account."
                    )
        return match

    def _merged_accounts(self, notes: list[str], holdings: bool = False):
        """Plaid accounts plus CSV accounts that no Plaid account covers. Returns (rows, plaid_accts, csv_accts, match, held)."""
        plaid_accts, plaid_held, _ = self._load_plaid(notes, holdings=holdings)
        csv_accts = self._csv_accounts()
        match = self._resolve(csv_accts, plaid_accts, notes)
        values, as_of = self._csv_values(csv_accts, notes)
        rows = list(plaid_accts)
        derived = False
        for cid, c in csv_accts.items():
            if cid in match:
                continue
            if values.get(cid):
                derived = True
                rows += [
                    {**c, "currency": cur, "current": _str(v), "available": None, "limit": None,
                     "basis": "holdings_market_value", "as_of": as_of[cid]}
                    for cur, v in sorted(values[cid].items())
                ]
            else:
                rows.append({**c, "currency": None, "current": None, "available": None, "limit": None, "basis": None,
                             "as_of": None})
        if derived:
            notes.append("CSV account balances are the market value of the latest holdings snapshot (see as_of); cash is not included.")
        return rows, plaid_accts, csv_accts, match, plaid_held

    def _merged_holdings(self, notes: list[str]) -> list[dict]:
        _, _, csv_accts, match, plaid_held = self._merged_accounts(notes, holdings=True)
        return self._holdings_from(csv_accts, match, plaid_held, notes)

    def _holdings_from(self, csv_accts: dict, match: dict, plaid_held: list[dict], notes: list[str]) -> list[dict]:
        covered = {h["account_id"] for h in plaid_held}
        rows = list(plaid_held)
        for h in store.latest_holdings(self.conn):
            acct = csv_accts.get(h["account_id"])
            if not acct:
                continue
            p = match.get(h["account_id"])
            if p and p["id"] in covered:
                continue
            rows.append({
                "account_id": acct["id"], "account": acct["name"], "account_mask": acct["mask"],
                "account_type": acct["type"], "symbol": clean_text(h["symbol"])[:MAX_SYMBOL], "name": clean_text(h["name"]),
                "quantity": h["quantity"], "price": h["price"] or None, "market_value": h["market_value"] or None,
                "cost_basis": h["book_value"] or None, "currency": _currency(h["currency"], notes),
                "security_type": None,
                "as_of": h["as_of"], "as_of_inferred": bool(h["as_of_inferred"]), "source": h["source"],
            })
        rows.sort(key=lambda r: (r["account"], r["symbol"]))
        return rows

    def _merged_transactions(self, notes: list[str], days: int, investments_only: bool):
        end = self.today()
        start = end - timedelta(days=days)
        # one fixed window per item (cached once per TTL); any `days` is then a local filter
        plaid_accts, _, plaid_txs = self._load_plaid(notes, tx_range=(end - timedelta(days=MAX_DAYS), end))
        plaid_txs = [t for t in plaid_txs if t["date"] and start.isoformat() <= t["date"] <= end.isoformat()]
        csv_accts = self._csv_accounts()
        match = self._resolve(csv_accts, plaid_accts, notes)
        covered = {(t["account_id"], t["date"]) for t in plaid_txs}
        rows = list(plaid_txs)
        cur = self.conn.execute(
            "SELECT account_id, date, type, symbol, amount, currency, description, source FROM transactions"
            " WHERE date >= ? AND date <= ?",
            (start.isoformat(), end.isoformat()),
        )
        for account_id, day, type_, symbol, amount, currency, description, source in cur.fetchall():
            acct = csv_accts.get(account_id)
            if not acct:
                continue
            p = match.get(account_id)
            if p and (p["id"], day) in covered:
                continue
            rows.append({
                "date": day, "description": clean_text(description), "amount": amount,
                "currency": _currency(currency, notes),
                "type": type_, "symbol": clean_text(symbol or "")[:MAX_SYMBOL] or None, "account_id": acct["id"], "account": acct["name"],
                "account_mask": acct["mask"], "source": source,
            })
        if investments_only:
            rows = [r for r in rows if r["symbol"] or r["type"] in INVESTMENT_TYPES]
        rows.sort(key=lambda r: (r["date"], r["description"], r["amount"] or ""), reverse=True)
        return rows


def _plaid_account(a: dict, item_short: str, clean: Callable[[str], str], notes: list[str]) -> dict:
    b = a.get("balances") or {}
    return {
        "id": short_hash(a["account_id"]), "_pid": a["account_id"], "name": clean(a.get("name") or a.get("official_name") or ""),
        "_official": clean(a.get("official_name") or ""), "type": clean(_enum(a.get("type"))).lower()[:MAX_KIND],
        "subtype": clean(_enum(a.get("subtype"))).lower()[:MAX_KIND] or None, "mask": (a.get("mask") or "")[-4:],
        "currency": _currency(b.get("iso_currency_code") or b.get("unofficial_currency_code"), notes),
        "current": _str(_dec(b.get("current"))), "available": _str(_dec(b.get("available"))),
        "limit": _str(_dec(b.get("limit"))), "basis": "reported_balance", "as_of": None, "source": "plaid", "item": item_short,
    }


def _plaid_holdings(resp: dict, by_pid: dict[str, dict], clean: Callable[[str], str], notes: list[str]) -> list[dict]:
    securities = {s["security_id"]: s for s in resp.get("securities", [])}
    rows = []
    for h in resp.get("holdings", []):
        acct = by_pid.get(h["account_id"])
        if not acct:
            continue
        sec = securities.get(h.get("security_id")) or {}
        rows.append({
            "account_id": acct["id"], "account": acct["name"], "account_mask": acct["mask"], "account_type": acct["type"],
            "symbol": _symbol(sec, clean) or "", "name": clean(sec.get("name") or ""),
            "quantity": _str(_dec(h.get("quantity"))), "price": _str(_dec(h.get("institution_price"))),
            "market_value": _str(_dec(h.get("institution_value"))), "cost_basis": _str(_dec(h.get("cost_basis"))),
            "currency": _row_currency(h, sec, acct, notes),
            "security_type": _security_type(sec.get("type")),
            "as_of": _date(h.get("institution_price_as_of")), "as_of_inferred": False,
            "source": "plaid",
        })
    return rows


def _plaid_transactions(
    resp: dict, by_pid: dict[str, dict], clean: Callable[[str], str], notes: list[str]
) -> list[dict]:
    securities = {s["security_id"]: s for s in resp.get("securities", [])}
    rows = []
    for t in resp.get("investment_transactions", []):
        acct = by_pid.get(t["account_id"])
        if not acct:
            continue
        sec = securities.get(t.get("security_id")) or {}
        plaid_type, subtype = _enum(t.get("type")).lower(), _enum(t.get("subtype")).lower()
        kind = _activity_type(f"{subtype} {plaid_type}")
        amount = _dec(t.get("amount"))
        rows.append({
            "date": _date(t.get("date")), "description": clean(t.get("name") or ""),
            "amount": _str(-amount if amount is not None else None),
            "currency": _row_currency(t, sec, acct, notes),
            "type": (plaid_type if plaid_type in PLAID_TX_TYPES else "other") if kind == "other" else kind,
            "symbol": _symbol(sec, clean),
            "account_id": acct["id"], "account": acct["name"], "account_mask": acct["mask"], "source": "plaid",
        })
    return rows


def _row_currency(row: dict, sec: dict, acct: dict, notes: list[str]) -> str | None:
    currency, corrected = holding_currency(row, sec)
    if corrected:
        notes.append(US_LISTED_NOTE)  # deduplicated by _result, so it appears once per response
    return _currency(currency, notes) or acct["currency"]


def _minimise(endpoint: str, resp: Any) -> Any:
    keep = KEEP.get(endpoint)
    if keep is None or not isinstance(resp, dict):
        return resp
    return {key: [{f: row[f] for f in fields if f in row} for row in resp.get(key) or []] for key, fields in keep.items()}


def _symbol(sec: dict, clean: Callable[[str], str]) -> str | None:
    return clean(sec.get("ticker_symbol") or "").upper()[:MAX_SYMBOL] or None


def _security_type(raw: Any) -> str | None:
    value = _enum(raw).strip().lower()
    if not value:
        return None
    return value if value in SECURITY_TYPES else "other"


def _date(raw: Any) -> str | None:
    value = str(raw or "")[:10]
    return value if DATE_RE.fullmatch(value) else None


def _family(norm: str) -> str | None:
    return next((fam for key, fam in FAMILIES.items() if key in norm), None)


def _types_compatible(csv_type: str, p: dict) -> bool:
    c = _norm(csv_type)
    if not c:
        return True
    for t in (_norm(p["type"]), _norm(p["subtype"] or "")):
        if t and (c in t or t in c or (_family(c) and _family(c) == _family(t))):
            return True
    return False


def _label(a: dict) -> str:
    return f"{a['name']} \u2022\u2022{a['mask']}"


def _match_accounts(csv_accts: dict, plaid_accts: list[dict]) -> tuple[dict[str, dict], list[str], set[str]]:
    """Unique CSV -> Plaid matches (mask + compatible type, then name). Also returns notes and the unmerged CSV ids."""
    proposals: dict[str, dict] = {}
    conflicts: list[str] = []
    conflicted: set[str] = set()
    for cid, c in csv_accts.items():
        cands = [p for p in plaid_accts if c["mask"] and c["mask"] == p["mask"] and _types_compatible(c["type"], p)]
        if not cands and c["name"]:
            name = c["name"].casefold()
            cands = [p for p in plaid_accts if name in (p["name"].casefold(), p["_official"].casefold())]
        if len(cands) > 1:
            conflicted.add(cid)
            conflicts.append(
                f"CSV account {_label(c)} not merged: it could match several Plaid accounts ("
                + ", ".join(_label(p) for p in cands) + "). Possible double count."
            )
        elif cands:
            proposals[cid] = cands[0]
    by_plaid: dict[str, list[str]] = defaultdict(list)
    for cid, p in proposals.items():
        by_plaid[p["id"]].append(cid)
    match: dict[str, dict] = {}
    for cid, p in proposals.items():
        group = by_plaid[p["id"]]
        if len(group) == 1:
            match[cid] = p
            continue
        conflicted.add(cid)
        if cid == group[0]:
            conflicts.append(
                "CSV accounts " + ", ".join(_label(csv_accts[g]) for g in group)
                + f" all map to Plaid account {_label(p)}; not merged. Possible double count."
            )
    return match, conflicts, conflicted




def _bucket(account_type: str) -> str:
    return account_type or "unknown"


# ---- output formatting ---------------------------------------------------------------------------------------

CENT = Decimal("0.01")
QTY_STEP = Decimal("0.000001")


def _money(value: Any) -> str | None:
    d = value if isinstance(value, Decimal) else _dec(value)
    return None if d is None else format(d.quantize(CENT, ROUND_HALF_UP) + 0, "f")  # + 0 turns -0.00 into 0.00


def _qty(value: Any) -> str | None:
    d = _dec(value)
    if d is None:
        return None
    s = format(d.quantize(QTY_STEP, ROUND_HALF_UP) + 0, "f")
    return s.rstrip("0").rstrip(".") if "." in s else s


def _pct(part: Decimal, total: Decimal) -> str:
    return format((part / total * 100).quantize(Decimal("0.1"), ROUND_HALF_UP), "f") if total else "0.0"


def _compact(value: Any) -> Any:
    """Drop None, empty strings, lists and dicts at every level."""
    if isinstance(value, dict):
        out = {k: _compact(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v is not None and v != "" and v != [] and v != {}}
    if isinstance(value, list):
        return [_compact(v) for v in value]
    return value


def _result(notes: list[str], **data: Any) -> dict:
    out = _compact(data)
    # several merge passes in one tool can raise the same note; keep the first of each, in order
    if notes:
        out["notes"] = list(dict.fromkeys(notes))
    return out


def _start(backend: Backend) -> list[str]:
    return list(backend.setup_notes)


def _full(detail: str) -> bool:
    return str(detail).strip().lower() == "full"


def _text(text: str | None, full: bool) -> str | None:
    """Display length for free text that has already been sanitised."""
    return cut(text, FULL_TEXT if full else CONCISE_TEXT)


def _account_filter(account: str | None):
    key = (account or "").strip().casefold()
    if not key:
        return None
    return lambda acct_id, mask, name: key in (acct_id, (mask or "").casefold(), (name or "").casefold())


# ---- tools ---------------------------------------------------------------------------------------------------


def accounts(backend: Backend, detail: str = "concise") -> dict:
    full = _full(detail)
    notes = _start(backend)
    rows, *_ = backend._merged_accounts(notes)
    out = []
    for r in rows:
        row = {"id": r["id"], "name": _text(r["name"], full),
               "type": r["type"] if full else (r["subtype"] or r["type"]), "last4": r["mask"],
               "currency": r["currency"], "balance": _money(r["current"])}
        if full:
            row |= {"subtype": r["subtype"], "available": _money(r["available"]), "limit": _money(r["limit"]),
                    "basis": r["basis"], "as_of": r["as_of"], "source": r["source"]}
        out.append(row)
    return _result(notes, accounts=out)


def holdings(backend: Backend, account: str | None = None, detail: str = "concise",
             limit: int = DEFAULT_HOLDINGS) -> dict:
    full = _full(detail)
    notes = _start(backend)
    limit = _clamp(limit, MAX_HOLDINGS, low=0)
    rows = backend._merged_holdings(notes)
    keep = _account_filter(account)
    if keep:
        rows = [r for r in rows if keep(r["account_id"], r["account_mask"], r["account"])]
        if not rows:
            notes.append("No holdings match that account. Use an id, last4 or name from the accounts tool.")
    rows.sort(key=lambda r: _dec(r["market_value"]) or Decimal("-Infinity"), reverse=True)
    totals: dict[str, Decimal] = defaultdict(Decimal)
    for r in rows:
        if (value := _dec(r["market_value"])) is not None and r["currency"]:
            totals[r["currency"]] += value
    out = []
    for r in rows[:limit]:
        row = {"symbol": r["symbol"], "name": _text(r["name"], full) if full or not r["symbol"] else None,
               "qty": _qty(r["quantity"]), "value": _money(r["market_value"]), "currency": r["currency"],
               "last4": r["account_mask"]}
        if full:
            row |= {"price": _money(r["price"]), "cost_basis": _money(r["cost_basis"]),
                    "security_type": r["security_type"], "account": _text(r["account"], full), "as_of": r["as_of"],
                    "source": r["source"]}
        out.append(row)
    summary = {"count": len(rows), "value": {c: _money(v) for c, v in sorted(totals.items())}}
    if len(rows) > limit:
        summary["omitted"] = len(rows) - limit
    return _result(notes, holdings=out, summary=summary)


def transactions(backend: Backend, days: int = 90, account: str | None = None, symbol: str | None = None,
                 kind: str | None = None, limit: int = 25, detail: str = "concise") -> dict:
    full = _full(detail)
    notes = _start(backend)
    days, limit = _clamp(days, MAX_DAYS), _clamp(limit, MAX_LIMIT, low=0)
    kind = (kind or "").strip().lower()
    rows = backend._merged_transactions(notes, days, investments_only=kind == "investment")
    present = sorted({r["type"] for r in rows if r["type"]})
    keep = _account_filter(account)
    if keep:
        rows = [r for r in rows if keep(r["account_id"], r["account_mask"], r["account"])]
    if symbol and symbol.strip():
        rows = [r for r in rows if (r["symbol"] or "").casefold() == symbol.strip().casefold()]
    if kind and kind != "investment":
        rows = [r for r in rows if r["type"] == kind]
        if kind not in present:
            notes.append(f"No '{cut(clean_text(kind), 20)}' transactions in this window. Kinds present: "
                         + (", ".join(present) or "none") + "; or use 'investment'.")
    flows: dict[str, dict[str, Decimal]] = defaultdict(lambda: {"in": Decimal(), "out": Decimal()})
    for r in rows:
        if (amount := _dec(r["amount"])) is not None:
            flows[r["currency"] or "???"]["in" if amount > 0 else "out"] += amount
    out = []
    for r in rows[:limit]:
        row = {"date": r["date"], "type": r["type"], "symbol": r["symbol"], "amount": _money(r["amount"]),
               "currency": r["currency"], "last4": r["account_mask"]}
        # the description mostly repeats type and symbol; concise keeps it only when there is no symbol
        if full or not r["symbol"]:
            row["desc"] = _text(r["description"], full)
        if full:
            row |= {"account": _text(r["account"], full), "source": r["source"]}
        out.append(row)
    summary = {"days": days, "count": len(rows),
               "totals": {c: {k: _money(v) for k, v in f.items() if v} for c, f in sorted(flows.items())}}
    if len(rows) > limit:
        summary["omitted"] = len(rows) - limit
    return _result(notes, transactions=out, summary=summary)


def summary(backend: Backend, currency: str = "CAD") -> dict:
    """Net worth and allocation, totalled separately per currency; nothing is converted.

    Net worth and by_account_type come from account balances only (basis "account_balances"): a Plaid balance is the
    institution's own total, already in the account's currency, so holdings are never added to it. by_security_type
    comes from holdings, grouped by each holding's currency (US-listed holdings in USD, see holding_currency). A
    currency that only holdings use, such as USD inside a CAD account, therefore has an allocation but no net worth.
    """
    notes = _start(backend)
    rows, _, csv_accts, match, plaid_held = backend._merged_accounts(notes, holdings=True)
    held = backend._holdings_from(csv_accts, match, plaid_held, notes)
    net: dict[str, dict[str, Decimal]] = defaultdict(lambda: defaultdict(Decimal))
    assets: dict[str, dict[str, Decimal]] = defaultdict(lambda: defaultdict(Decimal))
    secs: dict[str, dict[str, Decimal]] = defaultdict(lambda: defaultdict(Decimal))
    for r in rows:
        value = _dec(r["current"])
        if value is None or not r["currency"]:
            continue
        bucket = _bucket(r["subtype"] or r["type"])
        if r["type"] in LIABILITY_TYPES:
            net[r["currency"]][bucket] -= value
            continue
        net[r["currency"]][bucket] += value
        if value > 0:
            assets[r["currency"]][bucket] += value
    for h in held:
        value = _dec(h["market_value"])
        if value is not None and h["currency"] and value > 0:
            secs[h["currency"]][h["security_type"] or "unclassified"] += value

    def table(values: dict[str, Decimal], shares: dict[str, Decimal]) -> dict:
        # percentages are shares of positive asset balances; liabilities carry a value but no share
        total = sum(shares.values(), Decimal())
        ordered = sorted(values.items(), key=lambda kv: -kv[1])
        return {k: {"value": _money(v), "pct": _pct(shares[k], total) if k in shares else None} for k, v in ordered}

    by_currency = {
        cur: {"net_worth": _money(sum(net[cur].values(), Decimal())) if cur in net else None,
              "by_account_type": table(net.get(cur, {}), assets.get(cur, {})),
              "by_security_type": table(secs.get(cur, {}), secs.get(cur, {}))}
        for cur in sorted(set(net) | set(secs))
    }
    primary = currency.strip().upper()
    if not CURRENCY_RE.fullmatch(primary):
        notes.append("Invalid currency code; using CAD.")
        primary = "CAD"
    if len(by_currency) > 1:
        notes.append("Several currencies: each is totalled separately, percentages are within each currency, "
                     "nothing is converted.")
    return _result(notes, currency=primary, net_worth=by_currency.get(primary, {}).get("net_worth") or "0.00",
                   basis="account_balances", by_currency=by_currency)


def health(backend: Backend) -> dict:
    notes = _start(backend)
    items = []
    if not backend.api:
        return _result(notes, items=items)
    # account ids are learned first so the scrubber can remove them from item text below
    results = backend._fetch_all([(item, ep, ()) for item in backend.tokens for ep in ("accounts_get", "item_get")])
    backend._learn_ids(results)
    for item_id in backend.tokens:
        short = short_hash(item_id)
        resp = results[item_id, "item_get"]
        if isinstance(resp, Exception):
            notes.append(_error_note(short, resp, backend.clean))
            items.append({"id": short,
                          "error": backend.clean(resp.code) if isinstance(resp, PlaidError) else type(resp).__name__})
            continue
        item = resp.get("item") or {}
        status = resp.get("status") or {}  # top level of /item/get, beside "item"
        stamps = (_iso((status.get(k) or {}).get("last_successful_update")) for k in ("investments", "transactions"))
        updates = [t for t in stamps if TIMESTAMP_RE.fullmatch(t)]
        error = item.get("error") or {}
        code = backend.clean(_enum(error.get("error_code"))) or None
        if code == "ITEM_LOGIN_REQUIRED":
            notes.append(f"Plaid item {short} needs re-authentication. " + _reauth_hint(short))
        items.append({
            "id": short, "institution": _text(backend.clean(item.get("institution_name") or ""), False),
            "products": sorted(backend.clean(_enum(p)) for p in item.get("products") or []),
            "last_update": max(updates) if updates else None, "error": code,
        })
    return _result(notes, items=items)
