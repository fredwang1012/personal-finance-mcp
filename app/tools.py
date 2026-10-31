"""Read-only tool logic: merges Plaid data (every linked item) with the local CSV store.

Rules every tool follows:
  * Rows carry `source` ("plaid" | "csv"); Plaid wins when both cover the same account (and date, for transactions).
  * Only needed fields are returned. Account ids are short local hashes, never Plaid ids, tokens or full numbers.
  * Money values are Decimal strings; currencies are never converted.
  * Plaid failures become short notes (code + display message); other sources still answer.
Amount sign convention for transactions: negative = cash out of the account, positive = cash in. Plaid reports the
opposite for investment transactions, so its sign is flipped to match the CSV exports.
"""
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal
from typing import Any, Callable

from app import store
from app.csvimport import _activity_type
from app.plaid_client import PlaidAPI, PlaidError
from app.redact import clean_text, short_hash

MAX_DAYS = 730
MAX_LIMIT = 200
MAX_HOLDINGS = 500
LIABILITY_TYPES = {"credit", "loan"}
INVESTMENT_TYPES = {"buy", "sell", "dividend"}
LINK_CMD = "python -m app.cli link"
TOKEN_RE = re.compile(r"(?:access|link|public)-[a-z]+-[\w-]+")
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


def _public(row: dict) -> dict:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _error_note(short: str, exc: Exception, clean: Callable[[str], str] = clean_text) -> str:
    if isinstance(exc, PlaidError):
        note = f"Plaid item {short} failed: {clean(exc.code)}: {clean(exc.message)}"
        if exc.code == "ITEM_LOGIN_REQUIRED":
            note += f" Re-run `{LINK_CMD}` to reconnect it."
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


def _clamp(value: int, high: int) -> int:
    return max(1, min(int(value), high))


@dataclass
class Backend:
    """The data sources for one tool call: an optional Plaid client with per-item tokens, and the CSV store."""

    conn: sqlite3.Connection
    api: PlaidAPI | None = None
    tokens: dict[str, str] = field(default_factory=dict)  # item_id -> access token (never emitted)
    setup_notes: list[str] = field(default_factory=list)
    today: Callable[[], date] = date.today
    _pids: set[str] = field(default_factory=set)  # Plaid account ids seen so far; scrubbed from free text

    def clean(self, raw: Any) -> str:
        """Sanitise free text from Plaid and remove anything that looks like a token or a known id."""
        # redact on the raw string first: clean_text masks digit runs, which would hide a token from exact matching
        out = str(raw or "")
        for secret in sorted((*self.tokens.values(), *self.tokens, *self._pids), key=len, reverse=True):
            if secret:
                out = out.replace(secret, "[redacted]")
        out = TOKEN_RE.sub("[redacted]", out)
        return TOKEN_RE.sub("[redacted]", clean_text(out))

    def close(self) -> None:
        self.conn.close()

    # ---- gathering -------------------------------------------------------------------------------------------

    def _load_plaid(self, notes: list[str], holdings: bool = False, tx_range: tuple[date, date] | None = None):
        accounts: list[dict] = []
        held: list[dict] = []
        txs: list[dict] = []
        if not self.api:
            return accounts, held, txs
        for item_id, token in self.tokens.items():
            short = short_hash(item_id)
            try:
                raw_accounts = self.api.accounts_get(token).get("accounts", [])
                self._pids.update(a["account_id"] for a in raw_accounts)
                item_notes: list[str] = []
                item_accounts = [_plaid_account(a, short, self.clean, item_notes) for a in raw_accounts]
                by_pid = {a["_pid"]: a for a in item_accounts}
                item_held = (
                    _plaid_holdings(self.api.investments_holdings_get(token), by_pid, self.clean, item_notes)
                    if holdings
                    else []
                )
                item_txs = (
                    _plaid_transactions(
                        self.api.investments_transactions_get(token, *tx_range), by_pid, self.clean, item_notes
                    )
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
            r[0]: {"id": short_hash(r[0]), "name": r[1], "type": r[2].lower(), "subtype": None, "mask": r[3], "source": "csv"}
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
                "account_type": acct["type"], "symbol": h["symbol"], "name": clean_text(h["name"]),
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
        plaid_accts, _, plaid_txs = self._load_plaid(notes, tx_range=(start, end))
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
                "type": type_, "symbol": symbol or None, "account_id": acct["id"], "account": acct["name"],
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
        "_official": clean(a.get("official_name") or ""), "type": _enum(a.get("type")).lower(),
        "subtype": _enum(a.get("subtype")).lower() or None, "mask": (a.get("mask") or "")[-4:],
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
            "symbol": clean(sec.get("ticker_symbol") or "").upper(), "name": clean(sec.get("name") or ""),
            "quantity": _str(_dec(h.get("quantity"))), "price": _str(_dec(h.get("institution_price"))),
            "market_value": _str(_dec(h.get("institution_value"))), "cost_basis": _str(_dec(h.get("cost_basis"))),
            "currency": _currency(h.get("iso_currency_code") or sec.get("iso_currency_code"), notes) or acct["currency"],
            "security_type": _enum(sec.get("type")).lower() or None,
            "as_of": str(h.get("institution_price_as_of") or "")[:10] or None, "as_of_inferred": False,
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
            "date": str(t["date"])[:10], "description": clean(t.get("name") or ""),
            "amount": _str(-amount if amount is not None else None),
            "currency": _currency(t.get("iso_currency_code"), notes) or acct["currency"],
            "type": plaid_type if kind == "other" else kind,
            "symbol": clean(sec.get("ticker_symbol") or "").upper() or None,
            "account_id": acct["id"], "account": acct["name"], "account_mask": acct["mask"], "source": "plaid",
        })
    return rows


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


def _result(notes: list[str], **data: Any) -> dict:
    # several merge passes in one tool can raise the same note; keep the first of each, in order
    return {**data, "notes": list(dict.fromkeys(notes))}


def _start(backend: Backend) -> list[str]:
    return list(backend.setup_notes)


# ---- tools ---------------------------------------------------------------------------------------------------


def list_accounts(backend: Backend) -> dict:
    notes = _start(backend)
    rows, *_ = backend._merged_accounts(notes)
    accounts = [
        {
            **{k: r[k] for k in ("id", "name", "type", "subtype", "mask", "currency", "source")},
            "balances": {k: r[k] for k in ("current", "available", "limit", "basis", "as_of")},
        }
        for r in rows
    ]
    return _result(notes, accounts=accounts)


def get_balances(backend: Backend) -> dict:
    notes = _start(backend)
    rows, *_ = backend._merged_accounts(notes)
    balances = [
        {k: r[k] for k in ("id", "name", "type", "subtype", "mask", "currency", "current", "available", "basis", "as_of", "source")}
        for r in rows
    ]
    return _result(notes, balances=balances)


def get_holdings(backend: Backend, account: str | None = None) -> dict:
    notes = _start(backend)
    rows = backend._merged_holdings(notes)
    if account:
        key = account.strip().casefold()
        rows = [r for r in rows if key in (r["account_id"], r["account_mask"], r["account"].casefold())]
    truncated = len(rows) > MAX_HOLDINGS
    if truncated:
        notes.append(f"Showing the first {MAX_HOLDINGS} of {len(rows)} holdings; filter by account to see the rest.")
    return _result(notes, holdings=[_public(r) for r in rows[:MAX_HOLDINGS]], total_count=len(rows), truncated=truncated)


def _transactions_result(backend: Backend, days: int, limit: int, investments_only: bool) -> dict:
    notes = _start(backend)
    days, limit = _clamp(days, MAX_DAYS), _clamp(limit, MAX_LIMIT)
    rows = backend._merged_transactions(notes, days, investments_only)
    out = {"days": days, "transactions": [_public(r) for r in rows[:limit]], "total_count": len(rows),
           "truncated": len(rows) > limit}
    if out["truncated"]:
        by_type: dict[str, dict] = {}
        for r in rows:
            entry = by_type.setdefault(r["type"], {"count": 0, "_totals": defaultdict(Decimal)})
            entry["count"] += 1
            amount = _dec(r["amount"])
            if amount is not None:
                entry["_totals"][r["currency"]] += amount
        out["summary"] = {
            "note": f"All {len(rows)} matching rows summarised; only the most recent {limit} are listed.",
            "by_type": {
                t: {"count": e["count"], "total_by_currency": {c: _str(v) for c, v in sorted(e["_totals"].items())}}
                for t, e in sorted(by_type.items())
            },
        }
    return _result(notes, **out)


def get_transactions(backend: Backend, days: int = 90, limit: int = 100) -> dict:
    return _transactions_result(backend, days, limit, investments_only=False)


def get_investment_transactions(backend: Backend, days: int = 90, limit: int = 100) -> dict:
    return _transactions_result(backend, days, limit, investments_only=True)


def _pct(part: Decimal, total: Decimal) -> str:
    return format((part / total * 100).quantize(Decimal("0.01")), "f") if total else "0.00"


def net_worth(backend: Backend, currency: str = "CAD") -> dict:
    notes = _start(backend)
    rows, *_ = backend._merged_accounts(notes)
    by_cur: dict[str, dict[str, Decimal]] = defaultdict(lambda: defaultdict(Decimal))
    for r in rows:
        value = _dec(r["current"])
        if value is None or not r["currency"]:
            continue
        if r["type"] in LIABILITY_TYPES:
            value = -value
        by_cur[r["currency"]][_bucket(r["subtype"] or r["type"])] += value
    currencies = {
        cur: {"total": _str(sum(types.values(), Decimal())), "by_account_type": {t: _str(v) for t, v in sorted(types.items())}}
        for cur, types in sorted(by_cur.items())
    }
    primary = currency.strip().upper()
    if not CURRENCY_RE.fullmatch(primary):
        notes.append("Invalid currency code; using CAD.")
        primary = "CAD"
    mixed = len(currencies) > 1
    if mixed:
        notes.append("Several currencies are present. They are reported separately and not converted.")
    return _result(
        notes, primary_currency=primary, primary_total=currencies.get(primary, {}).get("total", "0"),
        by_currency=currencies, mixed_currencies=mixed,
    )


def allocation(backend: Backend) -> dict:
    notes = _start(backend)
    rows, _, csv_accts, match, plaid_held = backend._merged_accounts(notes, holdings=True)
    holdings = backend._holdings_from(csv_accts, match, plaid_held, notes)
    acct_vals: dict[str, dict[str, Decimal]] = defaultdict(lambda: defaultdict(Decimal))
    sec_vals: dict[str, dict[str, Decimal]] = defaultdict(lambda: defaultdict(Decimal))
    for r in rows:
        value = _dec(r["current"])
        if value is not None and r["currency"] and r["type"] not in LIABILITY_TYPES and value > 0:
            acct_vals[r["currency"]][_bucket(r["subtype"] or r["type"])] += value
    for h in holdings:
        value = _dec(h["market_value"])
        if value is not None and h["currency"] and value > 0:
            sec_vals[h["currency"]][h["security_type"] or "unclassified"] += value

    def table(vals: dict[str, Decimal]) -> list[dict]:
        total = sum(vals.values(), Decimal())
        return [{"type": k, "value": _str(v), "percent": _pct(v, total)} for k, v in sorted(vals.items(), key=lambda kv: -kv[1])]

    out = {
        cur: {"by_account_type": table(acct_vals.get(cur, {})), "by_security_type": table(sec_vals.get(cur, {}))}
        for cur in sorted(set(acct_vals) | set(sec_vals))
    }
    if len(out) > 1:
        notes.append("Several currencies are present. Percentages are computed within each currency; nothing is converted.")
    return _result(notes, by_currency=out)


def item_health(backend: Backend) -> dict:
    notes = _start(backend)
    items = []
    for item_id, token in backend.tokens.items():
        short = short_hash(item_id)
        if not backend.api:
            break
        try:
            item = backend.api.item_get(token).get("item") or {}
        except Exception as exc:
            notes.append(_error_note(short, exc, backend.clean))
            items.append({"id": short, "institution": None, "products": [], "last_successful_update": None,
                          "error_code": backend.clean(exc.code) if isinstance(exc, PlaidError) else type(exc).__name__})
            continue
        status = item.get("status") or {}
        updates = [
            str((status.get(k) or {}).get("last_successful_update"))
            for k in ("investments", "transactions")
            if TIMESTAMP_RE.fullmatch(str((status.get(k) or {}).get("last_successful_update") or ""))
        ]
        error = item.get("error") or {}
        code = backend.clean(_enum(error.get("error_code"))) or None
        if code == "ITEM_LOGIN_REQUIRED":
            notes.append(f"Plaid item {short} needs re-authentication. Re-run `{LINK_CMD}` to reconnect it.")
        items.append({
            "id": short, "institution": backend.clean(item.get("institution_name") or "") or None,
            "products": sorted(backend.clean(_enum(p)) for p in item.get("products") or []),
            "last_successful_update": max(updates) if updates else None, "error_code": code,
        })
    return _result(notes, items=items)
