import asyncio
import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from app import csvimport, secrets, server, store, tools
from app.plaid_client import PlaidError
from app.redact import short_hash

FIX = Path(__file__).parent / "fixtures"
TOKEN_OK, TOKEN_BAD = "access-sandbox-TOKENMARK-ok", "access-sandbox-TOKENMARK-bad"
PID_TFSA, PID_USD = "PLAIDACCTID-tfsa-marker", "PLAIDACCTID-usd-marker"
ITEM_OK, ITEM_BAD = "ITEMID-ok-marker", "ITEMID-bad-marker"
FORBIDDEN = [TOKEN_OK, TOKEN_BAD, PID_TFSA, PID_USD, ITEM_OK, ITEM_BAD, "TEST-0000-1111", "TEST-0000-2222",
             "TEST-0000-3333", "0000-1111", "reqid-marker"]
TODAY = date(2024, 3, 10)


def _account(pid, name, subtype, mask, currency, current):
    return {"account_id": pid, "name": name, "official_name": name + " official", "type": "investment",
            "subtype": subtype, "mask": mask,
            "balances": {"current": current, "available": None, "limit": None, "iso_currency_code": currency}}


class FakePlaid:
    def __init__(self, tx_count=1):
        self.tx_count = tx_count

    def _check(self, token):
        if token == TOKEN_BAD:
            raise PlaidError("ITEM_LOGIN_REQUIRED", "the login details of this item have changed")

    def accounts_get(self, token):
        self._check(token)
        return {"accounts": [_account(PID_TFSA, "TFSA", "tfsa", "1111", "CAD", 1000.5),
                             _account(PID_USD, "USD Margin", "margin", "3333", "USD", 200)],
                "item": {"item_id": ITEM_OK, "access_token": TOKEN_OK}}

    def investments_holdings_get(self, token):
        self._check(token)
        return {"securities": [{"security_id": "s1", "name": "Plaid Fund", "ticker_symbol": "plf", "type": "etf",
                                "iso_currency_code": "CAD"}],
                "holdings": [{"account_id": PID_TFSA, "security_id": "s1", "quantity": 3, "institution_price": 10.5,
                              "institution_value": 31.5, "cost_basis": 30, "iso_currency_code": "CAD"},
                             {"account_id": PID_USD, "security_id": "s1", "quantity": 2, "institution_price": 5,
                              "institution_value": 10, "cost_basis": 9, "iso_currency_code": "USD"}]}

    def investments_transactions_get(self, token, start, end):
        self._check(token)
        txs = [{"account_id": PID_TFSA, "security_id": "s1", "date": date(2024, 1, 15), "name": "Plaid buy",
                "amount": 255, "quantity": 10, "price": 25.5, "type": "buy", "subtype": "buy",
                "iso_currency_code": "CAD"}]
        for i in range(self.tx_count - 1):
            txs.append({"account_id": PID_USD, "security_id": "s1", "date": date(2024, 2, 1 + i % 20),
                        "name": f"Dividend {i}", "amount": -1, "type": "cash", "subtype": "dividend",
                        "iso_currency_code": "USD"})
        txs = [t for t in txs if start <= t["date"] <= end]
        return {"investment_transactions": txs, "securities": [{"security_id": "s1", "ticker_symbol": "PLF"}]}

    def item_get(self, token):
        self._check(token)
        # plaid-python's ItemGetResponse shape: status is top level, beside item, with datetime values
        return {"item": {"item_id": ITEM_OK, "institution_name": "Wealthsimple",
                         "products": ["transactions", "investments"], "error": None},
                "status": {"investments": {"last_successful_update": datetime(2024, 3, 9, 10, tzinfo=timezone.utc),
                                           "last_failed_update": None},
                           "transactions": {"last_successful_update": datetime(2024, 3, 8, 9, tzinfo=timezone.utc)},
                           "last_webhook": None},
                "request_id": "reqid-marker"}


@pytest.fixture
def csv_conn(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    csvimport.import_file(FIX / "activities_synthetic.csv", conn)
    # same CSV account as the activities file (name, type and mask), so the two files describe one account
    holdings = tmp_path / "holdings.csv"
    holdings.write_text((FIX / "holdings_synthetic.csv").read_text().replace("Fake TFSA", "TFSA"))
    csvimport.import_file(holdings, conn)
    yield conn
    conn.close()


@pytest.fixture
def backend(csv_conn):
    return tools.Backend(csv_conn, FakePlaid(), {ITEM_OK: TOKEN_OK}, today=lambda: TODAY)


@pytest.fixture
def csv_only(csv_conn):
    return tools.Backend(csv_conn, None, {}, ["No linked Plaid items; showing CSV data only."], today=lambda: TODAY)


def all_outputs(b):
    return [tools.list_accounts(b), tools.get_balances(b), tools.get_holdings(b), tools.get_transactions(b, 730),
            tools.get_investment_transactions(b, 730), tools.net_worth(b), tools.allocation(b), tools.item_health(b)]


def test_list_accounts_shape_and_merge(backend):
    out = tools.list_accounts(backend)
    assert [n for n in out["notes"] if "Possible double count" in n and "Non-registered" in n]
    assert not [n for n in out["notes"] if "TFSA" in n and "double" in n]
    by_name = {a["name"]: a for a in out["accounts"]}
    assert set(by_name["TFSA"]) == {"id", "name", "type", "subtype", "mask", "currency", "source", "balances"}
    assert by_name["TFSA"]["source"] == "plaid" and by_name["TFSA"]["balances"]["current"] == "1000.5"
    assert len(by_name["TFSA"]["id"]) == 8
    # CSV accounts that match a Plaid account (type + mask) are not listed twice
    assert [a["name"] for a in out["accounts"] if a["mask"] == "1111"] == ["TFSA"]
    assert by_name["Fake Crypto"]["source"] == "csv" and by_name["Fake Crypto"]["balances"]["current"] == "500"
    assert by_name["Non-registered"]["balances"]["current"] is None


def test_get_balances_shape(backend):
    rows = tools.get_balances(backend)["balances"]
    assert {"id", "name", "mask", "currency", "current", "available", "source"} <= set(rows[0])


def test_holdings_prefer_plaid_and_shape(backend):
    rows = tools.get_holdings(backend)["holdings"]
    assert {r["source"] for r in rows if r["account"] == "TFSA"} == {"plaid"}
    assert not [r for r in rows if r["symbol"] == "ZZTEST"]  # CSV snapshot for the same account is dropped
    plaid = next(r for r in rows if r["account"] == "TFSA")
    assert set(plaid) >= {"symbol", "name", "quantity", "price", "market_value", "cost_basis", "currency", "account",
                          "account_mask"}
    assert plaid["symbol"] == "PLF" and plaid["market_value"] == "31.5" and plaid["cost_basis"] == "30"
    assert [r["symbol"] for r in rows if r["source"] == "csv"] == ["ZZCOIN"]


def test_holdings_account_filter(backend):
    assert {r["account"] for r in tools.get_holdings(backend, "usd margin")["holdings"]} == {"USD Margin"}
    assert tools.get_holdings(backend, "no-such")["holdings"] == []


def test_transactions_prefer_plaid_by_account_and_date(backend):
    out = tools.get_transactions(backend, 730)
    jan15 = [t for t in out["transactions"] if t["date"] == "2024-01-15"]
    assert [(t["source"], t["description"]) for t in jan15] == [("plaid", "Plaid buy")]
    assert jan15[0]["amount"] == "-255" and jan15[0]["type"] == "buy" and jan15[0]["symbol"] == "PLF"
    assert {t["source"] for t in out["transactions"]} == {"plaid", "csv"}  # other CSV dates still appear
    assert set(out["transactions"][0]) == {"date", "description", "amount", "currency", "type", "symbol", "account_id",
                                           "account", "account_mask", "source"}
    assert not out["truncated"] and "summary" not in out


def test_transaction_limit_and_summary(csv_conn):
    b = tools.Backend(csv_conn, FakePlaid(tx_count=30), {ITEM_OK: TOKEN_OK}, today=lambda: TODAY)
    out = tools.get_transactions(b, 730, limit=5)
    assert len(out["transactions"]) == 5 and out["truncated"] and out["total_count"] > 5
    dates = [t["date"] for t in out["transactions"]]
    assert dates == sorted(dates, reverse=True)
    summary = out["summary"]["by_type"]
    assert sum(v["count"] for v in summary.values()) == out["total_count"]
    assert summary["dividend"]["total_by_currency"]["USD"] == "29"  # 29 plaid dividends of +1 after the sign flip
    assert tools.get_transactions(b, 99999, limit=99999)["days"] == 730  # clamped, not an error
    assert len(tools.get_transactions(b, 730, limit=99999)["transactions"]) <= 200


def test_days_window_applies(backend):
    out = tools.get_transactions(backend, 20)  # 2024-02-19 onward
    assert all(t["date"] >= "2024-02-19" for t in out["transactions"])


def test_investment_transactions_exclude_cash_movements(backend):
    types = {t["type"] for t in tools.get_investment_transactions(backend, 730)["transactions"]}
    assert {"buy", "sell", "dividend"} <= types
    assert not types & {"deposit", "fee", "interest", "transfer"}


def test_net_worth_never_converts(backend):
    out = tools.net_worth(backend)
    assert out["mixed_currencies"] and out["primary_currency"] == "CAD" and out["primary_total"] == "1500.5"
    assert out["by_currency"]["CAD"]["by_account_type"] == {"crypto": "500", "tfsa": "1000.5"}
    assert out["by_currency"]["USD"]["total"] == "200"
    assert any("not converted" in n for n in out["notes"])


def test_allocation_percentages(backend):
    cad = tools.allocation(backend)["by_currency"]["CAD"]
    assert {r["type"]: r["percent"] for r in cad["by_account_type"]} == {"tfsa": "66.68", "crypto": "33.32"}
    assert {r["type"]: r["percent"] for r in cad["by_security_type"]} == {"unclassified": "94.07", "etf": "5.93"}


def test_csv_only_mode(csv_only):
    accounts = tools.list_accounts(csv_only)
    assert accounts["notes"][0] == "No linked Plaid items; showing CSV data only."
    assert {a["source"] for a in accounts["accounts"]} == {"csv"}
    assert {t["source"] for t in tools.get_transactions(csv_only, 730)["transactions"]} == {"csv"}
    assert {h["symbol"] for h in tools.get_holdings(csv_only)["holdings"]} == {"ZZTEST", "ZZCOIN"}
    assert tools.item_health(csv_only)["items"] == []
    assert tools.net_worth(csv_only)["by_currency"]["CAD"]["total"] == "656.6"


def test_one_failing_item_still_returns_other_sources(csv_conn):
    b = tools.Backend(csv_conn, FakePlaid(), {ITEM_BAD: TOKEN_BAD, ITEM_OK: TOKEN_OK}, today=lambda: TODAY)
    out = tools.get_holdings(b)
    assert any("ITEM_LOGIN_REQUIRED" in n and tools.LINK_CMD in n for n in out["notes"])
    assert {r["source"] for r in out["holdings"]} == {"plaid", "csv"}
    health = tools.item_health(b)
    assert sorted(str(i["error_code"]) for i in health["items"]) == ["ITEM_LOGIN_REQUIRED", "None"]
    assert all("Traceback" not in n for n in health["notes"])


def test_only_failing_item_falls_back_to_csv(csv_conn):
    b = tools.Backend(csv_conn, FakePlaid(), {ITEM_BAD: TOKEN_BAD}, today=lambda: TODAY)
    out = tools.list_accounts(b)
    assert {a["source"] for a in out["accounts"]} == {"csv"} and "ITEM_LOGIN_REQUIRED" in out["notes"][0]


def test_item_health_shape(backend):
    item = tools.item_health(backend)["items"][0]
    assert item == {"id": item["id"], "institution": "Wealthsimple", "products": ["investments", "transactions"],
                    "last_successful_update": "2024-03-09T10:00:00+00:00", "error_code": None}
    assert len(item["id"]) == 8


def test_item_health_reads_top_level_status_not_item_status(csv_conn):
    class NestedStatus(FakePlaid):
        def item_get(self, token):
            r = super().item_get(token)
            r["item"]["status"] = r.pop("status")  # the old, wrong place
            return r

    b = tools.Backend(csv_conn, NestedStatus(), {ITEM_OK: TOKEN_OK}, today=lambda: TODAY)
    assert tools.item_health(b)["items"][0]["last_successful_update"] is None


def test_login_required_points_to_update_mode(csv_conn):
    class LoginRequired(FakePlaid):
        def item_get(self, token):
            r = super().item_get(token)
            r["item"]["error"] = {"error_code": "ITEM_LOGIN_REQUIRED"}
            return r

    short = short_hash(ITEM_OK)
    b = tools.Backend(csv_conn, LoginRequired(), {ITEM_OK: TOKEN_OK}, today=lambda: TODAY)
    notes = tools.item_health(b)["notes"]
    assert any(f"{tools.LINK_CMD} --update {short}" in n and "Trial slot" in n for n in notes)
    b = tools.Backend(csv_conn, FakePlaid(), {ITEM_BAD: TOKEN_BAD}, today=lambda: TODAY)
    notes = tools.get_holdings(b)["notes"]
    assert any(f"--update {short_hash(ITEM_BAD)}" in n and "Trial slot" in n for n in notes)


def test_no_secrets_or_ids_in_any_output(csv_conn):
    backends = [
        tools.Backend(csv_conn, FakePlaid(tx_count=30), {ITEM_BAD: TOKEN_BAD, ITEM_OK: TOKEN_OK}, today=lambda: TODAY),
        tools.Backend(csv_conn, None, {}, today=lambda: TODAY),
    ]
    for b in backends:
        for out in all_outputs(b):
            blob = json.dumps(out)
            for marker in FORBIDDEN:
                assert marker not in blob


def test_free_text_is_redacted(csv_conn):
    csv_conn.execute("UPDATE transactions SET description = 'ref 123456789012 ok'")
    out = tools.get_transactions(tools.Backend(csv_conn, None, {}, today=lambda: TODAY), 730)
    assert all("123456789012" not in t["description"] for t in out["transactions"])


def test_tools_registered_read_only():
    listed = asyncio.run(server.mcp.list_tools())
    assert {t.name for t in listed} == {"list_accounts", "get_balances", "get_holdings", "get_transactions",
                                        "get_investment_transactions", "net_worth", "allocation", "item_health"}
    for t in listed:
        a = t.annotations
        assert (a.read_only_hint, a.destructive_hint, a.idempotent_hint, a.open_world_hint) == (True, False, True, False)
        assert t.description
    held = next(t for t in listed if t.name == "get_holdings")
    assert "security_type" in held.description and "Bank" in held.description


def test_open_backend_without_keys_is_csv_only(monkeypatch, tmp_path):
    from app.config import settings

    monkeypatch.setattr(settings, "data_dir", tmp_path)
    b = server.open_backend()
    try:
        assert b.api is None and secrets.SET_KEYS_CMD in b.setup_notes[0]
    finally:
        b.close()


def test_open_backend_without_items_notes_link_command(monkeypatch, tmp_path):
    from app.config import settings

    monkeypatch.setattr(settings, "data_dir", tmp_path)
    secrets.set_plaid_keys(settings.plaid_env, "cid", "sec")
    b = server.open_backend()
    try:
        assert b.api is None and secrets.LINK_CMD in b.setup_notes[0]
    finally:
        b.close()


def _csv_account(conn, name, type_, mask, symbol="ZZ", value="100", currency="CAD"):
    acct = csvimport._hash("t", name, type_, mask)[:16]
    conn.execute("INSERT INTO accounts VALUES (?,?,?,?, 'csv', 'now', NULL)", (acct, name, type_, mask))
    conn.execute("INSERT INTO holdings VALUES (?, '2024-03-01', 0, ?, 'n', '1', '1', ?, ?, ?, 'csv', 'now', NULL)",
                 (acct, symbol, value, value, currency))
    conn.commit()


class PlaidWith(FakePlaid):
    def __init__(self, accounts, **kw):
        super().__init__(**kw)
        self.accounts = accounts

    def accounts_get(self, token):
        return {"accounts": self.accounts}

    def investments_holdings_get(self, token):
        return {"securities": [], "holdings": []}


def test_different_type_strings_same_mask_merge_once(tmp_path):
    conn = store.connect(tmp_path / "m.db")
    _csv_account(conn, "Managed", "MANAGED_TFSA", "4444", value="700")
    _csv_account(conn, "Brokerage", "NON_REGISTERED", "5555", value="300")
    plaid = PlaidWith([_account("p1", "My TFSA", "tfsa", "4444", "CAD", 700),
                       _account("p2", "Taxable", "brokerage", "5555", "CAD", 300)])
    b = tools.Backend(conn, plaid, {ITEM_OK: TOKEN_OK}, today=lambda: TODAY)
    out = tools.net_worth(b)
    assert out["primary_total"] == "1000" and not [n for n in out["notes"] if "double" in n]
    assert {a["source"] for a in tools.list_accounts(b)["accounts"]} == {"plaid"}
    assert tools.allocation(b)["by_currency"]["CAD"]["by_account_type"][0]["value"] == "700"


def test_ambiguous_mask_not_merged_with_note(tmp_path):
    conn = store.connect(tmp_path / "m.db")
    _csv_account(conn, "Managed", "TFSA", "4444", value="700")
    plaid = PlaidWith([_account("p1", "TFSA one", "tfsa", "4444", "CAD", 700),
                       _account("p2", "TFSA two", "tfsa", "4444", "CAD", 50)])
    out = tools.net_worth(tools.Backend(conn, plaid, {ITEM_OK: TOKEN_OK}, today=lambda: TODAY))
    assert out["primary_total"] == "1450"  # nothing merged, so the CSV account is counted and flagged
    assert any("Managed" in n and "TFSA one" in n and "TFSA two" in n and "Possible double count" in n
               for n in out["notes"])
    assert not any("p1" in n or "p2" in n for n in out["notes"])


def test_two_csv_accounts_to_one_plaid_account_not_merged(tmp_path):
    conn = store.connect(tmp_path / "m.db")
    _csv_account(conn, "Alpha", "TFSA", "4444", symbol="A", value="10")
    _csv_account(conn, "Beta", "MANAGED_TFSA", "4444", symbol="B", value="20")
    plaid = PlaidWith([_account("p1", "TFSA", "tfsa", "4444", "CAD", 30)])
    out = tools.net_worth(tools.Backend(conn, plaid, {ITEM_OK: TOKEN_OK}, today=lambda: TODAY))
    assert any("Alpha" in n and "Beta" in n and "all map to Plaid account TFSA" in n for n in out["notes"])
    assert out["primary_total"] == "60"


def test_csv_balance_has_as_of_and_cash_note(csv_only):
    rows = tools.get_balances(csv_only)
    crypto = next(r for r in rows["balances"] if r["name"] == "Fake Crypto")
    assert crypto["as_of"] == "2024-03-31"
    assert any("cash is not included" in n for n in rows["notes"])


def test_invalid_currency_falls_back_to_cad(backend):
    out = tools.net_worth(backend, "<script>")
    assert out["primary_currency"] == "CAD" and any("Invalid currency" in n for n in out["notes"])


class HostilePlaid(FakePlaid):
    def accounts_get(self, token):
        r = super().accounts_get(token)
        r["accounts"][0]["name"] = f"TFSA {TOKEN_OK} {PID_USD} 987654321098"
        return r

    def item_get(self, token):
        r = super().item_get(token)
        r["item"]["error"] = {"error_code": f"E {TOKEN_OK}"}
        r["item"]["institution_name"] = f"WS {PID_TFSA}"
        return r

    def investments_holdings_get(self, token):
        raise PlaidError("BAD", f"failed for {TOKEN_OK} and {ITEM_OK} and {PID_TFSA} and access-sandbox-zzz-123")


def test_markers_in_plaid_text_never_reach_output(csv_conn):
    b = tools.Backend(csv_conn, HostilePlaid(), {ITEM_OK: TOKEN_OK}, today=lambda: TODAY)
    blob = json.dumps(all_outputs(b)) + json.dumps(tools.get_holdings(b, "tfsa"))
    for marker in FORBIDDEN + ["987654321098", "access-sandbox-zzz-123"]:
        assert marker not in blob
    assert "BAD" in blob  # the code itself still surfaces


def test_missing_token_note_hides_item_id(monkeypatch, tmp_path):
    from app.config import settings

    monkeypatch.setattr(settings, "data_dir", tmp_path)
    secrets.set_plaid_keys(settings.plaid_env, "cid", "sec")
    secrets._save_items(settings.plaid_env, [ITEM_OK])  # listed, but no token stored
    out = server.list_accounts()
    blob = json.dumps(out) + json.dumps(server.item_health()) + json.dumps(server.get_holdings("x"))
    assert ITEM_OK not in blob and "access_token" not in blob
    assert any("has no stored access token" in n and secrets.LINK_CMD in n for n in out["notes"])


def test_corrupt_item_list_note_hides_key_names(monkeypatch, tmp_path, memory_keyring):
    from app.config import settings

    monkeypatch.setattr(settings, "data_dir", tmp_path)
    secrets.set_plaid_keys(settings.plaid_env, "cid", "sec")
    memory_keyring.set_password(secrets.SERVICE, f"linked_items_{settings.plaid_env}", "{not a list")
    blob = json.dumps(server.list_accounts())
    assert "linked_items" not in blob and "unreadable" in blob


def test_run_error_path_returns_short_message(monkeypatch, tmp_path):
    def boom(backend, *a):
        raise RuntimeError(f"secret {TOKEN_OK}")

    monkeypatch.setattr(server, "open_backend", lambda: tools.Backend(store.connect(tmp_path / "e.db"), None, {}))
    assert server._run(boom) == {"error": "Tool failed (RuntimeError)."}

    def fail():
        raise OSError(TOKEN_OK)

    monkeypatch.setattr(server, "open_backend", fail)
    assert TOKEN_OK not in json.dumps(server._run(boom))


def test_clean_redacts_known_secrets_before_digit_masking(csv_conn):
    token = "access-production-1234567890-abcdef"
    item = "item123456789"
    b = tools.Backend(csv_conn, FakePlaid(), {item: token}, today=lambda: TODAY)
    out = b.clean(f"failed for {token} on {item}")
    assert "[redacted]" in out
    assert "abcdef" not in out and "6789" not in out


def test_label_with_long_digit_run_is_an_identifier():
    from app import csvimport
    assert csvimport._looks_like_number("ABC12345678")
    assert not csvimport._looks_like_number("RRSP-2024-01")


def test_notes_are_deduplicated_in_order(tmp_path):
    conn = store.connect(tmp_path / "d.db")
    _csv_account(conn, "A", "TFSA", "1234", symbol="X", currency="cad")
    _csv_account(conn, "B", "RRSP", "5678", symbol="Y", currency="c$d")
    b = tools.Backend(conn, None, {}, ["first", "second", "first"], today=lambda: TODAY)
    for out in (tools.list_accounts(b), tools.get_holdings(b), tools.allocation(b)):
        assert out["notes"][:2] == ["first", "second"]
        assert len(out["notes"]) == len(set(out["notes"]))
        assert sum("invalid currency" in n for n in out["notes"]) == 1


def test_empty_csv_account_has_no_double_count_note(tmp_path):
    conn = store.connect(tmp_path / "e.db")
    conn.execute("INSERT INTO accounts VALUES ('emptyacct', 'Old Cash', 'CASH', '9999', 'csv', 'now', NULL)")
    conn.commit()
    plaid = PlaidWith([_account("p1", "TFSA", "tfsa", "4444", "CAD", 10)])
    out = tools.list_accounts(tools.Backend(conn, plaid, {ITEM_OK: TOKEN_OK}, today=lambda: TODAY))
    assert "Old Cash" in {a["name"] for a in out["accounts"]}
    assert not [n for n in out["notes"] if "double count" in n]


def test_invalid_currency_codes_become_placeholder(tmp_path):
    conn = store.connect(tmp_path / "c.db")
    _csv_account(conn, "Weird", "TFSA", "1234", symbol="W", value="5", currency="<b>X")
    conn.execute("INSERT INTO transactions VALUES ('h1', ?, '2024-03-01', 'fee', '', '', '', '', '-1', 'usd ',"
                 " 'fee', 'csv', 'now', NULL)", (conn.execute("SELECT account_id FROM accounts").fetchone()[0],))
    conn.commit()
    bad = _account("p1", "Plaid", "tfsa", "4444", "EVIL<script>", 10)
    b = tools.Backend(conn, PlaidWith([bad]), {ITEM_OK: TOKEN_OK}, today=lambda: TODAY)
    outs = [tools.list_accounts(b), tools.get_holdings(b), tools.get_transactions(b, 30), tools.net_worth(b)]
    blob = json.dumps(outs)
    assert "<b>X" not in blob and "EVIL" not in blob and "usd " not in blob
    assert {a["currency"] for a in outs[0]["accounts"]} == {"???"}
    assert outs[1]["holdings"][0]["currency"] == "???"
    assert outs[2]["transactions"][0]["currency"] == "???"
    assert all(any("invalid currency" in n for n in o["notes"]) for o in outs)


def test_item_health_alone_scrubs_account_ids(csv_conn):
    # each server call has a fresh Backend, so item_health must learn account ids itself before cleaning text
    b = tools.Backend(csv_conn, HostilePlaid(), {ITEM_OK: TOKEN_OK}, today=lambda: TODAY)
    blob = json.dumps(tools.item_health(b))
    assert PID_TFSA not in blob and TOKEN_OK not in blob and "WS" in blob
