import sqlite3
from pathlib import Path

import pytest

from app import csvimport, store
from app.cli import main

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "t.db")
    yield c
    c.close()


def test_parse_activities(conn):
    res = csvimport.import_file(FIX / "activities_synthetic.csv", conn)
    assert (res.kind, res.added, res.duplicates, res.rejected) == ("activities", 7, 0, [])
    rows = conn.execute("SELECT date, type, symbol, quantity, price, amount, currency, source FROM transactions ORDER BY date").fetchall()
    assert [r[1] for r in rows] == ["buy", "dividend", "sell", "deposit", "interest", "fee", "transfer"]
    assert rows[0] == ("2024-01-15", "buy", "ZZTEST", "10", "25.5", "-255", "CAD", "csv")
    assert rows[3][5] == "1000" and rows[5][5] == "-0.99"


def test_account_number_reduced_to_last4(conn):
    csvimport.import_file(FIX / "activities_synthetic.csv", conn)
    masks = {r[0] for r in conn.execute("SELECT mask FROM accounts")}
    assert masks == {"1111", "2222"}
    assert "TEST-0000" not in "\n".join(conn.iterdump())


def test_rows_tagged_with_file_hash_not_path(conn):
    csvimport.import_file(FIX / "activities_synthetic.csv", conn)
    sha, imported_at = conn.execute("SELECT file_sha256, imported_at FROM transactions LIMIT 1").fetchone()
    assert len(sha) == 64 and imported_at
    assert "fixtures" not in "\n".join(conn.iterdump())


def test_reimport_is_idempotent(conn):
    csvimport.import_file(FIX / "activities_synthetic.csv", conn)
    res = csvimport.import_file(FIX / "activities_synthetic.csv", conn)
    assert (res.added, res.duplicates) == (0, 7)
    assert conn.execute("SELECT count(*) FROM transactions").fetchone()[0] == 7


def test_identical_rows_within_file_both_kept(conn, tmp_path):
    f = tmp_path / "a.csv"
    line = "2024-01-02,Acct,TFSA,Buy,ZZ,CAD,1,2,-2,t\n"
    f.write_text("date,account_name,account_type,activity_type,symbol,currency,quantity,price,amount,description\n" + line * 2)
    assert csvimport.import_file(f, conn).added == 2
    assert csvimport.import_file(f, conn).added == 0


def test_holdings(conn):
    res = csvimport.import_file(FIX / "holdings_synthetic.csv", conn)
    assert (res.kind, res.added) == ("holdings", 2)
    row = conn.execute("SELECT symbol, quantity, market_value, book_value, currency, as_of FROM holdings WHERE symbol='ZZCOIN'").fetchone()
    assert row == ("ZZCOIN", "0.5", "500", "400", "CAD", "2024-03-31")
    assert csvimport.import_file(FIX / "holdings_synthetic.csv", conn).duplicates == 2


def test_malformed_rows_reported_without_contents(conn, tmp_path):
    f = tmp_path / "bad.csv"
    f.write_text(
        "date,account,type,symbol,amount,currency\n"
        "2024-01-01,Acct,Buy,ZZ,-5.00,CAD\n"
        "not-a-date,Acct,Buy,ZZ,-5.00,CAD\n"
        "2024-01-03,Acct,Buy,ZZ,SECRETAMOUNT,CAD\n"
        "2024-01-04,Acct,Buy,ZZ,-5.00,\n"
        "2024-01-05,,Buy,ZZ,-5.00,CAD\n"
    )
    res = csvimport.import_file(f, conn)
    assert res.added == 1
    assert [n for n, _ in res.rejected] == [3, 4, 5, 6]
    assert not any("SECRETAMOUNT" in r for _, r in res.rejected)


def test_unrecognised_and_binary_files_error(conn, tmp_path):
    f = tmp_path / "x.csv"
    f.write_text("foo,bar\n1,2\n")
    with pytest.raises(ValueError, match="headers found: foo, bar"):
        csvimport.import_file(f, conn)
    h = tmp_path / "z.csv"
    h.write_text("Acct 123456789012,Weird Header\n1,2\n")
    with pytest.raises(ValueError, match="weird_header") as info:
        csvimport.import_file(h, conn)
    assert "123456789012" not in str(info.value)
    g = tmp_path / "y.csv"
    g.write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(ValueError):
        csvimport.import_file(g, conn)


def test_cli_prints_counts_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(store, "db_path", lambda: tmp_path / "cli.db")
    assert main(["import-csv", str(FIX / "activities_synthetic.csv")]) == 0
    out = capsys.readouterr().out
    assert "added 7, duplicates skipped 0, rejected 0" in out
    assert "ZZTEST" not in out
    assert main(["import-csv", str(FIX / "activities_synthetic.csv"), str(tmp_path / "missing.csv")]) == 1
    assert "duplicates skipped 7" in capsys.readouterr().out
    with sqlite3.connect(tmp_path / "cli.db") as c:
        assert c.execute("SELECT count(*) FROM transactions").fetchone()[0] == 7


def test_fixtures_are_synthetic():
    for f in FIX.glob("*.csv"):
        text = f.read_text()
        assert "TEST-0000" in text
        assert "@" not in text


# ---- edge cases ----
from datetime import UTC, datetime  # noqa: E402


def _write(tmp_path, name, text, enc="utf-8"):
    f = tmp_path / name
    f.write_bytes(text.encode(enc))
    return f


def test_account_number_in_account_column_and_description_is_redacted(conn, tmp_path):
    f = _write(
        tmp_path, "r.csv",
        "date,account,type,symbol,amount,currency,description\n"
        "2024-01-01,1234 5678 9012,Transfer,,-5.00,CAD,Sent to acct 4000-1234-5678 today\n"
        "2024-01-02,Savings,Deposit,,5.00,CAD,from AB-77-XYZ12\n",
    )
    assert csvimport.import_file(f, conn).added == 2
    dump = "\n".join(conn.iterdump())
    for leak in ("123456789012", "1234 5678 9012", "4000-1234-5678", "40001234", "56789012"):
        assert leak not in dump
    assert conn.execute("SELECT name, mask FROM accounts WHERE mask='9012'").fetchone() == ("\u2022\u2022\u20229012", "9012")
    assert "\u2022\u2022\u20225678" in conn.execute("SELECT description FROM transactions WHERE date='2024-01-01'").fetchone()[0]


def test_exact_account_number_match_redacted_in_text(conn, tmp_path):
    f = _write(
        tmp_path, "r.csv",
        "date,account_name,account_number,type,amount,currency,description\n"
        "2024-01-01,Chequing,AB-77-XYZ12,Deposit,5.00,CAD,from AB-77-XYZ12\n",
    )
    csvimport.import_file(f, conn)
    assert "AB-77-XYZ12" not in "\n".join(conn.iterdump())


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1 234,56", "1234.56"), ("1\u00a0234,56", "1234.56"), ("12,5", "12.5"), ("1.234,56", "1234.56"),
        ("1,234.56", "1234.56"), ("1,234,567", "1234567"), ("12.00-", "-12"), ("+7.50", "7.5"), ("(5.00)", "-5"),
    ],
)
def test_decimal_formats(raw, expected):
    assert csvimport._decimal(raw, "amount") == expected


@pytest.mark.parametrize("raw", ["1,234", "1E+999999", "1E-999999", "abc", "1,2,3", "NaN", "Infinity", "1_000"])
def test_decimal_rejects(raw):
    with pytest.raises(csvimport.RowError) as exc:
        csvimport._decimal(raw, "amount")
    assert raw not in str(exc.value)


def test_same_row_in_two_unnumbered_accounts_not_collapsed(conn, tmp_path):
    head = "date,account_name,type,symbol,amount,currency\n"
    a = _write(tmp_path, "a.csv", head + "2024-01-01,Account A,Dividend,ZZ,1.00,CAD\n")
    b = _write(tmp_path, "b.csv", head + "2024-01-01,Account B,Dividend,ZZ,1.00,CAD\n")
    assert csvimport.import_file(a, conn).added == 1
    assert csvimport.import_file(b, conn).added == 1


def test_reworded_description_still_dedupes(conn, tmp_path):
    head = "date,account_name,type,symbol,amount,currency,description\n"
    csvimport.import_file(_write(tmp_path, "a.csv", head + "2024-01-01,A,Dividend,ZZ,1.00,CAD,old\n"), conn)
    assert csvimport.import_file(_write(tmp_path, "b.csv", head + "2024-01-01,A,Dividend,ZZ,1.00,CAD,new\n"), conn).duplicates == 1


def test_holdings_reexport_updates_and_latest(conn, tmp_path):
    head = "account_name,symbol,quantity,market_price,market_value,currency,as_of\n"
    csvimport.import_file(_write(tmp_path, "a.csv", head + "Acct,ZZ,2,10,20,CAD,2024-03-31\n"), conn)
    res = csvimport.import_file(_write(tmp_path, "b.csv", head + "Acct,ZZ,2,11,22,CAD,2024-03-31\n"), conn)
    assert (res.added, res.updated, res.duplicates) == (0, 1, 0)
    assert conn.execute("SELECT count(*), max(market_value) FROM holdings").fetchone() == (1, "22")
    csvimport.import_file(_write(tmp_path, "c.csv", head + "Acct,ZZ,3,12,36,CAD,2024-04-30\n"), conn)
    latest = store.latest_holdings(conn)
    assert [(h["as_of"], h["quantity"]) for h in latest] == [("2024-04-30", "3")]
    acct = conn.execute("SELECT account_id FROM accounts").fetchone()[0]
    assert len(store.latest_holdings(conn, acct)) == 1 and store.latest_holdings(conn, "nope") == []


def test_holdings_missing_as_of_uses_import_date(conn, tmp_path):
    f = _write(tmp_path, "h.csv", "account_name,symbol,quantity,currency\nAcct,ZZ,2,CAD\n")
    csvimport.import_file(f, conn, now=datetime(2024, 5, 6, tzinfo=UTC))
    assert conn.execute("SELECT as_of, as_of_inferred FROM holdings").fetchone() == ("2024-05-06", 1)
    assert csvimport.import_file(f, conn, now=datetime(2024, 5, 6, tzinfo=UTC)).duplicates == 1


def test_type_word_boundary_and_raw_type(conn, tmp_path):
    f = _write(
        tmp_path, "t.csv",
        "date,account_name,type,sub_type,amount,currency\n"
        "2024-01-01,A,Individual,Plan,1.00,CAD\n"
        "2024-01-02,A,Trade,E_TRFIN,1.00,CAD\n",
    )
    csvimport.import_file(f, conn)
    assert conn.execute("SELECT type, raw_type FROM transactions ORDER BY date").fetchall() == [
        ("other", "Individual / Plan"), ("transfer", "Trade / E_TRFIN")]


def test_quoted_newline_and_real_line_numbers(conn, tmp_path):
    f = _write(
        tmp_path, "q.csv",
        'date,account_name,type,amount,currency,description\n'
        '2024-01-01,A,Buy,1.00,CAD,"two\nlines"\n'
        'bad,A,Buy,1.00,CAD,x\n',
    )
    res = csvimport.import_file(f, conn)
    assert res.added == 1 and [n for n, _ in res.rejected] == [4]


@pytest.mark.parametrize("enc,prefix", [("utf-16", ""), ("utf-8", "\ufeff"), ("cp1252", "")])
def test_encodings(conn, tmp_path, enc, prefix):
    f = _write(tmp_path, "e.csv", prefix + "date,account_name,type,amount,currency,description\n2024-01-01,Caf\u00e9,Buy,1.00,CAD,\u00e9\n", enc)
    assert csvimport.import_file(f, conn).added == 1
    assert conn.execute("SELECT name FROM accounts").fetchone()[0] == "Caf\u00e9"


def test_duplicate_headers_rejected(conn, tmp_path):
    f = _write(tmp_path, "d.csv", "date,Account Name,account_name,type,amount,currency\n2024-01-01,A,B,Buy,1,CAD\n")
    with pytest.raises(ValueError, match="duplicate column"):
        csvimport.import_file(f, conn)


def test_free_text_sanitised_and_currency_validated(conn, tmp_path):
    f = _write(
        tmp_path, "s.csv",
        "date,account_name,type,amount,currency,description\n"
        f"2024-01-01,A,Buy,1.00,CAD,\"a\x07b\x1b[0m{'x' * 500}\"\n"
        "2024-01-02,A,Buy,1.00,CADX,ok\n",
    )
    res = csvimport.import_file(f, conn)
    assert res.added == 1 and res.rejected == [(3, "invalid currency")]
    desc = conn.execute("SELECT description FROM transactions").fetchone()[0]
    assert len(desc) == 300 and "\x07" not in desc and "\x1b" not in desc


def test_size_cap(conn, tmp_path, monkeypatch):
    monkeypatch.setattr(csvimport, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="50 MB"):
        csvimport.import_file(FIX / "activities_synthetic.csv", conn)


def test_csv_error_in_one_file_does_not_abort_others(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(store, "db_path", lambda: tmp_path / "e.db")
    bad = _write(tmp_path, "bad.csv", "date,account_name,type,amount,currency,description\n2024-01-01,A,Buy,1,CAD," + "x" * 200000 + "\n")
    assert main(["import-csv", str(bad), str(FIX / "activities_synthetic.csv")]) == 1
    out = capsys.readouterr().out
    assert "bad.csv: not imported (malformed CSV" in out and "added 7" in out


def _mk(tmp_path, text, name="f.csv"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


HOLD_HEAD = "Account Name,Account Number,Symbol,Name,Quantity,Market Price,Market Price Currency,Market Value,Book Value (Market),As Of\n"


def test_split_lots_in_one_file_are_summed(conn, tmp_path):
    path = _mk(tmp_path, HOLD_HEAD + "Fake TFSA,TEST-1111,ZZTEST,Fund,6,10,CAD,60,50,2024-03-31\n"
                  "Fake TFSA,TEST-1111,ZZTEST,Fund,4,10,CAD,40.5,30,2024-03-31\n")
    res = csvimport.import_file(path, conn)
    assert (res.added, res.merged, res.rejected) == (1, 1, [])
    assert conn.execute("SELECT quantity, market_value, book_value FROM holdings").fetchall() == [("10", "100.5", "80")]


def test_split_lots_with_different_currencies_are_rejected(conn, tmp_path):
    path = _mk(tmp_path, HOLD_HEAD + "Fake TFSA,TEST-1111,ZZTEST,Fund,6,10,CAD,60,50,2024-03-31\n"
                  "Fake TFSA,TEST-1111,ZZTEST,Fund,4,10,USD,40,30,2024-03-31\n")
    res = csvimport.import_file(path, conn)
    assert res.rejected == [(3, "same position listed in different currencies")]
    assert conn.execute("SELECT quantity, currency FROM holdings").fetchall() == [("6", "CAD")]


def test_alphanumeric_account_column_reduced_to_last4(conn, tmp_path):
    path = _mk(tmp_path, "Account,Symbol,Quantity,Market Price Currency\nAB-77-XYZ12,ZZTEST,1,CAD\n")
    csvimport.import_file(path, conn)
    name, mask = conn.execute("SELECT name, mask FROM accounts").fetchone()
    assert mask == "YZ12" and "AB-77" not in name
    assert "AB-77-XYZ12" not in "\n".join(conn.iterdump())


def test_plain_uppercase_account_name_stays_a_name(conn, tmp_path):
    path = _mk(tmp_path, "Account,Symbol,Quantity,Market Price Currency\nNON-REGISTERED,ZZTEST,1,CAD\n")
    csvimport.import_file(path, conn)
    assert conn.execute("SELECT name, mask FROM accounts").fetchone() == ("NON-REGISTERED", "")


def test_unchanged_split_lot_reimport_reports_duplicates_only(conn, tmp_path):
    path = _mk(tmp_path, HOLD_HEAD + "Fake TFSA,TEST-1111,ZZTEST,Fund,6,10,CAD,60,50,2024-03-31\n"
               "Fake TFSA,TEST-1111,ZZTEST,Fund,4,10,CAD,40,30,2024-03-31\n")
    csvimport.import_file(path, conn)
    res = csvimport.import_file(path, conn)
    assert (res.added, res.updated, res.duplicates) == (0, 0, 1)
    assert conn.execute("SELECT quantity FROM holdings").fetchall() == [("10",)]


def test_lot_with_missing_market_value_rejects_merge(conn, tmp_path):
    path = _mk(tmp_path, HOLD_HEAD + "Fake TFSA,TEST-1111,ZZTEST,Fund,6,10,CAD,60,50,2024-03-31\n"
               "Fake TFSA,TEST-1111,ZZTEST,Fund,4,10,CAD,,30,2024-03-31\n")
    res = csvimport.import_file(path, conn)
    assert res.rejected == [(3, "cannot combine lots: market value missing in one of them")]
    assert conn.execute("SELECT quantity, market_value FROM holdings").fetchall() == [("6", "60")]


def test_identifier_heuristic_case_insensitive_but_keeps_labels(conn, tmp_path):
    path = _mk(tmp_path, "Account,Symbol,Quantity,Market Price Currency\nab-77-xyz12,ZZ,1,CAD\nRRSP-2024-01,ZZ,1,CAD\n")
    csvimport.import_file(path, conn)
    rows = dict(conn.execute("SELECT name, mask FROM accounts").fetchall())
    label = next(n for n in rows if n.startswith("RRSP"))
    assert rows[label] == ""  # a label, not a number: nothing taken as the mask
    assert "ab-77-xyz12" not in rows and "yz12" in rows.values()
