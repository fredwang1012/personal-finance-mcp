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
    with pytest.raises(ValueError):
        csvimport.import_file(f, conn)
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
