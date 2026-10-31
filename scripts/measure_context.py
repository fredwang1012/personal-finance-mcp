"""Measure how much model context the MCP tools cost, using synthetic data only.

    py -3.12 -m uv run python scripts/measure_context.py

Reports the size of the tools/list payload and of each tool's tools/call result (default arguments), in characters
and approximate tokens (chars / 4). Plaid is replaced by an in-script fake and the store is a throwaway SQLite file,
so the keychain, the network and the real data directory are never touched.
"""
import asyncio
import json
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import server, store, tools  # noqa: E402

TODAY = date(2026, 3, 10)


class SyntheticPlaid:
    """Four accounts, 40 holdings and 150 investment transactions with float-noisy amounts, like real Plaid data."""

    def accounts_get(self, token):
        def acct(i, name, subtype, mask, cur, bal):
            return {"account_id": f"synthetic-account-{i}", "name": name, "official_name": name, "type": "investment",
                    "subtype": subtype, "mask": mask,
                    "balances": {"current": bal, "available": None, "limit": None, "iso_currency_code": cur}}

        return {"accounts": [acct(0, "TFSA", "tfsa", "0001", "CAD", 23012.12345678901),
                             acct(1, "RRSP", "rrsp", "0002", "CAD", 23012.123456789),
                             acct(2, "Non-registered", "non-registered", "0003", "CAD", 8123.4),
                             acct(3, "USD Margin", "margin", "0004", "USD", 1999.999999)]}

    def investments_holdings_get(self, token):
        secs = [{"security_id": f"s{i}", "name": f"Synthetic Fund Number {i}", "ticker_symbol": f"SYN{i}",
                 "type": "etf" if i % 3 else "equity", "iso_currency_code": "CAD"} for i in range(40)]
        held = [{"account_id": f"synthetic-account-{i % 4}", "security_id": f"s{i}", "quantity": 12.345678901 + i,
                 "institution_price": 41.23456789, "institution_value": (12.345678901 + i) * 41.23456789,
                 "cost_basis": 400.1 + i, "iso_currency_code": "USD" if i % 4 == 3 else "CAD"} for i in range(40)]
        return {"securities": secs, "holdings": held}

    def investments_transactions_get(self, token, start, end):
        txs = []
        for i in range(150):
            day = end - timedelta(days=i % 85)
            kind = ("buy", "buy"), ("sell", "sell"), ("cash", "dividend"), ("fee", "fee")
            t, sub = kind[i % 4]
            txs.append({"account_id": f"synthetic-account-{i % 4}", "security_id": f"s{i % 40}", "date": day,
                        "name": f"{sub.upper()} SYN{i % 40} - Synthetic Fund Number {i % 40} order filled",
                        "amount": 123.456789 * (1 if t == "buy" else -1), "type": t, "subtype": sub,
                        "iso_currency_code": "USD" if i % 4 == 3 else "CAD"})
        txs = [t for t in txs if start <= t["date"] <= end]
        return {"investment_transactions": txs, "securities": []}

    def item_get(self, token):
        return {"item": {"institution_name": "Wealthsimple", "products": ["investments"]}, "status": {}}


def _dump(model) -> str:
    return json.dumps(model.model_dump(by_alias=True, exclude_none=True, mode="json"), separators=(",", ":"))


async def measure(tmp: Path) -> None:
    def backend():
        b = tools.Backend(store.connect(tmp / "m.db"), SyntheticPlaid(), {"synthetic-item": "synthetic-token"})
        b.today = lambda: TODAY
        return b

    server.open_backend = backend
    listed = await server.mcp.list_tools()
    payload = "[" + ",".join(_dump(t) for t in listed) + "]"
    print(f"{'tools/list':<30}{len(payload):>8} chars {len(payload) // 4:>7} tokens ({len(listed)} tools)")
    for t in listed:
        print(f"  {t.name:<28}{len(_dump(t)):>8} chars")
    instructions = server.mcp.instructions or ""
    print(f"{'server instructions':<30}{len(instructions):>8} chars {len(instructions) // 4:>7} tokens")
    total = 0
    for t in listed:
        result = await server.mcp.call_tool(t.name, {})
        size = len(_dump(result))
        total += size
        print(f"{t.name:<30}{size:>8} chars {size // 4:>7} tokens")
    print(f"{'all outputs':<30}{total:>8} chars {total // 4:>7} tokens")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="pfmcp-measure-") as tmp:
        asyncio.run(measure(Path(tmp)))


if __name__ == "__main__":
    main()
