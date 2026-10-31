"""Read-only MCP server over stdio: python -m app.server.

Startup touches neither the network nor the keychain; credentials are read lazily on the first tool call.
"""
from typing import Callable

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from app import secrets, store, tools
from app.config import settings

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

CONVENTIONS = (
    "Money values are decimal strings in the row's own currency (e.g. CAD, USD); different currencies are never "
    "converted. Each row has source 'plaid' or 'csv' (Wealthsimple CSV import); Plaid wins when both cover an account. "
    "Account ids are short local ids and masks are the last 4 characters only. CSV holdings usually have "
    "security_type null (unclassified). Bank (non-investment) transactions are not covered. Check 'notes' for problems."
)
TX_CONVENTIONS = (
    " Transaction amounts: negative = cash out of the account, positive = cash in. 'days' is capped at "
    f"{tools.MAX_DAYS} and 'limit' at {tools.MAX_LIMIT}; beyond the limit the most recent rows are returned with a summary."
)

mcp = MCPServer("personal-finance-mcp", instructions="Read-only view of the owner's Wealthsimple accounts. " + CONVENTIONS)


def open_backend() -> tools.Backend:
    """Build the data sources for one call. Missing keys or items degrade to CSV-only with a note."""
    env = settings.plaid_env
    conn = store.connect()
    notes: list[str] = []
    tokens: dict[str, str] = {}
    api = None
    try:
        if not secrets.has_plaid_keys(env):
            notes.append(f"No Plaid keys stored; showing CSV data only. Run: {secrets.SET_KEYS_CMD}")
        else:
            try:
                item_ids = secrets.list_item_ids(env)
            except secrets.MissingSecret:
                item_ids = []
                notes.append(f"The stored list of linked items is unreadable. Run: {secrets.LINK_CMD}")
            if not item_ids:
                notes.append(f"No linked Plaid items; showing CSV data only. Run: {secrets.LINK_CMD}")
            for item_id in item_ids:
                try:
                    tokens[item_id] = secrets.get_access_token(env, item_id)
                except secrets.MissingSecret:
                    # the exception text names the keychain entry, which contains the raw item id
                    notes.append(f"Plaid item {tools._short(item_id)} has no stored access token. Run: {secrets.LINK_CMD}")
            if tokens:
                from app.plaid_client import RealPlaid

                api = RealPlaid.from_settings(settings)
    except secrets.MissingSecret:
        notes.append(f"Plaid keys are missing. Run: {secrets.SET_KEYS_CMD}")
    except Exception as exc:
        notes.append(f"Keychain or Plaid setup failed ({type(exc).__name__}); showing CSV data only.")
        tokens, api = {}, None
    return tools.Backend(conn, api, tokens, notes)


def _run(fn: Callable, *args) -> dict:
    try:
        backend = open_backend()
    except Exception as exc:
        return {"error": f"Could not open the local store ({type(exc).__name__})."}
    try:
        return fn(backend, *args)
    except Exception as exc:  # never leak a traceback or request data into model context
        return {"error": f"Tool failed ({type(exc).__name__})."}
    finally:
        backend.close()


@mcp.tool(description="List all accounts with name, type, subtype, mask (last 4), currency and balances. " + CONVENTIONS, annotations=READ_ONLY)
def list_accounts() -> dict:
    return _run(tools.list_accounts)


@mcp.tool(description="Current balances per account and currency. CSV-only accounts show the market value of their latest holdings snapshot. " + CONVENTIONS, annotations=READ_ONLY)
def get_balances() -> dict:
    return _run(tools.get_balances)


@mcp.tool(
    description=f"Holdings with symbol, name, quantity, price, market value, cost basis and currency (up to {tools.MAX_HOLDINGS} rows). "
    "Optionally filter by account (local id, mask or name). " + CONVENTIONS,
    annotations=READ_ONLY,
)
def get_holdings(account: str | None = None) -> dict:
    return _run(tools.get_holdings, account)


@mcp.tool(description="Recent transactions (investment activity from Plaid plus CSV imports). " + CONVENTIONS + TX_CONVENTIONS, annotations=READ_ONLY)
def get_transactions(days: int = 90, limit: int = 100) -> dict:
    return _run(tools.get_transactions, days, limit)


@mcp.tool(description="Recent investment transactions only (trades, dividends, anything with a symbol). " + CONVENTIONS + TX_CONVENTIONS, annotations=READ_ONLY)
def get_investment_transactions(days: int = 90, limit: int = 100) -> dict:
    return _run(tools.get_investment_transactions, days, limit)


@mcp.tool(
    description="Net worth totals by account type, reported separately for each currency (no conversion); "
    "'primary_total' is the total in the requested currency (default CAD). " + CONVENTIONS,
    annotations=READ_ONLY,
)
def net_worth(currency: str = "CAD") -> dict:
    return _run(tools.net_worth, currency)


@mcp.tool(description="Allocation percentages by account type and by security type, computed within each currency. " + CONVENTIONS, annotations=READ_ONLY)
def allocation() -> dict:
    return _run(tools.allocation)


@mcp.tool(description="Health of each linked Plaid item: institution, products, last successful update and error code.", annotations=READ_ONLY)
def item_health() -> dict:
    return _run(tools.item_health)


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
