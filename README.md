# personal-finance-mcp

A local, **read-only** MCP (Model Context Protocol) server that lets Claude answer questions about my own Wealthsimple
accounts: balances, holdings, allocation across TFSA / RRSP / FHSA / non-registered / cash / crypto, investment
activity and net worth. Data comes from Plaid, with Wealthsimple's own CSV exports as a fallback. The server runs on
my machine over stdio for Claude Desktop and Claude Code. Plaid credentials and access tokens stay in the Windows
Credential Manager; nothing that can move money is ever requested.

## What it does

Claude gets eight tools. All of them are annotated read-only, non-destructive and idempotent.

| Tool | Returns |
| --- | --- |
| `list_accounts` | Each account: short id, name, type, subtype, mask (last 4), currency, balances, source |
| `get_balances` | Current and available balance per account and currency |
| `get_holdings` | Symbol, name, quantity, price, market value, cost basis, currency, security type; optional account filter (up to 500 rows) |
| `get_transactions` | Investment activity from Plaid plus CSV-imported activity for the last `days` (max 730), newest first, at most `limit` (max 200) rows, with a per-type summary when truncated |
| `get_investment_transactions` | The same, limited to trades, dividends and anything with a symbol |
| `net_worth` | Totals by account type, per currency, with `primary_total` in the requested currency (default CAD) |
| `allocation` | Percentages by account type and by security type, computed within each currency |
| `item_health` | Per linked Plaid item: institution, products, last successful update, error code |

Every result has a `notes` list for anything Claude should know: a failed Plaid item, a CSV account that may be
counted twice, mixed currencies, missing keys. Money values are decimal strings, never floats.

Questions it can answer, for example:

- "What's my net worth in CAD, and how much of it is in the TFSA?"
- "How is my RRSP allocated between ETFs and individual stocks?"
- "What dividends did I get in the last 90 days?"
- "Which holdings have the biggest gain over cost basis?"
- "Is my Plaid connection still healthy?"

## Setup

Prerequisites: Windows, Python 3.12 with [uv](https://docs.astral.sh/uv/) (`py -3.12 -m pip install uv`), and a
free Plaid account.

```bash
py -3.12 -m uv sync
```

All commands below are run from the repo root. Settings live in an optional `.env`; see
[.env.example](.env.example). The only one most people change is `PLAID_ENV` (`sandbox` or `production`).

### 1. Plaid account

Sign up at [dashboard.plaid.com](https://dashboard.plaid.com). You get Sandbox keys straight away. For real data,
request the **Trial** plan for Production. It is free and uses real data, but it allows at most 10 Items (one Item is
one linked login at one institution), and removing an Item does **not** free its slot. Do everything in Sandbox
first, and link Production once.

### 2. Store the keys

```bash
py -3.12 -m uv run python -m app.cli set-plaid-keys
```

This prompts for the client_id and the secret for the current `PLAID_ENV` without echoing them, and stores them in
the Windows Credential Manager (service `personal-finance-mcp`). They never go in `.env`, argv or a file. Run it again
with `PLAID_ENV=production` set to store the Production secret; the client_id is shared. `status` shows which keys
exist and how many items are linked, never the values:

```bash
py -3.12 -m uv run python -m app.cli status
```

### 3. Link in Sandbox

```bash
py -3.12 -m uv run python -m app.cli link
```

This opens Plaid Link in your browser from a short-lived page on `127.0.0.1`. Pick any institution and sign in with
`user_good` / `pass_good`; if asked for an MFA code, use `1234`. The access token goes into the Credential Manager and
the command prints the item's short id. Then point Claude at the server (below) and ask it something.

### 4. Link in Production, once

Set `PLAID_ENV=production` in `.env`, store the Production secret with `set-plaid-keys`, and run `link` again. It warns
that the Item permanently takes one of the 10 Trial slots and asks you to type `yes`. Choose Wealthsimple in Plaid
Link and sign in there. Your Wealthsimple password and 2FA go only to Plaid inside Plaid Link; this code never sees
them.

**Wealthsimple caveat.** Plaid's coverage of Canadian investment accounts can be incomplete: some accounts, holdings
or activity may be missing or late. `item_health` shows the last successful update. That gap is why the CSV fallback
exists.

## CSV fallback

Wealthsimple lets you download your own data as CSV. In the web app (menu labels change over time):

- **Activities:** Activity tab, then download activities as CSV. Or Profile, Documents, Request documents,
  "Activities Export (CSV)", choose a period and accounts.
- **Holdings:** Profile, Documents, Request documents, "Holdings report (CSV)", choose accounts.
- **Monthly statements:** Documents, Custom download, bulk download monthly statements as CSV. Files with the same
  columns as the two above import the same way.

Then:

```bash
py -3.12 -m uv run python -m app.cli import-csv path/to/activities.csv path/to/holdings.csv
```

It prints, per file, how many rows were added, updated, skipped as duplicates or rejected, with the line number and
reason for each rejected row (never the row's contents). Re-importing is safe: transactions are de-duplicated by a
stable hash, and holdings are keyed on account, as-of date and symbol, with the latest import winning. Only the last 4
characters of an account number are stored, and long digit runs in text fields are masked.

The file type is detected from the header names (case and spacing do not matter; unknown columns are ignored):

| File | Needs | Also reads |
| --- | --- | --- |
| Activities | a date (`transaction_date`, `date`, `trade_date` or `settlement_date`), a type (`activity_type`, `transaction_type`, `type`), an amount (`net_cash_amount`, `amount`, `net_amount`) and `currency` | `account_id` / `account_number`, `account_name`, `account_type`, `activity_sub_type`, `symbol`, `quantity`, `share_price` / `price`, `description` |
| Holdings | `symbol`, `quantity` and a currency (`currency` or `market_price_currency`) | `account_name`, `account_type`, `account_number`, `name`, `market_price`, `market_value`, `book_value_market` / `book_value`, `as_of` |

The parser was built from Wealthsimple's public help pages and synthetic fixtures, not from a real export. If a real
file does not match, `import-csv` says the format is unrecognised and lists the headers it found (or reports the
rejected rows); compare them with the table above and adjust `ALIASES` in `app/csvimport.py`.

**If you imported CSVs before the account-id change** (CSV account ids now derive from name, type and last 4 only),
delete `data/finance.db` and run `import-csv` again on the same files. There is no migration.

## Use it from Claude Desktop

Open Claude Desktop, Settings, Developer, Edit Config. That opens `claude_desktop_config.json`, which on Windows is
`%APPDATA%\Claude\claude_desktop_config.json` (on macOS, `~/Library/Application Support/Claude/claude_desktop_config.json`).
Add the server under `mcpServers`, with your own repo path:

```json
{
  "mcpServers": {
    "personal-finance": {
      "command": "py",
      "args": ["-3.12", "-m", "uv", "run", "--directory", "C:\\dev\\UofT\\Projects\\personal-finance-mcp", "python", "-m", "app.server"]
    }
  }
}
```

`uv run --directory` changes into the repo first, so `.env` and `data/` are found wherever Claude starts the process.
Restart Claude Desktop; the tools appear under the tools menu in a new chat.

## Use it from Claude Code

```bash
claude mcp add personal-finance -- py -3.12 -m uv run --directory C:\dev\UofT\Projects\personal-finance-mcp python -m app.server
```

Add `-s user` before `personal-finance` to make it available in every project rather than just the current one. In
Git Bash, quote the path or use forward slashes. `claude mcp list` shows whether it connected.

## Security model

- **Read-only.** Plaid Link asks only for the `investments` and `transactions` products. No transfer, payment, auth or
  other money-movement endpoint is called or wrapped, and a test checks the product list and the client interface.
- **Secrets in the keychain.** The Plaid client_id, secrets and access tokens are stored only in the OS keychain via
  `keyring`. They are never written to files, logs, error messages or tool output. Plaid errors are reduced to the
  error code and display message. `.env` holds only the settings above.
- **No Wealthsimple credentials.** Linking happens in Plaid Link in your browser. The server only ever holds a
  revocable access token.
- **Localhost Link helper.** `link` binds `127.0.0.1` on an ephemeral port (or `--port`), checks the `Host` and
  `Origin` headers, embeds a one-time random state token that the exchange must echo, accepts one successful exchange
  and then exits, or exits after 10 minutes. The page has a CSP that only allows Plaid.
- **Local only.** The server speaks stdio to the Claude app on this machine. It opens no port.
- **Field minimisation.** Whatever a tool returns becomes model context, so tools return only what a question needs:
  accounts are referred to by an 8-character hash, never a Plaid id; masks are the last 4 characters; free text
  (account names, descriptions, institution names) has control characters stripped, long digit runs masked, anything
  that looks like a Plaid token or known id redacted, and is capped in length. Currency codes that are not three
  capital letters are replaced with `???`.
- **What Claude can see:** account names, types, last-4 masks, balances, holdings, investment transactions (date,
  sanitised description, amount, type, symbol), institution names and item health.
- **What Claude cannot see:** Plaid keys, access tokens, Plaid item or account ids, full account or routing numbers,
  your Wealthsimple login.
- **Exact money.** Amounts are `Decimal` and returned as strings. Transaction amounts use one sign convention:
  negative is cash out of the account, positive is cash in. Plaid reports investment transactions the other way round,
  so its sign is flipped to match the Wealthsimple exports.

Claude Desktop and Claude Code still send tool results to Anthropic as part of the conversation. Run it only if you
are comfortable with that for the fields above.

## Revoking access

1. List the linked items and remove one:

   ```bash
   py -3.12 -m uv run python -m app.cli unlink              # shows short id and institution
   py -3.12 -m uv run python -m app.cli unlink 1a2b3c4d     # asks you to type yes
   ```

   This calls Plaid `item_remove`, which invalidates the access token, then deletes the token from the keychain. If
   Plaid says the item no longer exists, the local copy is removed anyway. On any other error the token is kept so
   you can retry. In Production the Trial slot stays used.
2. Remove the connection on Plaid's side too: in the Plaid dashboard, and as the account owner at
   [my.plaid.com](https://my.plaid.com), where you can see and disconnect apps linked to your Wealthsimple login.
3. Delete `data/` to remove the local store, and remove the `personal-finance-mcp` entries from the Windows Credential
   Manager if you also want the Plaid keys gone.

## Limitations

- **No bank transactions.** Only investment transactions are fetched from Plaid. Chequing and card spending are not
  covered.
- **No currency conversion.** CAD and USD (and anything else) are always reported separately.
- **CSV balances are holdings market value** as of the latest snapshot date (`as_of`). Cash in those accounts is not
  included.
- **Merge rules.** Plaid wins when both sources cover an account. A CSV account merges into a Plaid account only when
  exactly one Plaid account has the same last 4 and a compatible type (or, failing that, the same name), and no other
  CSV account claims it. Holdings from the CSV are dropped for an account Plaid returns holdings for; CSV transactions
  are dropped for any account and date Plaid has transactions for.
- **Possible double count.** A CSV account with holdings or transactions that could not be matched to a Plaid account
  is still counted, with a "Possible double count" note, since it may be the same account under another name.
- **Plaid coverage.** See the Wealthsimple caveat above. Holdings and transactions from Plaid are fetched live on each
  call; nothing from Plaid is cached.

## Roadmap

- **Remote connector (next).** The same tools for Claude on the web, iPhone and iPad, served from my own VM over
  Tailscale Funnel with OAuth restricted to my GitHub account. Phase 1 is local stdio only.
- Savings rate and budgeting, once bank transactions are in.

## Tests

```bash
py -3.12 -m uv run pytest -q
```

No test uses the network, a real Plaid account or the real keychain: Plaid is faked and every test runs with an
in-memory keyring. `tests/test_e2e.py` starts `python -m app.server` as a subprocess and speaks MCP over stdio
(initialize, tools/list, tools/call) in a test-only mode. That mode is switched on by `PFMCP_FAKE_PLAID=1` and is
honoured only when `DATA_DIR` is inside pytest's temp directory, so it cannot turn on in a real setup.

## License

Copyright (c) 2026 Frederick Wang. All rights reserved. See [LICENSE](LICENSE).
