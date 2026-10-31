# personal-finance-mcp

A self-hosted, **read-only** MCP (Model Context Protocol) server that lets Claude analyze my own
Wealthsimple finances — holdings, allocation (TFSA / RRSP / FHSA / non-registered / Cash / Crypto),
transactions, savings rate and net worth — using live data, with no third-party aggregator holding my tokens.

## Security first (non-negotiable)

- **Read-only.** No money-movement products (no Auth-for-transfer, Transfer, or Payment Initiation). The server
  can read balances and positions; it can never move money.
- **Credentials and 2FA never touch this server.** Account linking goes through the data provider's own flow
  (e.g. Plaid Link); the server holds only a revocable, read-only access token — never the Wealthsimple password,
  and nothing that bypasses or weakens Wealthsimple's MFA.
- **Tokens encrypted at rest** (OS keychain via `keyring`), never committed. `.env` is gitignored; secrets are
  scanned pre-commit.
- **Local-only to start.** Phase 1 runs over stdio for Claude Desktop / Claude Code. No public endpoint without
  auth; any later remote access is over a private network (e.g. Tailscale), not the open internet.
- Tool outputs return only the fields a question needs (no full account numbers), because whatever a tool returns
  becomes model context.

## Status

Setup and research. The connection approach for Wealthsimple (Plaid vs. official export vs. alternatives), ranked
by security, is being finalized before any code lands. See the project's research notes.

## License

Copyright (c) 2026 Frederick Wang. All rights reserved. See [LICENSE](LICENSE).
