# Remote connector: claude.ai, iPhone and iPad

This runs the same five read-only tools on a small Linux VM so that Claude on the web, iOS and iPadOS can use them.
claude.ai calls custom connectors from Anthropic's cloud, so the server must be reachable over public HTTPS and
protected by OAuth.

- **Host:** an Oracle Cloud Always Free VM (Ubuntu 24.04 or Oracle Linux 9).
- **Public URL:** Tailscale Funnel, `https://<machine>.<tailnet>.ts.net`. No inbound port is opened for it.
- **Login:** your GitHub account, checked by numeric user id. Any other account gets 403 and nothing is issued.
- **Approval:** each client that Claude registers must be approved once on the server before it gets anything.
- **Cost:** $0.

Nothing here changes anything at Plaid or Wealthsimple. The server has no tool, route or endpoint that writes.

## How it fits together

```
claude.ai / iOS / iPadOS ──HTTPS──> Tailscale Funnel ──> 127.0.0.1:8765  python -m app.cli serve-http
                                                            ├─ /mcp            MCP Streamable HTTP, bearer token required
                                                            ├─ /.well-known/*  OAuth metadata (RFC 9728, RFC 8414)
                                                            ├─ /register       dynamic client registration (Claude callbacks only)
                                                            ├─ /authorize      -> GitHub login -> approval check -> consent page
                                                            └─ /token          PKCE S256, 1 h access tokens, rotating refresh tokens
```

Your tailnet is shared with another account, so tailnet membership is never treated as a credential. The service
listens on 127.0.0.1 only, and the only way in is the OAuth flow, which ends at your GitHub id and your approval.

Secrets on the server (the Plaid client id, secret and access tokens, the GitHub client secret and the token-signing
key) are systemd credentials. They are encrypted at rest with the host's credential key and decrypted by systemd only
for the service. They are never stored as plaintext files.

## 1. Oracle Cloud account

1. **Upgrade to Pay As You Go.** Console → **Billing & Cost Management** → **Upgrade and Manage Payment** →
   **Upgrade to Pay As You Go**. Always Free resources stay free. The upgrade stops Oracle from reclaiming an idle
   Always Free instance.
2. **Add a $1 budget alert.** **Billing & Cost Management** → **Budgets** → **Create Budget**:
   - Target: your root compartment.
   - Amount: 1 (USD).
   - Alert rule: actual spend, threshold 100 % of the budget, sent to your email.

   Add a second rule at forecast spend if you like. Any charge at all means something is not Always Free.

## 2. The VM

1. **Create the instance.** **Compute** → **Instances** → **Create instance**:
   - Image: **Canonical Ubuntu 24.04**, or Oracle Linux 9. You need systemd 250 or later, which both have.
   - Shape: `VM.Standard.A1.Flex` (Always Free eligible), 1 OCPU and 6 GB is plenty. `VM.Standard.E2.1.Micro` also
     works.
   - SSH keys: paste your **public** key. Do not let Oracle generate a password.
2. **Use SSH keys only.** The Ubuntu image already disables password login. Check, and enforce it:

   ```bash
   ssh ubuntu@<public-ip>            # opc@ on Oracle Linux
   sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin'   # expect "no" and "without-password"/"no"
   echo -e 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no' | \
     sudo tee /etc/ssh/sshd_config.d/90-keys-only.conf
   sudo systemctl reload ssh || sudo systemctl reload sshd
   ```

3. **Close every ingress port except SSH.** Open **Networking** → your VCN → **Security Lists** → default list. Delete
   every ingress rule except TCP 22. Better still, limit port 22 to your home IP. Funnel needs no inbound rule.
4. Install updates and enable automatic security updates:
   - Ubuntu: `sudo apt update && sudo apt full-upgrade -y && sudo apt install -y unattended-upgrades`
   - Oracle Linux: `sudo dnf upgrade -y && sudo dnf install -y dnf-automatic && sudo systemctl enable --now dnf-automatic.timer`

## 3. Tailscale and Funnel

1. Install Tailscale and join your tailnet:

   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up
   ```

   Do not enable Tailscale SSH (`--ssh`). Someone else's account shares this tailnet.
2. In the Tailscale admin console:
   - **DNS** → enable **MagicDNS** and **HTTPS Certificates**.
   - **Access controls** → allow Funnel for this machine (the `funnel` node attribute). The console offers to add it
     the first time you run `tailscale funnel`.

   While you are there, restrict tailnet access to this machine to your own user. It isn't needed for the connector,
   but it keeps the other account away from its SSH port.
3. Note the machine's name. `tailscale status --self` or the admin console shows `<machine>.<tailnet>.ts.net`. Your
   public URL is `https://<machine>.<tailnet>.ts.net`, and the **connector URL** is that plus `/mcp`.
4. Turn Funnel on. Its target is the local port the service will listen on (default 8765):

   ```bash
   sudo tailscale funnel --bg 8765
   tailscale funnel status          # https://<machine>.<tailnet>.ts.net (Funnel on) -> proxy http://127.0.0.1:8765
   ```

   `--bg` keeps it on across reboots. Funnel serves on port 443 (443, 8443 and 10000 are the only Funnel ports).
   Check the syntax for your version with `tailscale funnel --help`.

## 4. GitHub OAuth App

1. Open GitHub → **Settings** → **Developer settings** → **OAuth Apps** → **New OAuth App**, and fill in:

   | Field | Value |
   | - | - |
   | Application name | `personal-finance-mcp` |
   | Homepage URL | `https://<machine>.<tailnet>.ts.net` |
   | Authorization callback URL | `https://<machine>.<tailnet>.ts.net/oauth/github/callback` |
   | Enable Device Flow | off |

2. Copy the **Client ID**. It is not secret and goes in the env file in step 5.
3. **Generate a new client secret** and keep the page open for step 6. Do not paste it anywhere else.
4. Find your numeric user id. It is the id, not your login name:

   ```bash
   curl -s https://api.github.com/users/<your-login> | grep '"id"'
   ```

The server asks GitHub for no scopes, and it revokes the GitHub token straight after reading your id.

## 5. Install the code

The repository is not pushed anywhere, so copy a snapshot over SSH from the laptop (Git Bash, in the repo):

```bash
git archive --format=tar remote | ssh ubuntu@<public-ip> \
  "sudo mkdir -p /opt/personal-finance-mcp && sudo tar -x -C /opt/personal-finance-mcp"
ssh ubuntu@<public-ip>
sudo bash /opt/personal-finance-mcp/deploy/setup.sh
```

`setup.sh` does the following:
- Installs Python 3.12 and uv.
- Creates the unprivileged `pfmcp` user.
- Runs `uv sync --frozen --no-dev` from `uv.lock`.
- Installs the sandboxed unit `personal-finance-mcp.service` and the admin wrapper `/usr/local/bin/pfmcp`.
- Creates `/etc/personal-finance-mcp/env`.

It does not start anything.

Edit the settings:

```bash
sudo nano /etc/personal-finance-mcp/env
# PUBLIC_URL=https://<machine>.<tailnet>.ts.net   (no path, no trailing slash)
# GITHUB_CLIENT_ID=<from step 4>
# GITHUB_ALLOWED_USER_ID=<numeric id from step 4>
```

To update later, repeat the `git archive` line, re-run `setup.sh`, then `sudo systemctl restart personal-finance-mcp`.

## 6. Store the secrets

The service will not start until all five credentials exist.

**GitHub client secret and signing key** (on the VM):

```bash
cd /opt/personal-finance-mcp
sudo deploy/import-credential.sh github_client_secret            # paste; input is hidden
sudo deploy/import-credential.sh token_signing_key --generate    # 32 random bytes, never shown
```

**Plaid keys and the existing production access token: move them, do not relink.** Relinking would use another of
the 10 Production Trial slots. Instead, seal the keychain contents on the laptop to a one-time key made on the VM.
Only ciphertext ever leaves the laptop, so it does not matter where it is shown, piped or pasted. The cipher is
X25519 with HKDF-SHA256 and AES-256-GCM, from the `cryptography` package that is already locked.

1. On the VM, make the one-time key. Its private half is stored as an encrypted credential; only the public half is
   printed:

   ```bash
   sudo pfmcp bundle-key
   # Public key for export-bundle --to ...:
   # pfmcp-pub-1:3vQ...            <- copy this line
   ```

2. On the laptop, in the repo, with `PLAID_ENV=production` in `.env`, seal and send the bundle. `export-bundle`
   refuses to run without `--to`. Git Bash or PowerShell both work:

   ```bash
   py -3.12 -m uv run python -m app.cli status        # expect: plaid_env production, linked items: 1
   py -3.12 -m uv run python -m app.cli export-bundle --to pfmcp-pub-1:3vQ... | ssh ubuntu@<public-ip> "sudo pfmcp import-bundle"
   ```

   The pipe relies on the default `ubuntu` (or `opc`) user having passwordless sudo, as on Oracle's images. Without
   it, run `export-bundle --to ...` alone, copy the single `pfmcp-sealed-1:...` line it prints, then run
   `sudo pfmcp import-bundle` in an SSH session and paste the line. Both sides print the item's short id, so you can
   check they match.

3. Check on the VM:

   ```bash
   sudo pfmcp status                                   # plaid_env production, keys stored yes, linked items: 1
   sudo ls -l /etc/credstore.encrypted/personal-finance-mcp/   # five files, root-only, encrypted
   ```

`import-bundle` decrypts with the one-time key. It writes `plaid_client_id`, `plaid_secret_production` and
`plaid_items_production` with `systemd-creds encrypt`, then deletes the one-time key, so a stray copy of the
ciphertext is useless afterwards. If the key is lost or the import fails, run `bundle-key` again and re-export.

The laptop keeps its copy, so the local stdio server still works. Both copies are the same Plaid item, and
`unlink` on either machine revokes it for both.

**Linking on the server instead, only if there is no token to move.** This creates a new Item and uses a Trial slot.

```bash
ssh -L 8766:127.0.0.1:8766 ubuntu@<public-ip>
sudo pfmcp link --port 8766        # open the printed http://127.0.0.1:8766/... URL in the laptop's browser
sudo systemctl restart personal-finance-mcp   # the service reads credentials only when it starts
```

Restart the service after any change to the credentials: `import-bundle`, `link`, `unlink` or
`import-credential.sh`.

## 7. Start and check

```bash
sudo systemctl enable --now personal-finance-mcp
systemctl status personal-finance-mcp
journalctl -u personal-finance-mcp -n 50
curl -s https://<machine>.<tailnet>.ts.net/.well-known/oauth-protected-resource/mcp
# {"resource":"https://<machine>.<tailnet>.ts.net/mcp","authorization_servers":["https://<machine>.<tailnet>.ts.net"],...}
curl -si https://<machine>.<tailnet>.ts.net/mcp -X POST | head -5   # HTTP 401 with WWW-Authenticate: Bearer ... resource_metadata=...
```

If the service fails to start with a `MemoryDenyWriteExecute` or `SystemCallFilter` error in the journal, comment
out that one line in `/etc/systemd/system/personal-finance-mcp.service`, run `sudo systemctl daemon-reload`, and
restart. Keep the other sandbox lines.

**Check that real client addresses arrive.** Per-IP limits need the client's address, which Funnel should pass in
`X-Forwarded-For`. uvicorn trusts that header from 127.0.0.1 only. After the first requests from outside (the `curl`
lines above, run from the laptop), look for this warning:

```bash
journalctl -u personal-finance-mcp | grep "forwarded client address"
```

If the warning is there, Funnel did not send the address. Every request then shares one per-address bucket. That still
works for one owner: a stranger's sign-ins cannot push out yours, and `/mcp` calls are limited per OAuth client.

## 8. Add the connector in Claude, with the one-time approval

1. In claude.ai, open **Customize → Connectors** (in older layouts, **Settings → Connectors**) → **Add custom
   connector**.
   - Name: `Personal finance`.
   - URL: `https://<machine>.<tailnet>.ts.net/mcp`. It must match `PUBLIC_URL` + `/mcp` exactly.
   - Leave the OAuth client ID and secret empty. If asked how Claude identifies itself, choose **Register
     automatically** (Dynamic Client Registration).
2. Click **Connect**. Sign in to GitHub and authorize the OAuth App.
3. The first time, you land on **New connection needs approval** at `/oauth/pending`. It shows the time the client
   registered and an 8-character **fingerprint**. Nothing has been issued yet. Keep that browser tab open. On the VM:

   ```bash
   sudo pfmcp list-clients                 # the new client: status pending, registered just now
   sudo pfmcp approve-client <fingerprint>
   ```

   Only approve if you just clicked Connect in your own claude.ai. Someone else can register a client by adding your
   URL to their claude.ai account and sending you the sign-in link. The approval step stops their Claude from getting
   your data. Pending requests expire after 30 minutes.
4. **Reload the approval page** in the same browser. It now shows the consent page: the client's name, fingerprint
   and registration time, and a reminder to continue only if you just clicked Connect yourself. Click **Allow**, and
   the browser goes back to claude.ai with the connection made.

   This works whether or not Claude would reuse its registration. The waiting sign-in is tied to that browser by a
   cookie, so nobody else can complete it. If the tab was closed, click **Connect** in Claude again instead. If
   Claude registers a new client then, approve the new fingerprint too.
5. The connector appears in the Claude apps on iPhone and iPad signed in to the same account, with nothing to set up
   there. In a chat, turn it on from the **+** menu → **Connectors**. Under **Customize → Connectors** you can mark
   the tools **Always allow** or keep approving each call.

Claude registers a new client whenever the connector is added again. Approve each one the same way, and revoke old
ones with `sudo pfmcp revoke-client <fingerprint>`. Approved and revoked clients count toward a cap of 50
(`list-clients` shows how many are used), and only revoking makes room. Pending ones expire after 30 minutes, and
at most 20 wait at once, the oldest giving way.

## Operating it

- **Audit log:** `/var/lib/personal-finance-mcp/audit.log`, JSON lines. It records:
  - tool calls: tool name, time and OAuth client id only, never arguments or results;
  - OAuth events: registration, login allowed or denied (with the denied GitHub id), consent, token issue, refresh,
    and refresh-token reuse.
- **Tokens:**
  - Access tokens last 1 hour.
  - Refresh tokens rotate on every use and last 30 days, and you sign in again after 90 days at most.
  - Reusing an old refresh token, or two uses racing, revokes that whole login.
  - A code works once. Replaying it revokes the tokens it issued, and a wrong PKCE verifier destroys it.
  - Codes and tokens are stored only as HMAC digests keyed by the signing key.
- **Limits:**
  - Request bodies are capped at 64 KiB.
  - Rate limits come in two layers (over a limit gives 429). The model is in the `RateLimiter` docstring in
    `app/remote.py`.
    - **Layer 1, every request, before any database work:**
      - 600 requests per minute per exact address, plus a per-endpoint limit for that address: 10 registrations an
        hour, 30 sign-in requests a minute, 60 token requests a minute.
      - A flood backstop of 6000 a minute per network (/24 or /64). Neighbours on a shared network never share the
        per-address limits.
    - **Global:** 200 registrations a day in total, counted only after the address passed its own limit.
    - **Layer 2, only after authentication:**
      - 120 MCP requests a minute per OAuth client, and 60 a minute per address for MCP requests without a valid
        token.
      - 30 successful token grants a minute per client.

      A `client_id` that has not been authenticated never selects a bucket.
  - Sign-ins in progress are capped at 2 per client, 5 per address and 50 in total. A stranger's sign-ins never push
    out one for an approved client.
- **Errors:** clients see only a short error code, never a traceback. The access log is off because query strings
  carry OAuth state and GitHub codes.

## Revoke everything

Do as many of these as the situation needs. Each one alone cuts Claude off.

1. **Remove the connector:** claude.ai → **Customize → Connectors** → the connector → **Remove**.
2. **Revoke the OAuth clients and their tokens:** `sudo pfmcp revoke-client <fingerprint>` for one, or
   `sudo pfmcp revoke-client --all` for every client. To start from nothing, stop the service and delete
   `/var/lib/personal-finance-mcp/oauth.db`.
3. **Rotate the signing key.** This invalidates every token and every confidential client's secret at once:

   ```bash
   sudo /opt/personal-finance-mcp/deploy/import-credential.sh token_signing_key --generate
   sudo systemctl restart personal-finance-mcp
   ```

   It does **not** undo the approval of public clients, and Claude registers as a public client. An approved Claude
   client could sign in again, though only through your GitHub login. So pair the rotation with step 2.
4. **Rotate the GitHub secret:**
   1. On GitHub, open the OAuth App and click **Generate a new client secret**.
   2. Run `sudo /opt/personal-finance-mcp/deploy/import-credential.sh github_client_secret` and restart the service.
   3. Delete the old secret on GitHub.

   To shut the door completely, delete the OAuth App instead.
5. **Revoke the Plaid item.** `sudo pfmcp unlink` lists the items. `sudo pfmcp unlink <short-id>` calls Plaid
   `item_remove`, which kills the token on the laptop too, and deletes it from the credentials. Then restart the
   service and check the Plaid dashboard and [my.plaid.com](https://my.plaid.com). On the Trial plan the slot stays
   used.
6. **Stop public access:**

   ```bash
   sudo tailscale funnel --https=443 off     # or: sudo tailscale funnel reset
   sudo systemctl disable --now personal-finance-mcp
   ```

7. **Remove the data:**

   ```bash
   sudo rm -rf /etc/credstore.encrypted/personal-finance-mcp /var/lib/personal-finance-mcp
   ```

   Terminate the VM if you no longer need it.
