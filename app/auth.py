"""OAuth 2.1 authorization server for the remote connector, restricted to one GitHub account.

The MCP SDK supplies the HTTP endpoints (/authorize, /token, /register, metadata documents, PKCE S256 check, bearer
middleware); this module supplies the provider behind them plus two pages of its own:

  Claude -> /authorize -> GitHub login -> /oauth/github/callback (GitHub user id must equal the configured one,
  otherwise 403 and nothing is issued) -> consent page naming the client -> POST /oauth/consent -> code back to
  Claude's callback -> /token.

Rules enforced here:
- Dynamic client registration accepts only Claude's documented callback URLs as redirect URIs, and every new client
  starts `pending`: it gets no code until the owner approves it on the server (`python -m app.cli approve-client FP`).
  Otherwise anyone could add this URL in their own claude.ai account and send the owner the sign-in link; the owner
  would see "Allow Claude?" and the code would land in the attacker's Claude session. Pending clients expire after
  30 minutes and at most 20 may wait at once.
- The `resource` (RFC 8707) must be this server's MCP URL; tokens are bound to it and checked on every request.
- Access tokens live one hour. Refresh tokens rotate on every use; presenting a used one revokes its whole family.
- Codes and tokens are random strings stored only as HMAC-SHA256 digests keyed by the signing key; client secrets
  are derived from the signing key and never stored. Rotating the key therefore invalidates every token and client.
- Secret comparisons use hmac.compare_digest.
"""
import asyncio
import base64
import hashlib
import hmac
import html
import json
import secrets as pysecrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from app.audit import Audit
from app.redact import short_hash

CLAUDE_CALLBACKS = frozenset({"https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"})
SCOPE = "finance.read"
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
FAMILY_MAX_AGE = 90 * 86400  # after this the owner signs in again, however often Claude refreshed
CODE_TTL = 300
LOGIN_TTL = 600
CONSENT_TTL = 300
MAX_CLIENTS = 50
MAX_PENDING_CLIENTS = 20
PENDING_CLIENT_TTL = 1800
APPROVE_CMD = "python -m app.cli approve-client"
MAX_PENDING = 50
MAX_CLIENT_NAME = 80
GITHUB_CALLBACK_PATH = "/oauth/github/callback"
CONSENT_PATH = "/oauth/consent"
CONSENT_COOKIE = "__Host-pfm_consent"


def canonical(url: str | None) -> str:
    """Scheme and host lowercased, no trailing slash: the form resource URLs are compared in."""
    parts = urllib.parse.urlsplit(str(url or "").strip())
    return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), parts.query, ""))


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


@dataclass(frozen=True)
class AuthConfig:
    public_url: str  # https://vm.tailnet.ts.net
    allowed_user_id: int
    signing_key: bytes
    db_path: Path

    @property
    def resource(self) -> str:
        return self.public_url.rstrip("/") + "/mcp"


class GitHubError(Exception):
    """Login at GitHub failed; carries no response body."""


class GitHub:
    """GitHub OAuth App login, used only to learn the numeric id of the account that signed in."""

    AUTHORIZE = "https://github.com/login/oauth/authorize"
    TOKEN = "https://github.com/login/oauth/access_token"
    USER = "https://api.github.com/user"

    def __init__(self, client_id: str, client_secret: str, timeout: float = 10):
        self.client_id, self._secret, self.timeout = client_id, client_secret, timeout

    def authorize_url(self, redirect_uri: str, state: str, code_challenge: str) -> str:
        # no scope: reading the signed-in user's public id needs none. allow_signup=false hides account creation.
        query = {"client_id": self.client_id, "redirect_uri": redirect_uri, "state": state, "allow_signup": "false",
                 "code_challenge": code_challenge, "code_challenge_method": "S256"}
        return self.AUTHORIZE + "?" + urllib.parse.urlencode(query)

    def _call(self, req: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read(65536))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise GitHubError(type(exc).__name__) from None

    def _user_id(self, code: str, redirect_uri: str, code_verifier: str) -> int:
        body = urllib.parse.urlencode({"client_id": self.client_id, "client_secret": self._secret, "code": code,
                                       "redirect_uri": redirect_uri, "code_verifier": code_verifier}).encode()
        token = self._call(urllib.request.Request(self.TOKEN, data=body, headers={"Accept": "application/json"}))
        access = token.get("access_token")
        if not isinstance(access, str) or not access:
            raise GitHubError("no access token")
        try:
            user = self._call(urllib.request.Request(self.USER, headers={
                "Authorization": f"Bearer {access}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}))
        finally:
            self._revoke(access)
        uid = user.get("id")
        if not isinstance(uid, int):
            raise GitHubError("no user id")
        return uid

    def _revoke(self, access: str) -> None:
        # the GitHub token is only needed for the id lookup above, so it is revoked straight away (best effort)
        basic = base64.b64encode(f"{self.client_id}:{self._secret}".encode()).decode()
        req = urllib.request.Request(f"https://api.github.com/applications/{self.client_id}/token", method="DELETE",
                                     data=json.dumps({"access_token": access}).encode(),
                                     headers={"Authorization": f"Basic {basic}", "Accept": "application/vnd.github+json"})
        try:
            urllib.request.urlopen(req, timeout=self.timeout).close()
        except (urllib.error.URLError, OSError):
            pass

    async def user_id(self, code: str, redirect_uri: str, code_verifier: str) -> int:
        return await asyncio.to_thread(self._user_id, code, redirect_uri, code_verifier)


SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY, metadata TEXT NOT NULL, created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', last_used REAL
);
CREATE TABLE IF NOT EXISTS tokens (
    hash TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL, scopes TEXT NOT NULL, resource TEXT NOT NULL,
    subject TEXT, family TEXT NOT NULL, family_created REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL
);
CREATE INDEX IF NOT EXISTS tokens_family ON tokens(family);
"""


def fingerprint(client_id: str) -> str:
    """8-character id the owner types to approve or revoke a client."""
    return short_hash(client_id)


def _when(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "never"


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=5)
    db.executescript(SCHEMA)
    return db


def purge_clients(db: sqlite3.Connection, now: float) -> None:
    """Drop expired pending clients and long-revoked ones; neither holds tokens."""
    db.execute("DELETE FROM clients WHERE status = 'pending' AND created_at < ?", (now - PENDING_CLIENT_TTL,))
    db.execute("DELETE FROM clients WHERE status = 'revoked' AND created_at < ? AND client_id NOT IN "
               "(SELECT client_id FROM tokens)", (now - 30 * 86400,))


class ClientAdmin:
    """Owner commands on the server (list-clients, approve-client, revoke-client); they need no secrets."""

    def __init__(self, db_path: Path, clock: Callable[[], float] = time.time):
        self.db, self.clock = open_db(db_path), clock

    def rows(self) -> list[dict]:
        purge_clients(self.db, self.clock())
        rows = self.db.execute("SELECT client_id, metadata, created_at, status, last_used FROM clients "
                               "ORDER BY created_at").fetchall()
        return [{"fingerprint": fingerprint(cid), "name": (json.loads(meta).get("client_name") or "")[:MAX_CLIENT_NAME],
                 "registered": _when(created), "status": status, "last_used": _when(used)}
                for cid, meta, created, status, used in rows]

    def _match(self, fp: str, statuses: tuple[str, ...]) -> list[str]:
        purge_clients(self.db, self.clock())
        marks = ",".join("?" * len(statuses))
        ids = [r[0] for r in self.db.execute(f"SELECT client_id FROM clients WHERE status IN ({marks})", statuses)]
        wanted = fp.strip().lower()
        return [cid for cid in ids if hmac.compare_digest(fingerprint(cid), wanted)]

    def approve(self, fp: str) -> str | None:
        """Approve exactly one pending client; its fingerprint, or None when none or several match."""
        matches = self._match(fp, ("pending",))
        if len(matches) != 1:
            return None
        self.db.execute("UPDATE clients SET status = 'approved' WHERE client_id = ? AND status = 'pending'",
                        (matches[0],))
        return fingerprint(matches[0])

    def revoke(self, fp: str) -> str | None:
        """Revoke one client and delete every token it holds."""
        matches = self._match(fp, ("pending", "approved"))
        if len(matches) != 1:
            return None
        self.db.execute("DELETE FROM tokens WHERE client_id = ?", (matches[0],))
        self.db.execute("UPDATE clients SET status = 'revoked' WHERE client_id = ?", (matches[0],))
        return fingerprint(matches[0])

    def close(self) -> None:
        self.db.close()


def _page(title: str, body: str, status: int = 200, headers: dict | None = None) -> HTMLResponse:
    doc = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>body{{font-family:system-ui,sans-serif;max-width:32rem;"
        "margin:3rem auto;padding:0 1rem;line-height:1.5}button{font-size:1rem;padding:.6rem 1.2rem;margin:.3rem}"
        f"code{{background:#eee;padding:0 .2rem}}</style></head><body>{body}</body></html>"
    )
    base = {
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; "
                                   "form-action 'self' https://claude.ai https://claude.com",
        "X-Frame-Options": "DENY",
    }
    return HTMLResponse(doc, status_code=status, headers={**base, **(headers or {})})


class OwnerOAuthProvider:
    """OAuthAuthorizationServerProvider for the MCP SDK, plus the GitHub callback and consent handlers."""

    def __init__(self, cfg: AuthConfig, github, audit: Audit, clock: Callable[[], float] = time.time):
        self.cfg, self.github, self.audit, self.clock = cfg, github, audit, clock
        self._lock = threading.Lock()
        self.db = open_db(cfg.db_path)
        self._pending: dict[str, dict] = {}   # GitHub state -> authorization request waiting for login
        self._consents: dict[str, dict] = {}  # consent id -> approved login waiting for the owner's click
        self._codes: dict[str, dict] = {}     # code digest -> authorization code

    # --- helpers ------------------------------------------------------------------------------------------------

    def _digest(self, purpose: str, value: str) -> str:
        return hmac.new(self.cfg.signing_key, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()

    def client_secret_for(self, client_id: str) -> str:
        return self._digest("client", client_id)

    def _expire(self, table: dict, now: float) -> None:
        for key in [k for k, v in table.items() if v["expires_at"] < now]:
            del table[key]

    def _redirect_error(self, pending: dict, error: str) -> RedirectResponse:
        url = construct_redirect_uri(pending["redirect_uri"], error=error, state=pending["state"])
        return RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})

    # --- clients (dynamic registration) -------------------------------------------------------------------------

    def _client_row(self, client_id: str):
        """(status, created_at) of a client, or None. Expired pending clients are purged first."""
        with self._lock:
            purge_clients(self.db, self.clock())
            return self.db.execute("SELECT status, created_at FROM clients WHERE client_id = ?",
                                   (client_id,)).fetchone()

    def _approved(self, client_id: str) -> bool:
        row = self._client_row(client_id)
        return row is not None and row[0] == "approved"

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._lock:
            purge_clients(self.db, self.clock())
            row = self.db.execute("SELECT metadata FROM clients WHERE client_id = ? AND status != 'revoked'",
                                  (client_id,)).fetchone()
        if row is None:  # unknown or revoked: the token endpoint answers invalid_client, so Claude re-registers
            return None
        info = OAuthClientInformationFull.model_validate_json(row[0])
        if info.token_endpoint_auth_method != "none":
            info.client_secret = self.client_secret_for(client_id)
        return info

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in client_info.redirect_uris or []]
        if not uris or any(u not in CLAUDE_CALLBACKS for u in uris):
            raise RegistrationError("invalid_redirect_uri", "Only Claude's callback URLs can be registered.")
        if set(client_info.grant_types) - {"authorization_code", "refresh_token"}:
            raise RegistrationError("invalid_client_metadata", "Unsupported grant type.")
        if client_info.client_name:
            client_info.client_name = client_info.client_name[:MAX_CLIENT_NAME]
        now = self.clock()
        with self._lock:
            purge_clients(self.db, now)
            pending = self.db.execute("SELECT COUNT(*) FROM clients WHERE status = 'pending'").fetchone()[0]
            count = self.db.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
            if pending >= MAX_PENDING_CLIENTS or count >= MAX_CLIENTS:
                raise RegistrationError("invalid_client_metadata", "Too many registered clients; try again later.")
            if client_info.token_endpoint_auth_method != "none":
                # the SDK minted a random secret; replace it with one derived from the signing key so none is stored
                client_info.client_secret = self.client_secret_for(client_info.client_id)
            stored = client_info.model_copy(update={"client_secret": None})
            self.db.execute("INSERT INTO clients (client_id, metadata, created_at, status) VALUES (?, ?, ?, 'pending')",
                            (client_info.client_id, stored.model_dump_json(), now))
        self.audit.event("client_registered", client=client_info.client_id, client_name=client_info.client_name)

    # --- authorization ------------------------------------------------------------------------------------------

    def check_resource(self, resource: str | None) -> bool:
        return resource is None or hmac.compare_digest(canonical(resource), canonical(self.cfg.resource))

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not self.check_resource(params.resource):
            raise AuthorizeError("invalid_target", "Unknown resource.")
        now = self.clock()
        state, verifier = pysecrets.token_urlsafe(32), pysecrets.token_urlsafe(48)
        with self._lock:
            self._expire(self._pending, now)
            if len(self._pending) >= MAX_PENDING:
                raise AuthorizeError("temporarily_unavailable", "Too many sign-ins in progress.")
            self._pending[state] = {
                "client_id": client.client_id, "client_name": client.client_name or "",
                "redirect_uri": str(params.redirect_uri), "explicit": params.redirect_uri_provided_explicitly,
                "state": params.state, "code_challenge": params.code_challenge,
                "scopes": params.scopes or [SCOPE], "resource": self.cfg.resource,
                "verifier": verifier, "expires_at": now + LOGIN_TTL,
            }
        return self.github.authorize_url(self.cfg.public_url.rstrip("/") + GITHUB_CALLBACK_PATH, state, s256(verifier))

    async def github_callback(self, request: Request) -> Response:
        state = request.query_params.get("state", "")
        with self._lock:
            self._expire(self._pending, self.clock())
            pending = self._pending.pop(state, None)  # one use only
        if pending is None:
            return _page("Sign-in expired", "<h1>Sign-in expired</h1><p>Start again from Claude.</p>", 400)
        code = request.query_params.get("code")
        if not code:  # cancelled at GitHub
            return self._redirect_error(pending, "access_denied")
        try:
            uid = await self.github.user_id(code, self.cfg.public_url.rstrip("/") + GITHUB_CALLBACK_PATH,
                                            pending["verifier"])
        except GitHubError:
            self.audit.event("login_failed", client=pending["client_id"], reason="github")
            return _page("Sign-in failed", "<h1>Sign-in failed</h1><p>GitHub could not confirm the account.</p>", 502)
        if not hmac.compare_digest(str(uid), str(self.cfg.allowed_user_id)):
            self.audit.event("login_denied", client=pending["client_id"], github_user_id=uid)
            return _page("Not allowed", "<h1>Not allowed</h1><p>This GitHub account cannot use this server.</p>", 403)
        client_row = self._client_row(pending["client_id"])
        if client_row is None or client_row[0] == "revoked":
            return _page("Connection removed", "<h1>This connection was removed or expired</h1>"
                         "<p>Remove the connector in Claude and add it again.</p>", 403)
        fp = fingerprint(pending["client_id"])
        name = html.escape(pending["client_name"] or "An unnamed client")
        registered = html.escape(_when(client_row[1]))
        if client_row[0] == "pending":
            # nothing is issued: the owner must confirm on the server that this registration is their own
            self.audit.event("login_pending_client", client=pending["client_id"])
            body = (
                "<h1>New connection needs approval</h1>"
                f"<p><b>{name}</b> registered at {registered}, fingerprint <code>{fp}</code>.</p>"
                f"<p>To allow this connection, run on the server: <code>{APPROVE_CMD} {fp}</code>. "
                "Only do this if you just clicked Connect in your own claude.ai.</p>"
                f"<p>On the VM that is <code>sudo pfmcp approve-client {fp}</code>. Then click Connect in Claude "
                "again. The request expires 30 minutes after it was registered.</p>"
                "<p>If you did not just click Connect yourself, do nothing: someone may be trying to get you to "
                "give their Claude account access to your data.</p>"
            )
            return _page("Approval needed", body, 403)
        consent_id, csrf = pysecrets.token_urlsafe(32), pysecrets.token_urlsafe(32)
        with self._lock:
            self._expire(self._consents, self.clock())
            self._consents[consent_id] = {**pending, "csrf": csrf, "subject": str(uid),
                                          "expires_at": self.clock() + CONSENT_TTL}
        self.audit.event("login_allowed", client=pending["client_id"])
        host = html.escape(urllib.parse.urlsplit(pending["redirect_uri"]).hostname or "")
        body = (
            f"<h1>Allow {name}?</h1>"
            f"<p><b>{name}</b> (fingerprint <code>{fp}</code>, registered {registered}, approved on the server) "
            "is asking for read-only "
            "access to your personal finance data: accounts, balances, holdings and transactions. "
            "It cannot move money or change anything.</p>"
            f"<p>After you choose, you will be sent back to <b>{host}</b>.</p>"
            f"<form method=post action='{CONSENT_PATH}'>"
            f"<input type=hidden name=consent_id value='{consent_id}'><input type=hidden name=csrf value='{csrf}'>"
            "<button name=action value=approve>Allow</button><button name=action value=deny>Deny</button></form>"
        )
        cookie = f"{CONSENT_COOKIE}={csrf}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={CONSENT_TTL}"
        return _page(f"Allow {pending['client_name'] or 'client'}?", body, headers={"Set-Cookie": cookie})

    async def consent(self, request: Request) -> Response:
        form = await request.form()
        consent_id, csrf = str(form.get("consent_id", "")), str(form.get("csrf", ""))
        cookie = request.cookies.get(CONSENT_COOKIE, "")
        with self._lock:
            self._expire(self._consents, self.clock())
            entry = self._consents.pop(consent_id, None)
        if (entry is None or not csrf or not hmac.compare_digest(csrf, entry["csrf"])
                or not hmac.compare_digest(cookie, entry["csrf"])):
            return _page("Request expired", "<h1>Request expired</h1><p>Start again from Claude.</p>", 400)
        if form.get("action") != "approve" or not self._approved(entry["client_id"]):
            self.audit.event("consent_denied", client=entry["client_id"])
            return self._redirect_error(entry, "access_denied")
        code = pysecrets.token_urlsafe(32)
        with self._lock:
            self._expire(self._codes, self.clock())
            self._codes[self._digest("code", code)] = {**entry, "expires_at": self.clock() + CODE_TTL}
        self.audit.event("consent_approved", client=entry["client_id"])
        url = construct_redirect_uri(entry["redirect_uri"], code=code, state=entry["state"])
        clear = f"{CONSENT_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
        return RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store", "Set-Cookie": clear})

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        with self._lock:
            entry = self._codes.get(self._digest("code", authorization_code))
        if entry is None or entry["client_id"] != client.client_id or entry["expires_at"] < self.clock():
            return None
        return AuthorizationCode(
            code=authorization_code, scopes=entry["scopes"], expires_at=entry["expires_at"],
            client_id=entry["client_id"], code_challenge=entry["code_challenge"], redirect_uri=entry["redirect_uri"],
            redirect_uri_provided_explicitly=entry["explicit"], resource=entry["resource"], subject=entry["subject"],
        )

    # --- tokens -------------------------------------------------------------------------------------------------

    def _issue(self, client_id: str, scopes: list[str], subject: str | None, family: str, family_created: float):
        now = self.clock()
        access, refresh = "pfm_at_" + pysecrets.token_urlsafe(32), "pfm_rt_" + pysecrets.token_urlsafe(32)
        refresh_expiry = min(now + REFRESH_TTL, family_created + FAMILY_MAX_AGE)
        rows = [(self._digest("token", access), "access", now + ACCESS_TTL),
                (self._digest("token", refresh), "refresh", refresh_expiry)]
        with self._lock:
            self.db.execute("DELETE FROM tokens WHERE expires_at < ?", (now,))
            self.db.execute("UPDATE clients SET last_used = ? WHERE client_id = ?", (now, client_id))
            for digest, kind, expires in rows:
                self.db.execute("INSERT INTO tokens VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                                (digest, kind, client_id, " ".join(scopes), self.cfg.resource, subject, family,
                                 family_created, expires))
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL, refresh_token=refresh,
                          scope=" ".join(scopes))

    def _row(self, token: str, kind: str):
        digest = self._digest("token", token)
        with self._lock:
            row = self.db.execute(
                "SELECT hash, client_id, scopes, resource, subject, family, family_created, expires_at, used_at "
                "FROM tokens WHERE hash = ? AND kind = ?", (digest, kind)).fetchone()
        if row is None or not hmac.compare_digest(row[0], digest):
            return None
        keys = ("hash", "client_id", "scopes", "resource", "subject", "family", "family_created", "expires_at",
                "used_at")
        return dict(zip(keys, row))

    def _revoke_family(self, family: str) -> None:
        with self._lock:
            self.db.execute("DELETE FROM tokens WHERE family = ?", (family,))

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code) -> OAuthToken:
        with self._lock:  # pop first, so a code can be redeemed once even under concurrent requests
            entry = self._codes.pop(self._digest("code", authorization_code.code), None)
        if entry is None or not self._approved(client.client_id):
            raise TokenError("invalid_grant", "authorization code does not exist")
        tokens = self._issue(client.client_id, entry["scopes"], entry["subject"], pysecrets.token_urlsafe(16),
                             self.clock())
        self.audit.event("token_issued", client=client.client_id)
        return tokens

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        row = self._row(refresh_token, "refresh")
        if row is None or row["client_id"] != client.client_id:
            return None
        if row["used_at"] is not None:
            # a rotated-out refresh token came back: it may have been stolen, so end the whole session
            self._revoke_family(row["family"])
            self.audit.event("refresh_reuse_revoked", client=client.client_id)
            return None
        if (row["expires_at"] < self.clock() or not self.check_resource(row["resource"])
                or not self._approved(row["client_id"])):
            return None
        return RefreshToken(token=refresh_token, client_id=row["client_id"], scopes=row["scopes"].split(),
                            expires_at=int(row["expires_at"]), resource=row["resource"], subject=row["subject"])

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token, scopes) -> OAuthToken:
        row = self._row(refresh_token.token, "refresh")
        if row is None:
            raise TokenError("invalid_grant", "refresh token does not exist")
        with self._lock:
            used = self.db.execute("UPDATE tokens SET used_at = ? WHERE hash = ? AND used_at IS NULL",
                                   (self.clock(), row["hash"])).rowcount
        if used != 1:
            raise TokenError("invalid_grant", "refresh token already used")
        self.audit.event("token_refreshed", client=client.client_id)
        return self._issue(client.client_id, scopes, row["subject"], row["family"], row["family_created"])

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = self._row(token, "access")
        if (row is None or row["expires_at"] < self.clock() or not self.check_resource(row["resource"])
                or not self._approved(row["client_id"])):
            return None
        return AccessToken(token=token, client_id=row["client_id"], scopes=row["scopes"].split(),
                           expires_at=int(row["expires_at"]), resource=row["resource"], subject=row["subject"])

    async def revoke_token(self, token) -> None:
        for kind in ("access", "refresh"):
            row = self._row(token.token, kind)
            if row is not None:
                self._revoke_family(row["family"])

    def close(self) -> None:
        self.db.close()
