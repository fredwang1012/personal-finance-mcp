"""Remote connector over HTTP: OAuth end to end with a fake GitHub, bearer checks, metadata, limits, audit, read-only.

Everything runs in process through Starlette's TestClient: no network, no real GitHub, Plaid or keychain.
"""
import json
import re
import secrets as pysecrets
import urllib.parse
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app import secrets, server
from app.auth import CLAUDE_CALLBACKS, CONSENT_COOKIE, GITHUB_CALLBACK_PATH, ClientAdmin, fingerprint, s256
from app.config import ROOT, settings
from app.remote import Guard, Limits, RateLimiter, RemoteConfig, build_app
from tests.test_tools import FORBIDDEN, ITEM_OK, TOKEN_OK, FakePlaid, HostilePlaid

PUBLIC = "https://vm.example-tailnet.ts.net"
RESOURCE = PUBLIC + "/mcp"
CB = "https://claude.ai/api/mcp/auth_callback"
OWNER, STRANGER = 4242, 9999
KEY = b"k" * 64
TOOLS = {"list_accounts", "get_balances", "get_holdings", "get_transactions", "get_investment_transactions",
         "net_worth", "allocation", "item_health"}
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}


class FakeGitHub:
    """Stands in for GitHub: checks the PKCE pair the server used with it, then reports a fixed user id."""

    def __init__(self, uid: int):
        self.uid, self.challenges = uid, {}

    def authorize_url(self, redirect_uri, state, code_challenge):
        assert redirect_uri == PUBLIC + GITHUB_CALLBACK_PATH
        self.challenges[state] = code_challenge
        return "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode({"state": state})

    async def user_id(self, code, redirect_uri, code_verifier):
        assert s256(code_verifier) in self.challenges.values()
        return self.uid


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


class RecordingPlaid(FakePlaid):
    calls: list[str] = []

    def __getattribute__(self, name):
        if not name.startswith("_") and name not in ("tx_count", "calls"):
            RecordingPlaid.calls.append(name)
        return super().__getattribute__(name)


@pytest.fixture
def plaid(monkeypatch, tmp_path):
    """Keys and one item in the in-memory keyring, a recording fake Plaid, a temp data dir."""
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    secrets.set_plaid_keys(settings.plaid_env, "cid", "sec")
    secrets.set_access_token(settings.plaid_env, ITEM_OK, TOKEN_OK)
    RecordingPlaid.calls = []
    monkeypatch.setattr(server, "plaid_factory", lambda s: RecordingPlaid())


def make(tmp_path, uid=OWNER, limits=Limits(), public=PUBLIC, clock=None):
    clock = clock or Clock()
    cfg = RemoteConfig(public, 8765, OWNER, KEY, tmp_path / "remote")
    app, provider = build_app(cfg, FakeGitHub(uid), limits=limits, clock=clock, limiter=RateLimiter())
    provider.approval_refresh = 0  # see CLI approvals at once instead of within a second
    return app, provider, clock


@pytest.fixture
def remote(tmp_path, plaid):
    app, provider, clock = make(tmp_path)
    with TestClient(app, base_url=PUBLIC) as client:
        yield client, provider, clock
    provider.close()


def approve(provider, client_id: str) -> None:
    admin = ClientAdmin(provider.cfg.db_path, provider.clock)
    try:
        assert admin.approve(fingerprint(client_id)) == fingerprint(client_id)
    finally:
        admin.close()


def register(client, provider=None, **extra) -> dict:
    """Register like Claude does; with `provider`, also approve the client as the owner would on the server."""
    body = {"client_name": "Claude", "redirect_uris": [CB], "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none", **extra}
    r = client.post("/register", json=body)
    assert r.status_code == 201, r.text
    if provider is not None:
        approve(provider, r.json()["client_id"])
    return r.json()


def start_login(client, client_id, verifier, resource=RESOURCE):
    params = {"client_id": client_id, "response_type": "code", "redirect_uri": CB, "code_challenge": s256(verifier),
              "code_challenge_method": "S256", "state": "claude-state"}
    if resource is not None:
        params["resource"] = resource
    return client.get("/authorize", params=params, follow_redirects=False)


def query(url: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}


def login_code(client, client_id, verifier) -> str:
    r = start_login(client, client_id, verifier)
    assert r.status_code == 302 and r.headers["location"].startswith("https://github.com/")
    page = client.get(GITHUB_CALLBACK_PATH, params={"code": "gh-code", "state": query(r.headers["location"])["state"]})
    assert page.status_code == 200 and "Allow Claude?" in page.text
    consent_id = re.search(r"name=consent_id value='([^']+)'", page.text).group(1)
    csrf = re.search(r"name=csrf value='([^']+)'", page.text).group(1)
    r = client.post("/oauth/consent", data={"consent_id": consent_id, "csrf": csrf, "action": "approve"},
                    follow_redirects=False)
    assert r.status_code == 302
    back = query(r.headers["location"])
    assert r.headers["location"].startswith(CB + "?") and back["state"] == "claude-state"
    return back["code"]


def exchange(client, client_id, code, verifier, resource=RESOURCE, **extra):
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": CB, "client_id": client_id,
            "code_verifier": verifier, **extra}
    if resource is not None:
        data["resource"] = resource
    return client.post("/token", data=data)


def full_login(client, provider) -> tuple[str, dict]:
    client_id = register(client, provider)["client_id"]
    verifier = pysecrets.token_urlsafe(48)
    r = exchange(client, client_id, login_code(client, client_id, verifier), verifier)
    assert r.status_code == 200, r.text
    return client_id, r.json()


def rpc(client, token, method, params=None, rid=1):
    headers = {**MCP_HEADERS, **({"Authorization": f"Bearer {token}"} if token else {})}
    return client.post("/mcp", json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                       headers=headers)


def tool_payload(response) -> dict:
    result = response.json()["result"]
    assert not result.get("isError")
    payload = result.get("structuredContent") or json.loads(result["content"][0]["text"])
    return payload.get("result", payload)


# --- OAuth flow ---------------------------------------------------------------------------------------------------

def test_owner_login_end_to_end(remote):
    client, provider, _ = remote
    client_id, tokens = full_login(client, provider)
    assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 3600 and tokens["scope"] == "finance.read"
    assert tokens["refresh_token"]
    r = rpc(client, tokens["access_token"], "tools/call", {"name": "list_accounts", "arguments": {}})
    assert r.status_code == 200
    assert tool_payload(r)["accounts"][0]["name"] == "TFSA"
    # stored only as digests: no raw token, code or client secret in the database file
    dump = "\n".join(provider.db.iterdump())
    assert tokens["access_token"] not in dump and tokens["refresh_token"] not in dump


def test_other_github_account_gets_403_and_nothing(remote, tmp_path):
    client, provider, clock = remote
    app, other, _ = make(tmp_path / "x", uid=STRANGER)
    with TestClient(app, base_url=PUBLIC) as c:
        client_id = register(c, other)["client_id"]
        r = start_login(c, client_id, "v" * 50)
        page = c.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": query(r.headers["location"])["state"]})
        assert page.status_code == 403 and "Not allowed" in page.text
        assert "consent_id" not in page.text and CONSENT_COOKIE not in page.headers.get("set-cookie", "")
        assert other._consents == {} and other._codes == {}
        assert other.db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0
        audit = (tmp_path / "x" / "remote" / "audit.log").read_text()
        assert '"login_denied"' in audit and str(STRANGER) in audit
    other.close()


def test_pkce_mismatch_fails(remote):
    client, provider, _ = remote
    client_id = register(client, provider)["client_id"]
    verifier = pysecrets.token_urlsafe(48)
    code = login_code(client, client_id, verifier)
    r = exchange(client, client_id, code, pysecrets.token_urlsafe(48))
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_code_is_single_use(remote):
    client, provider, _ = remote
    client_id = register(client, provider)["client_id"]
    verifier = pysecrets.token_urlsafe(48)
    code = login_code(client, client_id, verifier)
    assert exchange(client, client_id, code, verifier).status_code == 200
    assert exchange(client, client_id, code, verifier).json()["error"] == "invalid_grant"


def test_wrong_resource_rejected_at_authorize_and_token(remote):
    client, provider, _ = remote
    client_id = register(client, provider)["client_id"]
    r = start_login(client, client_id, "v" * 50, resource="https://evil.example/mcp")
    assert r.status_code == 302 and query(r.headers["location"])["error"] == "invalid_target"
    assert r.headers["location"].startswith(CB)
    verifier = pysecrets.token_urlsafe(48)
    code = login_code(client, client_id, verifier)
    r = exchange(client, client_id, code, verifier, resource="https://vm.example-tailnet.ts.net/other")
    assert r.status_code == 400 and r.json()["error"] == "invalid_target"


def test_token_for_another_audience_is_rejected(tmp_path, plaid):
    # same database and key, but the server now answers for a different public URL: old tokens must not work
    app, provider, _ = make(tmp_path)
    with TestClient(app, base_url=PUBLIC) as c:
        _, tokens = full_login(c, provider)
    provider.close()
    other_url = "https://other.example-tailnet.ts.net"
    app, provider, _ = make(tmp_path, public=other_url)
    with TestClient(app, base_url=other_url) as c:
        assert rpc(c, tokens["access_token"], "tools/list").status_code == 401
        r = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                   "client_id": "x"})
        assert r.status_code in (400, 401)
    provider.close()


def test_expired_access_token_rejected(remote):
    client, provider, clock = remote
    _, tokens = full_login(client, provider)
    assert rpc(client, tokens["access_token"], "tools/list").status_code == 200
    clock.now += 3601
    r = rpc(client, tokens["access_token"], "tools/list")
    assert r.status_code == 401 and "invalid_token" in r.headers["www-authenticate"]


def test_refresh_rotates_and_reuse_revokes_the_family(remote):
    client, provider, _ = remote
    client_id, first = full_login(client, provider)
    refresh = lambda token: client.post("/token", data={"grant_type": "refresh_token", "refresh_token": token,
                                                         "client_id": client_id, "resource": RESOURCE})
    r = refresh(first["refresh_token"])
    assert r.status_code == 200
    second = r.json()
    assert second["refresh_token"] != first["refresh_token"] and second["access_token"] != first["access_token"]
    assert rpc(client, second["access_token"], "tools/list").status_code == 200
    # the used refresh token comes back: rejected, and everything issued from that login is revoked
    r = refresh(first["refresh_token"])
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    assert refresh(second["refresh_token"]).json()["error"] == "invalid_grant"
    assert rpc(client, second["access_token"], "tools/list").status_code == 401


def test_confidential_client_secret_is_derived_and_checked(remote):
    client, provider, _ = remote
    info = register(client, provider, token_endpoint_auth_method="client_secret_post")
    assert info["client_secret"] == provider.client_secret_for(info["client_id"])
    assert info["client_secret"] not in "\n".join(provider.db.iterdump())
    verifier = pysecrets.token_urlsafe(48)
    code = login_code(client, info["client_id"], verifier)
    assert exchange(client, info["client_id"], code, verifier, client_secret="wrong").status_code == 401
    assert exchange(client, info["client_id"], code, verifier, client_secret=info["client_secret"]).status_code == 200


def test_registration_only_accepts_claude_callbacks(remote):
    client, provider, _ = remote
    for uris in (["https://evil.example/cb"], [CB, "https://evil.example/cb"], ["http://localhost:3000/callback"]):
        r = client.post("/register", json={"redirect_uris": uris, "token_endpoint_auth_method": "none"})
        assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri"
    assert CLAUDE_CALLBACKS == {"https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"}
    assert register(client, provider, redirect_uris=sorted(CLAUDE_CALLBACKS))["client_id"]


def test_consent_needs_matching_cookie_and_csrf(remote):
    client, provider, _ = remote
    client_id = register(client, provider)["client_id"]
    r = start_login(client, client_id, "v" * 50)
    page = client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": query(r.headers["location"])["state"]})
    consent_id = re.search(r"name=consent_id value='([^']+)'", page.text).group(1)
    csrf = re.search(r"name=csrf value='([^']+)'", page.text).group(1)
    client.cookies.clear()
    r = client.post("/oauth/consent", data={"consent_id": consent_id, "csrf": csrf, "action": "approve"},
                    follow_redirects=False)
    assert r.status_code == 400
    # and the consent cannot be replayed after the failed attempt
    client.cookies.set(CONSENT_COOKIE, csrf)
    r = client.post("/oauth/consent", data={"consent_id": consent_id, "csrf": csrf, "action": "approve"},
                    follow_redirects=False)
    assert r.status_code == 400


def test_consent_page_names_client_escaped_and_deny_returns_access_denied(remote):
    client, provider, _ = remote
    client_id = register(client, provider, client_name="<script>x</script>")["client_id"]
    r = start_login(client, client_id, "v" * 50)
    page = client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": query(r.headers["location"])["state"]})
    assert "&lt;script&gt;x&lt;/script&gt;" in page.text and "<script>x" not in page.text
    assert "claude.ai" in page.text and "frame-ancestors 'none'" in page.headers["content-security-policy"]
    consent_id = re.search(r"name=consent_id value='([^']+)'", page.text).group(1)
    csrf = re.search(r"name=csrf value='([^']+)'", page.text).group(1)
    r = client.post("/oauth/consent", data={"consent_id": consent_id, "csrf": csrf, "action": "deny"},
                    follow_redirects=False)
    assert query(r.headers["location"]) == {"error": "access_denied", "state": "claude-state"}


def test_github_state_is_single_use(remote):
    client, provider, _ = remote
    client_id = register(client, provider)["client_id"]
    state = query(start_login(client, client_id, "v" * 50).headers["location"])["state"]
    assert client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": state}).status_code == 200
    assert client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": state}).status_code == 400


# --- resource server ----------------------------------------------------------------------------------------------

def test_unauthenticated_mcp_gets_401_with_resource_metadata(remote):
    client, provider, _ = remote
    for token in (None, "pfm_at_not-a-real-token"):
        r = rpc(client, token, "tools/list")
        assert r.status_code == 401
        header = r.headers["www-authenticate"]
        assert header.startswith("Bearer ")
        assert f'resource_metadata="{PUBLIC}/.well-known/oauth-protected-resource/mcp"' in header
        assert 'scope="finance.read"' in header
    for method in ("GET", "DELETE"):
        assert client.request(method, "/mcp", headers=MCP_HEADERS).status_code == 401


def test_metadata_documents(remote):
    client, provider, _ = remote
    prm = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert prm["resource"] == RESOURCE  # exactly the URL entered in Claude
    assert prm["authorization_servers"] == [PUBLIC]
    assert prm["scopes_supported"] == ["finance.read"]
    asm = client.get("/.well-known/oauth-authorization-server").json()
    assert asm["issuer"] == PUBLIC
    assert asm["authorization_endpoint"] == PUBLIC + "/authorize"
    assert asm["token_endpoint"] == PUBLIC + "/token"
    assert asm["registration_endpoint"] == PUBLIC + "/register"
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["token_endpoint_auth_methods_supported"] == ["none", "client_secret_post", "client_secret_basic"]
    assert "client_id_metadata_document_supported" not in asm  # so Claude uses DCR
    assert asm["response_types_supported"] == ["code"]
    assert set(asm["grant_types_supported"]) == {"authorization_code", "refresh_token"}
    assert "revocation_endpoint" not in asm


def test_tools_list_over_http_is_read_only_and_complete(remote):
    client, provider, _ = remote
    _, tokens = full_login(client, provider)
    listed = rpc(client, tokens["access_token"], "tools/list").json()["result"]["tools"]
    assert {t["name"] for t in listed} == TOOLS
    for t in listed:
        a = t["annotations"]
        assert (a["readOnlyHint"], a["destructiveHint"], a["idempotentHint"], a["openWorldHint"]) == (
            True, False, True, False), t["name"]
    assert rpc(client, tokens["access_token"], "resources/list").json()["result"]["resources"] == []
    assert rpc(client, tokens["access_token"], "prompts/list").json()["result"]["prompts"] == []


def test_every_tool_over_http_calls_only_read_endpoints(remote):
    client, provider, _ = remote
    _, tokens = full_login(client, provider)
    for i, name in enumerate(sorted(TOOLS)):
        r = rpc(client, tokens["access_token"], "tools/call", {"name": name, "arguments": {}}, rid=i + 2)
        assert r.status_code == 200 and "error" not in tool_payload(r), name
    read_only = {"accounts_get", "investments_holdings_get", "investments_transactions_get", "item_get"}
    assert RecordingPlaid.calls and set(RecordingPlaid.calls) <= read_only


def test_no_route_or_code_path_can_write(remote):
    client, provider, _ = remote
    app = client.app.app  # inside the Guard
    paths = {getattr(r, "path", None) for r in app.routes}
    assert paths == {"/.well-known/oauth-authorization-server", "/authorize", "/token", "/register", "/mcp",
                     "/.well-known/oauth-protected-resource/mcp", GITHUB_CALLBACK_PATH, "/oauth/consent",
                     "/oauth/pending"}
    # the HTTP server's code never references a Plaid call that links, unlinks or moves anything
    writes = ("item_remove", "exchange_public_token", "create_link_token", "link_token", "transfer", "payment")
    for module in ("server.py", "tools.py", "remote.py", "auth.py", "audit.py"):
        source = (ROOT / "app" / module).read_text()
        assert not [w for w in writes if w in source], module


def test_markers_never_reach_http_output(remote, monkeypatch):
    client, provider, _ = remote
    monkeypatch.setattr(server, "plaid_factory", lambda s: HostilePlaid())
    _, tokens = full_login(client, provider)
    blob = ""
    for i, name in enumerate(sorted(TOOLS)):
        blob += rpc(client, tokens["access_token"], "tools/call", {"name": name, "arguments": {}}, rid=i + 2).text
    blob += rpc(client, tokens["access_token"], "tools/call",
                {"name": "get_holdings", "arguments": {"account": "tfsa"}}, rid=50).text
    assert "BAD" in blob  # the Plaid error code still surfaces, so the hostile fake really ran
    for marker in FORBIDDEN + ["987654321098", "access-sandbox-zzz-123"]:
        assert marker not in blob, marker


# --- hardening ----------------------------------------------------------------------------------------------------

def test_rate_limits_trip(tmp_path, plaid):
    limits = Limits(register_addr=(2, 3600), token_addr=(3, 60), mcp_client=(3, 60))
    app, provider, _ = make(tmp_path, limits=limits)
    with TestClient(app, base_url=PUBLIC) as c:
        client_id, tokens = full_login(c, provider)  # one /register, one /token
        for _ in range(2):
            r = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": "x", "client_id": client_id})
            assert r.status_code == 400
        r = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": "x", "client_id": client_id})
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
        register(c, provider)
        assert c.post("/register", json={"redirect_uris": [CB]}).status_code == 429
        codes = [rpc(c, tokens["access_token"], "tools/list").status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
    provider.close()


def test_body_size_limit(remote):
    client, provider, _ = remote
    r = client.post("/register", content=b"{" + b" " * 70_000 + b"}", headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_audit_log_has_tool_names_and_client_only(remote, tmp_path):
    client, provider, _ = remote
    client_id, tokens = full_login(client, provider)
    rpc(client, tokens["access_token"], "tools/call",
        {"name": "get_holdings", "arguments": {"account": "ARGMARKER-1234"}})
    rpc(client, tokens["access_token"], "tools/call", {"name": "list_accounts", "arguments": {}}, rid=2)
    rpc(client, tokens["access_token"], "tools/call", {"name": "NAMEMARKER", "arguments": {}}, rid=3)
    text = (tmp_path / "remote" / "audit.log").read_text()
    lines = [json.loads(line) for line in text.splitlines()]
    calls = [line for line in lines if line["event"] == "tool_call"]
    assert [(c["tool"], c["client"]) for c in calls] == [
        ("get_holdings", client_id), ("list_accounts", client_id), ("unknown", client_id)]
    assert all(set(c) == {"ts", "event", "tool", "client"} for c in calls)
    for secret in ("ARGMARKER", "NAMEMARKER", "TFSA", "1000.5", tokens["access_token"], tokens["refresh_token"],
                   "code_verifier", "gh-code"):
        assert secret not in text


def test_errors_never_return_tracebacks():
    async def broken(scope, receive, send):
        raise RuntimeError("SECRET-DETAIL in /home/pfmcp/app.py line 3")

    c = TestClient(Guard(broken, RateLimiter(), Limits(), RESOURCE), raise_server_exceptions=False)
    r = c.get("/anything")  # no `with`: the broken app has no lifespan
    assert r.status_code == 500 and r.json() == {"error": "server_error"}
    assert "SECRET" not in r.text and "Traceback" not in r.text
    assert r.headers["x-content-type-options"] == "nosniff"


def test_disallowed_host_header_rejected(remote):
    client, provider, _ = remote
    _, tokens = full_login(client, provider)
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={**MCP_HEADERS, "Authorization": f"Bearer {tokens['access_token']}", "Host": "evil.example"})
    assert r.status_code in (400, 421)


def test_serve_http_refuses_incomplete_config(monkeypatch, capsys):
    from app import cli

    monkeypatch.setattr(settings, "public_url", "http://insecure.example")
    monkeypatch.setattr(settings, "github_client_id", "")
    monkeypatch.setattr(settings, "github_allowed_user_id", 0)
    assert cli.main(["serve-http"]) == 1
    err = capsys.readouterr().err
    assert "https://" in err and "GITHUB_CLIENT_ID" in err and "GITHUB_ALLOWED_USER_ID" in err
    assert "token_signing_key" in err


# --- out-of-band client approval ----------------------------------------------------------------------------------

def owner_login_page(client, client_id):
    r = start_login(client, client_id, "v" * 50)
    return client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": query(r.headers["location"])["state"]})


def test_pending_client_gets_nothing_even_after_owner_login(remote):
    # the phishing case: someone else's claude.ai registered this client and sent the owner the link
    client, provider, _ = remote
    client_id = register(client)["client_id"]  # not approved
    page = owner_login_page(client, client_id)
    fp = fingerprint(client_id)
    assert page.status_code == 403 and "needs approval" in page.text
    assert f"python -m app.cli approve-client {fp}" in page.text
    assert "Only do this if you just clicked Connect in your own claude.ai." in page.text
    assert "UTC" in page.text  # registration time shown
    assert "consent_id" not in page.text and "set-cookie" not in page.headers
    assert provider._consents == {} and provider._codes == {}
    assert provider.db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0


def test_approved_client_completes_after_retry(remote):
    client, provider, _ = remote
    client_id = register(client)["client_id"]
    assert owner_login_page(client, client_id).status_code == 403
    approve(provider, client_id)
    page = owner_login_page(client, client_id)
    assert page.status_code == 200 and fingerprint(client_id) in page.text and "registered" in page.text
    verifier = pysecrets.token_urlsafe(48)
    r = exchange(client, client_id, login_code(client, client_id, verifier), verifier)
    assert r.status_code == 200 and rpc(client, r.json()["access_token"], "tools/list").status_code == 200


def test_revoked_client_tokens_rejected(remote):
    client, provider, _ = remote
    client_id, tokens = full_login(client, provider)
    admin = ClientAdmin(provider.cfg.db_path)
    assert admin.revoke(fingerprint(client_id)) == fingerprint(client_id)
    admin.close()
    assert rpc(client, tokens["access_token"], "tools/list").status_code == 401
    r = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                    "client_id": client_id})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"  # Claude re-registers on this
    assert start_login(client, client_id, "v" * 50).status_code == 400  # unknown client: no redirect at all


def test_expired_pending_clients_are_purged_and_capped(tmp_path, plaid):
    app, provider, clock = make(tmp_path, limits=Limits(register_addr=(100, 3600), register_global=(100, 86400)))
    with TestClient(app, base_url=PUBLIC) as client:
        _purge_and_cap(client, provider, clock)
    provider.close()


def _purge_and_cap(client, provider, clock):
    client_id = register(client)["client_id"]
    clock.now += 1801
    admin = ClientAdmin(provider.cfg.db_path, clock)
    assert admin.rows() == [] and admin.approve(fingerprint(client_id)) is None
    first = [register(client)["client_id"] for _ in range(20)]
    newest = register(client)["client_id"]  # over the cap: the oldest pending registration gives way
    ids = {r["fingerprint"] for r in admin.rows()}
    assert len(ids) == 20 and fingerprint(first[0]) not in ids and fingerprint(newest) in ids
    clock.now += 1801
    assert admin.rows() == []
    admin.close()


def test_register_rate_limit(tmp_path, plaid):
    app, provider, _ = make(tmp_path, limits=Limits(register_addr=(2, 3600)))
    with TestClient(app, base_url=PUBLIC) as c:
        register(c)
        register(c)
        assert c.post("/register", json={"redirect_uris": [CB]}).status_code == 429
    provider.close()


def test_client_cli_commands(remote, monkeypatch, capsys):
    from app import cli

    client, provider, _ = remote
    monkeypatch.setattr(settings, "data_dir", provider.cfg.db_path.parent)
    info = register(client, token_endpoint_auth_method="client_secret_post")
    fp = fingerprint(info["client_id"])
    assert cli.main(["list-clients"]) == 0
    out = capsys.readouterr().out
    assert fp in out and "pending" in out and "Claude" in out
    assert info["client_id"] not in out and info["client_secret"] not in out
    assert cli.main(["approve-client", "deadbeef"]) == 1
    assert cli.main(["approve-client", fp]) == 0
    assert cli.main(["approve-client", fp]) == 1  # no longer pending
    assert cli.main(["list-clients"]) == 0 and "approved" in capsys.readouterr().out
    assert cli.main(["revoke-client", fp]) == 0
    assert cli.main(["list-clients"]) == 0 and "revoked" in capsys.readouterr().out


# --- edge cases -------------------------------------------------------------------------------------------------

def test_reload_after_approval_continues_to_consent_without_new_registration(remote):
    client, provider, _ = remote
    client_id = register(client)["client_id"]
    verifier = pysecrets.token_urlsafe(48)
    r = start_login(client, client_id, verifier)
    callback = client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": query(r.headers["location"])["state"]},
                          follow_redirects=False)
    assert callback.status_code == 303 and callback.headers["location"] == "/oauth/pending"
    assert "__Host-pfm_hold=" in callback.headers["set-cookie"] and "SameSite=Lax" in callback.headers["set-cookie"]
    page = client.get("/oauth/pending")
    assert page.status_code == 403 and "reload this page" in page.text and "consent_id" not in page.text
    assert client.get("/oauth/pending").status_code == 403  # reload without approval: still pending
    assert provider._consents == {} and provider._codes == {}
    approve(provider, client_id)
    page = client.get("/oauth/pending")  # reload after approval: consent, same registration
    assert page.status_code == 200 and "Allow Claude?" in page.text
    assert "Only continue if you just clicked Connect in your own claude.ai." in page.text
    consent_id = re.search(r"name=consent_id value='([^']+)'", page.text).group(1)
    csrf = re.search(r"name=csrf value='([^']+)'", page.text).group(1)
    r = client.post("/oauth/consent", data={"consent_id": consent_id, "csrf": csrf, "action": "approve"},
                    follow_redirects=False)
    back = query(r.headers["location"])
    assert back["state"] == "claude-state"
    tokens = exchange(client, client_id, back["code"], verifier)
    assert tokens.status_code == 200
    assert provider.db.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 1
    assert client.get("/oauth/pending").status_code == 400  # the parked login was used up


def test_parked_login_is_bound_to_the_browser(remote):
    client, provider, _ = remote
    client_id = register(client)["client_id"]
    r = start_login(client, client_id, "v" * 50)
    client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": query(r.headers["location"])["state"]})
    approve(provider, client_id)
    other_browser = TestClient(client.app, base_url=PUBLIC)  # no `with`: the app's lifespan is already running
    page = other_browser.get("/oauth/pending")
    assert page.status_code == 400 and "consent_id" not in page.text
    other_browser.cookies.set("__Host-pfm_hold", "guessed-value")
    assert other_browser.get("/oauth/pending").status_code == 400
    assert provider._consents == {} and provider._codes == {}


def test_flood_of_pending_clients_cannot_block_owner_login(tmp_path, plaid):
    loose = Limits(per_addr=(10_000, 60), register_addr=(10_000, 3600), register_global=(10_000, 86400),
                   login_addr=(10_000, 60))
    app, provider, _ = make(tmp_path, limits=loose)
    with TestClient(app, base_url=PUBLIC) as owner:
        client_id = register(owner, provider)["client_id"]
        verifier = pysecrets.token_urlsafe(48)
        owner_state = query(start_login(owner, client_id, verifier).headers["location"])["state"]
        # strangers: from the owner's own address (no X-Forwarded-For case) and from many others
        for i in range(30):
            ip = "testclient" if i % 2 else f"203.0.113.{i}"
            stranger = TestClient(app, base_url=PUBLIC, client=(ip, 1000 + i))  # OAuth routes need no lifespan
            cid = register(stranger)["client_id"]
            for _ in range(3):
                start_login(stranger, cid, "x" * 50)
        assert len(provider._pending) <= 50
        page = owner.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": owner_state})
        assert page.status_code == 200 and "Allow Claude?" in page.text


def test_logins_per_client_are_capped(remote):
    client, provider, _ = remote
    client_id = register(client, provider)["client_id"]
    states = [query(start_login(client, client_id, "v" * 50).headers["location"])["state"] for _ in range(3)]
    assert sum(1 for v in provider._pending.values() if v["client_id"] == client_id) == 2
    assert client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": states[0]}).status_code == 400
    assert client.get(GITHUB_CALLBACK_PATH, params={"code": "gh", "state": states[2]}).status_code == 200


def test_unauthenticated_mcp_has_its_own_address_limit(tmp_path, plaid):
    limits = Limits(per_addr=(1000, 60), mcp_anonymous_addr=(2, 60))
    app, provider, _ = make(tmp_path, limits=limits)
    with TestClient(app, base_url=PUBLIC) as c:
        _, tokens = full_login(c, provider)
        assert all(rpc(c, tokens["access_token"], "tools/list").status_code == 200 for _ in range(40))
        assert [rpc(c, None, "tools/list").status_code for _ in range(3)] == [401, 401, 429]
    provider.close()


def test_replayed_code_revokes_what_it_issued(remote):
    client, provider, _ = remote
    client_id = register(client, provider)["client_id"]
    verifier = pysecrets.token_urlsafe(48)
    code = login_code(client, client_id, verifier)
    tokens = exchange(client, client_id, code, verifier).json()
    assert rpc(client, tokens["access_token"], "tools/list").status_code == 200
    assert exchange(client, client_id, code, verifier).json()["error"] == "invalid_grant"
    assert rpc(client, tokens["access_token"], "tools/list").status_code == 401


def test_wrong_pkce_verifier_burns_the_code(remote):
    client, provider, _ = remote
    client_id = register(client, provider)["client_id"]
    verifier = pysecrets.token_urlsafe(48)
    code = login_code(client, client_id, verifier)
    assert exchange(client, client_id, code, "w" * 50).json()["error"] == "invalid_grant"
    assert exchange(client, client_id, code, verifier).json()["error"] == "invalid_grant"


def test_losing_a_refresh_race_revokes_the_family(remote):
    import asyncio

    from mcp.server.auth.provider import TokenError

    client, provider, _ = remote
    client_id, tokens = full_login(client, provider)
    info = asyncio.run(provider.get_client(client_id))
    rt = asyncio.run(provider.load_refresh_token(info, tokens["refresh_token"]))
    second = asyncio.run(provider.exchange_refresh_token(info, rt, rt.scopes))  # the winner
    with pytest.raises(TokenError):
        asyncio.run(provider.exchange_refresh_token(info, rt, rt.scopes))  # the loser, same token
    assert rpc(client, second.access_token, "tools/list").status_code == 401


def test_basic_auth_client_id_is_parsed_for_rate_limits():
    import base64

    from app.remote import _basic_client_id

    assert _basic_client_id(b"Basic " + base64.b64encode(b"abc%2Did:secret")) == "abc-id"
    assert _basic_client_id(b"Bearer x") == "" and _basic_client_id(b"Basic !!!") == ""


# --- rate limiting regression suite (see app.remote.RateLimiter for the model) -------------------------------------

def refresh(client, client_id, refresh_token):
    return client.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token,
                                        "client_id": client_id, "resource": RESOURCE})


def test_forged_approved_client_id_on_token_is_still_capped(tmp_path, plaid):
    app, provider, _ = make(tmp_path, limits=Limits(token_addr=(5, 60)))
    with TestClient(app, base_url=PUBLIC) as owner:
        client_id, tokens = full_login(owner, provider)
        client_bucket = owner.app.limiter.clients.buckets[f"token:{client_id}"]
        before = list(client_bucket)  # the owner's own code exchange, counted after authentication
        attacker = TestClient(app, base_url=PUBLIC, client=("198.51.100.66", 4000))
        codes = [refresh(attacker, client_id, "pfm_rt_guessed").status_code for _ in range(8)]
        assert codes[:5] == [400] * 5 and set(codes[5:]) == {429}  # the approved id buys the attacker nothing
        assert client_bucket == before  # forged requests never touched the client's bucket
        assert refresh(owner, client_id, tokens["refresh_token"]).status_code == 200  # owner unaffected
    provider.close()


def test_conflicting_or_duplicate_client_id_rejected(remote):
    import base64

    client, provider, _ = remote
    form = {"grant_type": "refresh_token", "refresh_token": "x"}
    r = client.post("/token", content="grant_type=refresh_token&refresh_token=x&client_id=a&client_id=b",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 400 and "more than once" in r.json()["error_description"]
    basic = {"Authorization": "Basic " + base64.b64encode(b"b:secret").decode()}
    r = client.post("/token", data={**form, "client_id": "a"}, headers=basic)
    assert r.status_code == 400 and "more than once" in r.json()["error_description"]
    r = client.post("/token", data={**form, "client_id": "b"}, headers=basic)  # same id twice is consistent
    assert "more than once" not in r.text


def test_neighbour_on_same_network_does_not_use_up_owner_login(tmp_path, plaid):
    app, provider, _ = make(tmp_path, limits=Limits(login_addr=(3, 60)))
    with TestClient(app, base_url=PUBLIC) as setup:
        client_id = register(setup, provider)["client_id"]
    neighbour = TestClient(app, base_url=PUBLIC, client=("203.0.113.9", 4000))
    owner = TestClient(app, base_url=PUBLIC, client=("203.0.113.10", 4000))  # same /24
    codes = [start_login(neighbour, client_id, "v" * 50).status_code for _ in range(5)]
    assert codes[:3] == [302] * 3 and set(codes[3:]) == {429}
    assert start_login(owner, client_id, "v" * 50).status_code == 302
    provider.close()


def test_anonymous_flood_keeps_register_cap_and_owner_traffic(tmp_path, plaid, monkeypatch):
    monkeypatch.setattr(RateLimiter, "MAX_ADDR_KEYS", 20)
    monkeypatch.setattr(RateLimiter, "MAX_NET_KEYS", 20)
    app, provider, _ = make(tmp_path, limits=Limits(register_global=(5, 86400)))
    with TestClient(app, base_url=PUBLIC) as owner:
        client_id, tokens = full_login(owner, provider)
        limiter = owner.app.limiter
        for i in range(200):  # 10x the table sizes: distinct networks and addresses
            stranger = TestClient(app, base_url=PUBLIC, client=(f"10.{i // 250}.{i % 250}.9", 4000))
            stranger.get("/.well-known/oauth-authorization-server")
            if i % 20 == 0:
                stranger.post("/register", json={"redirect_uris": [CB]})
        assert len(limiter.addr.buckets) <= 20 and len(limiter.net.buckets) <= 20  # live buckets kept, none added
        assert limiter.take([(None, "overflow", limiter.OVERFLOW_RULE)])  # the shared overflow is drained
        assert limiter.globals["register"][1] <= 5  # never reset; new networks were refused before reaching it
        r = refresh(owner, client_id, tokens["refresh_token"])
        assert r.status_code == 200
        assert rpc(owner, r.json()["access_token"], "tools/list").status_code == 200
        # the owner arriving from a brand-new network during the flood still gets authenticated calls through
        roaming = TestClient(app, base_url=PUBLIC, client=("198.51.100.77", 4000))
        r = refresh(roaming, client_id, r.json()["refresh_token"])
        assert r.status_code == 200
        assert rpc(roaming, r.json()["access_token"], "tools/list").status_code == 200
    provider.close()


def test_one_address_at_its_register_cap_spends_no_global_quota(tmp_path, plaid):
    app, provider, _ = make(tmp_path, limits=Limits(register_addr=(2, 3600), register_global=(3, 86400)))
    with TestClient(app, base_url=PUBLIC) as first:
        register(first)
        register(first)
        for _ in range(10):
            assert first.post("/register", json={"redirect_uris": [CB]}).status_code == 429
        other = TestClient(app, base_url=PUBLIC, client=("198.51.100.4", 4000))
        r = other.post("/register", json={"redirect_uris": [CB], "token_endpoint_auth_method": "none"})
        assert r.status_code == 201  # the third global slot was still free
        third = TestClient(app, base_url=PUBLIC, client=("192.0.2.4", 4000))
        assert third.post("/register", json={"redirect_uris": [CB]}).status_code == 429  # global cap reached
    provider.close()


class DbSpy:
    def __init__(self, db):
        self.db, self.calls = db, 0

    def execute(self, *args, **kwargs):
        self.calls += 1
        return self.db.execute(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.db, name)


def test_no_database_work_before_layer1_passes(tmp_path, plaid):
    app, provider, _ = make(tmp_path, limits=Limits(per_addr=(3, 60)))
    with TestClient(app, base_url=PUBLIC) as c:
        spy = provider.db = DbSpy(provider.db)
        for _ in range(3):
            c.post("/token", data={"grant_type": "refresh_token", "refresh_token": "x", "client_id": "junk"})
        assert spy.calls > 0  # requests that passed layer 1 did reach the database
        spy.calls = 0
        assert c.post("/token", data={"grant_type": "refresh_token", "refresh_token": "x",
                                      "client_id": "junk"}).status_code == 429
        assert c.post("/register", json={"redirect_uris": [CB]}).status_code == 429
        assert c.get("/authorize", params={"client_id": "x"}).status_code == 429
        assert c.post("/mcp", json={}, headers={**MCP_HEADERS, "Authorization": "Bearer pfm_at_x"}).status_code == 429
        assert spy.calls == 0
    provider.close()


def test_token_rate_limit_counts_only_authenticated_grants(tmp_path, plaid):
    app, provider, _ = make(tmp_path, limits=Limits(token_client=(2, 60)))
    with TestClient(app, base_url=PUBLIC) as c:
        client_id, tokens = full_login(c, provider)  # the code exchange is grant 1
        for _ in range(5):  # failed grants do not count against the client
            assert refresh(c, client_id, "pfm_rt_wrong").json()["error"] == "invalid_grant"
        second = refresh(c, client_id, tokens["refresh_token"])
        assert second.status_code == 200  # grant 2
        r = refresh(c, client_id, second.json()["refresh_token"])
        assert r.status_code == 400 and "Too many token requests" in r.json()["error_description"]
        # refused before anything was consumed: that refresh token is still unused
        assert provider._row(second.json()["refresh_token"], "refresh")["used_at"] is None
    provider.close()


def test_live_buckets_survive_and_idle_ones_are_reclaimed():
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    limiter.addr.max_keys = 5
    rules = Limits(per_addr=(100, 60), per_net=(1000, 60))
    for i in range(5):
        limiter.layer1(f"192.0.2.{i}", None, rules, False)
    live = set(limiter.addr.buckets)
    for i in range(50):  # table full of live buckets: newcomers are limited by their network bucket only
        assert limiter.layer1(f"198.51.100.{i}", None, rules, False)[0] is None
    assert set(limiter.addr.buckets) == live
    now[0] = 121  # two windows later the old buckets no longer count and are reclaimed on demand
    limiter.layer1("203.0.113.1", None, rules, False)
    assert set(limiter.addr.buckets) == {"a:203.0.113.1"}


def test_full_table_sweep_is_throttled(monkeypatch):
    from app import remote

    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    limiter.addr.max_keys = 3
    sweeps = []
    original = remote._Table.sweep
    monkeypatch.setattr(remote._Table, "sweep", lambda self, t: (sweeps.append(t), original(self, t)))
    rules = Limits()
    for i in range(3):
        limiter.layer1(f"192.0.2.{i}", None, rules, False)
    for i in range(100):
        limiter.layer1(f"198.51.100.{i}", None, rules, False)
    assert len([t for t in sweeps if t == 0.0]) == 1
    now[0] = 2.0
    limiter.layer1("203.0.113.5", None, rules, False)
    assert len(sweeps) == 2


def test_ip_buckets_aggregate_networks():
    from app.remote import ip_bucket

    assert ip_bucket("203.0.113.7") == ip_bucket("203.0.113.250") == "203.0.113.0/24"
    assert ip_bucket("2001:db8:1:2::5") == ip_bucket("2001:db8:1:2:ffff::1") == "2001:db8:1:2::/64"
    assert ip_bucket("testclient") == "testclient"


def test_missing_forwarded_address_is_warned_once(tmp_path, plaid, caplog):
    app, provider, _ = make(tmp_path)
    with TestClient(app, base_url=PUBLIC, client=("127.0.0.1", 5000)) as c, caplog.at_level("WARNING"):
        c.get("/.well-known/oauth-authorization-server")
        c.get("/.well-known/oauth-authorization-server")
    assert sum("X-Forwarded-For" in r.message for r in caplog.records) == 1
    provider.close()


def test_revoke_all_clients(remote, monkeypatch, capsys):
    from app import cli

    client, provider, _ = remote
    monkeypatch.setattr(settings, "data_dir", provider.cfg.db_path.parent)
    _, tokens = full_login(client, provider)
    register(client)
    assert cli.main(["revoke-client", "--all"]) == 0
    assert "2 client" in capsys.readouterr().out
    assert rpc(client, tokens["access_token"], "tools/list").status_code == 401
    assert cli.main(["list-clients"]) == 0
    rows = [line.split()[1] for line in capsys.readouterr().out.splitlines()[1:-1]]
    assert rows == ["revoked", "revoked"]
