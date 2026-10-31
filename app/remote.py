"""Remote connector: the same read-only tools over MCP Streamable HTTP, behind OAuth (python -m app.cli serve-http).

Binds 127.0.0.1 only; Tailscale Funnel forwards public HTTPS to it. Every MCP request needs a bearer token issued by
app.auth for this exact resource URL. Around the SDK's app sit a body-size cap, two-layer rate limits (see
RateLimiter), an audit log of tool names (never arguments or results) and an error guard that never returns a
traceback.
"""
import base64
import ipaddress
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.routes import build_metadata, cors_middleware
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware import Middleware
from starlette.routing import Route

from app import server
from app.audit import Audit
from app.auth import (
    CONSENT_PATH,
    GITHUB_CALLBACK_PATH,
    PENDING_PATH,
    SCOPE,
    AuthConfig,
    OwnerOAuthProvider,
    canonical,
    request_ip,
)

log = logging.getLogger("personal-finance-mcp.remote")

MAX_BODY = 64 * 1024  # MCP requests here are tiny tool calls; DCR and token forms are smaller still
TOOL_NAMES = frozenset(fn.__name__ for fn, _ in server.TOOLS)


@dataclass(frozen=True)
class Limits:
    """(requests, window seconds) per bucket. See RateLimiter for where each one applies."""
    per_addr: tuple[int, int] = (600, 60)          # layer 1, every request, exact client address
    per_net: tuple[int, int] = (6000, 60)          # layer 1, every request, /24 or /64: flood backstop only
    register_addr: tuple[int, int] = (10, 3600)    # layer 1, POST /register, exact address
    login_addr: tuple[int, int] = (30, 60)         # layer 1, /authorize and /oauth/*, exact address
    token_addr: tuple[int, int] = (60, 60)         # layer 1, POST /token, exact address
    register_global: tuple[int, int] = (200, 86400)  # global, after layer 1 passed
    mcp_client: tuple[int, int] = (120, 60)        # layer 2, authenticated /mcp, per OAuth client
    token_client: tuple[int, int] = (30, 60)       # layer 2, /token grant that passed the SDK's checks
    mcp_anonymous_addr: tuple[int, int] = (60, 60)  # layer 2, /mcp without a valid token, exact address


def ip_bucket(ip: str) -> str:
    """The network an address belongs to for the flood backstop: /24 for IPv4, /64 for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip[:64]
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 64}", strict=False))


# A bucket is [window_start, count_this_window, count_previous_window, window]: an approximate sliding window in
# constant memory (the previous window's count is weighted by how much of it still overlaps).
def _roll(b: list, now: float) -> None:
    if now >= b[0] + b[3]:
        windows = int((now - b[0]) // b[3])
        b[2] = b[1] if windows == 1 else 0
        b[1] = 0
        b[0] += windows * b[3]


def _retry_after(b: list, limit: int, now: float) -> int | None:
    _roll(b, now)
    estimate = b[2] * (1 - (now - b[0]) / b[3]) + b[1]
    return max(1, int(b[0] + b[3] - now) + 1) if estimate >= limit else None


class _Table:
    """Per-key buckets. A bucket is dropped only once idle for two windows (it then no longer affects anything);
    a live bucket is never evicted. When full, `room_for` says no for new keys and the caller decides."""

    def __init__(self, max_keys: int):
        self.max_keys, self.buckets, self._last_sweep = max_keys, {}, float("-inf")

    def sweep(self, now: float) -> None:
        for key in [k for k, b in self.buckets.items() if now >= b[0] + 2 * b[3]]:
            del self.buckets[key]
        self._last_sweep = now

    def room_for(self, key: str, now: float, sweep_interval: float) -> bool:
        if key in self.buckets or len(self.buckets) < self.max_keys:
            return True
        if now - self._last_sweep >= sweep_interval:  # throttled: a flood cannot make every request scan
            self.sweep(now)
        return len(self.buckets) < self.max_keys


class RateLimiter:
    """Rate limiting model for the remote connector.

    Layer 1, before anything else and with no database work, on every request (/token and /mcp included):
      - an exact per-address bucket (generous; never shared with neighbours) plus, for /register, /authorize and
        /oauth/*, and /token, an exact per-address bucket for that endpoint;
      - a per-network bucket (/24, /64) with a much higher limit, only as a flood backstop.
      Address and network buckets live in separate tables, so neither can drain or push out the other. All are
      checked first and recorded only if every one passes. If the address table is full, a new address is limited
      by its network bucket alone. If the network table is full, a new network shares one strict overflow bucket,
      except on /mcp and /token, which go on to layer 2 (so a flood cannot starve the owner's authenticated calls;
      their failures are then counted against the overflow bucket afterwards).
    Global caps (registrations per day) are counted only after layer 1 passed; they are never evicted.
    Layer 2, only once the SDK has authenticated the request, keyed by the authenticated OAuth client:
      - /mcp with a valid bearer token: per-client bucket (ClientRateLimit). Without one: an exact per-address
        bucket.
      - /token: per-client bucket counted by the provider in exchange_*, i.e. after client authentication, grant
        lookup and PKCE. Nothing is ever routed on an unauthenticated client_id.
    Logins in progress are capped separately in app.auth (per client, per address, in total).
    """

    MAX_ADDR_KEYS = 100_000
    MAX_NET_KEYS = 50_000
    MAX_CLIENT_KEYS = 1000
    OVERFLOW_RULE = (60, 60)
    SWEEP_INTERVAL = 1.0

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.addr, self.net = _Table(self.MAX_ADDR_KEYS), _Table(self.MAX_NET_KEYS)
        self.clients = _Table(self.MAX_CLIENT_KEYS)
        self.globals: dict[str, list] = {}  # never evicted

    def take(self, specs: list[tuple["_Table | None", str, tuple[int, int]]]) -> int | None:
        """Check every (table, key, rule) bucket (table None = global) and record in all of them only if every one
        passes. Returns seconds to wait, or None."""
        now = self.clock()
        found = []
        for table, key, (limit, window) in specs:
            store = self.globals if table is None else table.buckets
            bucket = store.get(key) or [now, 0, 0, window]
            retry = _retry_after(bucket, limit, now)
            if retry:
                return retry
            found.append((store, key, bucket))
        for store, key, bucket in found:
            store[key] = bucket
            bucket[1] += 1
        return None

    def take_client(self, key: str, rule: tuple[int, int]) -> int | None:
        """Layer 2: a bucket for one authenticated OAuth client."""
        now = self.clock()
        if not self.clients.room_for(key, now, self.SWEEP_INTERVAL):
            self.clients.sweep(now)  # bounded by the number of clients; full only if something is very wrong
        return self.take([(self.clients, key, rule)])

    def layer1(self, ip: str, endpoint: tuple[str, tuple[int, int]] | None, rules: "Limits",
               may_skip_overflow: bool) -> tuple[int | None, bool]:
        """(retry seconds or None, whether the network table was full and the overflow bucket was skipped)."""
        now = self.clock()
        net = ip_bucket(ip)
        specs, skipped = [], False
        addr_keys = [(f"a:{ip}", rules.per_addr)]
        if endpoint is not None:
            addr_keys.append((f"{endpoint[0]}:{ip}", endpoint[1]))
        for key, rule in addr_keys:
            if self.addr.room_for(key, now, self.SWEEP_INTERVAL):
                specs.append((self.addr, key, rule))
        if self.net.room_for(f"n:{net}", now, self.SWEEP_INTERVAL):
            specs.append((self.net, f"n:{net}", rules.per_net))
        elif may_skip_overflow:
            skipped = True
        else:
            specs.append((None, "overflow", self.OVERFLOW_RULE))
        return self.take(specs), skipped


async def _send_json(send, status: int, body: dict, headers: list | None = None) -> None:
    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode()),
                            (b"cache-control", b"no-store"), *(headers or [])]})
    await send({"type": "http.response.body", "body": data})


async def _too_many(send, retry: int) -> None:
    await _send_json(send, 429, {"error": "rate_limited", "error_description": "Too many requests."},
                     [(b"retry-after", str(retry).encode())])


class _TooLarge(Exception):
    pass


SECURITY_HEADERS = [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer")]


class Guard:
    """Outermost layer: error guard, body cap, per-IP and per-endpoint rate limits, /token resource check."""

    def __init__(self, app, limiter: RateLimiter, limits: Limits, resource: str, provider=None):
        self.app, self.limiter, self.limits, self.resource, self.provider = app, limiter, limits, resource, provider
        self._warned_no_forwarded_ip = False

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = False

        async def guarded_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = list(message.get("headers", []))
                if message.get("status") == 401 and scope.get("path") == "/mcp":
                    # RFC 6750 / MCP 2025-11-25: name the scope the client should ask for
                    headers = [(k, v + f', scope="{SCOPE}"'.encode()) if k.lower() == b"www-authenticate" else (k, v)
                               for k, v in headers]
                message = {**message, "headers": [*headers, *SECURITY_HEADERS]}
            await send(message)

        try:
            await self._handle(scope, receive, guarded_send)
        except _TooLarge:
            if not started:
                await _send_json(guarded_send, 413, {"error": "too_large"})
        except Exception as exc:  # never a traceback or exception text to the client
            log.error("request failed: %s", type(exc).__name__)
            if not started:
                await _send_json(guarded_send, 500, {"error": "server_error"})

    async def _handle(self, scope, receive, send):
        path, method = scope.get("path", ""), scope.get("method", "")
        # uvicorn's proxy_headers puts the Funnel client address here (only 127.0.0.1 is trusted to set it)
        ip = (scope.get("client") or ("unknown",))[0]
        if ip in ("127.0.0.1", "::1") and not self._warned_no_forwarded_ip:
            self._warned_no_forwarded_ip = True
            log.warning("request without a forwarded client address (no X-Forwarded-For from the proxy); "
                        "per-address limits then apply to all clients together")
        request_ip.set(ip)
        headers = dict(scope.get("headers") or [])
        try:
            length = int(headers.get(b"content-length", b"0") or 0)
        except ValueError:
            length = MAX_BODY + 1
        if length > MAX_BODY:
            return await _send_json(send, 413, {"error": "too_large"})

        # layer 1: cheap, before any parsing or database work
        lim, rules = self.limiter, self.limits
        is_token, is_register = (path == "/token" and method == "POST"), (path == "/register" and method == "POST")
        endpoint = (("register", rules.register_addr) if is_register
                    else ("login", rules.login_addr) if path == "/authorize" or path.startswith("/oauth/")
                    else ("token", rules.token_addr) if is_token else None)
        retry, skipped_overflow = lim.layer1(ip, endpoint, rules, may_skip_overflow=is_token or path == "/mcp")
        if retry:
            return await _too_many(send, retry)
        scope.setdefault("state", {})["pfm_overflow"] = skipped_overflow
        if is_register:  # global cap, counted only once this address passed its own limits
            retry = lim.take([(None, "register", rules.register_global)])
            if retry:
                return await _too_many(send, retry)

        received = 0

        async def counted_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > MAX_BODY:
                    raise _TooLarge()
            return message

        if not is_token:
            return await self.app(scope, counted_receive, send)

        body = b""
        while True:
            message = await counted_receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        form = urllib.parse.parse_qs(body.decode("latin-1"))
        form_ids = form.get("client_id", [])
        basic_id = _basic_client_id(headers.get(b"authorization", b""))
        if len(form_ids) > 1 or (form_ids and basic_id and form_ids[0] != basic_id):
            return await _send_json(send, 400, {"error": "invalid_request",
                                                "error_description": "client_id given more than once."})
        resource = (form.get("resource") or [None])[0]
        if resource is not None and canonical(resource) != canonical(self.resource):
            return await _send_json(send, 400, {"error": "invalid_target", "error_description": "Unknown resource."})
        code, verifier = (form.get("code") or [None])[0], (form.get("code_verifier") or [None])[0]
        if self.provider is not None and code and verifier:
            self.provider.burn_code_on_bad_verifier(code, verifier)  # in memory only
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        status = 0

        async def watch(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        await self.app(scope, replay, watch)
        if skipped_overflow and status >= 400:
            lim.take([(None, "overflow", lim.OVERFLOW_RULE)])  # failed attempts from an overflowed network


def _basic_client_id(header: bytes) -> str:
    """client_id from an HTTP Basic Authorization header (client_secret_basic), or ''."""
    try:
        scheme, _, value = header.decode("latin-1").partition(" ")
        if scheme.lower() != "basic":
            return ""
        return urllib.parse.unquote(base64.b64decode(value).decode("utf-8").split(":", 1)[0])
    except (ValueError, UnicodeDecodeError):
        return ""


class ClientRateLimit:
    """Layer 2 for /mcp, inside the SDK's auth middleware so the authenticated OAuth client is known."""

    def __init__(self, app, limiter: RateLimiter, rule: tuple[int, int], anonymous_rule: tuple[int, int]):
        self.app, self.limiter, self.rule, self.anonymous_rule = app, limiter, rule, anonymous_rule

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/mcp":
            user = scope.get("user")
            if isinstance(user, AuthenticatedUser):
                retry = self.limiter.take_client(f"mcp:{user.access_token.client_id}", self.rule)
            elif (scope.get("state") or {}).get("pfm_overflow"):
                retry = self.limiter.take([(None, "overflow", self.limiter.OVERFLOW_RULE)])
            else:
                ip = (scope.get("client") or ("unknown",))[0]
                retry = self.limiter.take([(self.limiter.addr, f"mcp-anon:{ip}", self.anonymous_rule)])
            if retry:
                return await _too_many(send, retry)
        await self.app(scope, receive, send)


class AuditMiddleware:
    """MCP-level middleware: one audit line per tool call with the tool name and OAuth client id only."""

    def __init__(self, audit: Audit):
        self.audit = audit

    async def __call__(self, ctx, call_next):
        if ctx.method == "tools/call":
            name = (ctx.params or {}).get("name")
            token = get_access_token()
            self.audit.event("tool_call", tool=name if name in TOOL_NAMES else "unknown",
                             client=token.client_id if token else "unknown")
        return await call_next(ctx)


@dataclass(frozen=True)
class RemoteConfig:
    public_url: str
    port: int
    allowed_user_id: int
    signing_key: bytes
    data_dir: Path


def check_public_url(url: str) -> str | None:
    """Why the PUBLIC_URL setting is unusable, or None."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return "PUBLIC_URL must be an https:// URL, e.g. https://vm.your-tailnet.ts.net"
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return "PUBLIC_URL must be just scheme and host (the MCP endpoint is PUBLIC_URL/mcp)"
    return None


def build_app(cfg: RemoteConfig, github, limits: Limits = Limits(), clock: Callable[[], float] = time.time,
              limiter: RateLimiter | None = None):
    """The ASGI app; returns (app, provider). `github` is app.auth.GitHub or a test fake."""
    public = cfg.public_url.rstrip("/")
    audit = Audit(cfg.data_dir / "audit.log")
    auth_cfg = AuthConfig(public_url=public, allowed_user_id=cfg.allowed_user_id, signing_key=cfg.signing_key,
                          db_path=cfg.data_dir / "oauth.db")
    provider = OwnerOAuthProvider(auth_cfg, github, audit, clock)
    settings = AuthSettings(
        issuer_url=public,
        resource_server_url=auth_cfg.resource,
        validate_token_resource=True,
        required_scopes=[SCOPE],
        client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[SCOPE],
                                                              default_scopes=[SCOPE]),
        revocation_options=RevocationOptions(enabled=False),
    )
    mcp = server.build_server(auth=settings, auth_server_provider=provider, middleware=[AuditMiddleware(audit)])
    mcp.custom_route(GITHUB_CALLBACK_PATH, methods=["GET"])(provider.github_callback)
    mcp.custom_route(CONSENT_PATH, methods=["POST"])(provider.consent)
    mcp.custom_route(PENDING_PATH, methods=["GET"])(provider.pending)
    host = urllib.parse.urlsplit(public).netloc
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        # Funnel may present either the public host or the loopback target, so both are accepted
        allowed_hosts=[host, f"127.0.0.1:{cfg.port}", f"localhost:{cfg.port}"],
        allowed_origins=[public, "https://claude.ai", "https://claude.com"],
    )
    app = mcp.streamable_http_app(stateless_http=True, json_response=True, transport_security=security,
                                  max_request_body_size=MAX_BODY)
    _advertise_public_clients(app, settings)
    limiter = limiter or RateLimiter()
    # layer 2: appended after the SDK's auth middleware, so it runs with the authenticated user known
    app.user_middleware.append(Middleware(ClientRateLimit, limiter=limiter, rule=limits.mcp_client,
                                          anonymous_rule=limits.mcp_anonymous_addr))
    # layer 2 for /token: the provider calls this once the SDK has authenticated the client and validated the grant
    provider.client_rate_limit = lambda client_id: limiter.take_client(f"token:{client_id}", limits.token_client)
    return Guard(app, limiter, limits, auth_cfg.resource, provider), provider


def _advertise_public_clients(app, settings: AuthSettings) -> None:
    """The SDK's AS metadata omits `none` from token_endpoint_auth_methods_supported although its token endpoint
    accepts public clients (Claude registers as one). Serve the same document with `none` added."""
    metadata = build_metadata(settings.issuer_url, settings.service_documentation_url,
                              settings.client_registration_options, settings.revocation_options)
    metadata.token_endpoint_auth_methods_supported = ["none", "client_secret_post", "client_secret_basic"]
    path = "/.well-known/oauth-authorization-server"
    for i, route in enumerate(app.router.routes):
        if getattr(route, "path", None) == path:
            app.router.routes[i] = Route(path, endpoint=cors_middleware(MetadataHandler(metadata).handle,
                                                                        ["GET", "OPTIONS"]), methods=["GET", "OPTIONS"])
            return
    raise RuntimeError("authorization server metadata route not found")


def serve() -> int:
    """Run on 127.0.0.1 with settings and secrets from the configured backend."""
    import sys

    import uvicorn

    from app import secrets
    from app.auth import GitHub
    from app.config import settings

    problems = []
    if err := check_public_url(settings.public_url):
        problems.append(err)
    if not settings.github_client_id:
        problems.append("GITHUB_CLIENT_ID is not set")
    if settings.github_allowed_user_id <= 0:
        problems.append("GITHUB_ALLOWED_USER_ID (your numeric GitHub id) is not set")
    try:
        key, gh_secret = secrets.get_signing_key(), secrets.get_github_client_secret()
    except secrets.MissingSecret as exc:
        problems.append(str(exc))
    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        return 1
    server.install_test_mode()
    cfg = RemoteConfig(settings.public_url, settings.http_port, settings.github_allowed_user_id, key,
                       settings.data_dir)
    app, _ = build_app(cfg, GitHub(settings.github_client_id, gh_secret))
    print(f"Serving {cfg.public_url.rstrip('/')}/mcp from http://127.0.0.1:{cfg.port}", file=sys.stderr)
    # access_log off: query strings carry OAuth state and GitHub codes. proxy_headers trusts only 127.0.0.1.
    uvicorn.run(app, host="127.0.0.1", port=cfg.port, access_log=False, server_header=False, proxy_headers=True,
                forwarded_allow_ips="127.0.0.1", limit_concurrency=32, timeout_keep_alive=5, log_level="warning")
    return 0
