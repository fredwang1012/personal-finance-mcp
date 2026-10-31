"""Remote connector: the same read-only tools over MCP Streamable HTTP, behind OAuth (python -m app.cli serve-http).

Binds 127.0.0.1 only; Tailscale Funnel forwards public HTTPS to it. Every MCP request needs a bearer token issued by
app.auth for this exact resource URL. Around the SDK's app sit a body-size cap, per-client rate limits, an audit log
of tool names (never arguments or results) and an error guard that never returns a traceback.
"""
import base64
import json
import logging
import time
import urllib.parse
from collections import OrderedDict, deque
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
    """(requests, window seconds) per key."""
    per_ip: tuple[int, int] = (300, 60)
    register_ip: tuple[int, int] = (10, 3600)
    register_global: tuple[int, int] = (200, 86400)  # pending clients are capped and expire, so this can be loose
    token_client: tuple[int, int] = (30, 60)
    token_global: tuple[int, int] = (120, 60)
    login_ip: tuple[int, int] = (30, 60)
    mcp_client: tuple[int, int] = (120, 60)
    mcp_unauthenticated_ip: tuple[int, int] = (60, 60)


class RateLimiter:
    """Sliding-window counter in memory. Restarting the service resets it, which is acceptable for one owner.

    Buckets idle for longer than their window are dropped, and the number of keys is capped (least recently used
    goes first), so a flood of distinct keys cannot grow memory without bound."""

    MAX_KEYS = 10000

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.hits: OrderedDict[str, tuple[deque, int]] = OrderedDict()  # key -> (timestamps, window)

    def _evict(self, now: float) -> None:
        while self.hits:
            key, (q, window) = next(iter(self.hits.items()))
            if q and q[-1] > now - window and len(self.hits) <= self.MAX_KEYS:
                break  # the least recently used bucket is still live, so all later ones are too
            del self.hits[key]

    def hit(self, key: str, rule: tuple[int, int]) -> int | None:
        """Record a request; return seconds to wait if over the limit, else None."""
        limit, window = rule
        now = self.clock()
        q, _ = self.hits.pop(key, (deque(), window))
        self.hits[key] = (q, window)  # most recently used goes last
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            return max(1, int(q[0] + window - now) + 1)
        q.append(now)
        self._evict(now)
        return None


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
                        "per-IP limits then apply to all clients together")
        request_ip.set(ip)
        headers = dict(scope.get("headers") or [])
        try:
            length = int(headers.get(b"content-length", b"0") or 0)
        except ValueError:
            length = MAX_BODY + 1
        if length > MAX_BODY:
            return await _send_json(send, 413, {"error": "too_large"})

        lim, rules = self.limiter, self.limits
        # /mcp is limited after authentication instead (ClientRateLimit), so strangers sharing the owner's
        # address cannot use up the owner's quota
        checks = [] if path == "/mcp" else [(f"ip:{ip}", rules.per_ip)]
        if path == "/register" and method == "POST":
            checks += [(f"register:{ip}", rules.register_ip), ("register", rules.register_global)]
        elif path == "/authorize" or path.startswith("/oauth/"):
            checks.append((f"login:{ip}", rules.login_ip))
        for key, rule in checks:
            retry = lim.hit(key, rule)
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

        if path == "/token" and method == "POST":
            body = b""
            while True:
                message = await counted_receive()
                body += message.get("body", b"")
                if not message.get("more_body"):
                    break
            form = urllib.parse.parse_qs(body.decode("latin-1"))
            client_id = (form.get("client_id") or [_basic_client_id(headers.get(b"authorization", b""))])[0][:64]
            for key, rule in ((f"token:{client_id}", rules.token_client), ("token", rules.token_global)):
                retry = lim.hit(key, rule)
                if retry:
                    return await _too_many(send, retry)
            resource = (form.get("resource") or [None])[0]
            if resource is not None and canonical(resource) != canonical(self.resource):
                return await _send_json(send, 400, {"error": "invalid_target",
                                                    "error_description": "Unknown resource."})
            code, verifier = (form.get("code") or [None])[0], (form.get("code_verifier") or [None])[0]
            if self.provider is not None and code and verifier:
                self.provider.burn_code_on_bad_verifier(code, verifier)
            replayed = False

            async def replay():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            return await self.app(scope, replay, send)
        return await self.app(scope, counted_receive, send)


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
    """Inside the SDK's auth middleware, so the authenticated OAuth client is known: per-client limit on /mcp."""

    def __init__(self, app, limiter: RateLimiter, rule: tuple[int, int], anonymous_rule: tuple[int, int]):
        self.app, self.limiter, self.rule, self.anonymous_rule = app, limiter, rule, anonymous_rule

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/mcp":
            user = scope.get("user")
            if isinstance(user, AuthenticatedUser):
                retry = self.limiter.hit(f"mcp:{user.access_token.client_id}", self.rule)
            else:
                ip = (scope.get("client") or ("unknown",))[0]
                retry = self.limiter.hit(f"mcp-anon:{ip}", self.anonymous_rule)
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
    # appended after the SDK's auth middleware, so it runs with the authenticated user known
    app.user_middleware.append(Middleware(ClientRateLimit, limiter=limiter, rule=limits.mcp_client,
                                          anonymous_rule=limits.mcp_unauthenticated_ip))
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
