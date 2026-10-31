"""Short-lived localhost helper that hosts Plaid Link so the owner can link Wealthsimple in their own browser.

Binds 127.0.0.1 on an ephemeral port, serves one page, accepts one successful token exchange, then exits
(or exits after a timeout). The owner's credentials and 2FA only ever go to Plaid inside Plaid Link.

In update mode (re-authenticating an existing Item) there is nothing to exchange: the page only reports success,
once, and nothing new is stored.
"""
import hmac
import json
import secrets as pysecrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app import secrets
from app.plaid_client import PlaidAPI, PlaidError
from app.redact import short_hash

PAGE = Path(__file__).parent / "static" / "link.html"
TIMEOUT_SECONDS = 600
_MAX_BODY = 8192
# What Plaid Link needs: its script and iframe from cdn.plaid.com, and calls to *.plaid.com
CSP = (
    "default-src 'none'; script-src 'self' https://cdn.plaid.com 'unsafe-inline'; "
    "connect-src 'self' https://*.plaid.com; frame-src https://cdn.plaid.com https://*.plaid.com; "
    "style-src 'unsafe-inline'; img-src https://*.plaid.com data:"
)


class StoreError(RuntimeError):
    """The keychain write failed after Plaid issued a token."""


def confirm_production(env: str, input_fn=input) -> bool:
    """Production Items permanently use one of the limited Trial slots, so require an explicit 'yes'."""
    if env != "production":
        return True
    print(
        "WARNING: you are linking in PRODUCTION. Each linked Item permanently uses one of the 10 "
        "Trial plan slots, even if you remove it later."
    )
    try:
        return input_fn('Type exactly "yes" (lowercase, nothing else) to continue: ') == "yes"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


class LinkServer(ThreadingHTTPServer):
    daemon_threads = True  # an idle connection must never keep the process or shutdown waiting

    def __init__(self, plaid: PlaidAPI, env: str, link_token: str, port: int = 0, update_item: str | None = None):
        super().__init__(("127.0.0.1", port), _Handler)
        self.plaid = plaid
        self.env = env
        self.link_token = link_token
        self.update_item = update_item  # set in update mode: the existing Item being re-authenticated
        self.state = pysecrets.token_urlsafe(32)
        self.item_id: str | None = None
        self._lock = threading.Lock()
        self._exchanged = False

    @property
    def port(self) -> int:
        return self.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def allowed_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}

    def handle_error(self, request, client_address) -> None:
        # The default prints a traceback, whose frames can hold tokens; the type name is enough
        print(f"Link helper: request failed ({getattr(sys.exc_info()[0], '__name__', 'error')}).", file=sys.stderr)

    def stop_soon(self) -> None:
        # shutdown() blocks until serve_forever returns, so it cannot run on the serving thread
        threading.Thread(target=self.shutdown, daemon=True).start()

    def run(self, timeout: float = TIMEOUT_SECONDS) -> str | None:
        """Serve until one exchange succeeds or the timeout passes. Returns the linked item id, if any."""
        timer = threading.Timer(timeout, self.shutdown)
        timer.daemon = True
        timer.start()
        try:
            self.serve_forever(poll_interval=0.1)
        finally:
            timer.cancel()
            self.server_close()
        return self.item_id

    def exchange(self, public_token: str) -> str:
        """Single use: the first success wins and later calls raise."""
        with self._lock:
            if self._exchanged:
                raise PermissionError("already exchanged")
            access_token, item_id = self.plaid.exchange_public_token(public_token)
            short = short_hash(item_id)
            try:
                secrets.set_access_token(self.env, item_id, access_token)
            except Exception:
                # Without a stored token the Item is orphaned (and burns a Trial slot), so release it
                print(f"WARNING: could not store the token for item {short} in the keychain.")
                try:
                    self.plaid.item_remove(access_token)
                except Exception:
                    print(f"WARNING: could not remove item {short} from Plaid either; remove it in the Plaid dashboard.")
                raise StoreError(short) from None
            self._exchanged = True
            self.item_id = item_id
        return item_id

    def complete_update(self) -> str:
        """Update mode: record the single success. No token changes hands and nothing is stored."""
        with self._lock:
            if self._exchanged or self.update_item is None:
                raise PermissionError("already completed")
            self._exchanged = True
            self.item_id = self.update_item
        return self.item_id


class _Handler(BaseHTTPRequestHandler):
    server: LinkServer
    timeout = 5  # seconds a connection may sit idle before its thread gives up

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass

    def _send(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self) -> bool:
        return (self.headers.get("Host") or "").lower() in self.server.allowed_hosts()

    def do_GET(self):
        if not self._host_ok():
            return self._send(400, b"bad host")
        if self.path != "/":
            return self._send(404, b"not found")
        config = json.dumps({"state": self.server.state, "link_token": self.server.link_token,
                             "update": self.server.update_item is not None})
        config = config.replace("<", "\\u003c")  # keep the JSON from closing the script element
        page = PAGE.read_text(encoding="utf-8").replace("__CONFIG__", config)
        self._send(200, page.encode(), "text/html; charset=utf-8")

    def do_POST(self):
        if not self._host_ok():
            return self._send(400, b"bad host")
        update = self.server.update_item is not None
        if self.path != ("/complete" if update else "/exchange"):
            return self._send(404, b"not found")
        origin = self.headers.get("Origin")
        if origin is not None and origin.removeprefix("http://") not in self.server.allowed_hosts():
            return self._send(403, b"forbidden")
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            return self._send(415, b"json required")
        try:
            length = int(self.headers.get("Content-Length", ""))
            if not 0 < length <= _MAX_BODY:
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            state = payload["state"]
            public_token = "" if update else payload["public_token"]
            if not isinstance(state, str) or not isinstance(public_token, str):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self._send(400, b"bad request")
        if not hmac.compare_digest(state.encode(), self.server.state.encode()):
            return self._send(403, b"forbidden")
        if update:
            try:
                item_id = self.server.complete_update()
            except PermissionError:
                return self._send(409, b"already completed")
            print(f"Re-authenticated item {short_hash(item_id)}. Nothing new was stored.")
            self.server.stop_soon()
            return self._send(200, b'{"ok": true}', "application/json")
        try:
            item_id = self.server.exchange(public_token)
        except PermissionError:
            return self._send(409, b"already linked")
        except StoreError:
            self.server.stop_soon()
            return self._send(500, b"could not store token")
        except PlaidError as exc:
            print(f"Plaid rejected the link: {exc.code}")
            return self._send(502, b"exchange failed")
        print(f"Linked item {short_hash(item_id)}. Token stored in the OS keychain.")
        self.server.stop_soon()  # before replying, so a broken pipe cannot keep the helper alive
        self._send(200, b'{"ok": true}', "application/json")


def run_link(plaid: PlaidAPI, env: str, input_fn=input, open_browser=webbrowser.open,
             timeout: float = TIMEOUT_SECONDS, port: int = 0, update: tuple[str, str] | None = None) -> int:
    """Link a new Item, or with update=(item_id, access_token) re-authenticate that existing Item in update mode,
    which creates no Item, so uses no Trial slot and needs no confirmation."""
    if update is None:
        if not confirm_production(env, input_fn):
            print("Cancelled; nothing linked.")
            return 1
        server = LinkServer(plaid, env, plaid.create_link_token(), port)
    else:
        item_id, access_token = update
        server = LinkServer(plaid, env, plaid.create_link_token(access_token), port, update_item=item_id)
        print(f"Update mode for item {short_hash(item_id)}: re-authenticating it; no new Item is created.")
    print(f"Opening {server.url} (expires in {int(timeout // 60)} minutes). Complete the link in your browser.")
    open_browser(server.url)
    if server.run(timeout) is None:
        print("Timed out without linking anything." if update is None else "Timed out; the item was not re-authenticated.")
        return 1
    return 0
