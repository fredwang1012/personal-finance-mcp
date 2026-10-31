"""Short-lived localhost helper that hosts Plaid Link so the owner can link Wealthsimple in their own browser.

Binds 127.0.0.1 on an ephemeral port, serves one page, accepts one successful token exchange, then exits
(or exits after a timeout). The owner's credentials and 2FA only ever go to Plaid inside Plaid Link.
"""
import hmac
import json
import secrets as pysecrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from app import secrets
from app.plaid_client import PlaidAPI, PlaidError

PAGE = Path(__file__).parent / "static" / "link.html"
TIMEOUT_SECONDS = 600
_MAX_BODY = 8192


def confirm_production(env: str, input_fn=input) -> bool:
    """Production Items permanently use one of the limited Trial slots, so require an explicit 'yes'."""
    if env != "production":
        return True
    print(
        "WARNING: you are linking in PRODUCTION. Each linked Item permanently uses one of the 10 "
        "Trial plan slots, even if you remove it later."
    )
    return input_fn("Type exactly 'yes' to continue: ") == "yes"


class LinkServer(HTTPServer):
    def __init__(self, plaid: PlaidAPI, env: str, link_token: str):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.plaid = plaid
        self.env = env
        self.link_token = link_token
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
            secrets.set_access_token(self.env, item_id, access_token)
            self._exchanged = True
            self.item_id = item_id
        return item_id


class _Handler(BaseHTTPRequestHandler):
    server: LinkServer

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass

    def _send(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self) -> bool:
        return self.headers.get("Host") in self.server.allowed_hosts()

    def do_GET(self):
        if not self._host_ok():
            return self._send(400, b"bad host")
        if self.path != "/":
            return self._send(404, b"not found")
        config = json.dumps({"state": self.server.state, "link_token": self.server.link_token})
        config = config.replace("<", "\\u003c")  # keep the JSON from closing the script element
        page = PAGE.read_text(encoding="utf-8").replace("__CONFIG__", config)
        self._send(200, page.encode(), "text/html; charset=utf-8")

    def do_POST(self):
        if not self._host_ok():
            return self._send(400, b"bad host")
        if self.path != "/exchange":
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
            state, public_token = payload["state"], payload["public_token"]
            if not isinstance(state, str) or not isinstance(public_token, str):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self._send(400, b"bad request")
        if not hmac.compare_digest(state.encode(), self.server.state.encode()):
            return self._send(403, b"forbidden")
        try:
            item_id = self.server.exchange(public_token)
        except PermissionError:
            return self._send(409, b"already linked")
        except PlaidError as exc:
            print(f"Plaid rejected the link: {exc.code}")
            return self._send(502, b"exchange failed")
        print(f"Linked item {item_id}. Token stored in the OS keychain.")
        self._send(200, b'{"ok": true}', "application/json")
        self.server.stop_soon()


def run_link(plaid: PlaidAPI, env: str, input_fn=input, open_browser=webbrowser.open,
             timeout: float = TIMEOUT_SECONDS) -> int:
    if not confirm_production(env, input_fn):
        print("Cancelled; nothing linked.")
        return 1
    server = LinkServer(plaid, env, plaid.create_link_token())
    print(f"Opening {server.url} (expires in {int(timeout // 60)} minutes). Complete the link in your browser.")
    open_browser(server.url)
    item_id = server.run(timeout)
    if item_id is None:
        print("Timed out without linking anything.")
        return 1
    return 0
