"""End to end: run `python -m app.server` as a subprocess and talk MCP over stdio (newline-delimited JSON-RPC).

The server runs in the guarded test mode (PFMCP_FAKE_PLAID=1, PYTEST_CURRENT_TEST set, DATA_DIR inside pytest's temp
tree): fake Plaid,
in-memory keyring. PYTHON_KEYRING_BACKEND points at keyring's always-failing backend as a second fence, so any
attempt to open the real OS keychain would fail instead of reading it.
"""
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from app import testmode, tools
from app.config import ROOT

TIMEOUT = 20  # seconds per response
FAIL_KEYRING = "keyring.backends.fail.Keyring"
TOOLS = {"accounts", "holdings", "transactions", "summary", "health"}


class StdioClient:
    def __init__(self, data_dir: Path, fake: bool | str = True, under_pytest: bool = True):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PLAID_", "PFMCP_", "PYTEST_"))}
        env.update(DATA_DIR=str(data_dir), PLAID_ENV="sandbox", PYTHON_KEYRING_BACKEND=FAIL_KEYRING,
                   PYTHONUNBUFFERED="1")
        if fake:
            env["PFMCP_FAKE_PLAID"] = "1" if fake is True else fake
        if under_pytest:  # the guard also wants this; passed on explicitly rather than by inheritance
            env["PYTEST_CURRENT_TEST"] = os.environ["PYTEST_CURRENT_TEST"]
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "app.server"], cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.lines: queue.Queue = queue.Queue()
        self.stderr: list[bytes] = []
        threading.Thread(target=self._pump, args=(self.proc.stdout, self.lines.put), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.proc.stderr, self.stderr.append), daemon=True).start()
        self._id = 0

    @staticmethod
    def _pump(stream, sink):
        for line in iter(stream.readline, b""):
            sink(line)

    def send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message).encode() + b"\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self.send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        while True:
            try:
                line = self.lines.get(timeout=TIMEOUT)
            except queue.Empty:
                raise AssertionError(f"no reply to {method} within {TIMEOUT}s; stderr: {b''.join(self.stderr)!r}")
            message = json.loads(line)
            if message.get("id") == self._id:
                return message

    def close(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            pass
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait(timeout=TIMEOUT)
            self.proc.stdout.close()
            self.proc.stderr.close()


def handshake(client: StdioClient) -> dict:
    init = client.request("initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "e2e-test", "version": "0"},
    })
    client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return init


@pytest.fixture
def client(tmp_path):
    c = StdioClient(tmp_path / "data")
    yield c
    c.close()


def test_stdio_server_end_to_end(client, tmp_path):
    init = handshake(client)
    assert "error" not in init
    assert init["result"]["serverInfo"]["name"] == "personal-finance-mcp"
    assert "tools" in init["result"]["capabilities"]

    listed = client.request("tools/list")["result"]["tools"]
    assert {t["name"] for t in listed} == TOOLS
    for t in listed:
        a = t["annotations"]
        assert (a["readOnlyHint"], a["destructiveHint"], a["idempotentHint"], a["openWorldHint"]) == (
            True, False, True, True), t["name"]
    assert "untrusted" in init["result"]["instructions"]

    call = client.request("tools/call", {"name": "accounts", "arguments": {}})["result"]
    assert not call.get("isError")
    assert "structuredContent" not in call and len(call["content"]) == 1  # one compact text block, nothing doubled
    text = call["content"][0]["text"]
    assert chr(10) not in text
    payload = json.loads(text)
    assert payload == {"accounts": [{
        "id": payload["accounts"][0]["id"], "name": "TFSA", "account_kind": "tfsa", "kind_basis": "subtype",
        "tax": "tax-free", "last4": "0001", "currency": "CAD", "balance": "1234.56", "cash_estimate": "109.56",
    }], "fx": {"pair": "USDCAD", "rate": "1.25", "date": "2024-01-02", "source": "Bank of Canada"},
        "notes": [tools.US_LISTED_NOTE, tools.CASH_NOTE]}
    # 1234.56 - 1000 CAD - 100 USD x 1.25: the fake rate was used, so the Bank of Canada was never called; and there is
    # no keychain failure note, so the in-memory keyring was used
    for name, args in [("holdings", {"detail": "full"}), ("transactions", {"detail": "full"}), ("summary", {}),
                       ("health", {})]:
        result = client.request("tools/call", {"name": name, "arguments": args})["result"]
        assert not result.get("isError") and "error" not in json.loads(result["content"][0]["text"]), name
        call["content"].append(result["content"][0])
    blob = json.dumps(call)
    assert testmode.FAKE_TOKEN not in blob and testmode.FAKE_ITEM not in blob and "fake-account" not in blob
    assert (tmp_path / "data" / "finance.db").exists()  # the store was created in the temp DATA_DIR only


HOSTILE_MARKERS = [testmode.FAKE_TOKEN, testmode.FAKE_ITEM, "fake-account", "fake-secret", "fake-client-id",
                   "evil.example", "access-sandbox"]  # injected phrases may remain, shortened


def test_stdio_hostile_plaid_text_never_reaches_output(tmp_path):
    c = StdioClient(tmp_path / "data", fake="hostile")
    try:
        handshake(c)
        calls = [("accounts", {}), ("accounts", {"detail": "full"}), ("holdings", {}), ("holdings", {"detail": "full"}),
                 ("transactions", {}), ("transactions", {"detail": "full", "limit": 200}), ("summary", {}),
                 ("health", {})]
        blob = ""
        for name, args in calls:
            result = c.request("tools/call", {"name": name, "arguments": args})["result"]
            payload = json.loads(result["content"][0]["text"])
            assert not result.get("isError") and "error" not in payload, name
            blob += result["content"][0]["text"]
        assert "Wealthsimple" not in blob or "WS" in blob  # the hostile fake really ran
        assert '"security_type":"other"' in blob and "[link]" in blob and "[email]" in blob
        # the derived fields ran on hostile data too
        assert '"account_kind":"tfsa"' in blob and '"cash_estimate"' in blob and '"by_kind"' in blob
        for marker in HOSTILE_MARKERS:
            assert marker not in blob, marker
    finally:
        c.close()


def assert_fake_mode_off(c: StdioClient) -> None:
    # with the failing keyring backend the server reports a keychain problem instead of fake data
    handshake(c)
    call = c.request("tools/call", {"name": "accounts", "arguments": {}})["result"]
    payload = json.loads(call["content"][0]["text"])
    assert "accounts" not in payload
    assert any("Keychain or Plaid setup failed" in n for n in payload["notes"])
    assert b"PFMCP_FAKE_PLAID ignored" in b"".join(c.stderr)  # printed before the server answers


def test_switch_is_ignored_outside_pytest_temp():
    # a temp dir that is not under pytest-of-<user>: fake mode must stay off
    with tempfile.TemporaryDirectory(prefix="pfmcp-e2e-") as tmp:
        c = StdioClient(Path(tmp) / "data")
        try:
            assert_fake_mode_off(c)
        finally:
            c.close()


def test_switch_is_ignored_without_pytest_marker(tmp_path):
    # a pytest temp DATA_DIR alone is not enough: PYTEST_CURRENT_TEST must be set too
    c = StdioClient(tmp_path / "data", under_pytest=False)
    try:
        assert_fake_mode_off(c)
    finally:
        c.close()


def test_guard(tmp_path, monkeypatch):
    assert testmode.allowed(tmp_path)
    assert not testmode.allowed(ROOT / "data")
    assert not testmode.allowed(Path(tempfile.gettempdir()))
    assert not testmode.allowed(Path(tempfile.gettempdir()) / "elsewhere" / "pytest-of-x")
    assert not testmode.allowed(ROOT / "pytest-of-x")
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    assert not testmode.allowed(tmp_path)
