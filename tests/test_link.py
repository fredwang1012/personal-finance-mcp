import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

import keyring

from app import link, secrets, tools
from app.plaid_client import PRODUCTS, PlaidError


class FakePlaid:
    def __init__(self, fail_with: PlaidError | None = None):
        self.exchanged: list[str] = []
        self.fail_with = fail_with

    def create_link_token(self):
        return "link-sandbox-fake"

    def exchange_public_token(self, public_token):
        if self.fail_with:
            raise self.fail_with
        self.exchanged.append(public_token)
        return "access-sandbox-fake", "item-1"


@pytest.fixture
def helper():
    fake = FakePlaid()
    server = link.LinkServer(fake, "sandbox", fake.create_link_token())
    thread = threading.Thread(target=server.run, args=(30,), daemon=True)
    thread.start()
    yield server, fake, thread
    if thread.is_alive():
        server.shutdown()
        thread.join(5)


def request(server, path="/exchange", body=None, host=None, content_type="application/json", method="POST",
            origin=None):
    headers = {"Host": host or f"127.0.0.1:{server.port}"}
    if origin is not None:
        headers["Origin"] = origin
    if content_type:
        headers["Content-Type"] = content_type
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(f"http://127.0.0.1:{server.port}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def test_products_are_read_only_pair():
    assert PRODUCTS == ["investments", "transactions"]


def test_binds_loopback_and_page_embeds_state(helper):
    server, _, _ = helper
    assert server.server_address[0] == "127.0.0.1"
    status, body = request(server, "/", method="GET", content_type=None)
    page = body.decode()
    assert status == 200
    assert server.state in page and "link-sandbox-fake" in page
    assert "https://cdn.plaid.com/link/v2/stable/link-initialize.js" in page
    assert "textContent" in page and "innerHTML" not in page
    assert len(server.state) >= 32


def test_exchange_stores_token_in_keychain_then_shuts_down(helper):
    server, fake, thread = helper
    status, _ = request(server, body={"state": server.state, "public_token": "public-x"})
    assert status == 200
    assert fake.exchanged == ["public-x"]
    assert secrets.get_access_token("sandbox", "item-1") == "access-sandbox-fake"
    assert secrets.list_item_ids("sandbox") == ["item-1"]
    thread.join(5)
    assert not thread.is_alive()
    assert server.item_id == "item-1"


def test_wrong_state_is_forbidden(helper):
    server, fake, _ = helper
    status, _ = request(server, body={"state": "nope", "public_token": "public-x"})
    assert status == 403
    assert fake.exchanged == []
    assert secrets.list_item_ids("sandbox") == []


def test_wrong_host_is_rejected(helper):
    server, fake, _ = helper
    good = {"state": server.state, "public_token": "public-x"}
    assert request(server, body=good, host="evil.example")[0] == 400
    assert request(server, body=good, host="127.0.0.1:1")[0] == 400
    assert request(server, "/", method="GET", content_type=None, host="evil.example")[0] == 400
    assert fake.exchanged == []


def test_localhost_host_header_is_accepted(helper):
    server, fake, _ = helper
    status, _ = request(server, body={"state": server.state, "public_token": "p"}, host=f"localhost:{server.port}")
    assert status == 200


def test_requires_json_content_type_and_valid_body(helper):
    server, fake, _ = helper
    good = {"state": server.state, "public_token": "p"}
    assert request(server, body=good, content_type="text/plain")[0] == 415
    assert request(server, body=good, content_type=None)[0] == 415
    assert request(server, body=b"not json")[0] == 400
    assert request(server, body={"state": server.state})[0] == 400
    assert fake.exchanged == []


def test_second_exchange_refused():
    fake = FakePlaid()
    server = link.LinkServer(fake, "sandbox", "t")
    try:
        server.exchange("p1")
        with pytest.raises(PermissionError):
            server.exchange("p2")
        assert fake.exchanged == ["p1"]
    finally:
        server.server_close()


def test_plaid_failure_does_not_consume_the_link(helper):
    server, fake, thread = helper
    fake.fail_with = PlaidError("INVALID_PUBLIC_TOKEN", "bad token")
    body = {"state": server.state, "public_token": "p"}
    status, payload = request(server, body=body)
    assert status == 502 and b"INVALID" not in payload
    fake.fail_with = None
    assert request(server, body=body)[0] == 200


def test_times_out_and_shuts_down():
    server = link.LinkServer(FakePlaid(), "sandbox", "t")
    result = []
    thread = threading.Thread(target=lambda: result.append(server.run(0.3)), daemon=True)
    thread.start()
    thread.join(5)
    assert not thread.is_alive()
    assert result == [None]


def test_production_requires_typed_yes():
    answers = iter(["y"])
    assert not link.confirm_production("production", lambda _: next(answers))
    assert not link.confirm_production("production", lambda _: "YES")
    assert link.confirm_production("production", lambda _: "yes")
    assert link.confirm_production("sandbox", lambda _: pytest.fail("must not prompt in sandbox"))


def test_production_warning_text(capsys):
    link.confirm_production("production", lambda _: "no")
    out = capsys.readouterr().out
    assert "10" in out and "Trial" in out and "permanently" in out


def test_run_link_declined_production_never_opens_browser():
    opened = []
    code = link.run_link(FakePlaid(), "production", input_fn=lambda _: "no", open_browser=opened.append)
    assert code == 1 and opened == []


def test_run_link_times_out_with_failure_code():
    opened = []
    code = link.run_link(FakePlaid(), "sandbox", open_browser=opened.append, timeout=0.2)
    assert code == 1 and len(opened) == 1 and opened[0].startswith("http://127.0.0.1:")


def test_origin_checks(helper):
    server, fake, _ = helper
    body = {"state": server.state, "public_token": "p"}
    assert request(server, body=body, origin="http://evil.example")[0] == 403
    assert request(server, body=body, origin="null")[0] == 403
    assert fake.exchanged == []
    assert request(server, body=body, origin=f"http://127.0.0.1:{server.port}")[0] == 200


def test_oversize_body_rejected(helper):
    server, fake, _ = helper
    big = {"state": server.state, "public_token": "p" * (link._MAX_BODY + 1)}
    assert request(server, body=big)[0] == 400
    assert fake.exchanged == []


def test_host_header_is_case_insensitive(helper):
    server, _, _ = helper
    assert request(server, "/", method="GET", content_type=None, host=f"LocalHost:{server.port}")[0] == 200


def test_page_has_csp_allowing_only_plaid(helper):
    server, _, _ = helper
    req = urllib.request.Request(server.url, headers={"Host": f"127.0.0.1:{server.port}"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "https://cdn.plaid.com" in csp


def test_idle_socket_does_not_stall_server(helper):
    server, fake, thread = helper
    idle = socket.create_connection(("127.0.0.1", server.port))
    try:
        assert request(server, "/", method="GET", content_type=None)[0] == 200
        started = time.monotonic()
        server.shutdown()
        thread.join(5)
        assert not thread.is_alive() and time.monotonic() - started < 3
    finally:
        idle.close()


def test_timeout_with_idle_socket_still_stops():
    server = link.LinkServer(FakePlaid(), "sandbox", "t")
    idle = socket.create_connection(("127.0.0.1", server.port))
    thread = threading.Thread(target=server.run, args=(0.3,), daemon=True)
    thread.start()
    thread.join(5)
    idle.close()
    assert not thread.is_alive()


def test_keychain_failure_removes_orphaned_item(helper, monkeypatch, capsys):
    server, fake, thread = helper
    removed = []
    fake.item_remove = removed.append

    def broken(*_a, **_k):
        raise keyring.errors.KeyringError("locked")

    monkeypatch.setattr(secrets, "set_access_token", broken)
    status, _ = request(server, body={"state": server.state, "public_token": "p"})
    assert status == 500
    assert removed == ["access-sandbox-fake"]
    out = capsys.readouterr().out
    assert tools._short("item-1") in out and "item-1" not in out and "access-sandbox-fake" not in out
    assert server.item_id is None
    thread.join(5)
    assert not thread.is_alive()


def test_fixed_port_still_binds_loopback():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = link.LinkServer(FakePlaid(), "sandbox", "t", port)
    try:
        assert server.server_address == ("127.0.0.1", port)
    finally:
        server.server_close()
