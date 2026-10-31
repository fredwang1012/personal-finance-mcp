import json
import re
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

import keyring

from app import link, secrets
from app.redact import short_hash
from app.plaid_client import PRODUCTS, PlaidError


class FakePlaid:
    def __init__(self, fail_with: PlaidError | None = None):
        self.exchanged: list[str] = []
        self.fail_with = fail_with

    def create_link_token(self, access_token=None):
        self.link_token_for = access_token
        return "link-sandbox-update" if access_token else "link-sandbox-fake"

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
            origin=None, raw=False):
    """Paths are under the helper's path secret unless raw=True."""
    if not raw:
        path = server.route(path.lstrip("/"))
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


def test_products_are_investments_only():
    assert PRODUCTS == ["investments"]


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
        page = resp.read().decode()
    assert "default-src 'none'" in csp and "https://cdn.plaid.com" in csp
    assert "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    nonce = re.search(r"'nonce-([\w-]+)'", csp).group(1)
    assert page.count(f'<script nonce="{nonce}"') == 2 and "__NONCE__" not in page
    with urllib.request.urlopen(urllib.request.Request(server.url), timeout=5) as resp:
        assert nonce not in resp.headers["Content-Security-Policy"]  # fresh per response


def test_every_route_needs_the_path_secret(helper):
    server, fake, _ = helper
    assert server.url.endswith(server.route()) and len(server.path_secret) >= 24
    good = {"state": server.state, "public_token": "public-x"}
    for path in ("/", "/exchange", "/complete", "/link.html", f"/{server.path_secret}", f"/x{server.path_secret}/",
                 f"/{server.path_secret}/x", f"/{server.path_secret[:-1]}/"):
        status, body = request(server, path, method="GET", content_type=None, raw=True)
        assert (status, body) == (404, b"not found"), path
        assert server.state.encode() not in body and b"link-sandbox" not in body
    for path in ("/exchange", f"/{server.path_secret[:-1]}/exchange", f"/{server.path_secret}/complete"):
        assert request(server, path, body=good, raw=True)[0] == 404, path
    assert fake.exchanged == []
    assert request(server, body=good)[0] == 200


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
    assert short_hash("item-1") in out and "item-1" not in out and "access-sandbox-fake" not in out
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


def test_production_prompt_interrupted_cancels(capsys):
    for error in (EOFError, KeyboardInterrupt):
        def ask(_prompt, error=error):
            raise error

        opened = []
        assert link.run_link(FakePlaid(), "production", input_fn=ask, open_browser=opened.append) == 1
        assert opened == [] and "cancelled" in capsys.readouterr().out.lower()


@pytest.fixture
def update_helper():
    fake = FakePlaid()
    server = link.LinkServer(fake, "sandbox", fake.create_link_token("access-sandbox-old"), update_item="item-old")
    thread = threading.Thread(target=server.run, args=(30,), daemon=True)
    thread.start()
    yield server, fake, thread
    if thread.is_alive():
        server.shutdown()
        thread.join(5)


def test_update_mode_completes_without_exchange_and_stores_nothing(update_helper, capsys):
    server, fake, thread = update_helper
    status, body = request(server, "/", method="GET", content_type=None)
    assert status == 200 and b'"update": true' in body and b"link-sandbox-update" in body
    assert request(server, body={"state": server.state, "public_token": "p"})[0] == 404  # no /exchange in update mode
    assert request(server, "/complete", body={"state": server.state})[0] == 200
    thread.join(5)
    assert not thread.is_alive() and server.item_id == "item-old"
    assert fake.exchanged == [] and secrets.list_item_ids("sandbox") == []
    out = capsys.readouterr().out
    assert short_hash("item-old") in out and "item-old" not in out


def test_update_mode_keeps_helper_checks(update_helper):
    server, _, thread = update_helper
    good = {"state": server.state}
    assert request(server, "/complete", body={"state": "nope"})[0] == 403
    assert request(server, "/complete", body=good, host="evil.example")[0] == 400
    assert request(server, "/complete", body=good, origin="http://evil.example")[0] == 403
    assert request(server, "/complete", body=good, content_type="text/plain")[0] == 415
    assert server.item_id is None and thread.is_alive()
    server.complete_update()
    with pytest.raises(PermissionError):  # one-shot
        server.complete_update()


def test_new_link_server_refuses_update_completion():
    server = link.LinkServer(FakePlaid(), "sandbox", "t")
    try:
        with pytest.raises(PermissionError):
            server.complete_update()
    finally:
        server.server_close()


def test_run_link_update_mode_uses_access_token_and_skips_confirmation():
    fake, opened = FakePlaid(), []
    code = link.run_link(fake, "production", input_fn=lambda _: pytest.fail("update mode must not prompt"),
                         open_browser=opened.append, timeout=0.2, update=("item-old", "access-sandbox-old"))
    assert code == 1 and len(opened) == 1  # timed out, but the page was opened in update mode
    assert fake.link_token_for == "access-sandbox-old"


def test_handler_errors_log_type_only(capsys):
    server = link.LinkServer(FakePlaid(), "sandbox", "t")
    try:
        try:
            raise ValueError("access-sandbox-secret in a message")
        except ValueError:
            server.handle_error(None, ("127.0.0.1", 1))
    finally:
        server.server_close()
    captured = capsys.readouterr()
    assert "ValueError" in captured.err and "access-sandbox-secret" not in captured.err
    assert "Traceback" not in captured.err and captured.out == ""
