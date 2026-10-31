import pytest

from app import cli, secrets
from app.plaid_client import PlaidError
from app.redact import short_hash as _short

ITEM_A, ITEM_B = "ITEMID-aaaa-marker", "ITEMID-bbbb-marker"
TOKEN_A, TOKEN_B = "access-sandbox-TOKEN-a", "access-sandbox-TOKEN-b"


class FakePlaid:
    def __init__(self, remove_error: PlaidError | None = None):
        self.removed: list[str] = []
        self.remove_error = remove_error

    def item_get(self, token):
        return {"item": {"institution_name": "Wealthsimple" if token == TOKEN_A else "Other Bank"}}

    def item_remove(self, token):
        if self.remove_error:
            raise self.remove_error
        self.removed.append(token)


@pytest.fixture
def linked():
    secrets.set_access_token("sandbox", ITEM_A, TOKEN_A)
    secrets.set_access_token("sandbox", ITEM_B, TOKEN_B)


def run(fake, short_id, answer="yes", env="sandbox"):
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        return answer

    return cli.run_unlink(lambda: fake, env, short_id, ask), prompts


def assert_clean(text):
    for marker in (ITEM_A, ITEM_B, TOKEN_A, TOKEN_B):
        assert marker not in text


def test_list_shows_short_ids_and_institutions(linked, capsys):
    code, prompts = run(FakePlaid(), None)
    out = capsys.readouterr().out
    assert code == 0 and prompts == []
    assert f"{_short(ITEM_A)}  Wealthsimple" in out and f"{_short(ITEM_B)}  Other Bank" in out
    assert_clean(out)


def test_list_without_keys_still_lists(linked, capsys):
    def no_keys():
        raise secrets.MissingSecret("Missing secret 'plaid_client_id'.")

    assert cli.run_unlink(no_keys, "sandbox", None) == 0
    out = capsys.readouterr().out
    assert f"{_short(ITEM_A)}  institution unknown" in out
    assert_clean(out)


def test_list_with_nothing_linked(capsys):
    assert run(FakePlaid(), None)[0] == 0
    assert "No linked items" in capsys.readouterr().out


def test_unlink_removes_at_plaid_and_locally(linked, capsys):
    fake = FakePlaid()
    code, prompts = run(fake, _short(ITEM_A).upper())
    captured = capsys.readouterr()
    assert code == 0 and fake.removed == [TOKEN_A]
    assert "Wealthsimple" in prompts[0] and '"yes"' in prompts[0]
    assert secrets.list_item_ids("sandbox") == [ITEM_B]
    assert not secrets.has_secret(f"access_token_sandbox_{ITEM_A}")
    assert secrets.get_access_token("sandbox", ITEM_B) == TOKEN_B
    assert "Trial" not in captured.out
    assert_clean(captured.out + captured.err + "".join(prompts))


def test_unlink_requires_typed_yes(linked, capsys):
    for answer in ("y", "YES", "", "yes "):
        fake = FakePlaid()
        code, _ = run(fake, _short(ITEM_A), answer)
        assert code == 1 and fake.removed == []
    assert secrets.get_access_token("sandbox", ITEM_A) == TOKEN_A
    assert "Cancelled" in capsys.readouterr().out


def test_item_not_found_still_cleans_up_locally(linked, capsys):
    fake = FakePlaid(PlaidError("ITEM_NOT_FOUND", "the requested item was not found"))
    assert run(fake, _short(ITEM_A))[0] == 0
    assert secrets.list_item_ids("sandbox") == [ITEM_B]
    assert not secrets.has_secret(f"access_token_sandbox_{ITEM_A}")
    assert "no longer knows" in capsys.readouterr().out


@pytest.mark.parametrize("error", [PlaidError("INTERNAL_SERVER_ERROR", "try again"), TimeoutError("slow")])
def test_other_failures_keep_the_token(linked, capsys, error):
    fake = FakePlaid(error)
    assert run(fake, _short(ITEM_A))[0] == 1
    assert secrets.get_access_token("sandbox", ITEM_A) == TOKEN_A
    assert secrets.list_item_ids("sandbox") == [ITEM_A, ITEM_B]
    out = capsys.readouterr().out
    assert "kept" in out
    assert_clean(out)


def test_unknown_short_id_is_not_echoed(linked, capsys):
    code, prompts = run(FakePlaid(), ITEM_A)  # a raw item id pasted by mistake
    captured = capsys.readouterr()
    assert code == 1 and prompts == []
    assert_clean(captured.out + captured.err)
    assert secrets.list_item_ids("sandbox") == [ITEM_A, ITEM_B]


def test_production_reminds_that_the_trial_slot_is_not_freed(capsys):
    secrets.set_access_token("production", ITEM_A, TOKEN_A)
    assert run(FakePlaid(), _short(ITEM_A), env="production")[0] == 0
    out = capsys.readouterr().out
    assert "Trial" in out and "not freed" in out


def test_listed_item_without_token_is_removed_locally(capsys):
    secrets._save_items("sandbox", [ITEM_A])
    fake = FakePlaid()
    assert run(fake, _short(ITEM_A))[0] == 0
    assert fake.removed == [] and secrets.list_item_ids("sandbox") == []
    assert_clean(capsys.readouterr().out)


def test_main_parses_unlink(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "unlink", lambda item, local_only=False: seen.append((item, local_only)) or 0)
    assert cli.main(["unlink"]) == 0 and cli.main(["unlink", "abcd1234"]) == 0
    assert cli.main(["unlink", "abcd1234", "--local-only"]) == 0
    assert seen == [(None, False), ("abcd1234", False), ("abcd1234", True)]
    with pytest.raises(SystemExit):
        cli.main(["unlink", "--local-only"])


def failing_delete(memory_keyring, monkeypatch):
    def delete_password(service, username):
        # a real backend's message can name the entry, which embeds the raw item id
        raise RuntimeError(f"cannot delete {service}/{username}")

    monkeypatch.setattr(memory_keyring, "delete_password", delete_password)


def test_local_cleanup_failure_after_plaid_removal_is_reported_without_ids(linked, memory_keyring, monkeypatch, capsys):
    failing_delete(memory_keyring, monkeypatch)
    fake = FakePlaid()
    code, prompts = run(fake, _short(ITEM_A))
    captured = capsys.readouterr()
    assert code == 1 and fake.removed == [TOKEN_A]
    assert "removed at Plaid; local cleanup failed" in captured.out and "run unlink again to finish" in captured.out
    assert "RuntimeError" in captured.out and "cannot delete" not in captured.out
    assert_clean(captured.out + captured.err + "".join(prompts))


def test_main_does_not_leak_a_traceback_on_cleanup_failure(linked, memory_keyring, monkeypatch, capsys):
    failing_delete(memory_keyring, monkeypatch)
    monkeypatch.setattr(cli, "unlink", lambda item, local_only=False: cli.run_unlink(
        lambda: FakePlaid(), "sandbox", item, lambda _: "yes", local_only))
    assert cli.main(["unlink", _short(ITEM_A)]) == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert_clean(captured.out + captured.err)


def test_rerun_after_plaid_removal_cleans_up_on_invalid_access_token(linked, capsys):
    fake = FakePlaid(PlaidError("INVALID_ACCESS_TOKEN", "the provided access token is invalid"))
    assert run(fake, _short(ITEM_A))[0] == 0
    assert secrets.list_item_ids("sandbox") == [ITEM_B]
    assert not secrets.has_secret(f"access_token_sandbox_{ITEM_A}")
    out = capsys.readouterr().out
    assert "no longer knows" in out and "INVALID_ACCESS_TOKEN" in out
    assert_clean(out)


def test_local_only_deletes_locally_without_calling_plaid(linked, capsys):
    def no_plaid():
        raise AssertionError("--local-only must not contact Plaid")

    prompts = []
    code = cli.run_unlink(no_plaid, "sandbox", _short(ITEM_A), lambda p: prompts.append(p) or "yes", local_only=True)
    captured = capsys.readouterr()
    assert code == 0 and '"yes"' in prompts[0]
    assert "does NOT revoke" in captured.out
    assert secrets.list_item_ids("sandbox") == [ITEM_B]
    assert not secrets.has_secret(f"access_token_sandbox_{ITEM_A}")
    assert secrets.get_access_token("sandbox", ITEM_B) == TOKEN_B
    assert_clean(captured.out + captured.err + "".join(prompts))


def test_local_only_requires_typed_yes(linked, capsys):
    assert cli.run_unlink(lambda: FakePlaid(), "sandbox", _short(ITEM_A), lambda _: "y", local_only=True) == 1
    assert secrets.get_access_token("sandbox", ITEM_A) == TOKEN_A
    assert "Cancelled" in capsys.readouterr().out


def test_local_only_cleanup_failure_is_reported_without_ids(linked, memory_keyring, monkeypatch, capsys):
    failing_delete(memory_keyring, monkeypatch)
    assert cli.run_unlink(lambda: FakePlaid(), "sandbox", _short(ITEM_A), lambda _: "yes", local_only=True) == 1
    captured = capsys.readouterr()
    assert "local cleanup failed" in captured.out and "removed at Plaid" not in captured.out
    assert_clean(captured.out + captured.err)


@pytest.mark.parametrize("local_only", [False, True])
@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt])
def test_interrupted_prompt_cancels(linked, capsys, error, local_only):
    fake = FakePlaid()

    def ask(_prompt):
        raise error

    assert cli.run_unlink(lambda: fake, "sandbox", _short(ITEM_A), ask, local_only=local_only) == 1
    assert fake.removed == [] and secrets.get_access_token("sandbox", ITEM_A) == TOKEN_A
    assert "Cancelled" in capsys.readouterr().out


def test_main_parses_link_update(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "link", lambda port=0, update_short=None: seen.append((port, update_short)) or 0)
    assert cli.main(["link"]) == 0 and cli.main(["link", "--update", "abcd1234"]) == 0
    assert seen == [(0, None), (0, "abcd1234")]


def test_link_update_resolves_item_and_stores_nothing_new(linked, monkeypatch, capsys):
    from app import link as link_mod

    calls = []
    monkeypatch.setattr(link_mod, "run_link", lambda api, env, port=0, update=None: calls.append(update) or 0)
    assert cli.run_link_cli(lambda: FakePlaid(), "sandbox", update_short=_short(ITEM_B).upper()) == 0
    assert calls == [(ITEM_B, TOKEN_B)]
    assert sorted(secrets.list_item_ids("sandbox")) == sorted([ITEM_A, ITEM_B])
    assert_clean(capsys.readouterr().out)


def test_link_update_unknown_or_tokenless_item_is_refused(monkeypatch, capsys):
    from app import link as link_mod

    monkeypatch.setattr(link_mod, "run_link", lambda *a, **k: pytest.fail("must not start Link"))
    secrets._save_items("sandbox", [ITEM_A])  # listed, but no token stored
    assert cli.run_link_cli(lambda: FakePlaid(), "sandbox", update_short=ITEM_A) == 1  # raw id is not a short id
    assert cli.run_link_cli(lambda: FakePlaid(), "sandbox", update_short=_short(ITEM_A)) == 1
    captured = capsys.readouterr()
    assert_clean(captured.out + captured.err)


def test_link_update_drives_update_mode_end_to_end(linked, capsys):
    class LinkFake(FakePlaid):
        def create_link_token(self, access_token=None):
            self.token_for = access_token
            return "link-sandbox-update"

    fake = LinkFake()
    code = cli.run_link_cli(lambda: fake, "sandbox", update_short=_short(ITEM_A), open_browser=lambda _url: None,
                            timeout=0.2)
    assert code == 1 and fake.token_for == TOKEN_A  # timed out after starting Link in update mode
    assert_clean(capsys.readouterr().out)


def test_link_unexpected_error_prints_type_only(capsys):
    class Broken(FakePlaid):
        def create_link_token(self, access_token=None):
            raise ConnectionError(f"failed to reach plaid with {TOKEN_A}")

    assert cli.run_link_cli(lambda: Broken(), "sandbox") == 1
    captured = capsys.readouterr()
    assert "ConnectionError" in captured.err and TOKEN_A not in captured.out + captured.err
    assert "Traceback" not in captured.err
