import pytest

from app import cli, secrets
from app.plaid_client import PlaidError
from app.tools import _short

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
    monkeypatch.setattr(cli, "unlink", lambda item: seen.append(item) or 0)
    assert cli.main(["unlink"]) == 0 and cli.main(["unlink", "abcd1234"]) == 0
    assert seen == [None, "abcd1234"]
