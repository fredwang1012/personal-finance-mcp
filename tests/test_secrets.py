import getpass

import pytest

from app import cli, secrets


def test_plaid_keys_round_trip():
    secrets.set_plaid_keys("sandbox", "cid-123", "sec-456")
    assert secrets.get_client_id() == "cid-123"
    assert secrets.get_plaid_secret("sandbox") == "sec-456"
    assert secrets.has_plaid_keys("sandbox")
    assert not secrets.has_plaid_keys("production")
    secrets.delete_plaid_keys("sandbox")
    assert not secrets.has_plaid_keys("sandbox")


def test_access_token_round_trip_and_item_list():
    secrets.set_access_token("sandbox", "item1", "tok-1")
    secrets.set_access_token("sandbox", "item1", "tok-1b")
    secrets.set_access_token("sandbox", "item2", "tok-2")
    assert secrets.get_access_token("sandbox", "item1") == "tok-1b"
    assert secrets.list_item_ids("sandbox") == ["item1", "item2"]
    assert secrets.list_item_ids("production") == []
    secrets.delete_access_token("sandbox", "item1")
    assert secrets.list_item_ids("sandbox") == ["item2"]
    secrets.delete_access_token("sandbox", "item1")  # deleting twice is harmless


def test_missing_secret_names_command_without_values():
    with pytest.raises(secrets.MissingSecret, match="python -m app.cli set-plaid-keys"):
        secrets.get_client_id()
    with pytest.raises(secrets.MissingSecret, match="plaid_secret_production"):
        secrets.get_plaid_secret("production")
    with pytest.raises(secrets.MissingSecret, match="python -m app.cli link"):
        secrets.get_access_token("sandbox", "nope")


def test_set_plaid_keys_prompts_and_status_hides_values(monkeypatch, capsys):
    answers = iter(["cid-SECRETVALUE", "sec-SECRETVALUE"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["set-plaid-keys"]) == 0
    secrets.set_access_token(cli.settings.plaid_env, "item1", "tok-SECRETVALUE")
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "SECRETVALUE" not in out
    assert "client_id stored: yes" in out
    assert "secret stored: yes" in out
    assert "linked items: 1" in out


def test_status_when_nothing_stored(capsys):
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "client_id stored: no" in out
    assert "linked items: 0" in out


def test_empty_input_stores_nothing(monkeypatch):
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "")
    assert cli.main(["set-plaid-keys"]) == 1
    assert not secrets.has_plaid_keys(cli.settings.plaid_env)


def test_delete_plaid_keys_keeps_shared_client_id():
    secrets.set_plaid_keys("sandbox", "cid", "sec-sb")
    secrets.set_plaid_keys("production", "cid", "sec-prod")
    secrets.delete_plaid_keys("sandbox")
    assert secrets.get_client_id() == "cid"
    assert secrets.has_plaid_keys("production")
    assert not secrets.has_plaid_keys("sandbox")


@pytest.mark.parametrize("raw", ["{not json", '{"a": 1}'])
def test_corrupt_linked_items_gives_friendly_error(memory_keyring, raw):
    memory_keyring.set_password(secrets.SERVICE, "linked_items_sandbox", raw)
    with pytest.raises(secrets.MissingSecret) as exc:
        secrets.list_item_ids("sandbox")
    assert secrets.LINK_CMD in str(exc.value)
    assert raw not in str(exc.value)
