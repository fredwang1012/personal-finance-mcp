"""Plaid credentials and access tokens, stored only in the OS keychain via keyring.

The list of linked item ids is not secret, but is kept in the keychain too so no state lands in plain files.
"""
import json

import keyring
from keyring.errors import PasswordDeleteError

SERVICE = "personal-finance-mcp"
SET_KEYS_CMD = "python -m app.cli set-plaid-keys"
LINK_CMD = "python -m app.cli link"
_ITEMS_KEY = "linked_items"


class MissingSecret(RuntimeError):
    """A required secret is absent. The message names the command that stores it and never contains a value."""


def _get(name: str, fix: str) -> str:
    value = keyring.get_password(SERVICE, name)
    if not value:
        raise MissingSecret(f"Missing secret '{name}'. Run: {fix}")
    return value


def _set(name: str, value: str) -> None:
    keyring.set_password(SERVICE, name, value)


def _delete(name: str) -> None:
    try:
        keyring.delete_password(SERVICE, name)
    except PasswordDeleteError:
        pass  # already absent


def has_secret(name: str) -> bool:
    return bool(keyring.get_password(SERVICE, name))


def _secret_key(env: str) -> str:
    return f"plaid_secret_{env}"


def _token_key(env: str, item_id: str) -> str:
    return f"access_token_{env}_{item_id}"


def get_client_id() -> str:
    return _get("plaid_client_id", SET_KEYS_CMD)


def get_plaid_secret(env: str) -> str:
    return _get(_secret_key(env), SET_KEYS_CMD)


def set_plaid_keys(env: str, client_id: str, secret: str) -> None:
    _set("plaid_client_id", client_id)
    _set(_secret_key(env), secret)


def delete_plaid_keys(env: str) -> None:
    # client_id is shared across environments, so only this environment's secret is removed
    _delete(_secret_key(env))


def has_plaid_keys(env: str) -> bool:
    return has_secret("plaid_client_id") and has_secret(_secret_key(env))


def get_access_token(env: str, item_id: str) -> str:
    return _get(_token_key(env, item_id), LINK_CMD)


def set_access_token(env: str, item_id: str, token: str) -> None:
    _set(_token_key(env, item_id), token)
    ids = list_item_ids(env)
    if item_id not in ids:
        _save_items(env, ids + [item_id])


def delete_access_token(env: str, item_id: str) -> None:
    _delete(_token_key(env, item_id))
    _save_items(env, [i for i in list_item_ids(env) if i != item_id])


def list_item_ids(env: str) -> list[str]:
    raw = keyring.get_password(SERVICE, f"{_ITEMS_KEY}_{env}")
    if not raw:
        return []
    try:
        ids = json.loads(raw)
    except json.JSONDecodeError:
        ids = None
    if not isinstance(ids, list):
        raise MissingSecret(
            f"The stored list of linked items for '{env}' is corrupt. Run: {LINK_CMD} to link again "
            f"(this replaces the list)."
        ) from None
    return ids


def _save_items(env: str, ids: list[str]) -> None:
    _set(f"{_ITEMS_KEY}_{env}", json.dumps(ids))
