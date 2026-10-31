"""Secrets: Plaid credentials and access tokens, plus the remote connector's GitHub client secret and signing key.

Two backends, chosen by the SECRETS_BACKEND setting:
- keyring (default): the OS keychain via `keyring`, service name `personal-finance-mcp`. The list of linked item ids
  is not secret but is kept there too, so no state lands in plain files.
- systemd: systemd credentials for a headless Linux server. Each secret is a file encrypted with `systemd-creds
  encrypt` (key held by the host, outside the data) in the credstore directory. Inside the service, systemd decrypts
  them into $CREDENTIALS_DIRECTORY (LoadCredentialEncrypted= in the unit), which is read-only to us. An administrator
  running the CLI as root outside the service reads and writes them through `systemd-creds` directly. All linked
  items of one environment live in one credential, `plaid_items_<env>` (JSON {item_id: access_token}), so the unit
  needs a fixed list of credential names.
"""
import json
import os
import subprocess
from pathlib import Path

import keyring
from keyring.errors import PasswordDeleteError

from app.config import settings

SERVICE = "personal-finance-mcp"
SET_KEYS_CMD = "python -m app.cli set-plaid-keys"
LINK_CMD = "python -m app.cli link"
REMOTE_KEYS_CMD = "python -m app.cli set-remote-secrets (or deploy/import-credential.sh on the server)"
_ITEMS_KEY = "linked_items"
GITHUB_SECRET = "github_client_secret"
SIGNING_KEY = "token_signing_key"


class MissingSecret(RuntimeError):
    """A required secret is absent. The message names the command that stores it and never contains a value."""


class _Keyring:
    def get(self, name: str) -> str | None:
        return keyring.get_password(SERVICE, name)

    def set(self, name: str, value: str) -> None:
        keyring.set_password(SERVICE, name, value)

    def delete(self, name: str) -> None:
        try:
            keyring.delete_password(SERVICE, name)
        except PasswordDeleteError:
            pass  # already absent


class SystemdCreds:
    """systemd credentials. `run` is subprocess.run, replaceable in tests."""

    def __init__(self, credstore: Path, credentials_dir: str | None, run=subprocess.run):
        self.credstore = Path(credstore)
        self.credentials_dir = Path(credentials_dir) if credentials_dir else None
        self.run = run

    @staticmethod
    def _check(name: str) -> None:
        if not name or not all(c.isalnum() or c in "_-." for c in name) or name.startswith("."):
            raise MissingSecret("Invalid credential name.")

    def get(self, name: str) -> str | None:
        self._check(name)
        if self.credentials_dir is not None:  # inside the service
            path = self.credentials_dir / name
            return path.read_text(encoding="utf-8") if path.is_file() else None
        path = self.credstore / name
        if not path.is_file():
            return None
        # values travel only through pipes, never argv; stderr is dropped because it can echo paths
        done = self.run(["systemd-creds", "decrypt", f"--name={name}", str(path), "-"],
                        capture_output=True, check=False)
        if done.returncode != 0:
            raise MissingSecret(f"systemd-creds could not decrypt '{name}' (run as root on the server).")
        return done.stdout.decode("utf-8")

    def set(self, name: str, value: str) -> None:
        self._check(name)
        if self.credentials_dir is not None:
            raise MissingSecret("Credentials are read-only inside the service; run the CLI as root on the server.")
        self.credstore.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.credstore / name
        tmp = path.with_name(path.name + ".tmp")
        done = self.run(["systemd-creds", "encrypt", f"--name={name}", "-", str(tmp)],
                        input=value.encode("utf-8"), capture_output=True, check=False)
        if done.returncode != 0:
            tmp.unlink(missing_ok=True)
            raise MissingSecret(f"systemd-creds could not encrypt '{name}' (run as root on the server).")
        os.replace(tmp, path)

    def delete(self, name: str) -> None:
        self._check(name)
        if self.credentials_dir is not None:
            raise MissingSecret("Credentials are read-only inside the service; run the CLI as root on the server.")
        (self.credstore / name).unlink(missing_ok=True)


def backend():
    if settings.secrets_backend == "systemd":
        return SystemdCreds(settings.credstore_dir, os.environ.get("CREDENTIALS_DIRECTORY"))
    return _Keyring()


def _systemd() -> bool:
    return settings.secrets_backend == "systemd"


def _get(name: str, fix: str) -> str:
    value = backend().get(name)
    if not value:
        raise MissingSecret(f"Missing secret '{name}'. Run: {fix}")
    return value


def _set(name: str, value: str) -> None:
    backend().set(name, value)


def _delete(name: str) -> None:
    backend().delete(name)


def has_secret(name: str) -> bool:
    return bool(backend().get(name))


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


# --- linked items -------------------------------------------------------------------------------------------------

def _items_name(env: str) -> str:
    return f"plaid_items_{env}"


def _load_items(env: str) -> dict[str, str]:
    """systemd backend only: {item_id: access_token} for one environment."""
    raw = backend().get(_items_name(env))
    if not raw:
        return {}
    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        items = None
    if not isinstance(items, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in items.items()):
        raise MissingSecret(f"The credential '{_items_name(env)}' is corrupt. Re-import it (see docs/REMOTE.md).")
    return items


def _store_items(env: str, items: dict[str, str]) -> None:
    _set(_items_name(env), json.dumps(items))


def get_access_token(env: str, item_id: str) -> str:
    if _systemd():
        token = _load_items(env).get(item_id)
        if not token:
            raise MissingSecret(f"Missing access token for a linked item in '{_items_name(env)}'. Run: {LINK_CMD}")
        return token
    return _get(_token_key(env, item_id), LINK_CMD)


def set_access_token(env: str, item_id: str, token: str) -> None:
    if _systemd():
        items = _load_items(env)
        items[item_id] = token
        _store_items(env, items)
        return
    _set(_token_key(env, item_id), token)
    ids = list_item_ids(env)
    if item_id not in ids:
        _save_items(env, ids + [item_id])


def delete_access_token(env: str, item_id: str) -> None:
    if _systemd():
        items = _load_items(env)
        items.pop(item_id, None)
        _store_items(env, items)
        return
    _delete(_token_key(env, item_id))
    _save_items(env, [i for i in list_item_ids(env) if i != item_id])


def list_item_ids(env: str) -> list[str]:
    if _systemd():
        return list(_load_items(env))
    raw = backend().get(f"{_ITEMS_KEY}_{env}")
    if not raw:
        return []
    try:
        ids = json.loads(raw)
    except json.JSONDecodeError:
        ids = None
    if not isinstance(ids, list):
        raise MissingSecret(
            f"The stored list of linked items for '{env}' is corrupt. Delete the keychain entry "
            f"'linked_items_{env}' (service '{SERVICE}'), then run: {LINK_CMD}"
        ) from None
    return ids


def _save_items(env: str, ids: list[str]) -> None:
    _set(f"{_ITEMS_KEY}_{env}", json.dumps(ids))


# --- remote connector ---------------------------------------------------------------------------------------------

def get_github_client_secret() -> str:
    return _get(GITHUB_SECRET, REMOTE_KEYS_CMD)


def get_signing_key() -> bytes:
    """Key for hashing OAuth tokens and deriving client secrets; at least 32 bytes of hex or text."""
    value = _get(SIGNING_KEY, REMOTE_KEYS_CMD).strip()
    if len(value) < 32:
        raise MissingSecret(f"The secret '{SIGNING_KEY}' is too short (need at least 32 characters). Run: {REMOTE_KEYS_CMD}")
    return value.encode("utf-8")


def set_remote_secrets(github_client_secret: str, signing_key: str) -> None:
    _set(GITHUB_SECRET, github_client_secret)
    _set(SIGNING_KEY, signing_key)
