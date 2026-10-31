import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.store:
            raise PasswordDeleteError("not found")
        del self.store[(service, username)]


@pytest.fixture(autouse=True)
def memory_keyring():
    """Every test uses an in-memory keyring so the real OS keychain is never touched."""
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


@pytest.fixture(autouse=True)
def keyring_secrets_backend(monkeypatch):
    """Tests default to the keychain backend whatever the local .env says; systemd tests switch explicitly."""
    from app.config import settings

    monkeypatch.setattr(settings, "secrets_backend", "keyring")
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)


class RealPlaidInTests(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch, tmp_path):
    """No test reads the owner's real configuration or can reach real Plaid.

    - plaid_env is forced to sandbox and data_dir to a temp dir, whatever the local .env says.
    - server.plaid_factory raises until a test installs a fake.
    - RealPlaid can be built only with explicit fake credentials (tests/test_plaid_client.py); building it from
      settings or from stored secrets raises.
    """
    from app import plaid_client, server
    from app.config import settings

    monkeypatch.setattr(settings, "plaid_env", "sandbox")
    monkeypatch.setattr(settings, "data_dir", tmp_path / "isolated-data")

    def no_plaid(*_args, **_kwargs):
        raise RealPlaidInTests("tests must install a fake Plaid client")

    monkeypatch.setattr(server, "plaid_factory", no_plaid)
    monkeypatch.setattr(plaid_client.RealPlaid, "from_settings", classmethod(no_plaid))
    original_init = plaid_client.RealPlaid.__init__

    def guarded_init(self, env, country_codes, client_id=None, secret=None):
        if env != "sandbox" or not client_id or not secret:
            raise RealPlaidInTests("RealPlaid in tests needs env='sandbox' and explicit fake credentials")
        original_init(self, env, country_codes, client_id=client_id, secret=secret)

    monkeypatch.setattr(plaid_client.RealPlaid, "__init__", guarded_init)


@pytest.fixture(autouse=True)
def fresh_plaid_cache():
    """The server's Plaid cache lives for the process; no test may see another test's cached responses."""
    from app import server

    server.CACHE.clear()
    yield
    server.CACHE.clear()
