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
