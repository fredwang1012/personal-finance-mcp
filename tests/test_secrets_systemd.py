import os
"""systemd credentials backend with a fake credentials dir and a fake systemd-creds; plus the bundle move commands."""
import base64
import io
import json

import pytest

from app import cli, secrets
from app.config import settings


class FakeSystemdCreds:
    """Stands in for `systemd-creds`: 'encrypts' to a tagged base64 blob bound to the credential name."""

    def __init__(self):
        self.argv: list[list[str]] = []

    def __call__(self, args, input=None, capture_output=True, check=False):
        self.argv.append(list(args))
        assert args[0] == "systemd-creds" and args[2].startswith("--name=")
        name = args[2].removeprefix("--name=")

        class Done:
            returncode, stdout = 0, b""

        if args[1] == "encrypt":
            assert args[3] == "-"  # the value comes from stdin, never argv
            blob = b"FAKECRED:" + name.encode() + b":" + base64.b64encode(input)
            open(args[4], "wb").write(blob)
        elif args[1] == "decrypt":
            tag, cred_name, data = open(args[3], "rb").read().split(b":", 2)
            if tag != b"FAKECRED" or cred_name.decode() != name:
                Done.returncode = 1
            else:
                Done.stdout = base64.b64decode(data)
        return Done()


@pytest.fixture
def systemd(monkeypatch, tmp_path):
    fake = FakeSystemdCreds()
    monkeypatch.setattr(settings, "secrets_backend", "systemd")
    monkeypatch.setattr(settings, "credstore_dir", tmp_path / "credstore")
    monkeypatch.setattr(secrets, "backend",
                        lambda: secrets.SystemdCreds(settings.credstore_dir, None, run=fake))
    return fake


def test_service_reads_from_credentials_directory(monkeypatch, tmp_path):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "plaid_client_id").write_text("cid-1")
    (creds / "plaid_secret_production").write_text("sec-1")
    (creds / "plaid_items_production").write_text(json.dumps({"item-A": "access-production-A"}))
    (creds / "github_client_secret").write_text("gh-secret")
    (creds / "token_signing_key").write_text("k" * 64 + "\n")
    monkeypatch.setattr(settings, "secrets_backend", "systemd")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    assert secrets.get_client_id() == "cid-1"
    assert secrets.has_plaid_keys("production") and not secrets.has_plaid_keys("sandbox")
    assert secrets.list_item_ids("production") == ["item-A"]
    assert secrets.get_access_token("production", "item-A") == "access-production-A"
    assert secrets.get_github_client_secret() == "gh-secret"
    assert secrets.get_signing_key() == b"k" * 64
    with pytest.raises(secrets.MissingSecret, match="read-only"):
        secrets.set_access_token("production", "item-B", "x")
    with pytest.raises(secrets.MissingSecret) as missing:
        secrets.get_access_token("production", "item-SECRETID")
    assert "item-SECRETID" not in str(missing.value)


def test_admin_round_trip_through_systemd_creds(systemd, tmp_path):
    secrets.set_plaid_keys("production", "cid-2", "sec-VALUE-2")
    secrets.set_access_token("production", "item-1", "access-production-VALUE-1")
    secrets.set_access_token("production", "item-2", "access-production-VALUE-2")
    assert secrets.get_plaid_secret("production") == "sec-VALUE-2"
    assert secrets.list_item_ids("production") == ["item-1", "item-2"]
    secrets.delete_access_token("production", "item-1")
    assert secrets.list_item_ids("production") == ["item-2"]
    assert secrets.get_access_token("production", "item-2") == "access-production-VALUE-2"
    # values never on a command line, never plaintext at rest, no temp files left behind
    assert not [a for a in systemd.argv if any("VALUE" in part for part in a)]
    files = list((tmp_path / "credstore").iterdir())
    assert sorted(f.name for f in files) == ["plaid_client_id", "plaid_items_production", "plaid_secret_production"]
    assert not [f for f in files if b"VALUE" in f.read_bytes()]
    if os.name == "posix":  # Windows has no POSIX modes
        assert all((f.stat().st_mode & 0o777) == 0o600 for f in files)


def test_invalid_credential_names_refused(systemd):
    with pytest.raises(secrets.MissingSecret):
        secrets.backend().get("../etc/passwd")


def test_corrupt_items_credential(systemd):
    secrets.backend().set("plaid_items_production", "[1, 2]")
    with pytest.raises(secrets.MissingSecret, match="corrupt"):
        secrets.list_item_ids("production")


class Pipe(io.StringIO):
    def isatty(self):
        return False


class Tty(io.StringIO):
    def isatty(self):
        return True


MARKERS = ("access-production-XMARK", "item-XMARK", "sec-XMARK", "cid-XMARK")


def test_bundle_is_sealed_to_the_server_key_and_round_trips(monkeypatch, tmp_path, capsys):
    fake = FakeSystemdCreds()
    keyring_backend = secrets.backend

    def server_side():
        monkeypatch.setattr(settings, "secrets_backend", "systemd")
        monkeypatch.setattr(settings, "credstore_dir", tmp_path / "credstore")
        monkeypatch.setattr(secrets, "backend", lambda: secrets.SystemdCreds(settings.credstore_dir, None, run=fake))

    def laptop_side():
        monkeypatch.setattr(settings, "secrets_backend", "keyring")
        monkeypatch.setattr(secrets, "backend", keyring_backend)

    server_side()
    assert cli.bundle_key() == 0
    public = capsys.readouterr().out.strip().splitlines()[-1]
    assert public.startswith("pfmcp-pub-1:")
    assert (tmp_path / "credstore" / cli.BUNDLE_KEY).exists()

    laptop_side()
    secrets.set_plaid_keys("production", "cid-XMARK", "sec-XMARK")
    secrets.set_access_token("production", "item-XMARK", "access-production-XMARK")
    assert cli.export_bundle("production", None, Tty()) == 1  # no --to: refuses, writes nothing
    assert capsys.readouterr().out == ""
    out = Tty()  # a terminal is fine now: only ciphertext is written
    assert cli.export_bundle("production", public, out) == 0
    sealed = out.getvalue()
    assert sealed.startswith("pfmcp-sealed-1:")
    printed = capsys.readouterr()
    for marker in MARKERS:
        assert marker not in sealed and marker not in printed.out + printed.err

    server_side()
    assert cli.import_bundle("production", Pipe("pfmcp-sealed-1:AAAA")) == 1  # damaged
    assert cli.import_bundle("sandbox", Pipe(sealed)) == 1  # environment mismatch
    assert cli.import_bundle("production", Tty(sealed)) == 0  # pasted at a terminal also works
    printed = capsys.readouterr()
    assert not [m for m in MARKERS if m in printed.out + printed.err]
    assert secrets.get_client_id() == "cid-XMARK"
    assert secrets.get_access_token("production", "item-XMARK") == "access-production-XMARK"
    # the one-time key is gone, so the same ciphertext cannot be imported again
    assert not (tmp_path / "credstore" / cli.BUNDLE_KEY).exists()
    assert cli.import_bundle("production", Pipe(sealed)) == 1


def test_sealed_bundle_needs_the_matching_key():
    from app import bundle

    _, public = bundle.generate_keypair()
    other_private, _ = bundle.generate_keypair()
    sealed = bundle.seal(public, b"secret-XMARK")
    with pytest.raises(bundle.BundleError, match="wrong key"):
        bundle.open_sealed(other_private, sealed)
    with pytest.raises(bundle.BundleError):
        bundle.seal("not-a-key", b"x")


def test_import_bundle_refused_on_keychain_backend(capsys):
    assert cli.import_bundle("production", Pipe("{}")) == 1
    assert "SECRETS_BACKEND=systemd" in capsys.readouterr().err


def test_set_remote_secrets_keychain(monkeypatch, capsys):
    import getpass

    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "gh-SECRETVALUE")
    assert cli.main(["set-remote-secrets"]) == 0
    assert secrets.get_github_client_secret() == "gh-SECRETVALUE"
    first = secrets.get_signing_key()
    assert len(first) == 64
    assert cli.main(["set-remote-secrets"]) == 0 and secrets.get_signing_key() == first
    assert cli.main(["set-remote-secrets", "--rotate-signing-key"]) == 0 and secrets.get_signing_key() != first
    assert "SECRETVALUE" not in capsys.readouterr().out
