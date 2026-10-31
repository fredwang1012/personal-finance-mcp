"""Command line: python -m app.cli set-plaid-keys | status | link [--update ITEM_SHORT_ID] | unlink | import-csv
| serve-http | set-remote-secrets | bundle-key | export-bundle | import-bundle
| list-clients | approve-client | revoke-client."""
import argparse
import getpass
import json
import secrets as pysecrets
import sys

from app import secrets
from app.config import settings
from app.redact import clean_text, short_hash

# Plaid errors meaning the Item is already gone there, so only local cleanup is left
ALREADY_GONE = {"ITEM_NOT_FOUND", "INVALID_ACCESS_TOKEN"}


def set_plaid_keys() -> int:
    # getpass keeps values out of argv, shell history and the terminal
    print("Typing and pasting show nothing here. If Ctrl+V does nothing, paste with a right-click.")
    client_id = getpass.getpass("Plaid client_id: ").strip().strip('"')
    secret = getpass.getpass(f"Plaid {settings.plaid_env} secret: ").strip().strip('"')
    if not client_id or not secret:
        print("Both values are required; nothing stored.", file=sys.stderr)
        return 1
    secrets.set_plaid_keys(settings.plaid_env, client_id, secret)
    print(f"Stored Plaid keys for '{settings.plaid_env}' ({settings.secrets_backend} backend).")
    # enough to spot a failed paste without showing the secret: Plaid client ids are 24 characters, secrets 30
    print(f"Check: client_id ends in ...{client_id[-4:]} ({len(client_id)} characters); "
          f"secret has {len(secret)} characters.")
    return 0


def status() -> int:
    env = settings.plaid_env
    print(f"plaid_env: {env}")
    print(f"client_id stored: {'yes' if secrets.has_secret('plaid_client_id') else 'no'}")
    print(f"secret stored: {'yes' if secrets.has_secret(f'plaid_secret_{env}') else 'no'}")
    print(f"linked items: {len(secrets.list_item_ids(env))}")
    return 0


def _resolve_update(env: str, short_id: str) -> tuple[str, str] | None:
    """(item_id, access_token) for the linked item with this short id, or None after printing why not."""
    try:
        item_ids = secrets.list_item_ids(env)
    except secrets.MissingSecret as exc:
        print(str(exc), file=sys.stderr)
        return None
    wanted = short_id.strip().lower()
    matches = [i for i in item_ids if short_hash(i) == wanted]
    if not matches:
        # the argument is not echoed, in case a raw item id or token was pasted
        print("No linked item has that short id. Run `python -m app.cli unlink` to list them.", file=sys.stderr)
        return None
    token = _token_or_none(env, matches[0])
    if token is None:
        print(f"No access token is stored for item {wanted}; it cannot be updated. Unlink it and link again.",
              file=sys.stderr)
        return None
    return matches[0], token


def run_link_cli(api_factory, env: str, port: int = 0, update_short: str | None = None, **kwargs) -> int:
    from app.link import run_link
    from app.plaid_client import PlaidError

    update = None
    if update_short is not None:
        update = _resolve_update(env, update_short)
        if update is None:
            return 1
    try:
        return run_link(api_factory(), env, port=port, update=update, **kwargs)
    except (secrets.MissingSecret, PlaidError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # e.g. a network error from create_link_token; its text could carry request data
        print(f"Link failed ({type(exc).__name__}).", file=sys.stderr)
        return 1


def link(port: int = 0, update_short: str | None = None) -> int:
    from app.plaid_client import RealPlaid

    return run_link_cli(lambda: RealPlaid.from_settings(settings), settings.plaid_env, port, update_short)


def _institution(api, token: str | None) -> str:
    if api is None or token is None:
        return "institution unknown"
    try:
        name = (api.item_get(token).get("item") or {}).get("institution_name")
    except Exception:
        return "institution unknown"
    return clean_text(str(name or "")) or "institution unknown"


def _token_or_none(env: str, item_id: str) -> str | None:
    try:
        return secrets.get_access_token(env, item_id)
    except secrets.MissingSecret:
        return None


def _confirm(prompt: str, input_fn) -> bool:
    try:
        return input_fn(prompt) == "yes"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _delete_locally(env: str, item_id: str, short: str, after_plaid: bool) -> int:
    try:
        secrets.delete_access_token(env, item_id)
    except Exception as exc:  # the keyring's message can name the entry, which contains the raw item id
        where = f"Item {short} removed at Plaid; local" if after_plaid else f"Item {short}: local"
        print(f"{where} cleanup failed ({type(exc).__name__}), run unlink again to finish.")
        return 1
    print(f"Deleted its access token and list entry (secrets backend: {settings.secrets_backend}).")
    return 0


def run_unlink(api_factory, env: str, short_id: str | None, input_fn=input, local_only: bool = False) -> int:
    """List linked items, or remove one from Plaid and the keychain. Only short ids are ever printed."""
    from app.plaid_client import PlaidError

    try:
        item_ids = secrets.list_item_ids(env)
    except secrets.MissingSecret as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if not item_ids:
        print(f"No linked items for '{env}'.")
        return 0 if short_id is None else 1

    if short_id is None:
        try:
            api = api_factory()
        except Exception:
            api = None
        print(f"Linked items for '{env}':")
        for item_id in item_ids:
            print(f"  {short_hash(item_id)}  {_institution(api, _token_or_none(env, item_id))}")
        print("Remove one with: python -m app.cli unlink ITEM_SHORT_ID")
        return 0

    wanted = short_id.strip().lower()
    matches = [i for i in item_ids if short_hash(i) == wanted]
    if not matches:
        # the argument is not echoed, in case a raw item id or token was pasted
        print("No linked item has that short id. Run `python -m app.cli unlink` to list them.", file=sys.stderr)
        return 1
    item_id = matches[0]

    if local_only:
        print(f"WARNING: --local-only deletes item {wanted} from this machine only. It does NOT revoke access at Plaid; "
              "remove it in the Plaid dashboard or at my.plaid.com as well.")
        if not _confirm('Type "yes" to delete the local token and list entry: ', input_fn):
            print("Cancelled; nothing removed.")
            return 1
        return _delete_locally(env, item_id, wanted, after_plaid=False)

    token = _token_or_none(env, item_id)
    api = None
    if token is not None:
        try:
            api = api_factory()
        except (secrets.MissingSecret, PlaidError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"Could not set up the Plaid client ({type(exc).__name__}).", file=sys.stderr)
            return 1
    label = f"{wanted} ({_institution(api, token)})"
    if not _confirm(f'Unlink item {label} from Plaid ({env})? Type "yes" to continue: ', input_fn):
        print("Cancelled; nothing removed.")
        return 1

    if token is None:
        print(f"No access token is stored for item {wanted}; removing it from the local list only.")
    else:
        try:
            api.item_remove(token)
        except PlaidError as exc:
            if exc.code not in ALREADY_GONE:
                print(f"Plaid could not remove item {wanted} ({exc.code}). The access token was kept; try again later.")
                return 1
            print(f"Plaid no longer knows item {wanted} ({exc.code}); removing it locally.")
        except Exception as exc:
            print(f"Could not reach Plaid to remove item {wanted} ({type(exc).__name__}). The access token was kept.")
            return 1
        else:
            print(f"Removed item {wanted} at Plaid.")
    if _delete_locally(env, item_id, wanted, after_plaid=token is not None):
        return 1
    if env == "production":
        print("Reminder: on Plaid's Trial plan a removed Item still counts toward the 10-Item cap; the slot is not freed.")
    return 0


def unlink(short_id: str | None, local_only: bool = False) -> int:
    from app.plaid_client import RealPlaid

    return run_unlink(lambda: RealPlaid.from_settings(settings), settings.plaid_env, short_id, local_only=local_only)


BUNDLE_FORMAT = "personal-finance-mcp-bundle-1"
MAX_BUNDLE = 64 * 1024


def set_remote_secrets(rotate_signing_key: bool = False) -> int:
    """Keychain only (laptop testing of serve-http). On the server use deploy/import-credential.sh."""
    if settings.secrets_backend != "keyring":
        print("On the server, store these with deploy/import-credential.sh (see docs/REMOTE.md).", file=sys.stderr)
        return 1
    print("Typing and pasting show nothing here. Leave empty to keep the stored value.")
    github = getpass.getpass("GitHub OAuth App client secret: ").strip().strip('"')
    if github:
        secrets._set(secrets.GITHUB_SECRET, github)
    elif not secrets.has_secret(secrets.GITHUB_SECRET):
        print("No GitHub client secret stored yet; nothing changed.", file=sys.stderr)
        return 1
    if rotate_signing_key or not secrets.has_secret(secrets.SIGNING_KEY):
        secrets._set(secrets.SIGNING_KEY, pysecrets.token_hex(32))
        print("Generated a new token-signing key (every issued OAuth token and client is now invalid).")
    print("Stored the remote connector secrets in the OS keychain.")
    return 0


BUNDLE_KEY = "bundle_private_key"


def bundle_key() -> int:
    """Server: make a one-time keypair for import-bundle; store the private half, print only the public half."""
    from app.bundle import generate_keypair

    private, public = generate_keypair()
    try:
        secrets._set(BUNDLE_KEY, private)
    except secrets.MissingSecret as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("Public key for export-bundle --to (safe to copy; it is deleted again after a successful import):")
    print(public)
    return 0


def export_bundle(env: str, to: str | None, out=None) -> int:
    """Laptop: write this environment's Plaid keys and access tokens sealed to the server's public key.
    The output is ciphertext only, so it is harmless on a terminal or in a file."""
    from app.bundle import BundleError, seal

    out = out or sys.stdout
    if not to:
        print("export-bundle needs --to KEY, the public key printed by `bundle-key` on the server. It never writes "
              "the secrets unencrypted.", file=sys.stderr)
        return 1
    try:
        items = {i: secrets.get_access_token(env, i) for i in secrets.list_item_ids(env)}
        bundle = {"format": BUNDLE_FORMAT, "env": env, "plaid_client_id": secrets.get_client_id(),
                  "plaid_secret": secrets.get_plaid_secret(env), "items": items}
    except secrets.MissingSecret:
        # not the exception text: per-item messages name the keychain entry, which contains the raw item id
        print("Export failed: a Plaid key or access token is missing. Run status to check.", file=sys.stderr)
        return 1
    try:
        sealed = seal(to, json.dumps(bundle).encode())
    except BundleError as exc:
        print(f"Export failed: {exc}.", file=sys.stderr)
        return 1
    out.write(sealed + "\n")
    out.flush()
    print(f"Sealed Plaid keys and {len(items)} item(s) for '{env}': "
          f"{', '.join(short_hash(i) for i in items) or 'none'}.", file=sys.stderr)
    return 0


def import_bundle(env: str, inp=None) -> int:
    """Server: read a sealed bundle (pipe or paste), decrypt it with the bundle-key private half and store it."""
    from app.bundle import BundleError, open_sealed

    inp = inp or sys.stdin
    if settings.secrets_backend != "systemd":
        print("import-bundle is for the server (SECRETS_BACKEND=systemd).", file=sys.stderr)
        return 1
    try:
        private = secrets.backend().get(BUNDLE_KEY)
    except secrets.MissingSecret as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if not private:
        print("No bundle key here. Run `bundle-key` first and export with its public key.", file=sys.stderr)
        return 1
    raw = inp.readline(MAX_BUNDLE + 1)
    try:
        if len(raw) > MAX_BUNDLE:
            raise BundleError("input too large")
        bundle = json.loads(open_sealed(private, raw))
    except BundleError as exc:
        print(f"Nothing stored: {exc}.", file=sys.stderr)
        return 1
    except (json.JSONDecodeError, UnicodeDecodeError):
        bundle = None
    ok = (isinstance(bundle, dict) and bundle.get("format") == BUNDLE_FORMAT
          and all(isinstance(bundle.get(k), str) and bundle.get(k) for k in ("env", "plaid_client_id", "plaid_secret"))
          and isinstance(bundle.get("items"), dict)
          and all(isinstance(k, str) and k and isinstance(v, str) and v for k, v in bundle["items"].items()))
    if not ok:
        print("Input is not a valid export bundle; nothing stored.", file=sys.stderr)
        return 1
    if bundle["env"] != env:
        print(f"Bundle is for '{bundle['env']}' but PLAID_ENV here is '{env}'; nothing stored.", file=sys.stderr)
        return 1
    try:
        secrets.set_plaid_keys(env, bundle["plaid_client_id"], bundle["plaid_secret"])
        for item_id, token in bundle["items"].items():
            secrets.set_access_token(env, item_id, token)
        secrets._delete(BUNDLE_KEY)  # one-time key: a copy of the ciphertext is useless from now on
    except secrets.MissingSecret as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Stored Plaid keys and {len(bundle['items'])} item(s) for '{env}': "
          f"{', '.join(short_hash(i) for i in bundle['items']) or 'none'}. Deleted the one-time bundle key. "
          "Restart the service: sudo systemctl restart personal-finance-mcp")
    return 0


def _client_admin():
    from app.auth import ClientAdmin

    return ClientAdmin(settings.data_dir / "oauth.db")


def list_clients() -> int:
    admin = _client_admin()
    try:
        rows = admin.rows()
        used, cap = admin.counts()
    finally:
        admin.close()
    if rows:
        print(f"{'fingerprint':<12} {'status':<9} {'registered':<24} {'last used':<24} name")
        for r in rows:
            print(f"{r['fingerprint']:<12} {r['status']:<9} {r['registered']:<24} {r['last_used']:<24} "
                  f"{clean_text(r['name'])}")
    else:
        print("No registered OAuth clients.")
    # pending clients expire on their own; approved ones stay until revoked, and revoked ones linger 30 days
    print(f"{used} of {cap} client slots used. Revoke approved clients you no longer use with "
          "`revoke-client FINGERPRINT`.")
    return 0


def approve_client(fp: str) -> int:
    admin = _client_admin()
    try:
        done = admin.approve(fp)
    finally:
        admin.close()
    if done is None:
        print("No single pending client has that fingerprint (pending requests expire after 30 minutes). "
              "Run list-clients.", file=sys.stderr)
        return 1
    print(f"Approved client {done}. Click Connect in Claude again to finish.")
    return 0


def revoke_client(fp: str | None, everything: bool = False) -> int:
    admin = _client_admin()
    try:
        if everything:
            n = admin.revoke_all()
            print(f"Revoked {n} client(s) and deleted every token.")
            return 0
        done = admin.revoke(fp or "")
    finally:
        admin.close()
    if done is None:
        print("No single active client has that fingerprint. Run list-clients.", file=sys.stderr)
        return 1
    print(f"Revoked client {done} and deleted all of its tokens.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("set-plaid-keys", help="prompt for Plaid client_id and secret and store them in the keychain")
    sub.add_parser("status", help="show environment, whether keys exist, and linked item count")
    link_parser = sub.add_parser("link", help="open Plaid Link in your browser to link Wealthsimple")
    link_parser.add_argument(
        "--port", type=int, default=0, help="fixed port on 127.0.0.1 (default 0 = ephemeral), e.g. for an SSH port-forward"
    )
    link_parser.add_argument(
        "--update", metavar="ITEM_SHORT_ID",
        help="re-authenticate an existing item (e.g. after ITEM_LOGIN_REQUIRED) instead of linking a new one",
    )
    unlink_parser = sub.add_parser("unlink", help="list linked items, or remove one from Plaid and the keychain")
    unlink_parser.add_argument("item", nargs="?", help="short id shown by `unlink` with no argument")
    unlink_parser.add_argument(
        "--local-only", action="store_true", help="delete only the local token and list entry; does not revoke at Plaid"
    )
    csv_parser = sub.add_parser("import-csv", help="import Wealthsimple Activities / holdings CSV exports into the local store")
    csv_parser.add_argument("paths", nargs="+", help="CSV files downloaded from Wealthsimple")
    http_parser = sub.add_parser("serve-http", help="serve the read-only tools over HTTPS-fronted Streamable HTTP with OAuth")
    http_parser.add_argument("--port", type=int, help="port on 127.0.0.1 (default: HTTP_PORT setting, 8765)")
    remote_parser = sub.add_parser("set-remote-secrets", help="store the GitHub client secret and a signing key (keychain)")
    remote_parser.add_argument("--rotate-signing-key", action="store_true", help="replace the signing key")
    sub.add_parser("bundle-key", help="server: make a one-time key for import-bundle and print its public half")
    export_parser = sub.add_parser("export-bundle", help="laptop: write Plaid keys and tokens sealed to the server's key")
    export_parser.add_argument("--to", metavar="KEY", help="public key printed by bundle-key on the server")
    sub.add_parser("import-bundle", help="server: decrypt a sealed bundle into systemd credentials (as root)")
    sub.add_parser("list-clients", help="list OAuth clients of the remote connector (fingerprint, status, use)")
    sub.add_parser("approve-client", help="approve one pending OAuth client").add_argument(
        "fingerprint", help="8-character fingerprint from list-clients")
    revoke_parser = sub.add_parser("revoke-client", help="revoke an OAuth client and delete its tokens")
    revoke_parser.add_argument("fingerprint", nargs="?", help="8-character fingerprint from list-clients")
    revoke_parser.add_argument("--all", action="store_true", help="revoke every client and delete every token")
    args = parser.parse_args(argv)
    if args.command == "list-clients":
        return list_clients()
    if args.command == "approve-client":
        return approve_client(args.fingerprint)
    if args.command == "revoke-client":
        if bool(args.all) == bool(args.fingerprint):
            parser.error("give a FINGERPRINT or --all")
        return revoke_client(args.fingerprint, args.all)
    if args.command == "serve-http":
        from app import remote

        if args.port:
            settings.http_port = args.port
        return remote.serve()
    if args.command == "set-remote-secrets":
        return set_remote_secrets(args.rotate_signing_key)
    if args.command == "bundle-key":
        return bundle_key()
    if args.command == "export-bundle":
        return export_bundle(settings.plaid_env, args.to)
    if args.command == "import-bundle":
        return import_bundle(settings.plaid_env)
    if args.command == "import-csv":
        from app.csvimport import import_paths

        return import_paths(args.paths)
    if args.command == "unlink":
        if args.local_only and not args.item:
            parser.error("--local-only needs an ITEM_SHORT_ID")
        return unlink(args.item, args.local_only)
    if args.command == "link":
        return link(args.port, args.update)
    return {"set-plaid-keys": set_plaid_keys, "status": status}[args.command]()


if __name__ == "__main__":
    sys.exit(main())
