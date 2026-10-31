"""Command line: python -m app.cli set-plaid-keys | status | link [--update ITEM_SHORT_ID] | unlink | import-csv."""
import argparse
import getpass
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
    print(f"Stored Plaid keys for '{settings.plaid_env}' in the OS keychain.")
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
    print("Deleted its access token and list entry from the OS keychain.")
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
    args = parser.parse_args(argv)
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
