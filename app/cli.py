"""Command line: python -m app.cli set-plaid-keys | status | link | unlink | import-csv."""
import argparse
import getpass
import sys

from app import secrets
from app.config import settings


def set_plaid_keys() -> int:
    # getpass keeps values out of argv, shell history and the terminal
    client_id = getpass.getpass("Plaid client_id: ").strip()
    secret = getpass.getpass(f"Plaid {settings.plaid_env} secret: ").strip()
    if not client_id or not secret:
        print("Both values are required; nothing stored.", file=sys.stderr)
        return 1
    secrets.set_plaid_keys(settings.plaid_env, client_id, secret)
    print(f"Stored Plaid keys for '{settings.plaid_env}' in the OS keychain.")
    return 0


def status() -> int:
    env = settings.plaid_env
    print(f"plaid_env: {env}")
    print(f"client_id stored: {'yes' if secrets.has_secret('plaid_client_id') else 'no'}")
    print(f"secret stored: {'yes' if secrets.has_secret(f'plaid_secret_{env}') else 'no'}")
    print(f"linked items: {len(secrets.list_item_ids(env))}")
    return 0


def link(port: int = 0) -> int:
    from app.link import run_link
    from app.plaid_client import PlaidError, RealPlaid

    try:
        return run_link(RealPlaid.from_settings(settings), settings.plaid_env, port=port)
    except (secrets.MissingSecret, PlaidError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _institution(api, token: str | None) -> str:
    if api is None or token is None:
        return "institution unknown"
    try:
        name = (api.item_get(token).get("item") or {}).get("institution_name")
    except Exception:
        return "institution unknown"
    from app.csvimport import _text

    return _text(str(name or "")) or "institution unknown"


def _token_or_none(env: str, item_id: str) -> str | None:
    try:
        return secrets.get_access_token(env, item_id)
    except secrets.MissingSecret:
        return None


def run_unlink(api_factory, env: str, short_id: str | None, input_fn=input) -> int:
    """List linked items, or remove one from Plaid and the keychain. Only short ids are ever printed."""
    from app.plaid_client import PlaidError
    from app.tools import _short

    try:
        item_ids = secrets.list_item_ids(env)
    except secrets.MissingSecret as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if not item_ids:
        print(f"No linked items for '{env}'.")
        return 0 if short_id is None else 1

    def api_or_none():
        try:
            return api_factory()
        except Exception:
            return None

    if short_id is None:
        api = api_or_none()
        print(f"Linked items for '{env}':")
        for item_id in item_ids:
            print(f"  {_short(item_id)}  {_institution(api, _token_or_none(env, item_id))}")
        print("Remove one with: python -m app.cli unlink ITEM_SHORT_ID")
        return 0

    wanted = short_id.strip().lower()
    matches = [i for i in item_ids if _short(i) == wanted]
    if not matches:
        # the argument is not echoed, in case a raw item id or token was pasted
        print("No linked item has that short id. Run `python -m app.cli unlink` to list them.", file=sys.stderr)
        return 1
    item_id = matches[0]
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
    if input_fn(f'Unlink item {label} from Plaid ({env})? Type "yes" to continue: ') != "yes":
        print("Cancelled; nothing removed.")
        return 1

    if token is None:
        print(f"No access token is stored for item {wanted}; removing it from the local list only.")
    else:
        try:
            api.item_remove(token)
        except PlaidError as exc:
            if exc.code != "ITEM_NOT_FOUND":
                print(f"Plaid could not remove item {wanted} ({exc.code}). The access token was kept; try again later.")
                return 1
            print(f"Plaid no longer knows item {wanted}; removing it locally.")
        except Exception as exc:
            print(f"Could not reach Plaid to remove item {wanted} ({type(exc).__name__}). The access token was kept.")
            return 1
        else:
            print(f"Removed item {wanted} at Plaid.")
    secrets.delete_access_token(env, item_id)
    print("Deleted its access token from the OS keychain.")
    if env == "production":
        print("Reminder: on Plaid's Trial plan a removed Item still counts toward the 10-Item cap; the slot is not freed.")
    return 0


def unlink(short_id: str | None) -> int:
    from app.plaid_client import RealPlaid

    return run_unlink(lambda: RealPlaid.from_settings(settings), settings.plaid_env, short_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("set-plaid-keys", help="prompt for Plaid client_id and secret and store them in the keychain")
    sub.add_parser("status", help="show environment, whether keys exist, and linked item count")
    link_parser = sub.add_parser("link", help="open Plaid Link in your browser to link Wealthsimple")
    link_parser.add_argument(
        "--port", type=int, default=0, help="fixed port on 127.0.0.1 (default 0 = ephemeral), e.g. for an SSH port-forward"
    )
    unlink_parser = sub.add_parser("unlink", help="list linked items, or remove one from Plaid and the keychain")
    unlink_parser.add_argument("item", nargs="?", help="short id shown by `unlink` with no argument")
    csv_parser = sub.add_parser("import-csv", help="import Wealthsimple Activities / holdings CSV exports into the local store")
    csv_parser.add_argument("paths", nargs="+", help="CSV files downloaded from Wealthsimple")
    args = parser.parse_args(argv)
    if args.command == "import-csv":
        from app.csvimport import import_paths

        return import_paths(args.paths)
    if args.command == "unlink":
        return unlink(args.item)
    if args.command == "link":
        return link(args.port)
    return {"set-plaid-keys": set_plaid_keys, "status": status}[args.command]()


if __name__ == "__main__":
    sys.exit(main())
