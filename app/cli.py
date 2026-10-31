"""Command line for managing secrets: python -m app.cli set-plaid-keys | status."""
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("set-plaid-keys", help="prompt for Plaid client_id and secret and store them in the keychain")
    sub.add_parser("status", help="show environment, whether keys exist, and linked item count")
    link_parser = sub.add_parser("link", help="open Plaid Link in your browser to link Wealthsimple")
    link_parser.add_argument(
        "--port", type=int, default=0, help="fixed port on 127.0.0.1 (default 0 = ephemeral), e.g. for an SSH port-forward"
    )
    csv_parser = sub.add_parser("import-csv", help="import Wealthsimple Activities / holdings CSV exports into the local store")
    csv_parser.add_argument("paths", nargs="+", help="CSV files downloaded from Wealthsimple")
    args = parser.parse_args(argv)
    if args.command == "import-csv":
        from app.csvimport import import_paths

        return import_paths(args.paths)
    if args.command == "link":
        return link(args.port)
    return {"set-plaid-keys": set_plaid_keys, "status": status}[args.command]()


if __name__ == "__main__":
    sys.exit(main())
