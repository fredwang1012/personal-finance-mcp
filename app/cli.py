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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("set-plaid-keys", help="prompt for Plaid client_id and secret and store them in the keychain")
    sub.add_parser("status", help="show environment, whether keys exist, and linked item count")
    args = parser.parse_args(argv)
    return set_plaid_keys() if args.command == "set-plaid-keys" else status()


if __name__ == "__main__":
    sys.exit(main())
