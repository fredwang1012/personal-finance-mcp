#!/usr/bin/env bash
# Store one secret for personal-finance-mcp as an encrypted systemd credential.
#
#   sudo deploy/import-credential.sh NAME             # prompts with hidden input
#   sudo deploy/import-credential.sh NAME --generate  # random 64-hex-character value (for token_signing_key)
#
# The value is read without echo and piped straight into `systemd-creds encrypt`; it never touches argv, the shell
# history or a plaintext file. Restart the service afterwards: sudo systemctl restart personal-finance-mcp
set -euo pipefail

CREDSTORE=/etc/credstore.encrypted/personal-finance-mcp
ALLOWED="plaid_client_id plaid_secret_production plaid_items_production github_client_secret token_signing_key"

name="${1:-}"
mode="${2:-}"
if [[ -z "$name" || " $ALLOWED " != *" $name "* ]]; then
    echo "usage: $0 NAME [--generate]   where NAME is one of: $ALLOWED" >&2
    exit 2
fi
if [[ $EUID -ne 0 ]]; then
    echo "run as root (sudo): systemd-creds needs the host key" >&2
    exit 1
fi

umask 077
mkdir -p "$CREDSTORE"
chmod 700 "$CREDSTORE"
tmp="$CREDSTORE/.$name.tmp"
trap 'rm -f "$tmp"' EXIT

if [[ "$mode" == "--generate" ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | systemd-creds encrypt --name="$name" - "$tmp"
elif [[ -z "$mode" ]]; then
    IFS= read -rsp "Value for $name (input hidden): " value
    echo
    if [[ -z "$value" ]]; then
        echo "empty value; nothing stored" >&2
        exit 1
    fi
    printf '%s' "$value" | systemd-creds encrypt --name="$name" - "$tmp"
    unset value
else
    echo "unknown option: $mode" >&2
    exit 2
fi
mv -f "$tmp" "$CREDSTORE/$name"
trap - EXIT
echo "Stored $name in $CREDSTORE (encrypted). Restart: sudo systemctl restart personal-finance-mcp"
