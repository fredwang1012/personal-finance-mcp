#!/usr/bin/env bash
# One-time server setup for personal-finance-mcp on Ubuntu 24.04 or Oracle Linux 9 (systemd >= 250).
# Run as root from the unpacked code in /opt/personal-finance-mcp:  sudo bash deploy/setup.sh
# Safe to re-run after updating the code. It does not start the service; docs/REMOTE.md says when.
set -euo pipefail

APP=/opt/personal-finance-mcp
USER_NAME=pfmcp
UV_VERSION=0.13.5

if [[ $EUID -ne 0 ]]; then echo "run as root (sudo)" >&2; exit 1; fi
if [[ "$(cd "$(dirname "$0")/.." && pwd)" != "$APP" ]]; then
    echo "unpack the code to $APP first (see docs/REMOTE.md)" >&2; exit 1
fi
systemd_version=$(systemctl --version | awk 'NR==1 {print $2}')
if (( systemd_version < 250 )); then
    echo "systemd $systemd_version is too old: LoadCredentialEncrypted= needs 250+ (Ubuntu 24.04, Oracle Linux 9)" >&2
    exit 1
fi

echo "== packages"
if command -v apt-get >/dev/null; then
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -yq python3.12 python3.12-venv curl ca-certificates
elif command -v dnf >/dev/null; then
    dnf install -y python3.12 curl ca-certificates
else
    echo "unsupported distribution (need apt-get or dnf)" >&2; exit 1
fi

echo "== service user"
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/personal-finance-mcp --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
fi

echo "== uv $UV_VERSION"
# The release tarball is checked against its published SHA-256 file instead of piping an installer into sh.
# For a stronger pin, put the hash you verified once in UV_SHA256 below and it is checked instead.
UV_SHA256="${UV_SHA256:-}"
if ! command -v uv >/dev/null || [[ "$(uv --version | awk '{print $2}')" != "$UV_VERSION" ]]; then
    case "$(uname -m)" in
        x86_64) triple=x86_64-unknown-linux-gnu ;;
        aarch64) triple=aarch64-unknown-linux-gnu ;;
        *) echo "unsupported CPU $(uname -m)" >&2; exit 1 ;;
    esac
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    base="https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-$triple.tar.gz"
    curl -fLsS -o "$tmp/uv.tar.gz" "$base"
    if [[ -n "$UV_SHA256" ]]; then
        echo "$UV_SHA256  $tmp/uv.tar.gz" | sha256sum -c -
    else
        curl -fLsS -o "$tmp/uv.tar.gz.sha256" "$base.sha256"
        echo "$(awk '{print $1}' "$tmp/uv.tar.gz.sha256")  $tmp/uv.tar.gz" | sha256sum -c -
    fi
    tar -xzf "$tmp/uv.tar.gz" -C "$tmp"
    install -m 0755 "$tmp/uv-$triple/uv" "$tmp/uv-$triple/uvx" /usr/local/bin/
    rm -rf "$tmp"
    trap - EXIT
fi

echo "== dependencies (locked)"
cd "$APP"
# only-system: use the distribution's python3.12, never a downloaded interpreter
UV_PYTHON_PREFERENCE=only-system UV_PROJECT_ENVIRONMENT="$APP/.venv" uv sync --frozen --no-dev --python python3.12
chown -R root:root "$APP"
chmod -R go-w "$APP"

echo "== settings"
install -d -m 0750 -o root -g "$USER_NAME" /etc/personal-finance-mcp
if [[ ! -f /etc/personal-finance-mcp/env ]]; then
    install -m 0640 -o root -g "$USER_NAME" deploy/env.example /etc/personal-finance-mcp/env
    echo "   created /etc/personal-finance-mcp/env: edit PUBLIC_URL, GITHUB_CLIENT_ID, GITHUB_ALLOWED_USER_ID"
fi
install -d -m 0700 /etc/credstore.encrypted/personal-finance-mcp

echo "== unit and admin wrapper"
install -m 0644 deploy/personal-finance-mcp.service /etc/systemd/system/personal-finance-mcp.service
install -m 0755 deploy/pfmcp /usr/local/bin/pfmcp
systemctl daemon-reload

echo "Done. Next: store the credentials (docs/REMOTE.md, step 6), then: sudo systemctl enable --now personal-finance-mcp"
