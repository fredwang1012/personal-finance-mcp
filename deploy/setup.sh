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
if ! command -v uv >/dev/null || [[ "$(uv --version | awk '{print $2}')" != "$UV_VERSION" ]]; then
    curl -LsSf "https://astral.sh/uv/$UV_VERSION/install.sh" | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
fi

echo "== dependencies (locked)"
cd "$APP"
UV_PROJECT_ENVIRONMENT="$APP/.venv" uv sync --frozen --no-dev --python python3.12
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
