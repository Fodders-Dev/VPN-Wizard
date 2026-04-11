#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${VPNW_APP_DIR:-/opt/vpn-wizard/app}"
VENV_DIR="${VPNW_VENV_DIR:-/opt/vpn-wizard/venv}"
REPO_URL="${VPNW_DEPLOY_REPO:-https://github.com/Fodders-Dev/VPN-Wizard.git}"
BRANCH="${VPNW_DEPLOY_BRANCH:-main}"

mkdir -p "$(dirname "$APP_DIR")"

if [ ! -d "$APP_DIR/.git" ]; then
  git clone --branch "$BRANCH" --single-branch "$REPO_URL" "$APP_DIR"
fi

cd "$APP_DIR"

current_commit="$(git rev-parse HEAD 2>/dev/null || true)"
git fetch origin "$BRANCH" --depth=1
next_commit="$(git rev-parse FETCH_HEAD)"

if [ "$current_commit" = "$next_commit" ]; then
  exit 0
fi

git reset --hard "$next_commit"
"$VENV_DIR/bin/pip" install -r requirements-server.txt
"$VENV_DIR/bin/pip" install --no-deps -e .
systemctl restart vpn-wizard
