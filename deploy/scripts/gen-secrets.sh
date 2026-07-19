#!/usr/bin/env bash
# Fodder VPN 2 — generate the secrets needed by the Remnawave panel .env.
# Usage:  bash gen-secrets.sh
# Paste the printed values into deploy/remnawave/.env (and reuse the DB password
# in both DATABASE_URL and POSTGRES_PASSWORD).
set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required (apt-get install -y openssl)" >&2
  exit 1
fi

DB_PW="$(openssl rand -hex 16)"

echo "# --- paste into deploy/remnawave/.env ---"
echo "JWT_AUTH_SECRET=$(openssl rand -hex 32)"
echo "JWT_API_TOKENS_SECRET=$(openssl rand -hex 32)"
echo "METRICS_PASS=$(openssl rand -hex 12)"
echo "POSTGRES_PASSWORD=${DB_PW}"
echo "# Use the SAME password inside DATABASE_URL:"
echo "DATABASE_URL=\"postgresql://postgres:${DB_PW}@remnawave-db:5432/postgres\""
