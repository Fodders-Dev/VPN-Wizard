#!/usr/bin/env bash
# Fodder VPN 2 — download the maintained legiz-ru RU split-routing templates
# straight from the official Remnawave templates repo. Run, then paste each file
# into the panel under Subscription Settings → Templates (per client type).
#
# These implement the "proxy foreign/blocked services, keep RF traffic direct"
# split using regularly-updated rule sets. Re-run to refresh.
set -euo pipefail

BASE="https://raw.githubusercontent.com/remnawave/templates/refs/heads/main/by-legiz/subscription-templates"
OUT="$(cd "$(dirname "$0")" && pwd)/vendored"
mkdir -p "$OUT"

fetch() { echo "-> $1"; curl -fsSL "$BASE/$1" -o "$OUT/$1"; }

# type in panel  ->  file
fetch xray-json-ru-bundle.json          # XRAY_JSON   (v2rayNG, etc.)
fetch singbox-ru-bundle.json            # SINGBOX     (Hiddify, sing-box)
fetch mihomo-ru-bundle.yaml             # MIHOMO      (Clash Meta / Mihomo)
fetch stash-ru-bundle.yaml              # STASH       (Stash on iOS)

echo
echo "Saved to: $OUT"
echo "Next: panel → Subscription Settings → Templates → paste each file into its"
echo "matching client type. See README.md in this folder."
