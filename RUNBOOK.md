# RUNBOOK

## Prereqs
- Python 3.10+
- SSH access with sudo on the VPS

## Install
```
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
pip install -r requirements-dev.txt
```

## CLI
Provision:
```
python -m vpn_wizard.cli provision --host <ip> --user <user> --password <pass> --client client1 --auto-mtu --tune --check --precheck
```

Export config + QR:
```
python -m vpn_wizard.cli export --host <ip> --user <user> --password <pass> --client client1 --out client1.conf --qr client1.png
```

Status:
```
python -m vpn_wizard.cli status --host <ip> --user <user> --password <pass>
```

Rollback last config:
```
python -m vpn_wizard.cli rollback --host <ip> --user <user> --password <pass>
```

Add client:
```
python -m vpn_wizard.cli client add --host <ip> --user <user> --password <pass> --name grandma-phone --qr grandma.png
```

List clients:
```
python -m vpn_wizard.cli client list --host <ip> --user <user> --password <pass>
```

Remove client:
```
python -m vpn_wizard.cli client remove --host <ip> --user <user> --password <pass> --name grandma-phone
```

Rotate client keys:
```
python -m vpn_wizard.cli client rotate --host <ip> --user <user> --password <pass> --name grandma-phone --qr grandma.png
```

## GUI
```
python -m vpn_wizard.gui
```

## API server (for Telegram bot/miniapp)
```
python -m vpn_wizard.server
```
Optional session tuning:
```
$env:VPNW_SESSION_TTL_SECONDS="86400"
$env:VPNW_SESSION_LIMIT="512"
```

Proxy mode defaults:
```
# optional, when miniapp runs in Proxy mode (ShadowTLS / legacy VLESS Reality)
$env:VPNW_SSH_DISCOVERY_PORTS="22,2222,22022,2200,2022,10022"
$env:VPNW_SSH_DISCOVERY_TIMEOUT="1.8"
```

## Single Railway service (API + bot in one)
```
$env:VPNW_BOT_TOKEN="YOUR_TOKEN"
$env:VPNW_MINIAPP_URL="https://vpn-wizard-production.up.railway.app/miniapp/"
python -m vpn_wizard.combined
```

## Telegram bot
```
$env:VPNW_BOT_TOKEN="YOUR_TOKEN"
$env:VPNW_MINIAPP_URL="https://vpn-wizard-production.up.railway.app/miniapp/"
python -m vpn_wizard.tg_bot
```
Commands: `/start`, `/help`, `/miniapp`, `/cancel`.
Default: bot requires subscription to `VPNW_REQUIRED_CHANNEL` (по умолчанию `@fodders_dev`). Set empty to disable.

## Whitelist-friendly profile (`/wl_add` via Yandex API Gateway)

Owner-only Telegram command that mints a `vless://` profile reachable through
`*.apigw.yandexcloud.net` (whitelisted by RU mobile networks). Adds a second
Xray inbound on the VPS (`vless+xhttp+tls`) and a Let's Encrypt cert obtained
via `acme.sh`.

### Production environment (`/etc/vpn-wizard.env` on bot host)

```
# Owner gating — only these Telegram user IDs can run /wl /wl_add.
VPNW_OWNER_IDS=<your_telegram_user_id>

# SSH access to the VPS that hosts Reality + WL inbound.
# Prefer a key over a password (passwordless via VPNW_WL_VPS_KEY_PATH).
VPNW_WL_VPS_HOST=<vps_ip>
VPNW_WL_VPS_USER=root
VPNW_WL_VPS_KEY_PATH=/etc/vpn-wizard/wl_vps_id_ed25519

# Yandex Cloud OAuth token (refresh by re-issuing on oauth.yandex.ru if leaked).
YC_OAUTH_TOKEN=<y0_...>

# Cert issuance — production hosts running nginx MUST pin "webroot".
# This guarantees the bot never stops nginx, regardless of other env values.
VPNW_WL_ACME_MODE=webroot

# Listening port for the WL Xray inbound (default 9443; pick something free).
VPNW_WL_LISTEN_PORT=9443

# DO NOT SET on hosts running nginx for production traffic. webroot mode
# never reads this anyway, but leave unset to avoid surprises.
# VPNW_WL_STOP_PORT80_SERVICE=
```

After editing: `sudo systemctl restart vpn-wizard`.

### What `webroot` mode does on the VPS

1. Confirms `systemctl is-active nginx` is `active`. If not — bails with a
   clear error. Never falls back to standalone, never stops any service.
2. Creates `/var/www/acme-webroot/.well-known/acme-challenge/`.
3. Writes a hostname-scoped server block to
   `/etc/nginx/conf.d/acme-vpnw-wl-<sslip-domain>.conf` that ONLY answers
   `/.well-known/acme-challenge/` for the specific sslip.io domain. No
   `default_server`, no wildcard match — existing vhosts are untouched.
4. Runs `nginx -t`. If invalid: deletes the snippet, raises an error, does
   NOT reload nginx.
5. `systemctl reload nginx` (no restart, zero downtime).
6. `acme.sh --issue --webroot ...` — Let's Encrypt fetches the challenge
   over plain HTTP from nginx.
7. Installs cert into `/usr/local/etc/xray/wl-certs/` and registers an Xray
   reload as the renewal hook (so quarterly auto-renewals don't need ops).

### Verification after deploy

```bash
# 1) Snippet is hostname-scoped, no default_server.
sudo cat /etc/nginx/conf.d/acme-vpnw-wl-*.conf
# 2) nginx config valid.
sudo nginx -t
# 3) ACME webroot reachable (test file).
sudo mkdir -p /var/www/acme-webroot/.well-known/acme-challenge
echo ok | sudo tee /var/www/acme-webroot/.well-known/acme-challenge/test
curl -sS http://<sslip-domain>/.well-known/acme-challenge/test  # expect: ok
sudo rm /var/www/acme-webroot/.well-known/acme-challenge/test
# 4) Service health after reload.
sudo systemctl status nginx --no-pager | head -10
sudo systemctl status xray --no-pager | head -10
# 5) WL inbound listening on the configured port (default 9443).
sudo ss -ltn | grep ':9443'
# 6) End-to-end from Telegram: /wl test1 then /wl_add test1.
```

### Renewals

`acme.sh` schedules itself via cron (or installs into systemd timers if
configured). Webroot renewals do not require any service stop — challenge
files are written under `/var/www/acme-webroot/.well-known/acme-challenge/`
where nginx is already serving. Xray reload is invoked automatically by the
`--reloadcmd` we register at install time.

## Tests
```
pytest
```

## Tyumen bypass (awg1)
Create a client with the `tyumen-` prefix to route it to the secondary interface:
```
python -m vpn_wizard.cli client add --host <ip> --user <user> --password <pass> --name tyumen-test --qr tyumen-test.png
```

VPS checks:
```
sudo systemctl status awg-quick@awg1
sudo wg show awg1
sudo ss -ulpn | rg 3478
sudo ufw status | rg 3478
```

Client config expectations:
- `Endpoint = <server_ip>:3478`
- `Address = 10.11.0.x/24`

## Notes
- Use `--key` instead of `--password` for key auth.
- Server configs stored under `/etc/wireguard/`.
- Disable tuning with `--no-tune`, disable MTU with `--mtu 0`, disable auto-MTU with `--no-auto-mtu`.
- Default UDP listen port: 3478 (override with `--listen-port` or miniapp advanced field).
- Miniapp is served at `http://<host>:8000/miniapp` when running the API server.
- Miniapp UI calls client configs "profiles" to reduce confusion for end users.
- Telegram miniapp requires a public HTTPS URL configured in BotFather.
- В Telegram WebApp скачивание конфигов/QR идет через data: ссылки (если загрузка не стартует, нажмите еще раз или используйте десктоп).
- В расширенных полях миниаппа есть безопасный режим (только проверка/precheck) — он не меняет сервер.
- Prefer the Railway-hosted miniapp in production so the Telegram WebApp and API share one origin.
- For cross-origin miniapp, set `VPNW_CORS_ORIGINS="https://your-miniapp-domain"` before running the API server.
- For miniapp "remember login", backend keeps temporary SSH sessions in memory (`VPNW_SESSION_TTL_SECONDS`, `VPNW_SESSION_LIMIT`).
- Set `window.API_BASE` in `web/miniapp/config.js` to your API server URL when hosting separately.
- You can also pass `?api=https://your-api-domain` in the miniapp URL to override API base.
- Miniapp now supports explicit SSH port input and `host:port` format (for non-standard SSH ports).
- Miniapp supports two setup modes: `VPN (AmneziaWG)` and `Proxy (ShadowTLS + SS2022)`.
- Proxy mode (ShadowTLS) exports an auto-config profile URL (Hiddify / sing-box). Legacy proxy mode exports a `vless://` link + QR.
- ShadowTLS proxy configs are pinned to the primary port by default (to avoid RU ISP port filtering breaking urltest-based failover). Optional urltest can be enabled via `VPNW_SHADOWTLS_ENABLE_URLTEST=1`.
- `/api/download/<id>/config` is a snapshot: if server/proxy was reconfigured, generate a fresh URL/profile (old URL may point to outdated settings).
