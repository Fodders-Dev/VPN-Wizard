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

# Domain for the WL cert. Default = <ip-dashes>.sslip.io but Let's Encrypt rate-limits
# sslip.io aggressively (shared public suffix). Point a domain you control at the VPS.
VPNW_WL_DOMAIN=rodnya-tree.ru

# DO NOT SET on hosts running nginx for production traffic. webroot mode
# never reads this anyway, but leave unset to avoid surprises.
# VPNW_WL_STOP_PORT80_SERVICE=
```

After editing: `sudo systemctl restart vpn-wizard`.

### What `webroot` mode does on the VPS

1. Confirms `systemctl is-active nginx` is `active`. If not — bails with a
   clear error. Never falls back to standalone, never stops any service.
2. Creates `/var/www/acme-webroot/.well-known/acme-challenge/`.
3. **Detects existing `server_name <domain>` blocks in nginx config:**
   - If an existing block claims the domain AND already serves
     `/.well-known/acme-challenge/` from `/var/www/acme-webroot` → reuses
     it as-is, does NOT touch nginx config or reload.
   - If an existing block claims the domain but lacks the ACME location →
     bails with a clear error and the exact location block to paste in.
     Writing a new server block here would duplicate `server_name` and
     nginx would silently ignore one of them.
   - No conflict (e.g. fresh sslip.io domain) → writes a hostname-scoped
     server block to `/etc/nginx/conf.d/acme-vpnw-wl-<domain>.conf` that
     ONLY answers `/.well-known/acme-challenge/` for that hostname. No
     `default_server`, no wildcard match — existing vhosts untouched.
4. If a new snippet was written: runs `nginx -t`. If invalid → deletes the
   snippet, raises an error, does NOT reload nginx.
5. `systemctl reload nginx` (no restart, zero downtime).
6. `acme.sh --issue --webroot ...` — Let's Encrypt fetches the challenge
   over plain HTTP from nginx.
7. Installs cert into `/usr/local/etc/xray/wl-certs/` and registers an Xray
   reload as the renewal hook (so quarterly auto-renewals don't need ops).

### Custom-domain prerequisites (`VPNW_WL_DOMAIN=mydomain.tld`)

When pointing a domain you control at the VPS (recommended over sslip.io to
avoid LE rate limits):

1. Add an A record `mydomain.tld → <vps_ipv4>` (60s TTL while testing).
2. The existing nginx :80 server block for that domain MUST include:
   ```
   location ^~ /.well-known/acme-challenge/ {
       default_type "text/plain";
       root /var/www/acme-webroot;
       try_files $uri =404;
   }
   ```
   …before any `return 301 https://...` redirect, so the challenge isn't
   redirected away. Then `sudo nginx -t && sudo systemctl reload nginx`.
3. Verify externally before `/wl_add`:
   ```
   sudo mkdir -p /var/www/acme-webroot/.well-known/acme-challenge
   echo ok | sudo tee /var/www/acme-webroot/.well-known/acme-challenge/test
   curl -sS http://mydomain.tld/.well-known/acme-challenge/test   # expect: ok
   sudo rm /var/www/acme-webroot/.well-known/acme-challenge/test
   ```
4. Then `/wl_add <name>` in Telegram. The bot detects the existing config,
   reuses it, and proceeds straight to `acme.sh`.

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
`--reloadcmd` we register at install time, which also re-applies cert key
group ownership (acme.sh overwrites the file with default 0600 root:root on
each renewal — without the hook the next renewal silently breaks Xray on
non-root installs).

### KNOWN LIMITATION: Yandex API Gateway does NOT stream responses

As of 2026-05, end-to-end VPN traffic does NOT flow through the WL profile
generated by `/wl_add`, even though every individual layer is healthy:

  * Xray on the VPS listens on :9443, accepts XHTTP uplink, logs the client.
  * Direct GET to `https://<backend>:9443/<path>` returns
    `HTTP/2 200 content-type: text/event-stream` immediately.
  * Yandex API Gateway proxies the XHTTP **uplink** correctly (POST returns 200,
    Xray's access.log shows `accepted ... email: <client>`).
  * **But** the **downlink** GET via the Gateway hangs without any response
    headers/body until the `read` timeout. All XHTTP modes (`packet-up`,
    `stream-up`, `stream-one`, `auto`) fail the same way.

Conclusion: Yandex API Gateway's HTTP integration buffers upstream responses
before forwarding to the client. XHTTP requires streaming on the downlink
regardless of mode, so this fronting architecture is fundamentally
incompatible with XHTTP. The bot still provisions the inbound, the cert,
and the Gateway successfully — but vless:// links won't carry traffic.

A different fronting architecture is needed before this is production-ready
for end users. Candidates (none implemented):
  - **Yandex Application Load Balancer (ALB)** — supports gRPC and chunked
    HTTP/2 streaming. More complex than API Gateway, costs more.
  - **Yandex Compute Cloud VM** as the WL endpoint — Yandex-owned IP, run
    Xray directly (skip the front entirely). Verifies Yandex IP ranges are
    whitelisted by the target mobile networks (gateway domains might be
    whitelisted, raw IPs might not).
  - Switch transport away from XHTTP (e.g. CONNECT-based proxy that survives
    response buffering). XHTTP was chosen because we expected Gateway to
    proxy WebSocket for VLESS+WS, which it doesn't either; this rules out
    most Xray transports through the Gateway.

The /wl_add command and surrounding plumbing remain shipped because they
land all the moving parts on the VPS correctly; only the public frontend
needs to be replaced. See `build_proxy_openapi_spec` docstring in
`src/vpn_wizard/yandex_cloud.py` for the authoritative diagnosis.

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
