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
- A successful WG/AWG setup now requires all runtime readiness checks to pass.
  `--no-check` only hides the CLI check report; it cannot bypass service,
  interface, IP forwarding or UDP listener validation. Failed API jobs retain
  their checks and do not publish a config download or QR.
- If `awg` exists but the module is missing, Wizard attempts `dkms autoinstall`
  and package configuration for the running kernel, then verifies the backend.
  For the confirmed Ubuntu `5.15.0-43-generic` timer API incompatibility, it
  backs up and repairs the module's compatibility header before rebuilding.
  The repair is restricted to that exact ABI. Remaining failures
  report the kernel and bounded DKMS build diagnostics instead of claiming success.
- Incident recovery for the original Ubuntu 22.04 kernel `5.15.0-43-generic`:
  copy both files from `deploy/scripts/repair-amneziawg-jammy-43.sh` and
  `src/vpn_wizard/patches/amneziawg-jammy-43-timers.patch` into one directory on the VPS,
  then run the shell script as root. It backs up configs and the module's
  compatibility header under `/root/fodder-awg-repair.*`, adds timer aliases
  restricted to that exact kernel ABI, rebuilds/configures DKMS and starts AWG.
  Existing client keys/configs are retained. This is an incident-specific repair,
  not a general kernel upgrade or a patch for newer kernels.
- Use `--key` instead of `--password` for key auth.
- Server configs stored under `/etc/wireguard/`.
- Disable tuning with `--no-tune`, disable MTU with `--mtu 0`, disable auto-MTU with `--no-auto-mtu`.
- Default UDP listen port: 3478 (override with `--listen-port` or miniapp advanced field).
- Miniapp is served at `http://<host>:8000/miniapp` when running the API server.
- Miniapp UI calls client configs "profiles" to reduce confusion for end users.
- Telegram miniapp requires a public HTTPS URL configured in BotFather.
- If Telegram widget shows `Bot domain invalid`, add the exact miniapp/web domain in BotFather (/setdomain) for your bot. Domains like `*.nip.io` must match what users open in browser.
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
