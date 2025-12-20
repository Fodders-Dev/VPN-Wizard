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
python -m vpn_wizard.cli provision --host <ip> --user <user> --password <pass> --client client1 --auto-mtu --tune --check
```

Export config + QR:
```
python -m vpn_wizard.cli export --host <ip> --user <user> --password <pass> --client client1 --out client1.conf --qr client1.png
```

Status:
```
python -m vpn_wizard.cli status --host <ip> --user <user> --password <pass>
```

## GUI
```
python -m vpn_wizard.gui
```

## API server (for Telegram bot/miniapp)
```
python -m vpn_wizard.server
```

## Telegram bot
```
$env:VPNW_BOT_TOKEN="YOUR_TOKEN"
$env:VPNW_MINIAPP_URL="https://your-domain/miniapp"
python -m vpn_wizard.tg_bot
```

## Tests
```
pytest
```

## Notes
- Use `--key` instead of `--password` for key auth.
- Server configs stored under `/etc/wireguard/`.
- Disable tuning with `--no-tune`, disable MTU with `--mtu 0`, disable auto-MTU with `--no-auto-mtu`.
- Miniapp is served at `http://<host>:8000/miniapp` when running the API server.
- Telegram miniapp requires a public HTTPS URL configured in BotFather.
- For cross-origin miniapp, set `VPNW_CORS_ORIGINS="https://your-miniapp-domain"` before running the API server.
- Set `window.API_BASE` in `web/miniapp/config.js` to your API server URL when hosting separately.
