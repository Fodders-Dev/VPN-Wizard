# Telegram setup

## BotFather
1) Create a bot and copy the token.
2) In BotFather, set a Mini App URL (must be HTTPS).
3) Set bot commands: `/start`, `/help`, `/miniapp`, `/cancel`.

## Run
```
$env:VPNW_BOT_TOKEN="YOUR_TOKEN"
$env:VPNW_MINIAPP_URL="https://your-domain/miniapp"
python -m vpn_wizard.server
python -m vpn_wizard.tg_bot
```

## Notes
- The miniapp is just a web UI, it calls the API server to do SSH provisioning.
- If you only want the bot wizard, you can skip the server.
- If miniapp is hosted separately (Vercel), set `window.API_BASE` in `web/miniapp/config.js`.
- Enable CORS with `VPNW_CORS_ORIGINS="https://your-miniapp-domain"`.
- You can also set the API on the fly via `?api=https://your-api-domain` in the miniapp URL.
- For a single Railway service, run `python -m vpn_wizard.combined` with `VPNW_BOT_TOKEN` set.
- To require a channel subscription, set `VPNW_REQUIRED_CHANNEL="@fodders_dev"`.
