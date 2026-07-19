# PLAN

- [x] Choose stack and repo layout
- [x] Implement core provisioning and export
- [x] Implement CLI commands
- [x] Implement GUI wizard
- [x] Write SPEC/RUNBOOK
- [x] Add miniapp support for SSH port (`ssh_port`, host:port parsing)
- [x] Add remember-login flow via API sessions (`/api/sessions/login`, `/api/sessions/revoke`)
- [x] Add miniapp server switching controls (use / forget login / delete)
- [x] Cover server-side session and host:port parsing with tests
- [x] Add anti-block proxy mode (ShadowTLS + SS2022 via sing-box) as primary
- [x] Keep legacy proxy mode (VLESS Reality via Xray) as fallback
- [x] Redact secrets in SSH progress logs (multiline commands / x25519 -i)
- [x] Preserve Fodders VPN 1 inside the managed Bedolaga subscription bot
- [x] Tie managed AmneziaWG peers to Remnawave expiry with suspend/resume
- [x] Add webhook plus periodic entitlement reconciliation for AmneziaWG
- [x] Publish NL/FI/TR/US as selectable nodes in one subscription
- [x] Enable Telegram Stars billing without giving Remnawave payment custody

Next: Провести финальный мобильный e2e: импорт AmneziaWG, подключение к NL/FI/TR/US и одна реальная покупка Telegram Stars с проверкой продления.
