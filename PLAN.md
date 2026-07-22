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
- [x] Prove managed AmneziaWG over UDP 443 end-to-end and make it the primary RF action
- [x] Replace the vague two-column "Партнёрка" entry with an explicit full-width sharing action
- [x] Add a private family web link with one independent AWG slot and no Telegram requirement
- [x] Apply owner entitlement, expiry and renewal to the family slot on every AWG server
- [x] Replace the stale 14-day tariff label and duplicate production trial settings with a 7-day trial
- [x] Replace old `/miniapp` buttons with one unified managed-VPN portal
- [x] Preserve the complete Fodders VPN 1 self-hosted flow at `/wizard` and `/vpn1`
- [x] Add bidirectional portal/Wizard navigation and Telegram native BackButton support

Next: Провести реальную покупку Telegram Stars и проверить полный цикл «оплата → продление → вывод».
