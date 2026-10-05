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
- [x] Retire the Bedolaga trial; replace it with permanent one-device NL access for channel members and a 12-hour web bridge
- [x] Replace old `/miniapp` buttons with one unified managed-VPN portal
- [x] Preserve the complete Fodders VPN 1 self-hosted flow at `/wizard` and `/vpn1`
- [x] Add bidirectional portal/Wizard navigation and Telegram native BackButton support
- [x] Reject partial AmneziaWG installs and failed runtime checks before issuing profiles
- [x] Cover missing kernel modules and readiness failures with regression tests
- [x] Recover the Ubuntu 5.15.0-43 self-hosted VPS and verify handshake, DNS and HTTPS egress

- [x] Add a server catalogue with real, stale-aware VPN statuses and alternate ports
- [x] Make free server selection consistent across issue, webhook and reconcile
- [x] Add configurable voluntary support details below the catalogue

- [x] Verify desktop/mobile catalogue and deploy with a rollback backup on NL

- [x] Open public anonymous profiles without codes or device limits
- [x] Verify public download/reuse, monitoring, donation UX and deploy final release

- [x] Переработать публичный интерфейс с Astra: минимальная копия, выразительный дизайн и проверка mobile/desktop перед публикацией

- [x] Усилить добровольную поддержку: заметные кнопки, карта с копированием и объяснение расходов

- [x] Поднять компактную поддержку перед скачиванием профилей; проверить desktop/mobile и опубликовать

- [x] Обновить Telegram-кабинет в минимальном стиле сайта; проверить бесплатный/платный доступ, mobile и опубликовать

- [x] Вернуть личные QR-коды в публичный каталог, явно предупредить о проблемных серверах и опубликовать после проверок.

- [x] Сделать существующий NL UDP 3478 основным вариантом сайта; сохранить NL UDP 443 и старые ключи.

- [x] Исправить повторную выдачу профилей после смены IP/порта без смены ключей.
- [x] Перевести FI на 46.38.156.229:3478; по разрешению владельца перенести личный awg0 на 443 без смены ключей.
- [x] Проверить FI VPN из сети владельца после смены IP и порта; подтверждены handshake и двусторонний трафик на UDP 3478 (2026-10-05).

Next: Поддерживать статусы по штатному монитору; альтернативный FI UDP 4500 не считать проверенным из РФ без отдельного клиентского теста.
