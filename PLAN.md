# PLAN

## Public server IP-age display (2026-10-30)

- [x] Add accessible whole-day IP-age labels to main and alternate exit cards.
- [x] Seed NL/FI dates, owner-approved US estimate and honest unknown TR date.
- [x] Publish to the Caddy-served static site and visually verify Chrome cards,
      including the FI alternate port.
- [x] Extend the one-shortcut migration workflow to update dates only on actual
      verified changes, with safe site backups and retry after sync failure.
- [x] Style IP age as a visible incident-free-days badge; mark the US estimate
      with `≈` and clear it on verified address change.


## FI address refresh (2026-10-30)

- [x] Wait for provider IP replacement, then verify the original SSH/AWG keys.
- [x] Update 151 stored profiles and both FI entries on the NL controller.
- [x] Synchronize the separate public API on 77.91.113.109 and verify download.

## All-server launcher and stable website entry (2026-10-26)

- [x] Add dedicated NL controller migration with unchanged loopback/AWG identities.
- [x] Resolve public URLs and XHTTP certificates from deployment configuration.
- [x] Make the US administration gateway follow the owner SSH alias.
- [x] Independently review and release the stable `/vpn/` entry on fodders.ru.
- [x] Complete interrupted NL migration recovery and release the launcher.
- [x] Verify Windows NL check and repeated apply against the current live IP.

## FI replacement and reusable IP workflow (2026-10-26)

- [x] Verified trusted SSH and cached AWG identities at 185.202.207.126.
- [x] Backed up all four control databases and FI AWG state; updated 124 profiles,
      registry, saved host and six owner Downloads exports without rotating keys.
- [x] Verified live FI download, retained key on repeat download and private QR.
- [x] Replaced hardcoded watchdog targets with registry-derived addresses.
- [x] Added owner PowerShell/CMD launcher and Desktop shortcut, with strict
      verification, backups, no-op repeats and truthful rollback reporting.
- [ ] Owner imports the refreshed FI profile and confirms real RF-device traffic.

## NL IP replacement (2026-10-25)

- [x] Verified the same SSH identity and retained AWG keys/peers at 82.25.60.19.
- [x] Backed up runtime configs and all four databases; migrated site, HTTPS,
      profile endpoints, bot/menu, panel/node records, watchdog and owner exports.
- [x] Verified 606 tests, live downloads/QR, repeat-key reuse and HTTPS from Windows.
- [x] Installed and exercised hourly XHTTP certificate synchronization.
- [x] Owner updated Main App and legacy /setdomain; browser login widget now loads.
- [ ] Owner imports a refreshed AWG profile and confirms actual device traffic.

- [x] Make AmneziaWG and installation immediately obvious on the public catalog; published, 590 tests and 320/390/1280px plus keyboard/guide checks passed.
- [x] Audit existing alternative listeners without touching AWG: NL ShadowTLS v3 TCP 10443 and VLESS/XHTTP/TLS TCP 9443 already exist.
- [ ] Trial Hiddify + existing ShadowTLS privately on the owner's home/mobile networks; no public alternative until real traffic is verified.

- [x] Убрать ложный NL self-ping: внешний замер с FI, честный источник и отсутствие замера вместо нуля.
- [x] Проверить и опубликовать понятный idle-статус NL и внешний пинг; Luna xhigh — UI, куратор — мониторинг и прод. 589 тестов; mobile 320/390 и desktop 1280 без переполнения.

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

- [x] Пересобрать вход вокруг бесплатного VPN и настройки своего VPS; сохранить старые аккаунты отдельно.
- [x] Добавить подробную инструкцию AmneziaWG, безопасные имена скачиваний и локальное исправление имени файла.
- [x] Проверить пользовательский путь в браузере, локальное исправление файлов, QR, Telegram iframe и обязательный вход для администрирования VPS; 569 тестов проходят.
- [x] Опубликовать бесплатное меню бота/сайта с резервной копией; live-выдача .conf и QR проверена, бот healthy, команды free/wizard/help, обе главные кнопки подтверждены через API.
- [ ] После ручного запуска эмулятора заменить старые иллюстрации новыми Android-снимками, включая переименование. Автоматический запуск AVD отклонён инструментом.

Next: Import the refreshed FI profile and confirm device traffic; synchronize both NL and public API registries on future exit IP changes.
