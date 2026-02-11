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
- [x] Add anti-block proxy mode (VLESS Reality): setup/status/client links in API + miniapp mode switch

Next: Добавить e2e-тесты miniapp сценариев для двух режимов (VPN/Proxy), включая сохранение сервера и переключение mode.
