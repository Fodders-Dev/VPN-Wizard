# VPN Wizard - SPEC

## Goal
Turn a rented VPS into a fast VPN and anti-block proxy with ready configs/links/QR codes.

The managed product uses the same Telegram bot for the original Fodders VPN 1
wizard and a paid subscription. Remnawave owns entitlement and VLESS node state;
Telegram Stars stay on the Telegram bot balance.

## Stack
- Python 3.10+
- Paramiko for SSH control
- Typer for CLI
- PySide6 for GUI wizard
- qrcode + Pillow for QR generation

## MVP Scope
- core: SSH connect, OS detect, WireGuard install, IP forwarding, NAT/firewall, client config generation
- core: anti-block proxy provisioning (sing-box):
  - primary: ShadowTLS v3 + Shadowsocks 2022 (SS2022) for RU networks (stable DNS/routing defaults)
  - ShadowTLS default: single TCP port (prefer 443) + pinned routing (no urltest auto-failover by default)
  - legacy fallback: VLESS Reality (Xray)
- core: optional network tuning (BBR, buffers) and MTU default for speed/stability
- cli: `provision`, `export`, `status`
- gui: wizard flow (server access -> configure -> progress -> download config + QR)
- self-hosted wizard (`/wizard/`): RU/EN локализация (RU по умолчанию), быстрый чек статуса сервера, выбор UDP порта, локальный список недавних серверов (без паролей)
- miniapp: поддержка SSH порта (включая формат host:port) и понятные подсказки при ошибке подключения к порту 22
- miniapp: remember login через временную серверную сессию (`session_id`) без хранения пароля/приватного ключа в localStorage
- miniapp: управление профилями доступа (список, статус/трафик, скачать конфиг/QR, удалить/перевыпустить), FAQ и онбординг
- miniapp: выбор режима подключения (VPN AmneziaWG или Proxy ShadowTLS) с отдельными подсказками
- miniapp: первичный экран - только доступ к серверу и проверка; после проверки показываются настройка или список профилей
- miniapp: переключение между сохраненными серверами + удаление сервера + "забыть вход" для конкретного сервера
- miniapp: QR для профилей открывается прямо в списке, с отдельной кнопкой скачивания (включая Telegram WebApp)
- miniapp: расширенный безопасный режим (только precheck), подробный FAQ о действиях на сервере
- bot: онбординг и ограничение доступа только для подписчиков канала
- managed bot: trial, Telegram Stars plans, preserved Fodders VPN 1, and `/awg`
- managed subscription: AmneziaWG is the only production connection method;
  selectable NL/FI/TR/US exits use independent obfuscated AWG profiles
- managed AmneziaWG: issue only for an ACTIVE Remnawave user; suspend the server
  peer on expiry and restore the same keys/config on renewal
- managed AmneziaWG reliability: signed links, HMAC webhook, and a two-minute
  reconciliation timer for missed lifecycle events
- managed bot UX: put the entitlement-checked AmneziaWG action first; label
  the old miniapp as legacy without removing any Fodders VPN 1 features
- managed bot growth UX: expose Bedolaga's existing one-level referral flow as
  a full-width "Share VPN" action; do not present it as a multi-level pyramid
- managed family UX: one private browser link per owner issues a separate AWG
  peer without Telegram; it follows the owner's expiry and resumes with the same keys
- managed portal (`/miniapp/` and `/connect/`): authenticate through Telegram
  initData + HttpOnly session, expose managed/family AWG actions, and link to the
  complete Fodders VPN 1 self-hosted wizard without storing signed links locally
- distribution: API server + Telegram bot + miniapp wizard UI
- distribution: async job queue + progress polling for miniapp

## Outputs
- Server: `/etc/wireguard/wg0.conf` and `/etc/wireguard/clients/<client>.conf`
- Server (proxy mode, primary): `/usr/local/etc/sing-box/config.json` (ShadowTLS inbound -> SS2022 inbound)
- Server (proxy mode, legacy): `/usr/local/etc/xray/config.json` with VLESS Reality inbound
- Local: exported client config + optional QR PNG
- Local (proxy mode, primary): auto-config JSON (sing-box/Hiddify profile URL)
  - includes a stable selector and conservative routing defaults for RU networks
- Local (proxy mode, legacy): exported `vless://` link (txt) + QR PNG

## Constraints
- Systemd required for `wg-quick@wg0`
- Distros: Debian/Ubuntu and RHEL-like (CentOS/Rocky/Alma/Fedora)
- Default UDP port: 3478 (configurable per server)
