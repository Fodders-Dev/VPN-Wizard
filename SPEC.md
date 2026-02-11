# VPN Wizard - SPEC

## Goal
Turn a rented VPS into a fast VPN and anti-block proxy with ready configs/links/QR codes.

## Stack
- Python 3.10+
- Paramiko for SSH control
- Typer for CLI
- PySide6 for GUI wizard
- qrcode + Pillow for QR generation

## MVP Scope
- core: SSH connect, OS detect, WireGuard install, IP forwarding, NAT/firewall, client config generation
- core: VLESS Reality anti-block proxy provisioning (Xray), client link/QR generation
- core: optional network tuning (BBR, buffers) and MTU default for speed/stability
- cli: `provision`, `export`, `status`
- gui: wizard flow (server access -> configure -> progress -> download config + QR)
- miniapp: RU/EN локализация (RU по умолчанию), быстрый чек статуса сервера, выбор UDP порта, локальный список недавних серверов (без паролей)
- miniapp: поддержка SSH порта (включая формат host:port) и понятные подсказки при ошибке подключения к порту 22
- miniapp: remember login через временную серверную сессию (`session_id`) без хранения пароля/приватного ключа в localStorage
- miniapp: управление профилями доступа (список, статус/трафик, скачать конфиг/QR, удалить/перевыпустить), FAQ и онбординг
- miniapp: выбор режима подключения (VPN AmneziaWG или Proxy VLESS Reality) с отдельными подсказками
- miniapp: первичный экран - только доступ к серверу и проверка; после проверки показываются настройка или список профилей
- miniapp: переключение между сохраненными серверами + удаление сервера + "забыть вход" для конкретного сервера
- miniapp: QR для профилей открывается прямо в списке, с отдельной кнопкой скачивания (включая Telegram WebApp)
- miniapp: расширенный безопасный режим (только precheck), подробный FAQ о действиях на сервере
- bot: онбординг и ограничение доступа только для подписчиков канала
- distribution: API server + Telegram bot + miniapp wizard UI
- distribution: async job queue + progress polling for miniapp

## Outputs
- Server: `/etc/wireguard/wg0.conf` and `/etc/wireguard/clients/<client>.conf`
- Server (proxy mode): `/usr/local/etc/xray/config.json` with VLESS Reality inbound
- Local: exported client config + optional QR PNG
- Local (proxy mode): exported `vless://` link (txt) + QR PNG

## Constraints
- Systemd required for `wg-quick@wg0`
- Distros: Debian/Ubuntu and RHEL-like (CentOS/Rocky/Alma/Fedora)
- Default UDP port: 3478 (configurable per server)
