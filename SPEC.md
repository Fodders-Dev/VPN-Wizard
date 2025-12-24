# VPN Wizard - SPEC

## Goal
Turn a rented VPS into a fast WireGuard VPN and deliver ready configs/QR codes.

## Stack
- Python 3.10+
- Paramiko for SSH control
- Typer for CLI
- PySide6 for GUI wizard
- qrcode + Pillow for QR generation

## MVP Scope
- core: SSH connect, OS detect, WireGuard install, IP forwarding, NAT/firewall, client config generation
- core: optional network tuning (BBR, buffers) and MTU default for speed/stability
- cli: `provision`, `export`, `status`
- gui: wizard flow (server access -> configure -> progress -> download config + QR)
- miniapp: RU/EN локализация (RU по умолчанию), быстрый чек статуса сервера, выбор UDP порта, локальный список недавних серверов (без паролей)
- distribution: API server + Telegram bot + miniapp wizard UI
- distribution: async job queue + progress polling for miniapp

## Outputs
- Server: `/etc/wireguard/wg0.conf` and `/etc/wireguard/clients/<client>.conf`
- Local: exported client config + optional QR PNG

## Constraints
- Systemd required for `wg-quick@wg0`
- Distros: Debian/Ubuntu and RHEL-like (CentOS/Rocky/Alma/Fedora)
- Default UDP port: 3478 (configurable per server)
