### TCP-безотказный доступ: Xray VLESS Reality (порт 443)

Этот скрипт `xray-reality-setup.sh` поднимает прокси Xray (VLESS Reality) на TCP 443. Он проходит даже сети с полным блоком UDP (кампус/операторы).

#### Установка на VPS
```bash
scp "xray-reality-setup.sh" root@YOUR_SERVER_IP:/root/
ssh root@YOUR_SERVER_IP 'bash -lc "chmod +x /root/xray-reality-setup.sh && sudo bash /root/xray-reality-setup.sh"'
```
Скрипт выведет vless:// ссылку и QR для первого клиента `client1`.

Добавить клиента позже:
```bash
ssh root@YOUR_SERVER_IP 'sudo bash /root/xray-reality-setup.sh --add-client phone'
ssh root@YOUR_SERVER_IP 'sudo bash /root/xray-reality-setup.sh --add-client iphone'
```

Параметры (опционально):
- `--port 443` — TCP порт (обычно 443)
- `--sni www.cloudflare.com` — домен для маскировки
- `--fingerprint chrome` — TLS fingerprint

#### Клиенты
- Android: v2rayNG (Google Play / GitHub). Нажмите “+” → “Импорт по ссылке” → вставьте `vless://...` из вывода, сохраните.
- iOS: Shadowrocket (App Store, платно) → “+” → “Scan QR code” или “Type URL” → вставьте ссылку.
- Windows/macOS/Linux: Nekoray/Clash Meta/Sing-Box — импорт ссылки `vless://...`.

#### Одновременное использование с WireGuard
- Для обычных сетей продолжайте пользоваться WireGuard (быстрее), а в “тяжёлых” сетях включайте Xray (TCP 443). Оба сервиса могут работать параллельно на сервере.

#### Проверка статуса
```bash
sudo systemctl status xray | cat
sudo tail -n 100 /var/log/xray/error.log | cat
``` 