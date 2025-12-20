### WireGuard: быстрый личный VPN (Linux, Android, iOS)

Этот репозиторий содержит скрипт `wg-setup.sh` для установки WireGuard на VPS (Debian/Ubuntu), настройки NAT, включения форвардинга и генерации клиентских конфигов + QR.

#### Требования
- VPS с публичным IPv4 (Европа/Азия/США)
- Ubuntu/Debian
- Порты UDP 51820 открыты в firewall

#### Установка на VPS
1) Скопируйте скрипт на сервер и запустите:
```bash
scp wg-setup.sh root@YOUR_SERVER_IP:/root/
ssh root@YOUR_SERVER_IP 'bash -lc "chmod +x /root/wg-setup.sh && sudo bash /root/wg-setup.sh --qr"'
```
Скрипт:
- установит WireGuard и включит IPv4 forwarding
- создаст `wg0` с подсетью `10.66.66.0/24`
- сгенерирует клиента `client1` и напечатает QR в терминал

Файлы:
- сервер: `/etc/wireguard/wg0.conf`
- клиенты: `/etc/wireguard/clients/*.conf`

Проверка:
```bash
sudo wg show | cat
```

#### Добавление клиентов позже
На сервере:
```bash
sudo bash /root/wg-setup.sh --add-client phone --qr
sudo bash /root/wg-setup.sh --add-client laptop
```
Конфиги лежат в `/etc/wireguard/clients/`. Можно скачать `scp` или показать QR.

#### Клиенты
- Linux (Debian/Ubuntu):
  ```bash
  sudo apt update && sudo apt install wireguard -y
  sudo mkdir -p /etc/wireguard && sudo cp client1.conf /etc/wireguard/wg0.conf
  sudo chmod 600 /etc/wireguard/wg0.conf
  sudo wg-quick up wg0
  ```
- Android: установите приложение WireGuard → импорт по QR или из файла.
- iOS: установите WireGuard из App Store → импорт по QR/файлу.

#### Полезные команды
```bash
sudo systemctl restart wg-quick@wg0
sudo systemctl status wg-quick@wg0 | cat
sudo wg show | cat
```

#### Параметры скрипта
- `--port 51820` — порт UDP
- `--dns 1.1.1.1` — DNS для клиентов
- `--interface wg0` — имя интерфейса
- `--add-client NAME` — создать клиента
- `--qr` — вывести QR в терминал

Если авто-детект публичного IP не сработает, в конфиге клиента будет `YOUR_SERVER_IP` — замените на адрес сервера. 