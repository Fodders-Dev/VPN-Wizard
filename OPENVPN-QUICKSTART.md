# OpenVPN (UDP/443 + TCP/443 fallback) — краткая выжимка

Этот файл — краткий чеклист по текущей настройке VPN. Держите его под рукой для быстрого повторения действий.

## Итоговое состояние
- Сервер Ubuntu 24.04 в NL, работает OpenVPN:
  - Основной сервер: `UDP/443`, включён DCO (ускорение).
  - Запасной маршрут: `TCP/443` (fallback, отдельный инстанс/конфиг).
- NAT и роутинг включены, клиенты получают интернет через туннель.
- Генерация профилей через скрипт `ovpn-add-client.sh` с приоритетом `UDP/443` и fallback на `TCP/443`.
- Клиентские профили используют современные AEAD‑шифры и твики производительности; DCO включён на клиентах 2.6+ и игнорируется на мобильных.

## Важные пути и сервисы (на сервере)
- UDP‑конфиг: `/etc/openvpn/server/udp443.conf`
- TCP‑конфиг: обычно `/etc/openvpn/server/server.conf` (или другой файл под ваш TCP‑инстанс)
- Сервисы systemd:
  - UDP: `openvpn-server@udp443`
  - TCP: обычно `openvpn-server@server` (или по имени файла конфига)
- Скрипт генерации профилей: `/root/ovpn-add-client.sh`
- Ключи/сертификаты (EasyRSA): `/etc/openvpn/easy-rsa/pki/...`
- TLS-ключ: `/etc/openvpn/tc.key`

## Как подключиться к серверу
- SSH: `ssh root@212.69.84.167`
- Смена пароля: `passwd`
- Рекомендация: позже отключить вход по паролю и перейти на SSH‑ключи.

## Памятка: подключение → профиль → выгрузка
1. **Проверить локальный ключ.**
   - Файл: `~/.ssh/id_ed25519` (приватный, `chmod 600 ~/.ssh/id_ed25519`).
   - Публичная часть: `~/.ssh/id_ed25519.pub`. В ней должна быть **одна строка** вида `ssh-ed25519 AAAA... email`. Если разбито на несколько строк — пересоздай файл: `ssh-keygen -y -f ~/.ssh/id_ed25519 > ~/.ssh/id_ed25519.pub`.
   - На сервере содержимое этой строки должно лежать в `~/.ssh/authorized_keys`.
2. **Если видишь `Permission denied (publickey)`:**
   - Разово войди по паролю: `ssh artem@212.69.84.167` → пароль `N4okFpso7S`.
   - После входа добавь ключ:
     ```
     mkdir -p ~/.ssh && chmod 700 ~/.ssh
     echo "<содержимое ~/.ssh/id_ed25519.pub>" >> ~/.ssh/authorized_keys
     chmod 600 ~/.ssh/authorized_keys
     ```
     Либо с локалки выполни `ssh-copy-id -i ~/.ssh/id_ed25519 artem@212.69.84.167` (запросит пароль один раз).
3. **Дальнейший вход:** `ssh -i ~/.ssh/id_ed25519 artem@212.69.84.167` (при необходимости `sudo -s` для root).
4. **Залить/обновить скрипт генерации:**
   ```
   scp ovpn-add-client.sh artem@212.69.84.167:~/ovpn-add-client.sh
   ssh -i ~/.ssh/id_ed25519 artem@212.69.84.167 \
     'sudo mv ~/ovpn-add-client.sh /root/ && sudo chmod +x /root/ovpn-add-client.sh'
   ```
5. **Создать профиль (пример для `android-pixel`):**
   ```
   ssh -i ~/.ssh/id_ed25519 artem@212.69.84.167 \
     'sudo /root/ovpn-add-client.sh android-pixel'
   ```
   Скрипт сообщит путь вида `/root/android-pixel.ovpn`.
6. **Скачать профиль на свой ПК (замени имя файла и папку):**
   ```
   scp -i ~/.ssh/id_ed25519 artem@212.69.84.167:/root/android-pixel.ovpn ~/Downloads/
   ```
   На Windows в Git Bash можно указать `~/Downloads`, в PowerShell — `C:\Users\<ты>\Downloads\android-pixel.ovpn`.
   - Если скрипт запускается через `sudo` и профиль хранится в `~/ovpn-profiles`, файл принадлежит root и имеет `chmod 600`. Перед `scp` сбрось права: `sudo chown artem:artem ~/ovpn-profiles/android-pixel.ovpn` (подставь имя) или скачай от root (`scp root@212.69.84.167:/home/artem/ovpn-profiles/...`).
7. **Импортировать** `.ovpn` в OpenVPN Connect/Viscosity/овский клиент на телефоне/ПК.

### Быстрый вариант "в одну команду на устройство"
```
DEVICE=android-pixel
ssh -i ~/.ssh/id_ed25519 artem@212.69.84.167 \
  "sudo /root/ovpn-add-client.sh ${DEVICE}"
scp -i ~/.ssh/id_ed25519 \
  artem@212.69.84.167:/root/${DEVICE}.ovpn ~/VPN-Profiles/
```
- В первую команду подставь имя профиля, скрипт создаст `/root/${DEVICE}.ovpn`.
- Вторая команда скачает файл в локальную папку (`~/VPN-Profiles` создай заранее или укажи свою).

## Быстрые команды управления (на сервере)
- Статусы: `systemctl status openvpn-server@udp443` и `systemctl status openvpn-server@server`
- Перезапуск: `systemctl restart openvpn-server@udp443`
- Порты: `ss -ulpn | grep :443` (UDP) и `ss -tlpn | grep :443` (TCP)

## Конфиг UDP/443 (с DCO, выжимка)
Минимально важные строки из `/etc/openvpn/server/udp443.conf`:
```
port 443
proto udp
dev tun
server 10.9.0.0 255.255.255.0
topology subnet
keepalive 10 60
explicit-exit-notify 1
user nobody
group nogroup

# Производительность
mssfix 1450
sndbuf 0
rcvbuf 0
push "sndbuf 0"
push "rcvbuf 0"

# AEAD‑шифры (современно и быстро)
data-ciphers AES-128-GCM:CHACHA20-POLY1305:AES-256-GCM
data-ciphers-fallback AES-128-GCM
ncp-ciphers AES-128-GCM:CHACHA20-POLY1305:AES-256-GCM
cipher AES-128-GCM

# Ключи
tls-crypt /etc/openvpn/tc.key
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem

# Включение DCO
ignore-unknown-option dco
dco
```
Примечание: при желании можно вместо `dev tun` использовать `dev ovpn-dco` (тоже включает DCO).

## DCO: как понять, что включён
- В логах сервиса видно строки вида: `DCO version: ...` и `DCO device tunX opened`:
  - `journalctl -u openvpn-server@udp443 | grep -i dco`
- На сервере модуль загружен: `lsmod | grep ovpn` → `ovpn_dco_v2`

## NAT/маршрутизация (уже включено)
- IPv4 форвардинг включён: `net.ipv4.ip_forward=1`
- NAT для подсети UDP: правило MASQUERADE на wan‑интерфейс (например, `ens1`) для `10.9.0.0/24` сохранено через `iptables-persistent`.
- Если TCP‑инстанс использует другую подсеть (часто `10.8.0.0/24`), нужно аналогичное правило для неё.

## Генерация профилей (на сервере)
1) Залить (или обновить) скрипт:
```
scp ovpn-add-client.sh root@212.69.84.167:/root/
ssh root@212.69.84.167 chmod +x /root/ovpn-add-client.sh
```
2) Сгенерировать профиль для устройства:
```
sudo /root/ovpn-add-client.sh <device_name>
```
3) Забирать локально:
```
scp root@212.69.84.167:/root/<device_name>.ovpn .
```
4) Импорт в клиент OpenVPN (ПК/мобилка) и подключение.

### Что внутри профиля (.ovpn)
- `remote <IP> 443 udp` как основной; `remote <IP> 443 tcp` как fallback
- AEAD‑шифры: `AES-128-GCM`, `CHACHA20-POLY1305` (+ fallback)
- Твики: `mssfix 1450`, `sndbuf 0`, `rcvbuf 0`, `fast-io`, `explicit-exit-notify 1`
- DCO‑директивы клиента: `ignore-unknown-option dco` и `dco` (ПК 2.6+ используют, iOS/Android игнорируют)

## Проверки после изменений
- UDP слушает: `ss -ulpn | grep :443`
- TCP слушает: `ss -tlpn | grep :443`
- Логи UDP: `journalctl -u openvpn-server@udp443 | tail -n 50`
- DCO упоминается в логах (см. выше).

## Опциональный тюнинг
- TCP‑fallback быстрее с BBR:
```
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr
```
Чтобы сохранить постоянно — добавить те же строки в `/etc/sysctl.d/99-bbr.conf` и выполнить `sysctl --system`.

## Частые проблемы и быстрые проверки
- Нет интернета в туннеле:
  - Проверить `ip a show tun*` (или `ovpn-dco`), `ip route`, NAT‑правила: `iptables -t nat -S | grep 10.9.0.0`
- UDP блокируется сетью: профиль сам упадёт на `TCP/443`.
- DCO упал из‑за несовпадений: временно уберите `dco` из конфига сервера или используйте `dev ovpn-dco`.

## Безопасность
- Сменить пароль root (`passwd`).
- Перейти на SSH‑ключи и отключить вход по паролю:
```
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl reload ssh
```

---
Если знаешь, что сеть часто режет UDP/443, можно добавить альтернативный порт или включить обфускацию/`tls-crypt` (уже включена). При необходимости расширим конфиг под конкретные сети и MTU.
