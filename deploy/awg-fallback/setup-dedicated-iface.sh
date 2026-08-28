#!/bin/bash
# Поднять ВЫДЕЛЕННЫЙ интерфейс AmneziaWG для продукта на чужой коробке.
#
# Нужен, когда экзит — чей-то личный сервер, и awg0/awg1 там уже заняты
# владельцем: продукт живёт на своём интерфейсе, со своей подсетью и своим
# каталогом клиентов, и пересобирать чужие интерфейсы не может.
#
# Пример: bash setup-dedicated-iface.sh awg9 443 10.99.0.1/24
#
# ВАЖНО: правила ниже обязаны совпадать с тем, что ставит провижинер
# (WireGuardProvisioner._post_rules в src/vpn_wizard/core.py). Один раз этот
# файл создавался руками без MSS-клэмпинга — у людей поднимался туннель, но
# крупные TCP-пакеты молча терялись: Telegram-текст ходил, а фото и сайты
# висели вечно. PMTU-клэмпинг оставляем как страховку, а MSS 1160 нужен потому,
# что на некоторых AWG-маршрутах вычисленные 1240 всё ещё дают ретрансляции.
set -euo pipefail

IFACE="${1:-awg9}"
PORT="${2:-443}"
CIDR="${3:-10.99.0.1/24}"
DIR=/etc/amnezia/amneziawg
CLIENTS="$DIR/clients_$IFACE"
EGRESS=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
NET=$(python3 -c "import ipaddress,sys;print(ipaddress.ip_interface(sys.argv[1]).network)" "$CIDR")

[ -e "$DIR/$IFACE.conf" ] && { echo "ОТКАЗ: $IFACE.conf уже существует"; exit 1; }
ss -uln | grep -q ":$PORT " && { echo "ОТКАЗ: udp/$PORT занят"; exit 1; }

mkdir -p "$CLIENTS"; chmod 700 "$CLIENTS"
umask 077
if [ ! -f "$DIR/server_private_$IFACE.key" ]; then
  awg genkey | tee "$DIR/server_private_$IFACE.key" | awg pubkey > "$DIR/server_public_$IFACE.key"
fi
PRIV=$(cat "$DIR/server_private_$IFACE.key")

# MTU 1280 безопасен на любых мобильных сетях. Клиентам выдаётся не больше этого
# значения — за этим следит _cap_mtu_to_interface в провижинере.
# Обфускация обязана совпадать с дефолтами core.py, иначе хендшейк не сойдётся.
cat > "$DIR/$IFACE.conf" <<EOF
[Interface]
Address = $CIDR
ListenPort = $PORT
PrivateKey = $PRIV
MTU = 1280
Jc = 2
Jmin = 40
Jmax = 70
S1 = 130
S2 = 37
H1 = 1028292012
H2 = 2027322962
H3 = 1500253145
H4 = 836814590
PostUp = iptables -w -I FORWARD 1 -i %i -j ACCEPT; iptables -w -I FORWARD 1 -o %i -j ACCEPT; iptables -w -t nat -A POSTROUTING -s $NET -o $EGRESS -j MASQUERADE; iptables -w -t mangle -I FORWARD 1 -i %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160; iptables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -w -D FORWARD -i %i -j ACCEPT; iptables -w -D FORWARD -o %i -j ACCEPT; iptables -w -t nat -D POSTROUTING -s $NET -o $EGRESS -j MASQUERADE; iptables -w -t mangle -D FORWARD -i %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1160; iptables -w -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
EOF
chmod 600 "$DIR/$IFACE.conf"

sysctl -qw net.ipv4.ip_forward=1
grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
command -v ufw >/dev/null && ufw status | grep -q "Status: active" && ufw allow "$PORT"/udp >/dev/null 2>&1 || true

systemctl enable --now "awg-quick@$IFACE"
sleep 2
echo "=== готово ==="
awg show "$IFACE" | grep -E "interface|listening|public key"
echo "MSS-клэмпинг: $(iptables -t mangle -S FORWARD | grep -c TCPMSS) правил"
