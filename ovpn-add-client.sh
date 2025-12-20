#!/usr/bin/env bash
set -euo pipefail

# OpenVPN client generator
# Usage:
#   sudo bash ovpn-add-client.sh <client_name>
# Creates /root/<client_name>.ovpn (embedded tls-crypt, ca, cert, key)

CLIENT_NAME="${1:-}"
if [[ -z "${CLIENT_NAME}" ]]; then
	echo "Usage: $0 <client_name>"; exit 1
fi

EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_CONF_LEGACY="/etc/openvpn/server/server.conf"
SERVER_CONF_UDP="/etc/openvpn/server/udp443.conf"
TC_KEY="/etc/openvpn/tc.key"

# Sanity check: ensure any server config exists (TCP legacy or UDP)
if [[ ! -f "${SERVER_CONF_LEGACY}" && ! -f "${SERVER_CONF_UDP}" ]]; then
    echo "OpenVPN server config not found at ${SERVER_CONF_LEGACY} or ${SERVER_CONF_UDP}."; exit 1
fi

apt update -y >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt install -y easy-rsa curl >/dev/null 2>&1 || true

install -d -m 700 "${EASYRSA_DIR}"
[[ -d "${EASYRSA_DIR}/pki" ]] || cp -r /usr/share/easy-rsa/* "${EASYRSA_DIR}/"
cd "${EASYRSA_DIR}"

if [[ ! -d pki ]]; then
	EASYRSA_BATCH=1 ./easyrsa init-pki
	EASYRSA_BATCH=1 EASYRSA_REQ_CN="ovpn-ca" ./easyrsa build-ca nopass
	EASYRSA_BATCH=1 ./easyrsa gen-dh
	EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
	openvpn --genkey secret "${TC_KEY}"
fi

# Create client cert/key if absent
if [[ ! -f "pki/issued/${CLIENT_NAME}.crt" ]]; then
	EASYRSA_BATCH=1 ./easyrsa build-client-full "${CLIENT_NAME}" nopass
fi

SRVIP=$(curl -4 -fsS https://ifconfig.co 2>/dev/null || curl -4 -fsS https://api.ipify.org 2>/dev/null || echo YOUR_SERVER_IP)
cat >"/root/${CLIENT_NAME}.ovpn" <<OVPN
client
dev tun

# Prefer UDP/443 for speed; TCP/443 as fallback
remote ${SRVIP} 443 udp
remote ${SRVIP} 443 tcp
remote-random
resolv-retry infinite
connect-retry 5 5
nobind
persist-key
persist-tun
remote-cert-tls server

# Fast AEAD ciphers (OpenVPN 2.4/2.5/2.6 compatible)
# 2.5+: data-ciphers; 2.4: ncp-ciphers + cipher
data-ciphers AES-128-GCM:CHACHA20-POLY1305:AES-256-GCM
data-ciphers-fallback AES-128-GCM
ncp-ciphers AES-128-GCM:CHACHA20-POLY1305:AES-256-GCM
cipher AES-128-GCM

# Throughput/stability tweaks
mssfix 1450
sndbuf 0
rcvbuf 0
fast-io
explicit-exit-notify 1

# Enable DCO when supported (ignored by older clients)
ignore-unknown-option dco
dco

verb 3
key-direction 1
redirect-gateway def1
dhcp-option DNS 1.1.1.1

<tls-crypt>
$(cat "${TC_KEY}")
</tls-crypt>
<ca>
$(cat "${EASYRSA_DIR}/pki/ca.crt")
</ca>
<cert>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "${EASYRSA_DIR}/pki/issued/${CLIENT_NAME}.crt")
</cert>
<key>
$(cat "${EASYRSA_DIR}/pki/private/${CLIENT_NAME}.key")
</key>
OVPN

chmod 600 "/root/${CLIENT_NAME}.ovpn"
echo "/root/${CLIENT_NAME}.ovpn" 
