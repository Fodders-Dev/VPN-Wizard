#!/usr/bin/env bash
set -euo pipefail

CLIENT_NAME="${1:-}"
if [[ -z "${CLIENT_NAME}" ]]; then
    echo "Usage: $0 <client_name>" >&2
    exit 1
fi

EASYRSA_DIR="/home/artem/openvpn-ca"
OUTPUT_DIR="/home/artem/ovpn-profiles"
TA_KEY="/etc/openvpn/server/ta.key"
TEMPLATE="/etc/openvpn/client-common.txt"

if [[ ! -d "${EASYRSA_DIR}" ]]; then
    echo "Easy-RSA dir not found at ${EASYRSA_DIR}" >&2
    exit 1
fi
if [[ ! -f "${TA_KEY}" ]]; then
    echo "TLS auth key not found at ${TA_KEY}" >&2
    exit 1
fi

install -d -m 700 "${OUTPUT_DIR}"
cd "${EASYRSA_DIR}"

if [[ ! -f "pki/issued/${CLIENT_NAME}.crt" ]]; then
    echo "[+] Generating request for ${CLIENT_NAME}"
    ./easyrsa gen-req "${CLIENT_NAME}" nopass
    echo "[+] Signing certificate for ${CLIENT_NAME}"
    ./easyrsa sign-req client "${CLIENT_NAME}"
else
    echo "[!] Certificate for ${CLIENT_NAME} already exists, reusing"
fi

SERVER_IP=$(curl -4 -fsS https://ifconfig.co 2>/dev/null \
          || curl -4 -fsS https://api.ipify.org 2>/dev/null \
          || echo "212.69.84.167")

OUTPUT_FILE="${OUTPUT_DIR}/${CLIENT_NAME}.ovpn"
{
    if [[ -f "${TEMPLATE}" ]]; then
        cat "${TEMPLATE}"
    else
        cat <<'CFG'
client
dev tun
proto tcp-client
resolv-retry infinite
nobind
persist-key
persist-tun
auth SHA256
cipher AES-256-GCM
key-direction 1
remote-cert-tls server
verb 3
CFG
    fi
    echo "remote ${SERVER_IP} 443"
    echo "<ca>"
    cat pki/ca.crt
    echo "</ca>"
    echo "<cert>"
    sed -n '/BEGIN CERTIFICATE/,$p' "pki/issued/${CLIENT_NAME}.crt"
    echo "</cert>"
    echo "<key>"
    cat "pki/private/${CLIENT_NAME}.key"
    echo "</key>"
    echo "<tls-auth>"
    cat "${TA_KEY}"
    echo "</tls-auth>"
} > "${OUTPUT_FILE}"

chmod 600 "${OUTPUT_FILE}"
echo "[+] Profile ready: ${OUTPUT_FILE}"
