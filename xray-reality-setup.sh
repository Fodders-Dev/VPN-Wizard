#!/usr/bin/env bash
set -euo pipefail

# Xray VLESS Reality installer/manager for Ubuntu/Debian
# - Installs Xray (XTLS/Xray-core) via official script
# - Creates VLESS Reality inbound on TCP 443
# - Generates x25519 keys, UUID client, shortId
# - Prints vless:// links and ASCII QR (for v2rayNG/Shadowrocket)
# - Add extra clients later with: --add-client NAME
#
# Clients supported: v2rayNG (Android), Shadowrocket (iOS), Nekoray/Clash Meta/Sing-Box (desktop)
#
# Usage:
#   sudo bash xray-reality-setup.sh                 # fresh install + first client "client1"
#   sudo bash xray-reality-setup.sh --add-client alice
#   sudo bash xray-reality-setup.sh --port 443 --sni www.cloudflare.com

XRAY_BIN="/usr/local/bin/xray"
XRAY_ETC="/usr/local/etc/xray"
XRAY_CONF="${XRAY_ETC}/config.json"
PORT="443"
SERVER_NAME="www.cloudflare.com"   # SNI to impersonate
FINGERPRINT="chrome"
ADD_CLIENT_NAME=""
SHOW_QR="true"

REALITY_PRIV_FILE="${XRAY_ETC}/reality_private.key"
REALITY_PUB_FILE="${XRAY_ETC}/reality_public.key"

bold(){ echo -e "\e[1m$*\e[0m"; }
info(){ echo -e "\e[36m$*\e[0m"; }
warn(){ echo -e "\e[33m$*\e[0m"; }
err(){  echo -e "\e[31m$*\e[0m"; }

require_root(){
	[[ $EUID -eq 0 ]] || { err "Run as root (use sudo)."; exit 1; }
}

parse_args(){
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--port) PORT="${2:-}"; shift 2;;
			--sni)  SERVER_NAME="${2:-}"; shift 2;;
			--fp|--fingerprint) FINGERPRINT="${2:-}"; shift 2;;
			--add-client) ADD_CLIENT_NAME="${2:-}"; shift 2;;
			--no-qr) SHOW_QR="false"; shift;;
			-h|--help) usage; exit 0;;
			*) shift;;
		esac
	done
}

usage(){
	cat <<EOF
$(bold "Xray VLESS Reality installer")
Options:
  --port <num>          TCP port (default 443)
  --sni <domain>        Server Name to impersonate for Reality (default ${SERVER_NAME})
  --fingerprint <name>  TLS fingerprint for clients (default ${FINGERPRINT})
  --add-client <name>   Add extra client and print link/QR
  --no-qr               Do not render QR in terminal
EOF
}

install_prereqs(){
	apt update -y
	DEBIAN_FRONTEND=noninteractive apt install -y curl jq qrencode >/dev/null 2>&1 || true
}

install_xray(){
	if [[ ! -x "${XRAY_BIN}" ]]; then
		bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" || {
			err "Xray install failed"; exit 1;
		}
	fi
	mkdir -p "${XRAY_ETC}"
}

# Returns derived public key for a given private key
derive_public_from_private(){
	local priv="$1"
	[[ -n "${priv}" ]] || { echo ""; return 0; }
	${XRAY_BIN} x25519 -i "${priv}" 2>/dev/null | awk '/Public/{print $3}' || true
}

# Read current private key from config if present
read_private_from_config(){
	jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "${XRAY_CONF}" 2>/dev/null || echo ""
}

ensure_reality_pubkey_var(){
	# Prefer env var; otherwise read from file or derive from config
	if [[ -z "${REALITY_PUBLIC_KEY:-}" ]]; then
		if [[ -f "${REALITY_PUB_FILE}" ]]; then
			REALITY_PUBLIC_KEY="$(cat "${REALITY_PUB_FILE}")"
		else
			local priv
			priv="$(read_private_from_config)"
			REALITY_PUBLIC_KEY="$(derive_public_from_private "${priv}")"
		fi
	fi
}

generate_reality_keys(){
	local keys
	keys="$(${XRAY_BIN} x25519)"
	REALITY_PRIVATE_KEY=$(echo "${keys}" | awk '/Private/{print $3}')
	REALITY_PUBLIC_KEY=$(echo "${keys}" | awk '/Public/{print $3}')
	# persist
	[[ -n "${REALITY_PRIVATE_KEY}" ]] && echo "${REALITY_PRIVATE_KEY}" > "${REALITY_PRIV_FILE}"
	[[ -n "${REALITY_PUBLIC_KEY}" ]] && echo "${REALITY_PUBLIC_KEY}" > "${REALITY_PUB_FILE}"
}

random_short_id(){
	head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-16
}

new_uuid(){
	uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid
}

public_ip(){
	curl -4 -fsS https://ifconfig.co 2>/dev/null || curl -4 -fsS https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP"
}

write_config(){
	local uuid="$1"; local short_id="$2";
	# Ensure keys are available
	if [[ -z "${REALITY_PRIVATE_KEY:-}" ]]; then
		if [[ -f "${REALITY_PRIV_FILE}" ]]; then
			REALITY_PRIVATE_KEY="$(cat "${REALITY_PRIV_FILE}")"
		else
			generate_reality_keys
		fi
	fi
	cat >"${XRAY_CONF}" <<JSON
{
  "log": { "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${uuid}", "flow": "xtls-rprx-vision", "email": "client1" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${SERVER_NAME}:443",
          "xver": 0,
          "serverNames": ["${SERVER_NAME}", "www.apple.com", "www.cloudflare.com"],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${short_id}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    }
  ],
  "outbounds": [ { "protocol": "freedom" }, { "protocol": "blackhole", "tag": "blocked" } ]
}
JSON
}

self_heal_config(){
	# If privateKey in config is empty, regenerate and patch
	local priv
	priv="$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "${XRAY_CONF}" 2>/dev/null || echo "")"
	if [[ -z "${priv}" ]]; then
		if [[ -f "${REALITY_PRIV_FILE}" ]]; then
			priv="$(cat "${REALITY_PRIV_FILE}")"
		else
			generate_reality_keys
			priv="${REALITY_PRIVATE_KEY}"
		fi
		# Patch config with privateKey
		jq \
			".inbounds[0].streamSettings.realitySettings.privateKey = \"${priv}\"" \
			"${XRAY_CONF}" > "${XRAY_CONF}.new" && mv "${XRAY_CONF}.new" "${XRAY_CONF}"
	fi
	# Ensure public key var is available afterward
	REALITY_PUBLIC_KEY="$(derive_public_from_private "${priv}")"
	[[ -n "${REALITY_PUBLIC_KEY}" ]] && echo "${REALITY_PUBLIC_KEY}" > "${REALITY_PUB_FILE}" || true
}

restart_xray(){
	systemctl enable xray >/dev/null 2>&1 || true
	systemctl restart xray
	sleep 0.5
	systemctl --no-pager -l status xray | sed -n '1,25p' || true
}

vless_link(){
	local uuid="$1"; local ip="$2"; local sni="$3"; local pbk="$4"; local sid="$5"; local port="$6"; local name="$7"
	echo "vless://${uuid}@${ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=${FINGERPRINT}&pbk=${pbk}&sid=${sid}&type=tcp#${name}"
}

print_client(){
	local name="$1"; local uuid="$2"; local sid="$3"; local ip
	ip=$(public_ip)
	bold "Client: ${name}"
	ensure_reality_pubkey_var
	local link
	link=$(vless_link "${uuid}" "${ip}" "${SERVER_NAME}" "${REALITY_PUBLIC_KEY:-}" "${sid}" "${PORT}" "${name}")
	echo "${link}"
	if [[ "${SHOW_QR}" == "true" ]] && command -v qrencode >/dev/null 2>&1; then
		echo ""; qrencode -t ansiutf8 "${link}" || true
	fi
}

add_client(){
	local name="$1"; local uuid sid
	uuid=$(new_uuid)
	sid=$(random_short_id)
	# Append client to config JSON
	jq \
		".inbounds[0].settings.clients += [{\"id\": \"${uuid}\", \"flow\": \"xtls-rprx-vision\", \"email\": \"${name}\"}] | .inbounds[0].streamSettings.realitySettings.shortIds += [\"${sid}\"]" \
		"${XRAY_CONF}" > "${XRAY_CONF}.new"
	mv "${XRAY_CONF}.new" "${XRAY_CONF}"
	restart_xray >/dev/null 2>&1 || true
	print_client "${name}" "${uuid}" "${sid}"
}

main(){
	require_root
	parse_args "$@"
	install_prereqs
	install_xray

	if [[ -n "${ADD_CLIENT_NAME}" && -f "${XRAY_CONF}" ]]; then
		self_heal_config
		add_client "${ADD_CLIENT_NAME}"
		return 0
	fi

	generate_reality_keys
	local uuid sid
	uuid=$(new_uuid)
	sid=$(random_short_id)
	write_config "${uuid}" "${sid}"
	self_heal_config
	restart_xray

	bold "Xray VLESS Reality is up on TCP ${PORT}"
	ensure_reality_pubkey_var
	info "Public key: ${REALITY_PUBLIC_KEY:-}"
	print_client "client1" "${uuid}" "${sid}"
	bold "Add more clients:"
	echo "  sudo bash xray-reality-setup.sh --add-client alice"
}

main "$@" 