#!/usr/bin/env bash
set -euo pipefail

# WireGuard quick installer and client manager for Debian/Ubuntu
# Features:
# - Installs WireGuard + qrencode (optional) on a fresh VPS
# - Configures server with NAT and IP forwarding
# - Generates first client config and QR code
# - Adds additional clients later with --add-client NAME
# - Prints paths to generated configs under /etc/wireguard/clients/
#
# Usage examples:
#   sudo bash wg-setup.sh                    # install with defaults and create client "client1"
#   sudo bash wg-setup.sh --port 51820 --dns 1.1.1.1
#   sudo bash wg-setup.sh --add-client phone
#   sudo bash wg-setup.sh --add-client laptop --qr
#
# Notes:
# - Default server subnet: 10.66.66.0/24
# - Default interface name: wg0
# - Default port: 51820

WG_INTERFACE="wg0"
WG_PORT="51820"
SERVER_SUBNET="10.66.66.0/24"
SERVER_ADDR="10.66.66.1/24"
CLIENT_DNS="1.1.1.1"
SHOW_QR="false"
ADD_CLIENT_NAME=""

bold() { echo -e "\e[1m$*\e[0m"; }
warn() { echo -e "\e[33m$*\e[0m"; }
info() { echo -e "\e[36m$*\e[0m"; }
err()  { echo -e "\e[31m$*\e[0m"; }

require_root() {
	if [[ "${EUID}" -ne 0 ]]; then
		err "Please run as root (use sudo)."; exit 1
	fi
}

require_apt() {
	if ! command -v apt >/dev/null 2>&1; then
		err "This script supports Debian/Ubuntu (apt) only."; exit 1
	fi
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--port)
				WG_PORT="${2:-}"; shift 2 ;;
			--dns)
				CLIENT_DNS="${2:-}"; shift 2 ;;
			--iface|--interface)
				WG_INTERFACE="${2:-}"; shift 2 ;;
			--qr)
				SHOW_QR="true"; shift ;;
			--add-client)
				ADD_CLIENT_NAME="${2:-}"; shift 2 ;;
			-h|--help)
				usage; exit 0 ;;
			*)
				# ignore unknown positional for simplicity
				shift ;;
		esac
	done
}

usage() {
	cat <<EOF
$(bold "WireGuard installer / manager")

Install server (defaults):
  sudo bash wg-setup.sh [--port ${WG_PORT}] [--dns ${CLIENT_DNS}] [--interface ${WG_INTERFACE}] [--qr]

Add new client:
  sudo bash wg-setup.sh --add-client <name> [--qr]

Files:
  Server conf:   /etc/wireguard/${WG_INTERFACE}.conf
  Clients dir:   /etc/wireguard/clients/
  Example client: /etc/wireguard/clients/client1.conf
EOF
}

detect_public_interface() {
	# Best-effort default route iface
	ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}' || true
}

detect_public_ip() {
	# Try to detect IPv4
	curl -4 -fsS https://ifconfig.co 2>/dev/null || curl -4 -fsS https://api.ipify.org 2>/dev/null || true
}

enable_ip_forwarding() {
	local sysctl_conf="/etc/sysctl.d/99-wireguard-forward.conf"
	cat >"${sysctl_conf}" <<CONF
net.ipv4.ip_forward=1
CONF
	sysctl -p "${sysctl_conf}" >/dev/null 2>&1 || true
}

install_packages() {
	apt update -y
	DEBIAN_FRONTEND=noninteractive apt install -y wireguard iproute2 curl qrencode || true
}

ensure_dirs() {
	mkdir -p /etc/wireguard
	chmod 700 /etc/wireguard
	mkdir -p /etc/wireguard/clients
}

generate_server_keys() {
	if [[ ! -f /etc/wireguard/server_private.key ]]; then
		wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
		chmod 600 /etc/wireguard/server_private.key
	fi
}

next_client_ip() {
	# Returns next available host IP in 10.66.66.0/24, starting from .2
	local used_ips
	used_ips=$(grep -E "AllowedIPs\s*=\s*10\\.66\\.66\\.[0-9]+/32" "/etc/wireguard/${WG_INTERFACE}.conf" 2>/dev/null | grep -oE "10\\.66\\.66\\.[0-9]+" || true)
	for i in $(seq 2 254); do
		local candidate="10.66.66.${i}"
		if ! grep -q "${candidate}" <<<"${used_ips}" 2>/dev/null; then
			echo "${candidate}"
			return 0
		fi
	done
	err "No free client IPs left in 10.66.66.0/24"; return 1
}

create_server_config() {
	local pub_iface="$1"
	local server_priv server_pub
	server_priv=$(cat /etc/wireguard/server_private.key)
	server_pub=$(cat /etc/wireguard/server_public.key)

	if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
		info "Server config already exists: /etc/wireguard/${WG_INTERFACE}.conf"
		return 0
	fi

	cat > "/etc/wireguard/${WG_INTERFACE}.conf" <<CFG
[Interface]
PrivateKey = ${server_priv}
Address = ${SERVER_ADDR}
ListenPort = ${WG_PORT}
SaveConfig = true
# NAT and forwarding rules
PostUp = iptables -t nat -A POSTROUTING -s ${SERVER_SUBNET} -o ${pub_iface} -j MASQUERADE; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s ${SERVER_SUBNET} -o ${pub_iface} -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT
CFG
	chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"
}

restart_wg() {
	systemctl enable wg-quick@"${WG_INTERFACE}" >/dev/null 2>&1 || true
	systemctl restart wg-quick@"${WG_INTERFACE}"
}

add_client() {
	local name="$1"; local endpoint_ip="$2"
	if [[ -z "${name}" ]]; then err "Client name required"; exit 1; fi

	local client_ip
	client_ip=$(next_client_ip)

	local cdir="/etc/wireguard/clients"
	mkdir -p "${cdir}"
	local cpriv="${cdir}/${name}_private.key"
	local cpub="${cdir}/${name}_public.key"
	wg genkey | tee "${cpriv}" | wg pubkey > "${cpub}"
	chmod 600 "${cpriv}"

	local server_pub
	server_pub=$(cat /etc/wireguard/server_public.key)

	# Append to server config and apply live
	cat >> "/etc/wireguard/${WG_INTERFACE}.conf" <<PEER

# ${name}
[Peer]
PublicKey = $(cat "${cpub}")
AllowedIPs = ${client_ip}/32
PEER

	# Apply live
	wg set "${WG_INTERFACE}" peer "$(cat "${cpub}")" allowed-ips "${client_ip}/32" || true

	local client_conf="${cdir}/${name}.conf"
	cat > "${client_conf}" <<CONF
[Interface]
PrivateKey = $(cat "${cpriv}")
Address = ${client_ip}/32
DNS = ${CLIENT_DNS}

[Peer]
PublicKey = ${server_pub}
Endpoint = ${endpoint_ip}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CONF
	chmod 600 "${client_conf}"

	info "Client created: ${client_conf}"
	if [[ "${SHOW_QR}" == "true" ]] && command -v qrencode >/dev/null 2>&1; then
		bold "QR for ${name}:"
		qrencode -t ansiutf8 < "${client_conf}" || true
	else
		warn "Use --qr to print a QR (requires qrencode)."
	fi
}

main() {
	require_root
	require_apt
	parse_args "$@"

	ensure_dirs
	install_packages
	generate_server_keys
	enable_ip_forwarding

	local pub_iface
	pub_iface=$(detect_public_interface)
	if [[ -z "${pub_iface}" ]]; then err "Failed to detect public interface"; exit 1; fi

	create_server_config "${pub_iface}"

	# Start/restart WireGuard
	restart_wg

	# Detect server public IP for client Endpoint
	local endpoint_ip
	endpoint_ip=$(detect_public_ip)
	if [[ -z "${endpoint_ip}" ]]; then
		warn "Could not auto-detect public IP. You will need to edit clients' Endpoint manually."
		endpoint_ip="YOUR_SERVER_IP"
	fi

	if [[ -n "${ADD_CLIENT_NAME}" ]]; then
		add_client "${ADD_CLIENT_NAME}" "${endpoint_ip}"
	else
		# Create default client if none requested
		add_client "client1" "${endpoint_ip}"
	fi

	bold "Done. Useful paths:"
	echo "  Server:  /etc/wireguard/${WG_INTERFACE}.conf"
	echo "  Clients: /etc/wireguard/clients/*.conf"
	bold "Commands:"
	echo "  Show status:    sudo wg show"
	echo "  Add new client: sudo bash wg-setup.sh --add-client <name> [--qr]"
}

main "$@" 