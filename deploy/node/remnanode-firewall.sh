#!/bin/sh
set -eu

: "${PANEL_IP:?Set PANEL_IP in /etc/default/remnanode-firewall}"
NODE_PORT="${NODE_PORT:-2222}"
INBOUND_TCP_PORTS="${INBOUND_TCP_PORTS:-}"

for port in $INBOUND_TCP_PORTS; do
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
        ufw allow "$port/tcp" >/dev/null
    else
        iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null ||
            iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
    fi
done

iptables -C INPUT -p tcp -s "$PANEL_IP" --dport "$NODE_PORT" -j ACCEPT 2>/dev/null ||
    iptables -I INPUT 1 -p tcp -s "$PANEL_IP" --dport "$NODE_PORT" -j ACCEPT
iptables -C INPUT -p tcp --dport "$NODE_PORT" -j DROP 2>/dev/null ||
    iptables -A INPUT -p tcp --dport "$NODE_PORT" -j DROP
