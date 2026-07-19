# Remnawave node

A node is the process that actually carries VPN traffic (runs Xray). The panel is
the brain; nodes are the muscle. You can run one node on the panel VPS and/or add
your existing VPS boxes as nodes.

## Add a node

1. In the panel UI → **Nodes → Create node**. Give it a name and the node's public
   IP and port (`2222`). The panel generates a **SECRET_KEY** (a long cert string).
2. On the node VPS:
   ```bash
   sudo mkdir -p /opt/remnanode && cd /opt/remnanode
   curl -o docker-compose.yml \
     https://raw.githubusercontent.com/Fodders-Dev/VPN-Wizard/main/deploy/node/docker-compose.yml
   # paste the SECRET_KEY from the panel into docker-compose.yml
   sudo docker compose up -d && sudo docker compose logs -f
   ```
3. Open the node's inbound ports in the firewall (whatever ports your Reality /
   SS2022 inbounds use — e.g. 443). Port `2222` only needs to be reachable from the
   panel. The included persistent rule restricts it:
   ```bash
   sudo install -m 0755 remnanode-firewall.sh /usr/local/sbin/remnanode-firewall
   sudo install -m 0644 remnanode-firewall.service /etc/systemd/system/
   printf 'PANEL_IP=%s\nNODE_PORT=2222\nINBOUND_TCP_PORTS="11443"\n' '203.0.113.10' |
     sudo tee /etc/default/remnanode-firewall >/dev/null
   sudo systemctl daemon-reload
   sudo systemctl enable --now remnanode-firewall.service
   ```
   Replace `203.0.113.10` with the panel's public IP.
4. Back in the panel, the node should flip to **online**. Assign the node's inbounds
   to your internal squad (see the master runbook, step 2–3).

## Notes

- `network_mode: host` + `NET_ADMIN` are required so Xray can bind inbound ports.
- Nodes hold no user database — losing a node loses no accounts. Re-provision and
  re-add. This is why panel + nodes is more resilient than the old per-user SSH model.
- To rotate an IP that got ASN-blocked: spin a fresh VPS, add it as a new node,
  move the squad's inbounds over, delete the old node. Users re-read the sub-URL
  automatically — no action on their side.
