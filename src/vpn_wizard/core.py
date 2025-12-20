from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import shlex
from typing import Callable, Optional

import paramiko


class RemoteCommandError(RuntimeError):
    pass


@dataclass
class SSHConfig:
    host: str
    user: str
    port: int = 22
    password: Optional[str] = None
    key_path: Optional[str] = None
    timeout: int = 20


class SSHRunner:
    def __init__(self, config: SSHConfig, logger: Optional[Callable[[str], None]] = None) -> None:
        self.config = config
        self.client: Optional[paramiko.SSHClient] = None
        self.log = logger or (lambda _: None)

    def __enter__(self) -> "SSHRunner":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        self.log("Connecting over SSH...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.config.host,
            port=self.config.port,
            username=self.config.user,
            password=self.config.password,
            key_filename=self.config.key_path,
            timeout=self.config.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self.client = client

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None

    def run(self, command: str, sudo: bool = False, check: bool = True) -> str:
        if not self.client:
            raise RuntimeError("SSH client not connected.")

        wrapped = f"bash -lc {shlex.quote(command)}"
        if sudo:
            if self.config.password:
                wrapped = f"sudo -S -p '' {wrapped}"
            else:
                wrapped = f"sudo {wrapped}"

        self.log(f"$ {command}")
        stdin, stdout, stderr = self.client.exec_command(wrapped, get_pty=True)
        if sudo and self.config.password:
            stdin.write(self.config.password + "\n")
            stdin.flush()

        out = stdout.read().decode("utf-8", "ignore").strip()
        err = stderr.read().decode("utf-8", "ignore").strip()
        status = stdout.channel.recv_exit_status()
        if check and status != 0:
            msg = f"Command failed ({status}): {command}"
            if err:
                msg += f"\nSTDERR: {err}"
            if out:
                msg += f"\nSTDOUT: {out}"
            raise RemoteCommandError(msg)
        if err and not out:
            return err
        return out


class WireGuardProvisioner:
    def __init__(
        self,
        ssh: SSHRunner,
        client_name: str = "client1",
        client_ip: str = "10.10.0.2/32",
        server_cidr: str = "10.10.0.1/24",
        listen_port: int = 51820,
        dns: str = "1.1.1.1",
        mtu: Optional[int] = None,
        auto_mtu: bool = True,
        mtu_fallback: int = 1280,
        mtu_probe_host: str = "1.1.1.1",
        tune: bool = True,
        progress: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.ssh = ssh
        self.client_name = client_name
        self.client_ip = client_ip
        self.server_cidr = server_cidr
        self.listen_port = listen_port
        self.dns = dns
        self.mtu = mtu
        self.auto_mtu = auto_mtu
        self.mtu_fallback = mtu_fallback
        self.mtu_probe_host = mtu_probe_host
        self.tune = tune
        self.progress = progress or (lambda _: None)
        self._resolved_mtu: Optional[int] = None
        self._name_pattern = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")

    def provision(self) -> None:
        self.progress("Detecting OS")
        os_info = self.detect_os()
        self.progress("Installing WireGuard")
        self.install_wireguard(os_info)
        self.progress("Configuring sysctl")
        self.configure_sysctl()
        self.progress("Setting up WireGuard")
        self.setup_wireguard()
        self.progress("Configuring firewall")
        self.enable_firewall()
        self.progress("Starting service")
        self.start_service()

    def _classify_os(self, os_info: dict) -> tuple[bool, bool, str, str]:
        distro = os_info.get("ID", "").lower()
        like = os_info.get("ID_LIKE", "").lower()
        is_deb = distro in {"ubuntu", "debian"} or "debian" in like
        is_rhel = (
            distro in {"centos", "rhel", "fedora", "almalinux", "rocky"} or "rhel" in like
        )
        return is_deb, is_rhel, distro, like

    def detect_os(self) -> dict:
        raw = self.ssh.run("cat /etc/os-release")
        info = {}
        for line in raw.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                info[key.strip()] = value.strip().strip('"')
        if not info:
            raise RuntimeError("Unable to detect OS from /etc/os-release.")
        return info

    def install_wireguard(self, os_info: dict) -> None:
        is_deb, is_rhel, distro, _ = self._classify_os(os_info)

        if is_deb:
            # Retry loop for apt lock
            import time
            max_retries = 10
            for i in range(max_retries):
                try:
                    self.ssh.run("DEBIAN_FRONTEND=noninteractive apt-get update -y", sudo=True)
                    self.ssh.run(
                        "DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard qrencode iptables curl",
                        sudo=True,
                    )
                    self.ssh.run(
                        "DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent || true",
                        sudo=True,
                        check=False,
                    )
                    return
                except RemoteCommandError as exc:
                    err_msg = str(exc).lower()
                    # Check for lock errors or generic failures
                    if "lock" in err_msg or "resource temporarily unavailable" in err_msg or "could not get lock" in err_msg:
                        if i < max_retries - 1:
                            self.progress(f"Apt locked, retrying in 10s... ({i+1}/{max_retries})")
                            time.sleep(10)
                            continue
                    # Check for generic exit code 100 which often means update needed or lock
                    if "failed (100)" in str(exc):
                         if i < max_retries - 1:
                            self.progress(f"Apt failed (likely locked), retrying in 10s... ({i+1}/{max_retries})")
                            time.sleep(10)
                            continue
                    raise exc
            return

        if is_rhel:
            pm = self.ssh.run(
                "command -v dnf >/dev/null && echo dnf || echo yum", check=False
            ).strip() or "yum"
            self.ssh.run(f"{pm} install -y epel-release || true", sudo=True, check=False)
            self.ssh.run(f"{pm} install -y wireguard-tools qrencode iptables curl", sudo=True)
            return

        raise RuntimeError(f"Unsupported distro: {distro}")

    def pre_check(self) -> list[dict]:
        checks: list[dict] = []
        try:
            os_info = self.detect_os()
            is_deb, is_rhel, distro, _ = self._classify_os(os_info)
            ok = is_deb or is_rhel
            checks.append({"name": "os_supported", "ok": ok, "details": distro or "unknown"})
        except Exception as exc:
            checks.append({"name": "os_supported", "ok": False, "details": str(exc)})

        ping = self.ssh.run(
            "ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 && echo ok || echo fail",
            check=False,
        ).strip()
        checks.append({"name": "ping", "ok": ping == "ok", "details": ping})

        sudo_ok = True
        details = "password auth"
        if not getattr(self.ssh, "config", None) or not self.ssh.config.password:
            sudo = self.ssh.run("sudo -n true && echo ok || echo fail", check=False).strip()
            sudo_ok = sudo == "ok"
            details = "passwordless" if sudo_ok else "sudo requires password"
        checks.append({"name": "sudo", "ok": sudo_ok, "details": details})

        port = self.listen_port
        port_state = self.ssh.run(
            f"ss -lun | awk '{{print $5}}' | grep -q ':{port}$' && echo busy || echo free",
            check=False,
        ).strip()
        checks.append({"name": "port_available", "ok": port_state != "busy", "details": port_state})

        wg0 = self.ssh.run(
            "test -f /etc/wireguard/wg0.conf && echo exists || echo missing",
            sudo=True,
            check=False,
        ).strip()
        checks.append({"name": "wg0_exists", "ok": wg0 == "missing", "details": wg0})
        return checks

    def configure_sysctl(self) -> None:
        self.ssh.run(
            "cat > /etc/sysctl.d/99-vpn-wizard.conf <<'EOF'\n"
            "net.ipv4.ip_forward=1\n"
            "net.ipv6.conf.all.forwarding=1\n"
            "EOF",
            sudo=True,
        )
        self.ssh.run("sysctl --system", sudo=True)
        if self.tune:
            self.ssh.run(
                "cat > /etc/sysctl.d/99-vpn-wizard-tuning.conf <<'EOF'\n"
                "net.core.default_qdisc=fq\n"
                "net.ipv4.tcp_congestion_control=bbr\n"
                "net.core.rmem_max=26214400\n"
                "net.core.wmem_max=26214400\n"
                "net.core.rmem_default=524288\n"
                "net.core.wmem_default=524288\n"
                "net.ipv4.udp_rmem_min=8192\n"
                "net.ipv4.udp_wmem_min=8192\n"
                "net.ipv4.tcp_mtu_probing=1\n"
                "EOF",
                sudo=True,
            )
            self.ssh.run("modprobe tcp_bbr || true", sudo=True, check=False)
            self.ssh.run(
                "sysctl -p /etc/sysctl.d/99-vpn-wizard-tuning.conf || true",
                sudo=True,
                check=False,
            )

    def setup_wireguard(self) -> None:
        client = self.client_name
        port = self.listen_port
        resolved_mtu = self.resolve_mtu()
        mtu_line = f"MTU = {resolved_mtu}\n" if resolved_mtu else ""
        mtu_line_client = f"MTU = {resolved_mtu}\n" if resolved_mtu else ""
        
        # Detect interface reliably
        iface = self.ssh.run("ip -4 route get 1.1.1.1 | awk '{print $5; exit}'", check=False).strip()
        if not iface:
            iface = "eth0" # Fallback
        
        self.ssh.run("mkdir -p /etc/wireguard/clients", sudo=True)
        self.backup_config()
        self.ssh.run(
            "if [ ! -f /etc/wireguard/server_private.key ]; then\n"
            "  umask 077\n"
            "  wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key\n"
            "fi",
            sudo=True,
        )
        self.ssh.run(
            f"if [ ! -f /etc/wireguard/clients/{client}.key ]; then\n"
            "  umask 077\n"
            f"  wg genkey | tee /etc/wireguard/clients/{client}.key | wg pubkey > /etc/wireguard/clients/{client}.pub\n"
            "fi",
            sudo=True,
        )
        self.ssh.run(
            "set -e\n"
            "server_priv=$(cat /etc/wireguard/server_private.key)\n"
            f"client_pub=$(cat /etc/wireguard/clients/{client}.pub)\n"
            "cat > /etc/wireguard/wg0.conf <<EOF\n"
            "[Interface]\n"
            f"Address = {self.server_cidr}\n"
            f"ListenPort = {port}\n"
            "PrivateKey = $server_priv\n"
            f"{mtu_line}"
            "PostUp = iptables -w -A FORWARD -i wg0 -j ACCEPT; "
            "iptables -w -A FORWARD -o wg0 -j ACCEPT; "
            f"iptables -w -t nat -A POSTROUTING -o {iface} -j MASQUERADE; "
            "ip6tables -w -A FORWARD -i wg0 -j ACCEPT; "
            "ip6tables -w -A FORWARD -o wg0 -j ACCEPT; "
            f"ip6tables -w -t nat -A POSTROUTING -o {iface} -j MASQUERADE\n"
            "PostDown = iptables -w -D FORWARD -i wg0 -j ACCEPT; "
            "iptables -w -D FORWARD -o wg0 -j ACCEPT; "
            f"iptables -w -t nat -D POSTROUTING -o {iface} -j MASQUERADE; "
            "ip6tables -w -D FORWARD -i wg0 -j ACCEPT; "
            "ip6tables -w -D FORWARD -o wg0 -j ACCEPT; "
            f"ip6tables -w -t nat -D POSTROUTING -o {iface} -j MASQUERADE\n"
            "\n"
            "[Peer]\n"
            "PublicKey = $client_pub\n"
            f"AllowedIPs = {self.client_ip}\n"
            "EOF\n"
            "chmod 600 /etc/wireguard/wg0.conf",
            sudo=True,
        )
        self.ssh.run(
            "set -e\n"
            f"client_priv=$(cat /etc/wireguard/clients/{client}.key)\n"
            "server_pub=$(cat /etc/wireguard/server_public.key)\n"
            "public_ip=$(curl -s https://api.ipify.org || wget -qO- https://api.ipify.org)\n"
            f"cat > /etc/wireguard/clients/{client}.conf <<EOF\n"
            "[Interface]\n"
            "PrivateKey = $client_priv\n"
            f"Address = {self.client_ip}\n"
            f"DNS = {self.dns}\n"
            f"{mtu_line_client}"
            "\n"
            "[Peer]\n"
            "PublicKey = $server_pub\n"
            f"Endpoint = $public_ip:{port}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
            "EOF\n"
            f"chmod 600 /etc/wireguard/clients/{client}.conf",
            sudo=True,
        )
        self.rebuild_wg0_from_clients()

    def enable_firewall(self) -> None:
        port = self.listen_port
        # UFW: Allow port and enable routing
        self.ssh.run(f"ufw allow {port}/udp || true", sudo=True, check=False)
        self.ssh.run(
            "sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY=\"ACCEPT\"/' /etc/default/ufw || true",
            sudo=True,
            check=False,
        )
        
        # Determine interface for NAT
        iface = self.ssh.run("ip -4 route get 1.1.1.1 | awk '{print $5; exit}'", check=False).strip()
        if not iface: 
            iface = "eth0"
            
        # Ensure UFW before.rules has the NAT instruction. Use cat for safety.
        # We append to a temp file then concat if missing.
        nat_marker = "# VPN Wizard NAT"
        
        nat_block = (
            f"\n{nat_marker}\n"
            f"*nat\n"
            f":POSTROUTING ACCEPT [0:0]\n"
            f"-A POSTROUTING -s {self.server_cidr} -o {iface} -j MASQUERADE\n"
            f"COMMIT\n"
        )
        
        # Python f-string newlines + ssh run is tricky with quotes.
        # We'll use a temp file on the server.
        self.ssh.run(
            f"cat > /tmp/vpn_wizard_nat_rules <<EOF{nat_block}EOF", 
            sudo=True, 
            check=False
        )
        
        self.ssh.run(
            f"grep -q '{nat_marker}' /etc/ufw/before.rules || cat /tmp/vpn_wizard_nat_rules >> /etc/ufw/before.rules || true", 
            sudo=True, 
            check=False
        )
        self.ssh.run("rm -f /tmp/vpn_wizard_nat_rules", sudo=True, check=False)
        
        self.ssh.run("ufw reload || true", sudo=True, check=False)
        
        # Firewalld
        self.ssh.run(
            f"firewall-cmd --permanent --add-port={port}/udp || true",
            sudo=True,
            check=False,
        )
        self.ssh.run(
            f"firewall-cmd --permanent --add-masquerade || true", 
            sudo=True, 
            check=False
        )
        self.ssh.run("firewall-cmd --reload || true", sudo=True, check=False)

    def start_service(self) -> None:
        self.ssh.run("systemctl enable --now wg-quick@wg0", sudo=True)

    def export_client_config(self) -> str:
        return self.ssh.run(
            f"cat /etc/wireguard/clients/{self.client_name}.conf", sudo=True
        )

    def list_clients(self) -> list[dict]:
        raw = self.ssh.run(
            "ls /etc/wireguard/clients/*.conf 2>/dev/null || true", sudo=True, check=False
        )
        names = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            name = line.strip().split("/")[-1].removesuffix(".conf")
            names.append(name)
        clients = []
        for name in names:
            conf = self.ssh.run(
                f"cat /etc/wireguard/clients/{name}.conf", sudo=True, check=False
            )
            pub = self.ssh.run(
                f"cat /etc/wireguard/clients/{name}.pub", sudo=True, check=False
            ).strip()
            ip = ""
            for line in conf.splitlines():
                if line.startswith("Address"):
                    ip = line.split("=", 1)[1].strip()
                    break
            clients.append({"name": name, "ip": ip, "public_key": pub})
        return clients

    def add_client(self, client_name: Optional[str] = None, client_ip: Optional[str] = None) -> dict:
        name = client_name or self.next_client_name()
        self._validate_client_name(name)
        has_wg0 = self.ssh.run(
            "test -f /etc/wireguard/wg0.conf && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if has_wg0 != "yes":
            raise RuntimeError("wg0.conf not found. Run provision first.")
        exists = self.ssh.run(
            f"test -f /etc/wireguard/clients/{name}.conf && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if exists == "yes":
            raise RuntimeError(f"Client {name} already exists.")

        ip = client_ip or self.next_client_ip()
        resolved_mtu = self.resolve_mtu()
        mtu_line = f"MTU = {resolved_mtu}\n" if resolved_mtu else ""

        self.ssh.run("mkdir -p /etc/wireguard/clients", sudo=True)
        self.ssh.run(
            "if [ ! -f /etc/wireguard/server_private.key ]; then\n"
            "  umask 077\n"
            "  wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key\n"
            "fi",
            sudo=True,
        )
        self.ssh.run(
            f"if [ ! -f /etc/wireguard/clients/{name}.key ]; then\n"
            "  umask 077\n"
            f"  wg genkey | tee /etc/wireguard/clients/{name}.key | wg pubkey > /etc/wireguard/clients/{name}.pub\n"
            "fi",
            sudo=True,
        )
        self.ssh.run(
            "set -e\n"
            f"client_priv=$(cat /etc/wireguard/clients/{name}.key)\n"
            "server_pub=$(cat /etc/wireguard/server_public.key)\n"
            "public_ip=$(curl -s https://api.ipify.org || wget -qO- https://api.ipify.org)\n"
            f"cat > /etc/wireguard/clients/{name}.conf <<EOF\n"
            "[Interface]\n"
            "PrivateKey = $client_priv\n"
            f"Address = {ip}\n"
            f"DNS = {self.dns}\n"
            f"{mtu_line}"
            "\n"
            "[Peer]\n"
            "PublicKey = $server_pub\n"
            f"Endpoint = $public_ip:{self.listen_port}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
            "EOF\n"
            f"chmod 600 /etc/wireguard/clients/{name}.conf",
            sudo=True,
        )
        self.backup_config()
        self.rebuild_wg0_from_clients()
        config = self.ssh.run(
            f"cat /etc/wireguard/clients/{name}.conf", sudo=True
        )
        return {"name": name, "ip": ip, "config": config}

    def remove_client(self, client_name: str) -> bool:
        self._validate_client_name(client_name)
        exists = self.ssh.run(
            f"test -f /etc/wireguard/clients/{client_name}.conf && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if exists != "yes":
            return False
        self.ssh.run(
            f"rm -f /etc/wireguard/clients/{client_name}.conf "
            f"/etc/wireguard/clients/{client_name}.key "
            f"/etc/wireguard/clients/{client_name}.pub",
            sudo=True,
        )
        self.backup_config()
        self.rebuild_wg0_from_clients()
        return True

    def rotate_client(self, client_name: str) -> dict:
        self._validate_client_name(client_name)
        current_ip = self._get_client_ip(client_name)
        if not current_ip:
            raise RuntimeError("Client not found.")
        self.remove_client(client_name)
        return self.add_client(client_name=client_name, client_ip=current_ip)

    def rebuild_wg0_from_clients(self) -> None:
        self.ssh.run(
            "set -e\n"
            "header=$(awk 'BEGIN{p=1} /^\\[Peer\\]/{p=0} {if(p) print}' /etc/wireguard/wg0.conf)\n"
            "tmp=$(mktemp)\n"
            "echo \"$header\" > $tmp\n"
            "for conf in /etc/wireguard/clients/*.conf; do\n"
            "  [ -f \"$conf\" ] || continue\n"
            "  name=$(basename \"$conf\" .conf)\n"
            "  pub=$(cat /etc/wireguard/clients/$name.pub)\n"
            "  ip=$(awk -F'= ' '/^Address/{print $2}' \"$conf\" | head -n1)\n"
            "  echo \"\" >> $tmp\n"
            "  echo \"[Peer]\" >> $tmp\n"
            "  echo \"PublicKey = $pub\" >> $tmp\n"
            "  echo \"AllowedIPs = $ip\" >> $tmp\n"
            "done\n"
            "mv $tmp /etc/wireguard/wg0.conf\n"
            "chmod 600 /etc/wireguard/wg0.conf\n"
            "systemctl restart wg-quick@wg0 || true\n",
            sudo=True,
        )

    def next_client_name(self) -> str:
        existing = {client["name"] for client in self.list_clients()}
        idx = 1
        while True:
            name = f"client{idx}"
            if name not in existing:
                return name
            idx += 1

    def next_client_ip(self) -> str:
        network = ipaddress.ip_network(self.server_cidr, strict=False)
        used = set()
        for client in self.list_clients():
            ip = client.get("ip", "")
            if not ip:
                continue
            try:
                used.add(ipaddress.ip_interface(ip).ip)
            except ValueError:
                continue
        server_ip = ipaddress.ip_interface(self.server_cidr).ip
        for host in network.hosts():
            if host == server_ip:
                continue
            if host not in used:
                return f"{host}/32"
        raise RuntimeError("No free IPs left in server CIDR.")

    def _get_client_ip(self, client_name: str) -> Optional[str]:
        conf = self.ssh.run(
            f"cat /etc/wireguard/clients/{client_name}.conf", sudo=True, check=False
        )
        if not conf:
            return None
        for line in conf.splitlines():
            if line.startswith("Address"):
                return line.split("=", 1)[1].strip()
        return None

    def _validate_client_name(self, name: str) -> None:
        if not self._name_pattern.match(name):
            raise RuntimeError("Invalid client name. Use letters, numbers, dash, underscore.")

    def backup_config(self) -> Optional[str]:
        path = self.ssh.run(
            "if [ -f /etc/wireguard/wg0.conf ]; then\n"
            "  ts=$(date +%Y%m%d%H%M%S)\n"
            "  cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak.$ts\n"
            "  echo /etc/wireguard/wg0.conf.bak.$ts\n"
            "fi",
            sudo=True,
            check=False,
        ).strip()
        if path:
            self.progress(f"Backup saved: {path}")
            return path
        return None

    def rollback_last_backup(self) -> Optional[str]:
        backup = self.ssh.run(
            "set -e\n"
            "latest=$(ls -t /etc/wireguard/wg0.conf.bak.* 2>/dev/null | head -n 1 || true)\n"
            "if [ -z \"$latest\" ]; then\n"
            "  echo ''\n"
            "  exit 0\n"
            "fi\n"
            "cp \"$latest\" /etc/wireguard/wg0.conf\n"
            "chmod 600 /etc/wireguard/wg0.conf\n"
            "systemctl restart wg-quick@wg0 || true\n"
            "echo \"$latest\"",
            sudo=True,
            check=False,
        ).strip()
        return backup or None

    def resolve_mtu(self) -> Optional[int]:
        if self._resolved_mtu is not None:
            return self._resolved_mtu
        if self.mtu is not None:
            self._resolved_mtu = self.mtu
            return self._resolved_mtu
        if not self.auto_mtu:
            self._resolved_mtu = None
            return None
        self.progress("Auto-detecting MTU")
        detected = self.detect_mtu()
        self._resolved_mtu = detected or self.mtu_fallback
        return self._resolved_mtu

    def detect_mtu(self) -> Optional[int]:
        has_ping = self.ssh.run(
            "command -v ping >/dev/null 2>&1 && echo ok || echo missing",
            check=False,
        ).strip()
        if has_ping != "ok":
            return None

        supports_df = self.ssh.run(
            "ping -h 2>&1 | grep -q ' -M ' && echo ok || echo no", check=False
        ).strip()
        if supports_df != "ok":
            return None

        target = self.mtu_probe_host
        low = 1200
        high = 1472
        best = None
        while low <= high:
            mid = (low + high) // 2
            result = self.ssh.run(
                f"ping -c 1 -W 1 -M do -s {mid} {target} >/dev/null 2>&1 && echo ok || echo fail",
                check=False,
            ).strip()
            if result == "ok":
                best = mid
                low = mid + 1
            else:
                high = mid - 1
        if best is None:
            return None
        path_mtu = best + 28
        wg_mtu = path_mtu - 80
        if wg_mtu < 1280:
            wg_mtu = 1280
        if wg_mtu > 1420:
            wg_mtu = 1420
        return wg_mtu

    def post_check(self) -> list[dict]:
        checks: list[dict] = []
        service = self.ssh.run(
            "systemctl is-active wg-quick@wg0 || true", sudo=True, check=False
        ).strip()
        checks.append(
            {"name": "service_active", "ok": service == "active", "details": service}
        )

        link = self.ssh.run(
            "ip link show wg0 >/dev/null 2>&1 && echo ok || echo missing",
            sudo=True,
            check=False,
        ).strip()
        checks.append({"name": "interface", "ok": link == "ok", "details": link})

        fwd = self.ssh.run(
            "sysctl -n net.ipv4.ip_forward 2>/dev/null || echo missing",
            sudo=True,
            check=False,
        ).strip()
        checks.append({"name": "ip_forward", "ok": fwd == "1", "details": fwd})

        port = self.listen_port
        udp = self.ssh.run(
            f"ss -lun | grep -q ':{port} ' && echo ok || echo missing",
            sudo=True,
            check=False,
        ).strip()
        checks.append({"name": "udp_listen", "ok": udp == "ok", "details": udp})
        return checks

    def status(self) -> dict:
        service = self.ssh.run("systemctl is-active wg-quick@wg0 || true", sudo=True, check=False)
        wg = self.ssh.run("wg show wg0 || true", sudo=True, check=False)
        return {"service": service.strip(), "wg": wg.strip()}

    def repair_network(self) -> list[str]:
        logs = []
        def log(msg: str):
            logs.append(msg)
            self.progress(msg)

        log("Starting network repair...")
        
        # 1. Force enable IP forwarding
        log("Enabling IP forwarding...")
        self.ssh.run(
            "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn-wizard-repair.conf && "
            "sysctl --system",
            sudo=True
        )
        # Fix UFW policy if present
        self.ssh.run(
            "sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY=\"ACCEPT\"/' /etc/default/ufw && ufw reload || true",
            sudo=True,
            check=False
        )

        # 2. Re-detect interface and fix wg0.conf
        log("Fixing NAT rules in wg0.conf...")
        iface = self.ssh.run("ip -4 route get 1.1.1.1 | awk '{print $5; exit}'", check=False).strip()
        if not iface:
            iface = "eth0" # Fallback
            log("Warning: Could not detect interface, assuming eth0")
        
        # We use sed to replace PostUp/PostDown lines in place
        # This is a bit brittle but safer than rewriting the whole file blindly
        # Actually, simpler to just re-apply the full config block for [Interface] if we could, 
        # but we don't want to lose the private key.
        # Let's simple append/replace the firewall rules.
        
        # Safe strategy: Read PrivateKey, then re-write the [Interface] block, then append Peers.
        # But we have rebuild_wg0_from_clients! We can use that.
        
        # Actually logic: 
        # 1. Update the template used in rebuild_wg0_from_clients? No, that method reads from existing wg0.conf header.
        # So we must fix the header in wg0.conf.
        
        full_conf = self.ssh.run("cat /etc/wireguard/wg0.conf", sudo=True)
        new_lines = []
        current_iface_line = False
        
        priv_key = ""
        port = str(self.listen_port)
        
        for line in full_conf.splitlines():
            if "PrivateKey" in line:
                priv_key = line.split("=", 1)[1].strip()
            if "ListenPort" in line:
                port = line.split("=", 1)[1].strip()
                
        if not priv_key:
            raise RuntimeError("Could not find PrivateKey in wg0.conf")

        # Re-write the [Interface] block cleanly
        log(f"Detected primary interface: {iface}")
        
        header = (
            "[Interface]\n"
            f"Address = {self.server_cidr}\n"
            f"ListenPort = {port}\n"
            f"PrivateKey = {priv_key}\n"
            f"PostUp = iptables -w -A FORWARD -i wg0 -j ACCEPT; iptables -w -A FORWARD -o wg0 -j ACCEPT; iptables -w -t nat -A POSTROUTING -o {iface} -j MASQUERADE\n"
            f"PostDown = iptables -w -D FORWARD -i wg0 -j ACCEPT; iptables -w -D FORWARD -o wg0 -j ACCEPT; iptables -w -t nat -D POSTROUTING -o {iface} -j MASQUERADE\n"
        )
        
        # Save just the peers from the old config
        peers_block = self.ssh.run(
            "awk '/^\\[Peer\\]/{p=1} p' /etc/wireguard/wg0.conf", 
            sudo=True, 
            check=False
        )
        
        # Combine
        new_conf = header + "\n" + peers_block
        
        # Write back
        self.ssh.run(
            f"cat > /etc/wireguard/wg0.conf.repair.tmp <<'EOF'\n{new_conf}\nEOF", 
            sudo=True
        )
        self.ssh.run("mv /etc/wireguard/wg0.conf.repair.tmp /etc/wireguard/wg0.conf", sudo=True)
        self.ssh.run("chmod 600 /etc/wireguard/wg0.conf", sudo=True)
        
        log("Restarting WireGuard...")
        self.ssh.run("systemctl restart wg-quick@wg0", sudo=True)
        
        log("Repair complete. Try connecting now.")
        return logs
