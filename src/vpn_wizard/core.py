from __future__ import annotations

from dataclasses import dataclass
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
            raise RemoteCommandError(f"Command failed ({status}): {command}\n{err}")
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
        mtu_fallback: int = 1420,
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
        distro = os_info.get("ID", "").lower()
        like = os_info.get("ID_LIKE", "").lower()
        is_deb = distro in {"ubuntu", "debian"} or "debian" in like
        is_rhel = distro in {"centos", "rhel", "fedora", "almalinux", "rocky"} or "rhel" in like

        if is_deb:
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

        if is_rhel:
            pm = self.ssh.run(
                "command -v dnf >/dev/null && echo dnf || echo yum", check=False
            ).strip() or "yum"
            self.ssh.run(f"{pm} install -y epel-release || true", sudo=True, check=False)
            self.ssh.run(f"{pm} install -y wireguard-tools qrencode iptables curl", sudo=True)
            return

        raise RuntimeError(f"Unsupported distro: {distro}")

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
        self.ssh.run("mkdir -p /etc/wireguard/clients", sudo=True)
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
            "iface=$(ip -4 route get 1.1.1.1 | awk '{print $5; exit}')\n"
            "cat > /etc/wireguard/wg0.conf <<EOF\n"
            "[Interface]\n"
            f"Address = {self.server_cidr}\n"
            f"ListenPort = {port}\n"
            "PrivateKey = $server_priv\n"
            f"{mtu_line}"
            "PostUp = iptables -w -A FORWARD -i wg0 -j ACCEPT; "
            "iptables -w -A FORWARD -o wg0 -j ACCEPT; "
            "iptables -w -t nat -A POSTROUTING -o $iface -j MASQUERADE\n"
            "PostDown = iptables -w -D FORWARD -i wg0 -j ACCEPT; "
            "iptables -w -D FORWARD -o wg0 -j ACCEPT; "
            "iptables -w -t nat -D POSTROUTING -o $iface -j MASQUERADE\n"
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

    def enable_firewall(self) -> None:
        port = self.listen_port
        self.ssh.run(f"ufw allow {port}/udp || true", sudo=True, check=False)
        self.ssh.run(
            f"firewall-cmd --permanent --add-port={port}/udp || true",
            sudo=True,
            check=False,
        )
        self.ssh.run("firewall-cmd --reload || true", sudo=True, check=False)

    def start_service(self) -> None:
        self.ssh.run("systemctl enable --now wg-quick@wg0", sudo=True)

    def export_client_config(self) -> str:
        return self.ssh.run(
            f"cat /etc/wireguard/clients/{self.client_name}.conf", sudo=True
        )

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
