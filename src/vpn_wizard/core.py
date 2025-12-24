from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
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

    def run(self, command: str, sudo: bool = False, check: bool = True, pty: bool = True) -> str:
        if not self.client:
            raise RuntimeError("SSH client not connected.")

        wrapped = f"bash -lc {shlex.quote(command)}"
        if sudo:
            if self.config.password:
                wrapped = f"sudo -S -p '' {wrapped}"
            else:
                wrapped = f"sudo {wrapped}"

        self.log(f"$ {command}")
        if sudo and self.config.password and pty:
            pty = False  # Avoid echoing the sudo password into stdout/stderr
        stdin, stdout, stderr = self.client.exec_command(wrapped, get_pty=pty)
        if sudo and self.config.password:
            stdin.write(self.config.password + "\n")
            stdin.flush()

        out = stdout.read().decode("utf-8", "ignore").strip()
        err = stderr.read().decode("utf-8", "ignore").strip()
        if self.config.password:
            out = out.replace(self.config.password, "***")
            err = err.replace(self.config.password, "***")
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
        listen_port: int = 3478,
        dns: str = "1.1.1.1, 1.0.0.1",
        mtu: Optional[int] = None,
        auto_mtu: bool = True,
        mtu_fallback: int = 1280,  # Revert to safe default to avoid fragmentation
        mtu_probe_host: str = "1.1.1.1",
        tune: bool = True,
        progress: Optional[Callable[[str], None]] = None,
        protocol: str = "amneziawg",  # "wireguard" or "amneziawg"
        allow_ipv6: bool = False,
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
        self.protocol = protocol
        self._public_ip_cache: Optional[str] = None
        self.allow_ipv6 = allow_ipv6
        
        # AmneziaWG obfuscation parameters (optimized for speed)
        # Lower overhead = higher throughput. Jmax=1000 was too aggressive.
        import random
        self.awg_jc = random.randint(1, 3)    # Minimal junk packets (was 3-10)
        self.awg_jmin = 40                    # Minimum junk size
        self.awg_jmax = 70                    # Reduced max junk size (was 1000!)
        self.awg_s1 = random.randint(15, 150)
        self.awg_s2 = random.randint(15, 150)
        while self.awg_s1 + 56 == self.awg_s2:
            self.awg_s2 = random.randint(15, 150)
        self.awg_h1 = random.randint(100000000, 2147483647)
        self.awg_h2 = random.randint(100000000, 2147483647)
        self.awg_h3 = random.randint(100000000, 2147483647)
        self.awg_h4 = random.randint(100000000, 2147483647)
        h_vals = {self.awg_h1, self.awg_h2, self.awg_h3, self.awg_h4}
        while len(h_vals) < 4:
            self.awg_h1 = random.randint(100000000, 2147483647)
            self.awg_h2 = random.randint(100000000, 2147483647)
            self.awg_h3 = random.randint(100000000, 2147483647)
            self.awg_h4 = random.randint(100000000, 2147483647)
            h_vals = {self.awg_h1, self.awg_h2, self.awg_h3, self.awg_h4}

    # ... (omitted) ...

    def provision(self) -> None:
        self.progress("Detecting OS")
        os_info = self.detect_os()
        
        if self.protocol == "amneziawg":
            self.progress("Installing AmneziaWG")
            self.install_amneziawg(os_info)
            self.progress("Configuring sysctl")
            self.configure_sysctl()
            self.progress("Setting up AmneziaWG")
            self.setup_amneziawg()
            self.progress("Configuring firewall")
            self.enable_firewall()
            self.progress("Starting AmneziaWG service")
            self.start_awg_service()
        else:
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

    def _release_apt_locks(self) -> None:
        """Aggressively release apt locks and kill blocking processes."""
        self.progress("Releasing apt locks...")
        self.ssh.run(
            "systemctl stop unattended-upgrades apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true; "
            "killall -9 unattended-upgrade apt apt-get dpkg 2>/dev/null || true; "
            "rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null || true; "
            "dpkg --configure -a 2>/dev/null || true",
            sudo=True,
            check=False,
        )
        import time
        time.sleep(2)

    def _clean_boot_partition(self) -> None:
        """Remove old kernels to free space in /boot."""
        self.progress("Cleaning old kernels to free space...")
        # Get current kernel version
        current = self.ssh.run("uname -r").strip()
        # List all installed kernels (linux-image-*) excluding current
        # This one-liner finds old kernels and purging them
        cmd = (
            f"current_kernel=$(uname -r); "
            f"dpkg -l 'linux-image-[0-9]*' | grep '^ii' | awk '{{print $2}}' | "
            f"grep -v \"$current_kernel\" | grep -v \"$(uname -r | cut -d- -f1-2)\" | "
            f"xargs -r apt-get -y purge"
        )
        self.ssh.run(cmd, sudo=True, check=False)
        self.ssh.run("apt-get autoremove -y", sudo=True, check=False)
        self.ssh.run("apt-get clean", sudo=True, check=False)

    def install_amneziawg(self, os_info: dict) -> None:
        """Install AmneziaWG kernel module and tools via PPA."""
        # Check if AmneziaWG tools are already installed
        awg_check = self.ssh.run("which awg 2>/dev/null && echo 'installed' || echo 'missing'", check=False)
        if "installed" in awg_check:
            self.progress("AmneziaWG already installed, skipping...")
            self.ssh.run("modprobe amneziawg 2>/dev/null || true", sudo=True, check=False)
            return
        
        is_deb, is_rhel, distro, _ = self._classify_os(os_info)
        
        if is_deb:
            # 1. Release locks
            self._release_apt_locks()
            
            # 2. Clean boot partition to avoid "No space left on device"
            self._clean_boot_partition()
            
            # Apt with 2 minute lock timeout
            apt = "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120"
            
            self.progress("Updating packages...")
            self.ssh.run(f"{apt} update -y", sudo=True)
            
            self.progress("Installing prerequisites...")
            self.ssh.run(f"{apt} install -y software-properties-common gnupg2 curl qrencode iptables", sudo=True)
            
            # Try to install headers - this often fails if space is low, so we try-catch
            try:
                self.ssh.run(f"{apt} install -y linux-headers-$(uname -r)", sudo=True)
            except RemoteCommandError:
                self.progress("Header install failed, trying explicit cleanup again...")
                self._clean_boot_partition()
                self.ssh.run(f"{apt} install -y linux-headers-$(uname -r)", sudo=True)

            self.progress("Adding AmneziaWG repository...")
            self.ssh.run(
                "add-apt-repository -y ppa:amnezia/ppa || "
                "(apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828 && "
                "echo 'deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' >> /etc/apt/sources.list)",
                sudo=True,
                check=False,
            )
            self.ssh.run(f"{apt} update -y", sudo=True)
            
            self.progress("Installing AmneziaWG...")
            try:
                self.ssh.run(f"{apt} install -y amneziawg", sudo=True)
            except RemoteCommandError as e:
                # DKMS/initramfs failure - try to force load module
                if "mkinitrd" in str(e) or "initramfs" in str(e) or "exit status" in str(e):
                    self.progress("DKMS failed, loading module manually...")
                    self.ssh.run("dpkg --configure -a --force-confdef || true", sudo=True, check=False)
                    self.ssh.run("modprobe amneziawg || true", sudo=True, check=False)
                    if "not_found" in self.ssh.run("which awg || echo 'not_found'", check=False):
                        raise RuntimeError("AmneziaWG tools not installed. Try reinstalling VPS.")
                else:
                    raise e
            return
        
        if is_rhel:
            pm = self.ssh.run("command -v dnf >/dev/null && echo dnf || echo yum", check=False).strip() or "yum"
            self.ssh.run(f"{pm} copr enable -y amneziavpn/amneziawg || true", sudo=True, check=False)
            self.ssh.run(f"{pm} install -y amneziawg-dkms amneziawg-tools qrencode curl", sudo=True)
            return
        
        raise RuntimeError(f"Unsupported distro for AmneziaWG: {distro}")

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

        conf_path = (
            "/etc/amnezia/amneziawg/awg0.conf"
            if self.protocol == "amneziawg"
            else "/etc/wireguard/wg0.conf"
        )
        conf_state = self.ssh.run(
            f"test -f {conf_path} && echo exists || echo missing",
            sudo=True,
            check=False,
        ).strip()
        checks.append(
            {"name": "server_conf_exists", "ok": conf_state == "missing", "details": conf_state}
        )
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
                "net.core.rmem_default=2097152\n"
                "net.core.wmem_default=2097152\n"
                "net.ipv4.udp_rmem_min=16384\n"
                "net.ipv4.udp_wmem_min=16384\n"
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

    def _allowed_ips(self) -> str:
        return "0.0.0.0/0, ::/0" if self.allow_ipv6 else "0.0.0.0/0"

    def _post_rules(self, ifname: str) -> tuple[str, str]:
        postup = (
            "sysctl -w net.ipv4.ip_forward=1; "
            "sysctl -w net.ipv6.conf.all.forwarding=1; "
            f"iptables -w -I FORWARD 1 -i {ifname} -j ACCEPT; "
            f"iptables -w -I FORWARD 1 -o {ifname} -j ACCEPT; "
            f"iptables -w -t nat -A POSTROUTING -s {self.server_cidr} -j MASQUERADE; "
            "iptables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN "
            "-j TCPMSS --clamp-mss-to-pmtu"
        )
        postdown = (
            f"iptables -w -D FORWARD -i {ifname} -j ACCEPT; "
            f"iptables -w -D FORWARD -o {ifname} -j ACCEPT; "
            f"iptables -w -t nat -D POSTROUTING -s {self.server_cidr} -j MASQUERADE; "
            "iptables -w -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN "
            "-j TCPMSS --clamp-mss-to-pmtu"
        )
        if self.allow_ipv6:
            postup += (
                f"; ip6tables -w -I FORWARD 1 -i {ifname} -j ACCEPT || true; "
                f"ip6tables -w -I FORWARD 1 -o {ifname} -j ACCEPT || true; "
                "ip6tables -w -t nat -A POSTROUTING -s fd42:42:42::/64 -j MASQUERADE || true"
            )
            postdown += (
                f"; ip6tables -w -D FORWARD -i {ifname} -j ACCEPT || true; "
                f"ip6tables -w -D FORWARD -o {ifname} -j ACCEPT || true; "
                "ip6tables -w -t nat -D POSTROUTING -s fd42:42:42::/64 -j MASQUERADE || true"
            )
        return postup, postdown

    def _resolve_listen_port(self, conf_path: str) -> int:
        port = self.ssh.run(
            f"awk -F'= ' '/^ListenPort/{{print $2; exit}}' {conf_path} 2>/dev/null || true",
            sudo=True,
            check=False,
            pty=False,
        ).strip()
        return int(port) if port.isdigit() else self.listen_port

    def _resolve_dns(self, clients_dir: str) -> str:
        dns = self.ssh.run(
            f"awk -F'= ' '/^DNS/{{print $2; exit}}' {clients_dir}/*.conf 2>/dev/null || true",
            sudo=True,
            check=False,
            pty=False,
        ).strip()
        return dns or self.dns

    def _resolve_allowed_ips(self, clients_dir: str) -> str:
        if not self.allow_ipv6:
            return self._allowed_ips()
        allowed = self.ssh.run(
            f"awk -F'= ' '/^AllowedIPs/{{print $2; exit}}' {clients_dir}/*.conf 2>/dev/null || true",
            sudo=True,
            check=False,
            pty=False,
        ).strip()
        return allowed or self._allowed_ips()

    def setup_wireguard(self) -> None:
        client = self.client_name
        port = self.listen_port
        resolved_mtu = self.resolve_mtu()
        mtu_line = f"MTU = {resolved_mtu}\n" if resolved_mtu else ""
        mtu_line_client = f"MTU = {resolved_mtu}\n" if resolved_mtu else ""
        allowed_ips = self._allowed_ips()
        postup, postdown = self._post_rules("wg0")
        
        # Detect interface reliably
        iface = self.ssh.run("ip -4 route get 1.1.1.1 | awk '{print $5; exit}'", check=False).strip()
        if not iface:
            iface = "eth0" # Fallback
        
        self.ssh.run("mkdir -p /etc/wireguard/clients", sudo=True)
        if not self.client_ip:
            self.client_ip = self.next_client_ip()

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
            f"PostUp = {postup}\n"
            f"PostDown = {postdown}\n"
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
            f"public_ip={self.get_public_ip()}\n"
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
            f"AllowedIPs = {allowed_ips}\n"
            "PersistentKeepalive = 15\n"
            "EOF\n"
            f"chmod 600 /etc/wireguard/clients/{client}.conf",
            sudo=True,
        )
        self.rebuild_wg0_from_clients()

    def setup_amneziawg(self) -> None:
        """Setup AmneziaWG with obfuscation parameters."""
        client = self.client_name
        port = self.listen_port
        resolved_mtu = self.resolve_mtu()
        mtu_line = f"MTU = {resolved_mtu}\n" if resolved_mtu else ""
        mtu_line_client = f"MTU = {resolved_mtu}\n" if resolved_mtu else ""
        allowed_ips = self._allowed_ips()
        postup, postdown = self._post_rules("awg0")
        
        # Resolve client IP if not set (prevent None/null in config)
        if not self.client_ip:
            self.client_ip = self.next_client_ip()
        
        # AWG obfuscation params block
        awg_params = (
            f"Jc = {self.awg_jc}\n"
            f"Jmin = {self.awg_jmin}\n"
            f"Jmax = {self.awg_jmax}\n"
            f"S1 = {self.awg_s1}\n"
            f"S2 = {self.awg_s2}\n"
            f"H1 = {self.awg_h1}\n"
            f"H2 = {self.awg_h2}\n"
            f"H3 = {self.awg_h3}\n"
            f"H4 = {self.awg_h4}\n"
        )
        
        self.ssh.run("mkdir -p /etc/amnezia/amneziawg/clients", sudo=True)
        self.backup_config()
        
        # Generate server keys using awg command
        self.ssh.run(
            "if [ ! -f /etc/amnezia/amneziawg/server_private.key ]; then\n"
            "  umask 077\n"
            "  awg genkey | tee /etc/amnezia/amneziawg/server_private.key | awg pubkey > /etc/amnezia/amneziawg/server_public.key\n"
            "fi",
            sudo=True,
        )
        
        # Generate client keys
        self.ssh.run(
            f"if [ ! -f /etc/amnezia/amneziawg/clients/{client}.key ]; then\n"
            "  umask 077\n"
            f"  awg genkey | tee /etc/amnezia/amneziawg/clients/{client}.key | awg pubkey > /etc/amnezia/amneziawg/clients/{client}.pub\n"
            "fi",
            sudo=True,
        )
        
        # Create server config (awg0.conf)
        self.ssh.run(
            "set -e\n"
            "server_priv=$(cat /etc/amnezia/amneziawg/server_private.key)\n"
            f"client_pub=$(cat /etc/amnezia/amneziawg/clients/{client}.pub)\n"
            "cat > /etc/amnezia/amneziawg/awg0.conf <<EOF\n"
            "[Interface]\n"
            f"Address = {self.server_cidr}\n"
            f"ListenPort = {port}\n"
            "PrivateKey = $server_priv\n"
            f"{mtu_line}"
            f"{awg_params}"
            f"PostUp = {postup}\n"
            f"PostDown = {postdown}\n"
            "\n"
            "[Peer]\n"
            "PublicKey = $client_pub\n"
            f"AllowedIPs = {self.client_ip}\n"
            "EOF\n"
            "chmod 600 /etc/amnezia/amneziawg/awg0.conf",
            sudo=True,
        )
        
        # Create client config
        self.ssh.run(
            "set -e\n"
            f"client_priv=$(cat /etc/amnezia/amneziawg/clients/{client}.key)\n"
            "server_pub=$(cat /etc/amnezia/amneziawg/server_public.key)\n"
            f"public_ip={self.get_public_ip()}\n"
            f"cat > /etc/amnezia/amneziawg/clients/{client}.conf <<EOF\n"
            "[Interface]\n"
            "PrivateKey = $client_priv\n"
            f"Address = {self.client_ip}\n"
            f"DNS = {self.dns}\n"
            f"{mtu_line_client}"
            f"{awg_params}"
            "\n"
            "[Peer]\n"
            "PublicKey = $server_pub\n"
            f"Endpoint = $public_ip:{port}\n"
            f"AllowedIPs = {allowed_ips}\n"
            "PersistentKeepalive = 15\n"
            "EOF\n"
            f"chmod 600 /etc/amnezia/amneziawg/clients/{client}.conf",
            sudo=True,
        )
        self.rebuild_awg0_from_clients()
    
    def _ensure_tyumen_interface_exists(self) -> None:
        """Create awg1.conf if it does not exist (Tyumen interface)."""
        # Always ensure firewall is open for this port, in case it was missed
        self.ssh.run(f"ufw allow {self.listen_port}/udp || true", sudo=True, check=False)

        exists = self.ssh.run("test -f /etc/amnezia/amneziawg/awg1.conf && echo yes || echo no", check=False).strip()
        if exists == "yes":
            current_port = self.ssh.run(
                "awk -F'= ' '/^ListenPort/ {print $2; exit}' /etc/amnezia/amneziawg/awg1.conf",
                sudo=True,
                check=False,
            ).strip()
            if current_port != str(self.listen_port):
                shown_port = current_port or "missing"
                self.progress(
                    f"Tyumen interface port mismatch (found {shown_port}, need {self.listen_port}). Updating..."
                )
                self.ssh.run(
                    f"sed -i 's/^ListenPort.*/ListenPort = {self.listen_port}/' /etc/amnezia/amneziawg/awg1.conf",
                    sudo=True,
                    check=False,
                )
                self.ssh.run("systemctl restart awg-quick@awg1", sudo=True, check=False)
            return

        self.progress("Initializing Tyumen interface (awg1)...")
        self.ssh.run("mkdir -p /etc/amnezia/amneziawg/clients_tyumen", sudo=True)
        
        # Ensure server keys for awg1
        self.ssh.run(
             "if [ ! -f /etc/amnezia/amneziawg/server_private_awg1.key ]; then\n"
             "  umask 077\n"
             "  awg genkey | tee /etc/amnezia/amneziawg/server_private_awg1.key | awg pubkey > /etc/amnezia/amneziawg/server_public_awg1.key\n"
             "fi",
             sudo=True
        )
        
        postup, postdown = self._post_rules("awg1")
        
        # AWG params are already mutated in self by add_client at this point
        awg_params = (
            f"Jc = {self.awg_jc}\n"
            f"Jmin = {self.awg_jmin}\n"
            f"Jmax = {self.awg_jmax}\n"
            f"S1 = {self.awg_s1}\n"
            f"S2 = {self.awg_s2}\n"
            f"H1 = {self.awg_h1}\n"
            f"H2 = {self.awg_h2}\n"
            f"H3 = {self.awg_h3}\n"
            f"H4 = {self.awg_h4}\n"
        )

        self.ssh.run(
            "set -e\n"
            "server_priv=$(cat /etc/amnezia/amneziawg/server_private_awg1.key)\n"
            "cat > /etc/amnezia/amneziawg/awg1.conf <<EOF\n"
            "[Interface]\n"
            f"Address = {self.server_cidr}\n"
            f"ListenPort = {self.listen_port}\n"
            "PrivateKey = $server_priv\n"
            "MTU = 1280\n"
            f"{awg_params}"
            f"PostUp = {postup}\n"
            f"PostDown = {postdown}\n"
            "EOF\n"
            "chmod 600 /etc/amnezia/amneziawg/awg1.conf\n"
            "systemctl enable --now awg-quick@awg1",
            sudo=True
        )

    def start_awg_service(self) -> None:
        """Start AmneziaWG service using awg-quick."""
        self.ssh.run("systemctl enable --now awg-quick@awg0", sudo=True)

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
            f"-A POSTROUTING -s {self.server_cidr} -j MASQUERADE\n"
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
        if self.protocol == "amneziawg":
            return self.ssh.run(
                f"cat /etc/amnezia/amneziawg/clients/{self.client_name}.conf", sudo=True, pty=False
            )
        return self.ssh.run(
            f"cat /etc/wireguard/clients/{self.client_name}.conf", sudo=True, pty=False
        )

    def _auto_detect_protocol(self) -> None:
        awg_path = "/etc/amnezia/amneziawg/awg0.conf"
        wg_path = "/etc/wireguard/wg0.conf"
        has_awg = (
            self.ssh.run(f"test -f {awg_path} && echo yes || echo no", sudo=True, check=False).strip()
            == "yes"
        )
        has_wg = (
            self.ssh.run(f"test -f {wg_path} && echo yes || echo no", sudo=True, check=False).strip()
            == "yes"
        )
        if self.protocol == "amneziawg" and not has_awg and has_wg:
            self.protocol = "wireguard"
        elif self.protocol != "amneziawg" and not has_wg and has_awg:
            self.protocol = "amneziawg"

    def export_client(self, client_name: str) -> dict:
        self._validate_client_name(client_name)
        self._auto_detect_protocol()
        if self.protocol == "amneziawg":
            candidates = [
                ("/etc/amnezia/amneziawg/clients", "awg0"),
                ("/etc/amnezia/amneziawg/clients_tyumen", "awg1"),
            ]
        else:
            candidates = [("/etc/wireguard/clients", "wg0")]

        for clients_dir, iface in candidates:
            exists = self.ssh.run(
                f"test -f {clients_dir}/{client_name}.conf && echo yes || echo no",
                sudo=True,
                check=False,
            ).strip()
            if exists != "yes":
                continue

            conf = self.ssh.run(
                f"cat {clients_dir}/{client_name}.conf", sudo=True, check=False, pty=False
            )
            pub = self.ssh.run(
                f"cat {clients_dir}/{client_name}.pub", sudo=True, check=False, pty=False
            ).strip()
            ip = ""
            for line in conf.splitlines():
                if line.startswith("Address"):
                    ip = line.split("=", 1)[1].strip()
                    break
            return {
                "name": client_name,
                "ip": ip,
                "public_key": pub,
                "config": conf,
                "interface": iface,
            }
        raise RuntimeError("Client not found.")

    def _parse_wg_show(self, output: str) -> dict[str, dict]:
        peers: dict[str, dict] = {}
        current = None
        for raw in output.splitlines():
            line = raw.strip()
            if line.startswith("peer:"):
                current = line.split(":", 1)[1].strip()
                peers[current] = {}
                continue
            if not current or not line:
                continue
            if line.startswith("endpoint:"):
                peers[current]["endpoint"] = line.split(":", 1)[1].strip()
            elif line.startswith("latest handshake:"):
                peers[current]["latest_handshake"] = line.split(":", 1)[1].strip()
            elif line.startswith("transfer:"):
                transfer = line.split(":", 1)[1].strip()
                parts = [part.strip() for part in transfer.split(",")]
                rx = parts[0].replace(" received", "").strip() if parts else ""
                tx = parts[1].replace(" sent", "").strip() if len(parts) > 1 else ""
                if rx:
                    peers[current]["transfer_rx"] = rx
                if tx:
                    peers[current]["transfer_tx"] = tx
        return peers

    def list_clients(self) -> list[dict]:
        self._auto_detect_protocol()
        if self.protocol == "amneziawg":
            dirs = [("/etc/amnezia/amneziawg/clients", "awg0")]
            tyumen_probe = self.ssh.run(
                "ls /etc/amnezia/amneziawg/clients_tyumen/*.conf 2>/dev/null | head -n 1 || true",
                sudo=True,
                check=False,
            ).strip()
            if tyumen_probe:
                dirs.append(("/etc/amnezia/amneziawg/clients_tyumen", "awg1"))

            stats_by_iface = {
                "awg0": self._parse_wg_show(
                    self.ssh.run("awg show awg0 || true", sudo=True, check=False)
                )
            }
            if any(item[1] == "awg1" for item in dirs):
                stats_by_iface["awg1"] = self._parse_wg_show(
                    self.ssh.run("awg show awg1 || true", sudo=True, check=False)
                )
        else:
            dirs = [("/etc/wireguard/clients", "wg0")]
            stats_by_iface = {
                "wg0": self._parse_wg_show(
                    self.ssh.run("wg show wg0 || true", sudo=True, check=False)
                )
            }

        clients = []
        for clients_dir, iface in dirs:
            raw = self.ssh.run(
                f"ls {clients_dir}/*.conf 2>/dev/null || true", sudo=True, check=False
            )
            names = []
            for line in raw.splitlines():
                if not line.strip():
                    continue
                name = line.strip().split("/")[-1].removesuffix(".conf")
                names.append(name)

            for name in names:
                conf = self.ssh.run(
                    f"cat {clients_dir}/{name}.conf", sudo=True, check=False, pty=False
                )
                pub = self.ssh.run(
                    f"cat {clients_dir}/{name}.pub", sudo=True, check=False, pty=False
                ).strip()
                ip = ""
                for line in conf.splitlines():
                    if line.startswith("Address"):
                        ip = line.split("=", 1)[1].strip()
                        break
                stats = stats_by_iface.get(iface, {}).get(pub, {})
                clients.append(
                    {
                        "name": name,
                        "ip": ip,
                        "public_key": pub,
                        "endpoint": stats.get("endpoint"),
                        "latest_handshake": stats.get("latest_handshake"),
                        "transfer_rx": stats.get("transfer_rx"),
                        "transfer_tx": stats.get("transfer_tx"),
                        "interface": iface,
                    }
                )
        return clients

    def add_client(self, client_name: Optional[str] = None, client_ip: Optional[str] = None) -> dict:
        name = (client_name or self.next_client_name()).strip()
        self._validate_client_name(name)
        is_tyumen = name.lower().startswith("tyumen")
        
        # Auto-detect protocol if config is missing (robustness against frontend defaults)
        # Check standard paths
        awg_path = "/etc/amnezia/amneziawg/awg0.conf"
        wg_path = "/etc/wireguard/wg0.conf"
        
        has_awg = self.ssh.run(f"test -f {awg_path} && echo yes || echo no", sudo=True, check=False).strip() == "yes"
        has_wg = self.ssh.run(f"test -f {wg_path} && echo yes || echo no", sudo=True, check=False).strip() == "yes"
        
        if self.protocol == "amneziawg" and not has_awg and has_wg:
             self.protocol = "wireguard"
        elif self.protocol != "amneziawg" and not has_wg and has_awg:
             self.protocol = "amneziawg"
        
        # Protocol-specific paths and commands
        if self.protocol == "amneziawg":
            # Tyumen "Magic" Interface Logic
            if is_tyumen:
                conf_dir = "/etc/amnezia/amneziawg"
                wg_conf = f"{conf_dir}/awg1.conf"
                clients_dir = f"{conf_dir}/clients_tyumen"
                cmd_genkey = "awg genkey"
                cmd_pubkey = "awg pubkey"
                rebuild_cmd = self.rebuild_awg1_from_clients
                self.server_cidr = "10.11.0.1/24" # Tyumen subnet
                # Mutate obfuscation params for Tyumen to be different from default
                self.awg_jc += 1
                self.awg_s1 += 5
                self.awg_s2 += 5
                self.awg_h1 += 123456
                
                # Ensure the secondary interface is actually initialized
                self._ensure_tyumen_interface_exists()
            else:
                conf_dir = "/etc/amnezia/amneziawg"
                wg_conf = f"{conf_dir}/awg0.conf"
                clients_dir = f"{conf_dir}/clients"
                cmd_genkey = "awg genkey"
                cmd_pubkey = "awg pubkey"
                rebuild_cmd = self.rebuild_awg0_from_clients
        else:
            conf_dir = "/etc/wireguard"
            wg_conf = f"{conf_dir}/wg0.conf"
            clients_dir = f"{conf_dir}/clients"
            cmd_genkey = "wg genkey"
            cmd_pubkey = "wg pubkey"
            rebuild_cmd = self.rebuild_wg0_from_clients

        # Final check
        has_conf = self.ssh.run(
            f"test -f {wg_conf} && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if has_conf != "yes":
            if is_tyumen:
                self._ensure_tyumen_interface_exists()
                has_conf = self.ssh.run(
                    f"test -f {wg_conf} && echo yes || echo no",
                    sudo=True,
                    check=False,
                ).strip()
            if has_conf != "yes":
                dir_listing = ""
                if self.protocol == "amneziawg":
                    dir_listing = self.ssh.run(
                        "ls -la /etc/amnezia/amneziawg 2>/dev/null || true",
                        sudo=True,
                        check=False,
                    ).strip()
                details = f"check={has_conf}"
                if dir_listing:
                    details += f"; dir=/etc/amnezia/amneziawg: {dir_listing}"
                raise RuntimeError(f"{os.path.basename(wg_conf)} not found. {details}")
            
        exists = self.ssh.run(
            f"test -f {clients_dir}/{name}.conf && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if exists == "yes":
            self.progress(f"Client {name} exists, overwriting...")
            # Remove old files to free up IP and allow clean regen
            self.ssh.run(
                f"rm -f {clients_dir}/{name}.conf {clients_dir}/{name}.key {clients_dir}/{name}.pub",
                sudo=True,
                check=False
            )
            
        ip = client_ip or self.next_client_ip()
        resolved_mtu = self.resolve_mtu()
        mtu_line = f"MTU = {resolved_mtu}\n" if resolved_mtu else ""
        listen_port = self._resolve_listen_port(wg_conf)
        dns_value = self._resolve_dns(clients_dir)
        allowed_ips = self._resolve_allowed_ips(clients_dir)

        self.ssh.run(f"mkdir -p {clients_dir}", sudo=True)

        if self.protocol == "amneziawg" and is_tyumen:
            server_priv_path = f"{conf_dir}/server_private_awg1.key"
            server_pub_path = f"{conf_dir}/server_public_awg1.key"
        else:
            server_priv_path = f"{conf_dir}/server_private.key"
            server_pub_path = f"{conf_dir}/server_public.key"

        # Ensure server keys exist (should be there if conf exists, but good to be safe)
        self.ssh.run(
            f"if [ ! -f {server_priv_path} ]; then\n"
            "  umask 077\n"
            f"  {cmd_genkey} | tee {server_priv_path} | {cmd_pubkey} > {server_pub_path}\n"
            "fi",
            sudo=True,
        )
        
        # Generate client keys
        self.ssh.run(
            f"if [ ! -f {clients_dir}/{name}.key ]; then\n"
            "  umask 077\n"
            f"  {cmd_genkey} | tee {clients_dir}/{name}.key | {cmd_pubkey} > {clients_dir}/{name}.pub\n"
            "fi",
            sudo=True,
        )

        
        # Prepare client config content
        awg_params = ""
        if self.protocol == "amneziawg":
            # For Tyumen, prefer server-side params to avoid mismatch; fall back to self.* if missing.
            if is_tyumen:
                raw_params = self.ssh.run(
                    f"grep -E '^(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4) =' {wg_conf} || true",
                    sudo=True,
                    check=False,
                )
                if raw_params.strip():
                    awg_params = raw_params.strip() + "\n"
                else:
                    awg_params = (
                        f"Jc = {self.awg_jc}\n"
                        f"Jmin = {self.awg_jmin}\n"
                        f"Jmax = {self.awg_jmax}\n"
                        f"S1 = {self.awg_s1}\n"
                        f"S2 = {self.awg_s2}\n"
                        f"H1 = {self.awg_h1}\n"
                        f"H2 = {self.awg_h2}\n"
                        f"H3 = {self.awg_h3}\n"
                        f"H4 = {self.awg_h4}\n"
                    )
            else:
                # For existing awg0, we must read from the file to match server config.
                # Use a safer read approach to avoid stripping issues
                raw_params = self.ssh.run(
                    f"grep -E '^(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4) =' {wg_conf} || true",
                    sudo=True,
                    check=False
                )
                # Ensure it ends with a newline and is clean
                if raw_params.strip():
                    awg_params = raw_params.strip() + "\n"

        self.ssh.run(
            "set -e\n"
            f"client_priv=$(cat {clients_dir}/{name}.key)\n"
            f"server_pub=$(cat {server_pub_path})\n"
            f"public_ip={self.get_public_ip()}\n"
            f"cat > {clients_dir}/{name}.conf <<EOF\n"
            "[Interface]\n"
            "PrivateKey = $client_priv\n"
            f"Address = {ip}\n"
            f"DNS = {dns_value}\n"
            f"{mtu_line}"
            f"{awg_params}"
            "\n"
            "[Peer]\n"
            "PublicKey = $server_pub\n"
            f"Endpoint = $public_ip:{listen_port}\n"
            f"AllowedIPs = {allowed_ips}\n"
            "PersistentKeepalive = 15\n"
            "EOF\n"
            f"chmod 600 {clients_dir}/{name}.conf",
            sudo=True,
        )
        
        self.backup_config()
        rebuild_cmd()
        
        config = self.ssh.run(
            f"cat {clients_dir}/{name}.conf", sudo=True, pty=False
        )
        iface_name = "wg0"
        if self.protocol == "amneziawg":
            iface_name = "awg1" if is_tyumen else "awg0"
        return {"name": name, "ip": ip, "config": config, "interface": iface_name}

    def remove_client(self, client_name: str) -> bool:
        self._validate_client_name(client_name)
        self._auto_detect_protocol()
        is_tyumen = client_name.lower().startswith("tyumen")

        if self.protocol == "amneziawg":
            if is_tyumen:
                clients_dir = "/etc/amnezia/amneziawg/clients_tyumen"
                rebuild_cmd = self.rebuild_awg1_from_clients
            else:
                clients_dir = "/etc/amnezia/amneziawg/clients"
                rebuild_cmd = self.rebuild_awg0_from_clients
        else:
            clients_dir = "/etc/wireguard/clients"
            rebuild_cmd = self.rebuild_wg0_from_clients

        exists = self.ssh.run(
            f"test -f {clients_dir}/{client_name}.conf && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if exists != "yes":
            return False
            
        self.ssh.run(
            f"rm -f {clients_dir}/{client_name}.conf "
            f"{clients_dir}/{client_name}.key "
            f"{clients_dir}/{client_name}.pub",
            sudo=True,
        )
        self.backup_config()
        rebuild_cmd()
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
            "  ip=$(grep '^Address' \"$conf\" | cut -d= -f2 | tr -d ' ' | tr -d '\\r' | head -n1)\n"
            "  echo \"\" >> $tmp\n"
            "  echo \"[Peer]\" >> $tmp\n"
            "  echo \"PublicKey = $pub\" >> $tmp\n"
            "  echo \"AllowedIPs = $ip\" >> $tmp\n"
            "done\n"
            "mv $tmp /etc/wireguard/wg0.conf\n"
            "chmod 600 /etc/wireguard/wg0.conf\n"
            "# Asynchronous restart to prevent SSH hang if connected via VPN\n"
            "nohup sh -c 'sleep 1; systemctl restart wg-quick@wg0' >/dev/null 2>&1 &\n",
            sudo=True,
        )

    def get_public_ip(self) -> str:
        """Get public IP, cached."""
        if self._public_ip_cache:
            return self._public_ip_cache
        
        # Check if host in config is an IP address
        if self.ssh.config.host.replace(".", "").isdigit():
            self._public_ip_cache = self.ssh.config.host
            return self._public_ip_cache
            
        # Fetch from remote
        self._public_ip_cache = self.ssh.run(
            "curl -s https://api.ipify.org || wget -qO- https://api.ipify.org", 
            check=False
        ).strip()
        return self._public_ip_cache

    def rebuild_awg0_from_clients(self) -> None:
        """Rebuild awg0.conf from all client configs, preserving server header."""
        self.ssh.run(
            "set -e\n"
            "header=$(awk 'BEGIN{p=1} /^\\[Peer\\]/{p=0} {if(p) print}' /etc/amnezia/amneziawg/awg0.conf)\n"
            "tmp=$(mktemp)\n"
            "echo \"$header\" > $tmp\n"
            "for conf in /etc/amnezia/amneziawg/clients/*.conf; do\n"
            "  [ -f \"$conf\" ] || continue\n"
            "  name=$(basename \"$conf\" .conf)\n"
            "  pub=$(cat /etc/amnezia/amneziawg/clients/$name.pub)\n"
            "  ip=$(grep '^Address' \"$conf\" | cut -d= -f2 | tr -d ' ' | tr -d '\\r' | head -n1)\n"
            "  echo \"\" >> $tmp\n"
            "  echo \"[Peer]\" >> $tmp\n"
            "  echo \"PublicKey = $pub\" >> $tmp\n"
            "  echo \"AllowedIPs = $ip\" >> $tmp\n"
            "done\n"
            "mv $tmp /etc/amnezia/amneziawg/awg0.conf\n"
            "chmod 600 /etc/amnezia/amneziawg/awg0.conf\n"
            "# Asynchronous restart to prevent SSH hang if connected via VPN\n"
            "nohup sh -c 'sleep 1; systemctl restart awg-quick@awg0' >/dev/null 2>&1 &\n",
            sudo=True,
        )

    def rebuild_awg1_from_clients(self) -> None:
        """Rebuild awg1.conf (Tyumen) from client configs."""
        self.ssh.run(
            "set -e\n"
            "header=$(awk 'BEGIN{p=1} /^\[Peer\]/{p=0} {if(p) print}' /etc/amnezia/amneziawg/awg1.conf)\n"
            "tmp=$(mktemp)\n"
            "echo \"$header\" > $tmp\n"
            "for conf in /etc/amnezia/amneziawg/clients_tyumen/*.conf; do\n"
            "  [ -f \"$conf\" ] || continue\n"
            "  name=$(basename \"$conf\" .conf)\n"
            "  pub=$(cat /etc/amnezia/amneziawg/clients_tyumen/$name.pub)\n"
            "  ip=$(grep '^Address' \"$conf\" | cut -d= -f2 | tr -d ' ' | tr -d '\\r' | head -n1)\n"
            "  echo \"\" >> $tmp\n"
            "  echo \"[Peer]\" >> $tmp\n"
            "  echo \"PublicKey = $pub\" >> $tmp\n"
            "  echo \"AllowedIPs = $ip\" >> $tmp\n"
            "done\n"
            "mv $tmp /etc/amnezia/amneziawg/awg1.conf\n"
            "chmod 600 /etc/amnezia/amneziawg/awg1.conf\n"
            "# Asynchronous restart\n"
            "nohup sh -c 'sleep 1; systemctl restart awg-quick@awg1' >/dev/null 2>&1 &\n",
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
        # Robustly find all used IPs by scanning the config files directly
        if self.server_cidr.startswith("10.11."): # Tyumen mode check
             conf_dir = "/etc/amnezia/amneziawg/clients_tyumen"
        elif self.protocol == "amneziawg":
            conf_dir = "/etc/amnezia/amneziawg/clients"
        else:
            conf_dir = "/etc/wireguard/clients"
        
        # Grep all Address lines from client configs
        # Output format: "Address = 10.10.0.2/32" -> "10.10.0.2"
        # We cut by space to handle "Address = 10.10..."
        cmd = (
            f"grep -h '^Address' {conf_dir}/*.conf 2>/dev/null "
            "| cut -d= -f2 "
            "| tr -d ' ' "
            "| tr -d '\\r' "
            "| cut -d/ -f1"
        )
        used_ips_output = self.ssh.run(cmd, sudo=True, check=False).strip()
        used_ips = set(used_ips_output.splitlines()) if used_ips_output else set()
        
        # Use server_cidr base to determine available IPs
        # server_cidr example: "10.10.0.1/24" -> base "10.10.0"
        network = ipaddress.ip_network(self.server_cidr, strict=False)
        # Iterate over hosts in the subnet (skipping .0 and .1 likely)
        # Using a simple heuristic compatible with earlier logic
        base = str(network.network_address).rsplit(".", 1)[0]
        
        for i in range(2, 255):
            ip = f"{base}.{i}"
            if ip not in used_ips:
                return f"{ip}/32"
                
        raise RuntimeError(f"No free IPs available in {self.server_cidr} subnet")

    def _get_client_ip(self, client_name: str) -> Optional[str]:
        self._auto_detect_protocol()
        if self.protocol == "amneziawg":
            if client_name.lower().startswith("tyumen"):
                clients_dir = "/etc/amnezia/amneziawg/clients_tyumen"
            else:
                clients_dir = "/etc/amnezia/amneziawg/clients"
        else:
            clients_dir = "/etc/wireguard/clients"

        conf = self.ssh.run(
            f"cat {clients_dir}/{client_name}.conf", sudo=True, check=False
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
        if self.protocol == "amneziawg":
            conf_path = "/etc/amnezia/amneziawg/awg0.conf"
            backup_prefix = "/etc/amnezia/amneziawg/awg0.conf.bak"
        else:
            conf_path = "/etc/wireguard/wg0.conf"
            backup_prefix = "/etc/wireguard/wg0.conf.bak"

        path = self.ssh.run(
            f"if [ -f {conf_path} ]; then\n"
            "  ts=$(date +%Y%m%d%H%M%S)\n"
            f"  cp {conf_path} {backup_prefix}.$ts\n"
            f"  echo {backup_prefix}.$ts\n"
            "fi",
            sudo=True,
            check=False,
        ).strip()
        if path:
            self.progress(f"Backup saved: {path}")
            return path
        return None

    def rollback_last_backup(self) -> Optional[str]:
        if self.protocol == "amneziawg":
            conf_path = "/etc/amnezia/amneziawg/awg0.conf"
            backup_glob = "/etc/amnezia/amneziawg/awg0.conf.bak.*"
            service_name = "awg-quick@awg0"
        else:
            conf_path = "/etc/wireguard/wg0.conf"
            backup_glob = "/etc/wireguard/wg0.conf.bak.*"
            service_name = "wg-quick@wg0"

        backup = self.ssh.run(
            "set -e\n"
            f"latest=$(ls -t {backup_glob} 2>/dev/null | head -n 1 || true)\n"
            "if [ -z \"$latest\" ]; then\n"
            "  echo ''\n"
            "  exit 0\n"
            "fi\n"
            f"cp \"$latest\" {conf_path}\n"
            f"chmod 600 {conf_path}\n"
            f"systemctl restart {service_name} || true\n"
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
        service_name = "awg-quick@awg0" if self.protocol == "amneziawg" else "wg-quick@wg0"
        iface = "awg0" if self.protocol == "amneziawg" else "wg0"
        service = self.ssh.run(
            f"systemctl is-active {service_name} || true", sudo=True, check=False
        ).strip()
        checks.append(
            {"name": "service_active", "ok": service == "active", "details": service}
        )

        link = self.ssh.run(
            f"ip link show {iface} >/dev/null 2>&1 && echo ok || echo missing",
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
        service_name = "awg-quick@awg0" if self.protocol == "amneziawg" else "wg-quick@wg0"
        show_cmd = "awg show awg0" if self.protocol == "amneziawg" else "wg show wg0"
        service = self.ssh.run(
            f"systemctl is-active {service_name} || true", sudo=True, check=False
        )
        wg = self.ssh.run(f"{show_cmd} || true", sudo=True, check=False)
        return {"service": service.strip(), "wg": wg.strip()}

    def get_system_report(self) -> str:
        """Collects deep diagnostics for debugging connectivity issues."""
        service_name = "awg-quick@awg0" if self.protocol == "amneziawg" else "wg-quick@wg0"
        show_cmd = "awg show all" if self.protocol == "amneziawg" else "wg show all"
        commands = [
            ("Service Status", f"systemctl status {service_name} --no-pager"),
            ("WireGuard Status", show_cmd),
            ("Interfaces", "ip addr"),
            ("Routes", "ip route"),
            ("IP Forwarding", "sysctl net.ipv4.ip_forward"),
            ("UFW Status", "ufw status verbose"),
            ("IPTables NAT", "iptables -t nat -S"),
            ("IPTables Filter", "iptables -S"),
            ("IP6Tables NAT", "ip6tables -t nat -S"),
            ("Sysctl Conf", "cat /etc/sysctl.d/99-vpn-wizard.conf || echo 'missing'"),
            ("UFW Before Rules", "tail -n 20 /etc/ufw/before.rules"),
            ("Journal Log", f"journalctl -u {service_name} -n 50 --no-pager"),
            ("Ping 1.1.1.1", "ping -c 3 1.1.1.1 || echo 'failed'"),
        ]
        
        report = ["=== VPN WIZARD DIAGNOSTIC REPORT ==="]
        for name, cmd in commands:
            report.append(f"\n--- {name} ---")
            try:
                out = self.ssh.run(cmd, sudo=True, check=False, pty=False)
                report.append(out)
            except Exception as e:
                report.append(f"Error running command: {e}")
        
        return "\n".join(report)

    def repair_network(self) -> list[str]:
        logs = []
        def log(msg: str):
            logs.append(msg)
            self.progress(msg)

        if self.protocol == "amneziawg":
            log("Repair is only supported for WireGuard mode.")
            return logs

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
        
        postup, postdown = self._post_rules("wg0")
        header = (
            "[Interface]\n"
            f"Address = {self.server_cidr}\n"
            f"ListenPort = {port}\n"
            f"PrivateKey = {priv_key}\n"
            f"PostUp = {postup}\n"
            f"PostDown = {postdown}\n"
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
