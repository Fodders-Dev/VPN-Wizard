from __future__ import annotations

import re
import shlex
from typing import Callable, Optional

from vpn_wizard.core import SSHRunner


class RelayProvisioner:
    SERVICE_PREFIX = "vpnw-relay-"
    _name_pattern = re.compile(r"^[a-zA-Z0-9_.:-]{1,255}$")

    def __init__(self, ssh: SSHRunner, progress: Optional[Callable[[str], None]] = None) -> None:
        self.ssh = ssh
        self.progress = progress or (lambda _: None)

    def _service_name(self, listen_port: int) -> str:
        return f"{self.SERVICE_PREFIX}{int(listen_port)}"

    def _validate_endpoint(self, host: str, port: int) -> tuple[str, int]:
        clean_host = str(host or "").strip()
        if not clean_host or not self._name_pattern.match(clean_host):
            raise RuntimeError("Relay host must be a valid IP address or domain name.")
        clean_port = int(port)
        if clean_port < 1 or clean_port > 65535:
            raise RuntimeError("Relay port must be between 1 and 65535.")
        return clean_host, clean_port

    def _ensure_prereqs(self) -> None:
        present = self.ssh.run("command -v socat >/dev/null 2>&1 && echo yes || echo no", check=False).strip()
        if present == "yes":
            return
        self.progress("Installing relay prerequisites")
        os_release = self.ssh.run("cat /etc/os-release", check=False)
        distro = ""
        for line in os_release.splitlines():
            if line.startswith("ID="):
                distro = line.split("=", 1)[1].strip().strip('"').lower()
                break
        if distro in {"ubuntu", "debian"}:
            self.ssh.run("DEBIAN_FRONTEND=noninteractive apt-get update -y", sudo=True)
            self.ssh.run("DEBIAN_FRONTEND=noninteractive apt-get install -y socat", sudo=True)
            return
        if distro in {"fedora", "centos", "rhel", "rocky", "almalinux"}:
            self.ssh.run("command -v dnf >/dev/null 2>&1 && dnf install -y socat || yum install -y socat", sudo=True)
            return
        raise RuntimeError(f"Unsupported relay OS for automatic socat install: {distro or 'unknown'}")

    def _ensure_firewall_port(self, listen_port: int) -> None:
        port = int(listen_port)
        ufw_active = self.ssh.run(
            "command -v ufw >/dev/null 2>&1 && "
            "ufw status 2>/dev/null | head -n 1 | grep -qi 'Status: active' && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if ufw_active == "yes":
            allowed = self.ssh.run(
                f"ufw status 2>/dev/null | grep -Eiq '^\\s*{port}/tcp\\s+ALLOW' && echo yes || echo no",
                sudo=True,
                check=False,
            ).strip()
            if allowed != "yes":
                self.progress(f"Opening TCP {port} on relay")
                self.ssh.run(f"ufw allow {port}/tcp", sudo=True, check=False)
            return

        firewalld_active = self.ssh.run(
            "command -v firewall-cmd >/dev/null 2>&1 && "
            "systemctl is-active firewalld >/dev/null 2>&1 && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if firewalld_active == "yes":
            allowed = self.ssh.run(
                f"firewall-cmd --quiet --query-port={port}/tcp && echo yes || echo no",
                sudo=True,
                check=False,
            ).strip()
            if allowed != "yes":
                self.progress(f"Opening TCP {port} on relay")
                self.ssh.run(f"firewall-cmd --add-port={port}/tcp", sudo=True, check=False)
                self.ssh.run(f"firewall-cmd --permanent --add-port={port}/tcp", sudo=True, check=False)
                self.ssh.run("firewall-cmd --reload", sudo=True, check=False)

    def _is_port_busy(self, listen_port: int) -> bool:
        state = self.ssh.run(
            f"ss -ltn | awk '{{print $4}}' | grep -q ':{int(listen_port)}$' && echo busy || echo free",
            check=False,
        ).strip()
        return state == "busy"

    def _port_owner(self, listen_port: int) -> str:
        raw = self.ssh.run(
            f'ss -ltnpH "sport = :{int(listen_port)}" 2>/dev/null | head -n 1 || true',
            check=False,
        )
        marker = 'users:(("'
        idx = raw.find(marker)
        if idx < 0:
            return ""
        rest = raw[idx + len(marker):]
        end = rest.find('"')
        return rest[:end] if end >= 0 else ""

    def _write_service(self, listen_port: int, origin_host: str, origin_port: int) -> None:
        service_name = self._service_name(listen_port)
        exec_start = (
            f"/usr/bin/socat -d -d "
            f"TCP4-LISTEN:{int(listen_port)},reuseaddr,fork,keepalive,nodelay "
            f"TCP4:{origin_host}:{int(origin_port)},keepalive,nodelay"
        )
        unit = (
            "[Unit]\n"
            f"Description=VPN Wizard relay on TCP {int(listen_port)}\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "Restart=always\n"
            "RestartSec=2\n"
            f"ExecStart={exec_start}\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        command = f"cat > /etc/systemd/system/{service_name}.service <<'EOF'\n{unit}\nEOF"
        self.ssh.run(command, sudo=True)

    def setup(self, *, origin_host: str, origin_port: int, listen_port: int) -> dict[str, int | str]:
        clean_origin_host, clean_origin_port = self._validate_endpoint(origin_host, origin_port)
        clean_listen_port = int(listen_port)
        if clean_listen_port < 1 or clean_listen_port > 65535:
            raise RuntimeError("Relay listen port must be between 1 and 65535.")

        self._ensure_prereqs()
        owner = self._port_owner(clean_listen_port)
        service_name = self._service_name(clean_listen_port)
        if owner and owner != "socat":
            raise RuntimeError(f"Relay port {clean_listen_port} is busy ({owner}).")
        if self._is_port_busy(clean_listen_port) and owner == "socat":
            self.progress(f"Reconfiguring existing relay on TCP {clean_listen_port}")
        else:
            self.progress(f"Preparing relay on TCP {clean_listen_port}")
        self._write_service(clean_listen_port, clean_origin_host, clean_origin_port)
        self._ensure_firewall_port(clean_listen_port)
        self.ssh.run("systemctl daemon-reload", sudo=True)
        self.ssh.run(f"systemctl enable --now {shlex.quote(service_name)}", sudo=True)
        state = self.ssh.run(f"systemctl is-active {shlex.quote(service_name)} || true", sudo=True, check=False).strip()
        if state != "active":
            raise RuntimeError("Relay service did not start correctly.")
        return {
            "origin_host": clean_origin_host,
            "origin_port": clean_origin_port,
            "listen_port": clean_listen_port,
            "service": service_name,
        }
