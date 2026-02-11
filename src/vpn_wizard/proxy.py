from __future__ import annotations

import json
import re
import shlex
import uuid
from typing import Callable, Optional
from urllib.parse import quote

from vpn_wizard.core import SSHRunner


class ProxyProvisioner:
    XRAY_BIN = "/usr/local/bin/xray"
    XRAY_ETC = "/usr/local/etc/xray"
    XRAY_CONF = f"{XRAY_ETC}/config.json"

    def __init__(
        self,
        ssh: SSHRunner,
        progress: Optional[Callable[[str], None]] = None,
        default_port: int = 443,
        default_sni: str = "www.cloudflare.com",
        fingerprint: str = "chrome",
    ) -> None:
        self.ssh = ssh
        self.progress = progress or (lambda _: None)
        self.default_port = default_port
        self.default_sni = default_sni
        self.fingerprint = fingerprint
        self._name_pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

    def _validate_name(self, name: Optional[str]) -> str:
        value = (name or "client1").strip()
        if not self._name_pattern.match(value):
            raise RuntimeError("Proxy client name must match [a-zA-Z0-9_-]{1,64}.")
        return value

    def _split_sni_from_dest(self, dest: str) -> str:
        clean = (dest or "").strip()
        if not clean:
            return self.default_sni
        if ":" in clean:
            left = clean.rsplit(":", 1)[0].strip()
            if left:
                return left
        return clean

    def _random_short_id(self) -> str:
        return uuid.uuid4().hex[:16]

    def _extract_reality_inbound(self, cfg: dict) -> Optional[dict]:
        inbounds = cfg.get("inbounds")
        if not isinstance(inbounds, list):
            return None
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue
            if inbound.get("protocol") != "vless":
                continue
            stream = inbound.get("streamSettings") or {}
            if stream.get("security") == "reality":
                return inbound
        return None

    def _read_config(self) -> Optional[dict]:
        state = self.ssh.run(
            f"test -f {self.XRAY_CONF} && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if state != "yes":
            return None
        raw = self.ssh.run(f"cat {self.XRAY_CONF}", sudo=True, check=False).strip()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid Xray config JSON: {exc}") from exc

    def _write_config(self, cfg: dict) -> None:
        payload = json.dumps(cfg, indent=2, ensure_ascii=False)
        cmd = f"cat > {self.XRAY_CONF} <<'JSON'\n{payload}\nJSON"
        self.ssh.run(cmd, sudo=True)

    def _generate_reality_keypair(self) -> tuple[str, str]:
        raw = self.ssh.run(f"{self.XRAY_BIN} x25519", sudo=True).strip()
        private = ""
        public = ""
        for line in raw.splitlines():
            match_priv = re.search(r"Private(?:\\s+key)?:\\s*(\\S+)", line, flags=re.IGNORECASE)
            if match_priv:
                private = match_priv.group(1).strip()
            match_pub = re.search(r"Public(?:\\s+key)?:\\s*(\\S+)", line, flags=re.IGNORECASE)
            if match_pub:
                public = match_pub.group(1).strip()
        if not private or not public:
            raise RuntimeError("Failed to generate Reality keys.")
        return private, public

    def _derive_public_key(self, private_key: str) -> str:
        raw = self.ssh.run(
            f"{self.XRAY_BIN} x25519 -i {shlex.quote(private_key)}",
            sudo=True,
            check=False,
        ).strip()
        for line in raw.splitlines():
            match_pub = re.search(r"Public(?:\\s+key)?:\\s*(\\S+)", line, flags=re.IGNORECASE)
            if match_pub:
                return match_pub.group(1).strip()
        raise RuntimeError("Failed to derive Reality public key.")

    def _public_ip(self) -> str:
        ip = self.ssh.run(
            "curl -4 -fsS https://ifconfig.co 2>/dev/null || "
            "curl -4 -fsS https://api.ipify.org 2>/dev/null || true",
            check=False,
        ).strip()
        return ip or getattr(self.ssh.config, "host", "") or "YOUR_SERVER_IP"

    def _ensure_prereqs(self) -> None:
        self.progress("Installing proxy prerequisites")
        self.ssh.run(
            "DEBIAN_FRONTEND=noninteractive apt-get update -y",
            sudo=True,
        )
        self.ssh.run(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y curl jq qrencode",
            sudo=True,
        )
        exists = self.ssh.run(
            f"test -x {self.XRAY_BIN} && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if exists != "yes":
            self.progress("Installing Xray-core")
            self.ssh.run(
                "bash -lc "
                + shlex.quote(
                    'bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"'
                ),
                sudo=True,
            )
        self.ssh.run(f"mkdir -p {self.XRAY_ETC}", sudo=True)

    def _restart_xray(self) -> None:
        self.ssh.run("systemctl enable xray >/dev/null 2>&1 || true", sudo=True, check=False)
        self.ssh.run("systemctl restart xray", sudo=True)

    def _build_link(
        self,
        *,
        client_uuid: str,
        host: str,
        port: int,
        sni: str,
        public_key: str,
        short_id: str,
        name: str,
    ) -> str:
        params = {
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": sni,
            "fp": self.fingerprint,
            "pbk": public_key,
            "sid": short_id,
            "type": "tcp",
        }
        query = "&".join(f"{key}={quote(str(value), safe='')}" for key, value in params.items())
        tag = quote(name, safe="-_.")
        return f"vless://{client_uuid}@{host}:{port}?{query}#{tag}"

    def _client_state(self, cfg: dict) -> tuple[dict, list[dict], list[str], str, int]:
        inbound = self._extract_reality_inbound(cfg)
        if not inbound:
            raise RuntimeError("VLESS Reality inbound not found in Xray config.")

        settings = inbound.setdefault("settings", {})
        clients = settings.setdefault("clients", [])
        if not isinstance(clients, list):
            raise RuntimeError("Invalid Xray config: clients must be a list.")

        stream = inbound.setdefault("streamSettings", {})
        reality = stream.setdefault("realitySettings", {})
        short_ids = reality.setdefault("shortIds", [])
        if not isinstance(short_ids, list):
            raise RuntimeError("Invalid Xray config: shortIds must be a list.")

        private_key = (reality.get("privateKey") or "").strip()
        if not private_key:
            raise RuntimeError("Reality privateKey is missing from Xray config.")

        port = inbound.get("port")
        if not isinstance(port, int):
            raise RuntimeError("Xray inbound port is invalid.")
        return inbound, clients, short_ids, private_key, port

    def _resolve_sni(self, inbound: dict) -> str:
        stream = inbound.get("streamSettings") or {}
        reality = stream.get("realitySettings") or {}
        names = reality.get("serverNames")
        if isinstance(names, list) and names:
            first = str(names[0]).strip()
            if first:
                return first
        dest = str(reality.get("dest") or "").strip()
        return self._split_sni_from_dest(dest)

    def detect_status(self) -> dict:
        cfg = self._read_config()
        if not cfg:
            return {"configured": False}
        inbound = self._extract_reality_inbound(cfg)
        if not inbound:
            return {"configured": False}
        settings = inbound.get("settings") or {}
        clients = settings.get("clients") or []
        service_state = self.ssh.run("systemctl is-active xray || true", sudo=True, check=False).strip()
        return {
            "configured": True,
            "protocol": "vless_reality",
            "listen_port": inbound.get("port"),
            "clients_count": len(clients) if isinstance(clients, list) else 0,
            "sni": self._resolve_sni(inbound),
            "service_active": service_state == "active",
        }

    def pre_check(self, listen_port: int) -> list[dict]:
        checks: list[dict] = []
        os_info = self.ssh.run("cat /etc/os-release", check=False)
        os_ok = "ID=" in os_info
        distro = "unknown"
        for line in os_info.splitlines():
            if line.startswith("ID="):
                distro = line.split("=", 1)[1].strip().strip('"')
                break
        checks.append({"name": "os_supported", "ok": os_ok, "details": distro})

        ping = self.ssh.run(
            "ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 && echo ok || echo fail",
            check=False,
        ).strip()
        checks.append({"name": "ping", "ok": ping == "ok", "details": ping})

        sudo_ok = True
        sudo_details = "password auth"
        if not getattr(self.ssh, "config", None) or not self.ssh.config.password:
            sudo = self.ssh.run("sudo -n true && echo ok || echo fail", check=False).strip()
            sudo_ok = sudo == "ok"
            sudo_details = "passwordless" if sudo_ok else "sudo requires password"
        checks.append({"name": "sudo", "ok": sudo_ok, "details": sudo_details})

        port_state = self.ssh.run(
            f"ss -ltn | awk '{{print $4}}' | grep -q ':{listen_port}$' && echo busy || echo free",
            check=False,
        ).strip()
        checks.append({"name": "port_available", "ok": port_state != "busy", "details": port_state})
        return checks

    def setup(self, client_name: Optional[str], listen_port: int, sni: Optional[str] = None) -> dict:
        name = self._validate_name(client_name)
        port = int(listen_port or self.default_port)
        if port < 1 or port > 65535:
            raise RuntimeError("Proxy port must be between 1 and 65535.")
        server_name = (sni or self.default_sni).strip() or self.default_sni

        self._ensure_prereqs()
        self.progress("Generating Reality keys")
        private_key, public_key = self._generate_reality_keypair()
        client_uuid = str(uuid.uuid4())
        short_id = self._random_short_id()

        config = {
            "log": {
                "access": "/var/log/xray/access.log",
                "error": "/var/log/xray/error.log",
                "loglevel": "warning",
            },
            "inbounds": [
                {
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": client_uuid, "flow": "xtls-rprx-vision", "email": name}],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": f"{server_name}:443",
                            "xver": 0,
                            "serverNames": [server_name, "www.cloudflare.com", "www.apple.com"],
                            "privateKey": private_key,
                            "shortIds": [short_id],
                        },
                    },
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                }
            ],
            "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "blocked"}],
        }
        self.progress("Writing Xray config")
        self._write_config(config)
        self.progress("Starting Xray service")
        self._restart_xray()

        host = self._public_ip()
        link = self._build_link(
            client_uuid=client_uuid,
            host=host,
            port=port,
            sni=server_name,
            public_key=public_key,
            short_id=short_id,
            name=name,
        )
        return {
            "name": name,
            "link": link,
            "listen_port": port,
            "sni": server_name,
        }

    def list_clients(self) -> list[dict]:
        cfg = self._read_config()
        if not cfg:
            return []
        _, clients, _, _, _ = self._client_state(cfg)
        result: list[dict] = []
        for idx, item in enumerate(clients):
            if not isinstance(item, dict):
                continue
            name = str(item.get("email") or "").strip() or f"client{idx + 1}"
            result.append({"name": name, "interface": "vless-reality"})
        return result

    def export_client(self, client_name: str) -> dict:
        name = self._validate_name(client_name)
        cfg = self._read_config()
        if not cfg:
            raise RuntimeError("Xray config not found.")
        inbound, clients, short_ids, private_key, port = self._client_state(cfg)
        index = -1
        for idx, item in enumerate(clients):
            if not isinstance(item, dict):
                continue
            if str(item.get("email") or "").strip() == name:
                index = idx
                break
        if index < 0:
            raise RuntimeError("Client not found.")
        client_uuid = str((clients[index] or {}).get("id") or "").strip()
        if not client_uuid:
            raise RuntimeError("Client UUID is missing in Xray config.")
        short_id = short_ids[index] if index < len(short_ids) else self._random_short_id()
        if index >= len(short_ids):
            short_ids.append(short_id)
            self._write_config(cfg)
            self._restart_xray()
        public_key = self._derive_public_key(private_key)
        sni = self._resolve_sni(inbound)
        host = self._public_ip()
        link = self._build_link(
            client_uuid=client_uuid,
            host=host,
            port=port,
            sni=sni,
            public_key=public_key,
            short_id=short_id,
            name=name,
        )
        return {"name": name, "link": link, "interface": "vless-reality"}

    def add_client(self, client_name: Optional[str]) -> dict:
        name = self._validate_name(client_name)
        cfg = self._read_config()
        if not cfg:
            raise RuntimeError("Xray config not found. Run proxy setup first.")
        _, clients, short_ids, _, _ = self._client_state(cfg)
        for item in clients:
            if not isinstance(item, dict):
                continue
            if str(item.get("email") or "").strip() == name:
                return self.export_client(name)

        clients.append(
            {
                "id": str(uuid.uuid4()),
                "flow": "xtls-rprx-vision",
                "email": name,
            }
        )
        short_ids.append(self._random_short_id())
        self._write_config(cfg)
        self._restart_xray()
        return self.export_client(name)

    def remove_client(self, client_name: str) -> bool:
        name = self._validate_name(client_name)
        cfg = self._read_config()
        if not cfg:
            return False
        _, clients, short_ids, _, _ = self._client_state(cfg)
        index = -1
        for idx, item in enumerate(clients):
            if not isinstance(item, dict):
                continue
            if str(item.get("email") or "").strip() == name:
                index = idx
                break
        if index < 0:
            return False
        del clients[index]
        if index < len(short_ids):
            del short_ids[index]
        self._write_config(cfg)
        self._restart_xray()
        return True
