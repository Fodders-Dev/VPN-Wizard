from __future__ import annotations

import json
import os
import re
import shlex
import uuid
from typing import Callable, Optional
from urllib.parse import quote

from vpn_wizard.core import SSHRunner


def _parse_domain_list(raw: str, fallback: tuple[str, ...]) -> tuple[str, ...]:
    values: list[str] = []
    for chunk in (raw or "").split(","):
        item = chunk.strip().lower().rstrip(".")
        if not item:
            continue
        values.append(item)
    deduped = list(dict.fromkeys(values))
    if not deduped:
        deduped = list(fallback)
    return tuple(deduped)


class ProxyProvisioner:
    XRAY_BIN = "/usr/local/bin/xray"
    XRAY_ETC = "/usr/local/etc/xray"
    XRAY_CONF = f"{XRAY_ETC}/config.json"
    FALLBACK_PORTS = (443, 2053, 2083, 2087, 2096, 8443)
    DEFAULT_SNI_CANDIDATES = _parse_domain_list(
        os.getenv(
            "VPNW_PROXY_SNI_CANDIDATES",
            "www.microsoft.com,www.apple.com,www.github.com,www.wikipedia.org,www.cloudflare.com",
        ),
        ("www.microsoft.com", "www.apple.com", "www.github.com", "www.wikipedia.org", "www.cloudflare.com"),
    )
    AVOID_SNI = set(
        _parse_domain_list(
            os.getenv("VPNW_PROXY_SNI_AVOID", "www.cloudflare.com,cloudflare.com"),
            ("www.cloudflare.com", "cloudflare.com"),
        )
    )
    _sni_pattern = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

    def __init__(
        self,
        ssh: SSHRunner,
        progress: Optional[Callable[[str], None]] = None,
        default_port: int = 443,
        default_sni: Optional[str] = None,
        fingerprint: str = "chrome",
    ) -> None:
        self.ssh = ssh
        self.progress = progress or (lambda _: None)
        self.default_port = default_port
        self.sni_candidates = list(self.DEFAULT_SNI_CANDIDATES)
        self.default_sni = self._normalize_sni(default_sni) or self.sni_candidates[0]
        if self.default_sni not in self.sni_candidates:
            self.sni_candidates.insert(0, self.default_sni)
        self.fingerprint = fingerprint
        self._name_pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

    def _validate_name(self, name: Optional[str]) -> str:
        value = (name or "client1").strip()
        if not self._name_pattern.match(value):
            raise RuntimeError("Proxy client name must match [a-zA-Z0-9_-]{1,64}.")
        return value

    def _normalize_sni(self, host: Optional[str]) -> str:
        value = str(host or "").strip().lower().rstrip(".")
        if not value:
            return ""
        return value

    def _is_valid_sni(self, host: str) -> bool:
        return bool(self._sni_pattern.match(host))

    def _is_avoided_sni(self, host: str) -> bool:
        value = self._normalize_sni(host)
        if not value:
            return True
        if value in self.AVOID_SNI:
            return True
        return any(value.endswith(f".{blocked}") for blocked in self.AVOID_SNI)

    def _split_sni_from_dest(self, dest: str) -> str:
        clean = self._normalize_sni(dest)
        if not clean:
            return self.default_sni
        if ":" in clean:
            left = clean.rsplit(":", 1)[0].strip()
            if left:
                return left
        return clean

    def _random_short_id(self) -> str:
        return uuid.uuid4().hex[:16]

    def _build_server_names(self, primary_sni: str) -> list[str]:
        ordered = [primary_sni] + self.sni_candidates + ["www.cloudflare.com", "www.apple.com"]
        seen: set[str] = set()
        result: list[str] = []
        for item in ordered:
            value = self._normalize_sni(item)
            if not value or value in seen or not self._is_valid_sni(value):
                continue
            seen.add(value)
            result.append(value)
            if len(result) >= 6:
                break
        return result

    def _probe_sni(self, host: str) -> bool:
        value = self._normalize_sni(host)
        if not value or not self._is_valid_sni(value):
            return False
        strict = self.ssh.run(
            "bash -lc "
            + shlex.quote(
                f"curl -m 6 --tlsv1.3 --http2 -fsSI https://{value} >/dev/null 2>&1 && echo ok || echo fail"
            ),
            check=False,
        ).strip()
        if strict == "ok":
            return True
        relaxed = self.ssh.run(
            "bash -lc " + shlex.quote(f"curl -m 6 -fsSI https://{value} >/dev/null 2>&1 && echo ok || echo fail"),
            check=False,
        ).strip()
        return relaxed == "ok"

    def _choose_best_sni(self, preferred: Optional[str], existing: Optional[str]) -> str:
        explicit = self._normalize_sni(preferred)
        if explicit:
            if not self._is_valid_sni(explicit):
                raise RuntimeError("Proxy SNI must be a valid domain name.")
            self.progress(f"Using custom proxy SNI: {explicit}")
            return explicit

        ordered: list[str] = []
        current = self._normalize_sni(existing)
        if current:
            ordered.append(current)
        for item in self.sni_candidates:
            ordered.append(self._normalize_sni(item))
        ordered.append(self.default_sni)

        deduped: list[str] = []
        seen: set[str] = set()
        for item in ordered:
            if not item or item in seen or not self._is_valid_sni(item):
                continue
            seen.add(item)
            deduped.append(item)

        preferred_pool = [item for item in deduped if not self._is_avoided_sni(item)]
        fallback_pool = [item for item in deduped if self._is_avoided_sni(item)]
        probe_order = preferred_pool + fallback_pool
        self.progress("Selecting Reality SNI automatically (RU-optimized)")
        for candidate in probe_order:
            ok = self._probe_sni(candidate)
            self.progress(f"SNI probe {candidate}: {'ok' if ok else 'fail'}")
            if ok:
                return candidate

        if current and self._is_valid_sni(current):
            return current
        if preferred_pool:
            return preferred_pool[0]
        if deduped:
            return deduped[0]
        return self.default_sni

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
        raw = self.ssh.run(f"{self.XRAY_BIN} x25519", sudo=True, check=False).strip()
        private = ""
        public = ""
        for line in raw.splitlines():
            match_priv = re.search(r"Private(?:\s*Key)?\s*:\s*(\S+)", line, flags=re.IGNORECASE)
            if match_priv:
                private = match_priv.group(1).strip()
            match_pub = re.search(r"Public(?:\s*Key)?\s*:\s*(\S+)", line, flags=re.IGNORECASE)
            if match_pub:
                public = match_pub.group(1).strip()
            if not public:
                match_password = re.search(r"Password(?:\s*Key)?\s*:\s*(\S+)", line, flags=re.IGNORECASE)
                if match_password:
                    # Xray 26+ prints Password as alias of the old Reality public key field.
                    public = match_password.group(1).strip()
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
            match_pub = re.search(r"Public(?:\s*Key)?\s*:\s*(\S+)", line, flags=re.IGNORECASE)
            if match_pub:
                return match_pub.group(1).strip()
            match_password = re.search(r"Password(?:\s*Key)?\s*:\s*(\S+)", line, flags=re.IGNORECASE)
            if match_password:
                return match_password.group(1).strip()
        raise RuntimeError("Failed to derive Reality public key.")

    def _is_port_busy(self, listen_port: int) -> bool:
        state = self.ssh.run(
            f"ss -ltn | awk '{{print $4}}' | grep -q ':{listen_port}$' && echo busy || echo free",
            check=False,
        ).strip()
        return state == "busy"

    def choose_free_port(self, preferred_port: Optional[int] = None) -> Optional[int]:
        candidates: list[int] = []
        if isinstance(preferred_port, int) and 1 <= preferred_port <= 65535:
            candidates.append(preferred_port)
        for port in self.FALLBACK_PORTS:
            if port not in candidates:
                candidates.append(port)
        for port in candidates:
            if not self._is_port_busy(port):
                return port
        return None

    def _public_ip(self) -> str:
        ip = self.ssh.run(
            "curl -4 -fsS https://ifconfig.co 2>/dev/null || "
            "curl -4 -fsS https://api.ipify.org 2>/dev/null || true",
            check=False,
        ).strip()
        return ip or getattr(self.ssh.config, "host", "") or "YOUR_SERVER_IP"

    def _ensure_prereqs(self) -> None:
        deps_ok = self.ssh.run(
            "command -v curl >/dev/null 2>&1 && "
            "command -v jq >/dev/null 2>&1 && "
            "command -v qrencode >/dev/null 2>&1 && echo ok || echo missing",
            check=False,
        ).strip()
        if deps_ok != "ok":
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

        port_state = "busy" if self._is_port_busy(listen_port) else "free"
        checks.append({"name": "port_available", "ok": port_state != "busy", "details": port_state})
        return checks

    def setup(self, client_name: Optional[str], listen_port: int, sni: Optional[str] = None) -> dict:
        name = self._validate_name(client_name)
        port = int(listen_port or self.default_port)
        if port < 1 or port > 65535:
            raise RuntimeError("Proxy port must be between 1 and 65535.")

        self._ensure_prereqs()
        config = self._read_config()
        existing_inbound = self._extract_reality_inbound(config or {}) if config else None
        existing_sni = self._resolve_sni(existing_inbound) if existing_inbound else None
        server_name = self._choose_best_sni(sni, existing_sni)

        if config and existing_inbound:
            self.progress("Reusing existing Reality config")
            inbound, clients, short_ids, private_key, current_port = self._client_state(config)
            stream = inbound.setdefault("streamSettings", {})
            reality = stream.setdefault("realitySettings", {})
            changed = False

            selected_sni = server_name
            selected_port = current_port
            if isinstance(port, int) and 1 <= port <= 65535 and port != current_port:
                selected_port = port
                inbound["port"] = selected_port
                changed = True

            if reality.get("dest") != f"{selected_sni}:443":
                reality["dest"] = f"{selected_sni}:443"
                changed = True

            existing_names_raw = reality.get("serverNames")
            existing_names: list[str] = []
            if isinstance(existing_names_raw, list):
                seen_names: set[str] = set()
                for item in existing_names_raw:
                    value = self._normalize_sni(item)
                    if not value or value in seen_names or not self._is_valid_sni(value):
                        continue
                    seen_names.add(value)
                    existing_names.append(value)
            if existing_names and existing_names[0] == selected_sni:
                server_names = existing_names
            else:
                server_names = self._build_server_names(selected_sni)
            if reality.get("serverNames") != server_names:
                reality["serverNames"] = server_names
                changed = True

            index = -1
            for idx, item in enumerate(clients):
                if not isinstance(item, dict):
                    continue
                if str(item.get("email") or "").strip() == name:
                    index = idx
                    break
            if index < 0:
                clients.append(
                    {
                        "id": str(uuid.uuid4()),
                        "flow": "xtls-rprx-vision",
                        "email": name,
                    }
                )
                index = len(clients) - 1
                changed = True

            entry = clients[index]
            if not isinstance(entry, dict):
                raise RuntimeError("Invalid Xray client entry format.")
            if not str(entry.get("id") or "").strip():
                entry["id"] = str(uuid.uuid4())
                changed = True
            if entry.get("flow") != "xtls-rprx-vision":
                entry["flow"] = "xtls-rprx-vision"
                changed = True
            if entry.get("email") != name:
                entry["email"] = name
                changed = True

            while len(short_ids) <= index:
                short_ids.append(self._random_short_id())
                changed = True
            short_id = str(short_ids[index] or "").strip()
            if not short_id:
                short_id = self._random_short_id()
                short_ids[index] = short_id
                changed = True

            if changed:
                self.progress("Updating Xray config")
                self._write_config(config)
                self.progress("Restarting Xray service")
                self._restart_xray()

            client_uuid = str(entry.get("id") or "").strip()
            public_key = self._derive_public_key(private_key)
            host = self._public_ip()
            link = self._build_link(
                client_uuid=client_uuid,
                host=host,
                port=selected_port,
                sni=selected_sni,
                public_key=public_key,
                short_id=short_id,
                name=name,
            )
            return {
                "name": name,
                "link": link,
                "listen_port": selected_port,
                "sni": selected_sni,
            }

        self.progress("Generating Reality keys")
        private_key, public_key = self._generate_reality_keypair()
        client_uuid = str(uuid.uuid4())
        short_id = self._random_short_id()
        server_names = self._build_server_names(server_name)
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
                            "serverNames": server_names,
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
