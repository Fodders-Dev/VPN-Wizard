from __future__ import annotations

import base64
import json
import os
import re
import shlex
import time
from typing import Callable, Optional

from vpn_wizard.core import SSHRunner


class ShadowTLSSSProvisioner:
    """
    Anti-block proxy for RU networks: ShadowTLS v3 + Shadowsocks 2022 (sing-box).

    Server:
      - inbound shadowtls (public TCP port) -> detour to inbound shadowsocks (localhost)
      - sing-box systemd service

    Client:
      - sing-box config (for Hiddify / sing-box) with TUN + strict_route + QUIC/IPv6 blocks.
    """

    SING_BOX_BIN = "/usr/local/bin/sing-box"
    SING_BOX_ETC = "/usr/local/etc/sing-box"
    CONFIG_PATH = "/usr/local/etc/sing-box/config.json"
    SERVICE_NAME = "sing-box"

    # Hiddify / sing-box interoperability:
    # - SS2022 EIH works only with AES methods;
    # - we keep AES-256 here because our generated keys are 32-byte base64 and
    #   this avoids "required 16, got 32" client-side failures.
    SS_METHOD = "2022-blake3-aes-256-gcm"
    SS_KEY_LEN = 32

    # RU DPI reality:
    # - 443 is the most reliable option;
    # - "CDN-ish" ports (2053/2083/2096/etc) are often filtered by some ISPs.
    # Keep a conservative list to avoid generating profiles that work in NL/US but fail in RU.
    FALLBACK_PORTS = (443, 8443, 9443, 10443, 4443, 5443, 6443, 7443)
    MAX_PUBLIC_PORTS = 1
    HANDSHAKE_CANDIDATES = (
        "www.microsoft.com",
        "www.apple.com",
        "www.github.com",
        "www.wikipedia.org",
        "www.cloudflare.com",
    )

    def __init__(self, ssh: SSHRunner, progress: Optional[Callable[[str], None]] = None) -> None:
        self.ssh = ssh
        self.progress = progress or (lambda _msg: None)
        self._name_pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
        self._sni_pattern = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9-]{1,63})+$")
        raw_max = (os.getenv("VPNW_SHADOWTLS_MAX_PUBLIC_PORTS") or "").strip()
        try:
            requested = int(raw_max) if raw_max else int(self.MAX_PUBLIC_PORTS)
        except ValueError:
            requested = int(self.MAX_PUBLIC_PORTS)
        self.max_public_ports = max(1, min(8, requested))
        self.enable_urltest = (os.getenv("VPNW_SHADOWTLS_ENABLE_URLTEST") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _validate_name(self, name: Optional[str]) -> str:
        value = (name or "client1").strip()
        if not self._name_pattern.match(value):
            raise RuntimeError("Proxy client name must match [a-zA-Z0-9_-]{1,64}.")
        return value

    def _normalize_sni(self, host: Optional[str]) -> str:
        return str(host or "").strip().lower().rstrip(".")

    def _is_valid_sni(self, host: str) -> bool:
        return bool(self._sni_pattern.match(host))

    def _random_b64(self, length: int) -> str:
        return base64.b64encode(os.urandom(int(length))).decode("ascii").strip()

    def _is_port_busy(self, listen_port: int) -> bool:
        state = self.ssh.run(
            f"ss -ltn | awk '{{print $4}}' | grep -q ':{listen_port}$' && echo busy || echo free",
            check=False,
        ).strip()
        return state == "busy"

    def _tcp_port_owner(self, listen_port: int) -> str:
        # Best-effort: parse process name from ss output.
        # Use ss filter expression to avoid regex quoting pitfalls (grep regex errors were observed in the wild).
        port = int(listen_port)
        raw = self.ssh.run(
            f'ss -ltnpH "sport = :{port}" 2>/dev/null | head -n 1 || true',
            check=False,
        )
        text = raw or ""
        marker = 'users:(("'
        idx = text.find(marker)
        if idx < 0:
            return ""
        rest = text[idx + len(marker) :]
        end = rest.find('"')
        if end < 0:
            return ""
        return rest[:end]

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

    def _select_public_ports(self, preferred_port: int, existing_ports: Optional[list[int]] = None) -> list[int]:
        """
        Build a stable list of public listen ports.

        Rules:
        - keep preferred port first;
        - keep already configured ports (don't drop existing profiles on re-run);
        - add extra free fallback ports from FALLBACK_PORTS;
        - cap list length for predictability.
        """
        selected: list[int] = []
        seen: set[int] = set()

        def _push(port: int) -> None:
            if not (1 <= int(port) <= 65535):
                return
            value = int(port)
            if value in seen:
                return
            seen.add(value)
            selected.append(value)

        _push(preferred_port)
        for port in existing_ports or []:
            _push(port)
        for port in self.FALLBACK_PORTS:
            if len(selected) >= self.max_public_ports:
                break
            if port in seen:
                continue
            if not self._is_port_busy(port):
                _push(port)

        return selected[: self.max_public_ports]

    def _ensure_firewall_port(self, listen_port: int) -> None:
        port = int(listen_port)
        if port < 1 or port > 65535:
            return

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
                self.progress(f"Opening TCP {port} in UFW")
                self.ssh.run(f"ufw allow {port}/tcp", sudo=True, check=False)
            return

        firewalld_active = self.ssh.run(
            "command -v firewall-cmd >/dev/null 2>&1 && "
            "systemctl is-active firewalld >/dev/null 2>&1 && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if firewalld_active == "yes":
            already = self.ssh.run(
                f"firewall-cmd --quiet --query-port={port}/tcp && echo yes || echo no",
                sudo=True,
                check=False,
            ).strip()
            if already != "yes":
                self.progress(f"Opening TCP {port} in firewalld")
                self.ssh.run(f"firewall-cmd --add-port={port}/tcp", sudo=True, check=False)
                self.ssh.run(f"firewall-cmd --permanent --add-port={port}/tcp", sudo=True, check=False)
                self.ssh.run("firewall-cmd --reload", sudo=True, check=False)

    def _ensure_tcp_tuning(self) -> None:
        # Same tuning as our Reality path: helps with loss/jitter and PMTUD blackholes.
        self.ssh.run(
            "cat > /etc/sysctl.d/99-vpn-wizard-proxy-tuning.conf <<'EOF'\n"
            "net.core.default_qdisc = fq\n"
            "net.ipv4.tcp_congestion_control = bbr\n"
            "net.ipv4.tcp_fastopen = 3\n"
            "net.ipv4.tcp_mtu_probing = 1\n"
            "net.ipv4.tcp_keepalive_time = 600\n"
            "net.ipv4.tcp_keepalive_intvl = 30\n"
            "net.ipv4.tcp_keepalive_probes = 5\n"
            "net.ipv4.tcp_slow_start_after_idle = 0\n"
            "EOF",
            sudo=True,
            check=False,
        )
        self.ssh.run("sysctl -p /etc/sysctl.d/99-vpn-wizard-proxy-tuning.conf >/dev/null 2>&1 || true", sudo=True, check=False)

    def _public_ip(self) -> str:
        ip = self.ssh.run(
            "curl -4 -fsS https://ifconfig.co 2>/dev/null || "
            "curl -4 -fsS https://api.ipify.org 2>/dev/null || true",
            check=False,
        ).strip()
        return ip or getattr(self.ssh.config, "host", "") or "YOUR_SERVER_IP"

    def _probe_sni(self, host: str) -> bool:
        value = self._normalize_sni(host)
        if not value or not self._is_valid_sni(value):
            return False
        strict = self.ssh.run(
            "bash -lc "
            + shlex.quote(f"curl -4 -m 6 --tlsv1.3 --http2 -fsSI https://{value} >/dev/null 2>&1 && echo ok || echo fail"),
            check=False,
        ).strip()
        if strict == "ok":
            return True
        relaxed = self.ssh.run(
            "bash -lc " + shlex.quote(f"curl -4 -m 6 -fsSI https://{value} >/dev/null 2>&1 && echo ok || echo fail"),
            check=False,
        ).strip()
        return relaxed == "ok"

    def _choose_handshake_sni(self, preferred: Optional[str], existing: Optional[str]) -> str:
        explicit = self._normalize_sni(preferred)
        if explicit:
            if not self._is_valid_sni(explicit):
                raise RuntimeError("Proxy SNI must be a valid domain name.")
            self.progress(f"Using custom proxy SNI: {explicit}")
            return explicit

        current = self._normalize_sni(existing)
        if current and self._probe_sni(current):
            return current

        self.progress("Selecting ShadowTLS handshake SNI automatically (RU-optimized)")
        for candidate in self.HANDSHAKE_CANDIDATES:
            value = self._normalize_sni(candidate)
            if not value:
                continue
            ok = self._probe_sni(value)
            self.progress(f"SNI probe {value}: {'ok' if ok else 'fail'}")
            if ok:
                return value
        return self.HANDSHAKE_CANDIDATES[0]

    def _ensure_prereqs(self) -> None:
        deps_ok = self.ssh.run(
            "command -v curl >/dev/null 2>&1 && "
            "command -v jq >/dev/null 2>&1 && "
            "command -v qrencode >/dev/null 2>&1 && echo ok || echo missing",
            check=False,
        ).strip()
        if deps_ok != "ok":
            self.progress("Installing proxy prerequisites")
            self.ssh.run("DEBIAN_FRONTEND=noninteractive apt-get update -y", sudo=True)
            self.ssh.run(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y curl jq qrencode ca-certificates",
                sudo=True,
            )

        exists = self.ssh.run(f"test -x {self.SING_BOX_BIN} && echo yes || echo no", sudo=True, check=False).strip()
        if exists != "yes":
            self.progress("Installing sing-box")
            install_cmd = r"""
set -euo pipefail
arch="$(uname -m)"
asset_suffix=""
case "$arch" in
  x86_64|amd64) asset_suffix="linux-amd64.tar.gz" ;;
  aarch64|arm64) asset_suffix="linux-arm64.tar.gz" ;;
  armv7l) asset_suffix="linux-armv7.tar.gz" ;;
  *) echo "Unsupported arch: $arch" >&2; exit 1 ;;
esac
tmp="$(mktemp -d)"
json="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest)"
url="$(printf '%s' "$json" | jq -r --arg suffix "$asset_suffix" '.assets[] | select(.name|endswith($suffix)) | .browser_download_url' | head -n 1)"
if [ -z "${url:-}" ] || [ "$url" = "null" ]; then
  echo "Failed to locate sing-box release asset for ${arch}" >&2
  exit 1
fi
curl -fsSL "$url" -o "$tmp/sing-box.tgz"
tar -xzf "$tmp/sing-box.tgz" -C "$tmp"
bin_path="$(find "$tmp" -maxdepth 3 -type f -name sing-box | head -n 1)"
if [ -z "${bin_path:-}" ]; then
  echo "sing-box binary not found in archive" >&2
  exit 1
fi
install -m 0755 "$bin_path" /usr/local/bin/sing-box
rm -rf "$tmp"
"""
            self.ssh.run(install_cmd, sudo=True)

        self.ssh.run(f"mkdir -p {self.SING_BOX_ETC}", sudo=True)

        # Install a minimal systemd unit if missing.
        unit_path = "/etc/systemd/system/sing-box.service"
        has_unit = self.ssh.run(f"test -f {unit_path} && echo yes || echo no", sudo=True, check=False).strip()
        if has_unit != "yes":
            self.progress("Installing sing-box systemd service")
            self.ssh.run(
                "cat > /etc/systemd/system/sing-box.service <<'UNIT'\n"
                "[Unit]\n"
                "Description=sing-box service (VPN Wizard)\n"
                "After=network.target nss-lookup.target\n"
                "\n"
                "[Service]\n"
                "ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json\n"
                "Restart=on-failure\n"
                "RestartSec=5s\n"
                "LimitNOFILE=1048576\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
                "UNIT",
                sudo=True,
            )
            self.ssh.run("systemctl daemon-reload", sudo=True, check=False)

    def _read_config(self) -> Optional[dict]:
        raw = self.ssh.run(f"test -f {self.CONFIG_PATH} && cat {self.CONFIG_PATH} || true", sudo=True, check=False).strip()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"Failed to parse sing-box config: {exc}") from exc

    def _backup_config(self) -> None:
        ts = time.strftime("%Y%m%d-%H%M%S")
        self.ssh.run(
            f"test -f {self.CONFIG_PATH} && cp -f {self.CONFIG_PATH} {self.CONFIG_PATH}.bak-{ts} || true",
            sudo=True,
            check=False,
        )

    def _write_config(self, cfg: dict) -> None:
        payload = json.dumps(cfg, indent=2, ensure_ascii=False)
        self._backup_config()
        self.ssh.run(f"cat > {self.CONFIG_PATH} <<'JSON'\n{payload}\nJSON", sudo=True)

    def _restart(self) -> None:
        self.ssh.run("systemctl enable sing-box >/dev/null 2>&1 || true", sudo=True, check=False)
        self.ssh.run("systemctl restart sing-box", sudo=True)

    def _extract_inbound(self, cfg: dict, inbound_type: str) -> Optional[dict]:
        for item in cfg.get("inbounds") or []:
            if isinstance(item, dict) and item.get("type") == inbound_type:
                return item
        return None

    def _extract_inbounds(self, cfg: dict, inbound_type: str) -> list[dict]:
        result: list[dict] = []
        for item in cfg.get("inbounds") or []:
            if isinstance(item, dict) and item.get("type") == inbound_type:
                result.append(item)
        return result

    def _build_shadowtls_inbound(
        self,
        *,
        tag: str,
        listen_port: int,
        handshake_server: str,
        users: list[dict],
    ) -> dict:
        return {
            "type": "shadowtls",
            "tag": tag,
            # Bind IPv4 explicitly to avoid edge cases with IPv6-only sockets on some kernels.
            "listen": "0.0.0.0",
            "listen_port": int(listen_port),
            "detour": "ss-in",
            "version": 3,
            "users": users,
            "handshake": {"server": handshake_server, "server_port": 443},
            "strict_mode": True,
        }

    def _state(self, cfg: dict) -> tuple[list[dict], dict, list[int], str, str]:
        stls_list = self._extract_inbounds(cfg, "shadowtls")
        ss = self._extract_inbound(cfg, "shadowsocks")
        if not stls_list or not ss:
            raise RuntimeError("sing-box ShadowTLS/Shadowsocks inbounds not found.")
        listen_ports: list[int] = []
        for stls in stls_list:
            port = stls.get("listen_port")
            if isinstance(port, int) and 1 <= port <= 65535 and port not in listen_ports:
                listen_ports.append(port)
        if not listen_ports:
            raise RuntimeError("ShadowTLS listen_port is missing/invalid.")
        method = str(ss.get("method") or "").strip()
        if not method:
            raise RuntimeError("Shadowsocks method is missing.")
        server_password = str(ss.get("password") or "").strip()
        if not server_password:
            raise RuntimeError("Shadowsocks server password is missing.")
        first_stls = stls_list[0]
        handshake = (first_stls.get("handshake") or {}) if isinstance(first_stls.get("handshake"), dict) else {}
        handshake_server = str(handshake.get("server") or "").strip()
        if not handshake_server:
            handshake_server = "www.microsoft.com"
        return stls_list, ss, listen_ports, server_password, handshake_server

    def detect_status(self) -> dict:
        cfg = self._read_config()
        if not cfg:
            return {"configured": False}
        stls_list = self._extract_inbounds(cfg, "shadowtls")
        ss = self._extract_inbound(cfg, "shadowsocks")
        if not stls_list or not ss:
            return {"configured": False}
        users = []
        raw_users = ss.get("users") or []
        if isinstance(raw_users, list):
            users = raw_users
        service_state = self.ssh.run("systemctl is-active sing-box || true", sudo=True, check=False).strip()
        primary = stls_list[0]
        handshake = (primary.get("handshake") or {}) if isinstance(primary.get("handshake"), dict) else {}
        listen_ports: list[int] = []
        for inbound in stls_list:
            port = inbound.get("listen_port")
            if isinstance(port, int) and 1 <= port <= 65535 and port not in listen_ports:
                listen_ports.append(port)
        return {
            "configured": True,
            "protocol": "shadowtls_ss",
            "listen_port": listen_ports[0] if listen_ports else None,
            "listen_ports": listen_ports,
            "clients_count": len(users),
            "sni": str(handshake.get("server") or "").strip() or None,
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

        ping = self.ssh.run("ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 && echo ok || echo fail", check=False).strip()
        checks.append({"name": "ping", "ok": ping == "ok", "details": ping})

        sudo_ok = True
        sudo_details = "password auth"
        if not getattr(self.ssh, "config", None) or not self.ssh.config.password:
            sudo = self.ssh.run("sudo -n true && echo ok || echo fail", check=False).strip()
            sudo_ok = sudo == "ok"
            sudo_details = "passwordless" if sudo_ok else "sudo requires password"
        checks.append({"name": "sudo", "ok": sudo_ok, "details": sudo_details})

        owner = self._tcp_port_owner(int(listen_port))
        if owner == self.SERVICE_NAME:
            checks.append(
                {
                    "name": "port_available",
                    "ok": True,
                    "details": f"in-use by {self.SERVICE_NAME} (reconfigure safe)",
                }
            )
        else:
            port_state = "busy" if self._is_port_busy(int(listen_port)) else "free"
            details = f"busy({owner})" if (port_state == "busy" and owner) else port_state
            checks.append({"name": "port_available", "ok": port_state != "busy", "details": details})
        return checks

    def setup(self, client_name: Optional[str], listen_port: int, sni: Optional[str] = None) -> dict:
        name = self._validate_name(client_name)
        port = int(listen_port)
        if port < 1 or port > 65535:
            raise RuntimeError("Proxy port must be between 1 and 65535.")

        self._ensure_prereqs()
        cfg = self._read_config()

        existing_sni = None
        existing_ports: list[int] = []
        if cfg:
            try:
                _stls_list, _ss, ports, _server_password, handshake_server = self._state(cfg)
                existing_sni = handshake_server
                existing_ports = ports
            except Exception:
                cfg = None

        handshake_server = self._choose_handshake_sni(sni, existing_sni)
        target_ports = self._select_public_ports(port, existing_ports)
        if not target_ports:
            raise RuntimeError("Could not find a free proxy TCP port automatically. Set it manually.")

        if cfg:
            _stls_list, ss, _current_ports, server_password, _existing_handshake = self._state(cfg)
            changed = False

            current_method = str(ss.get("method") or "").strip()
            if current_method and current_method != self.SS_METHOD:
                self.progress(f"Updating Shadowsocks method: {current_method} -> {self.SS_METHOD}")
                ss["method"] = self.SS_METHOD
                changed = True

            mux = ss.get("multiplex") if isinstance(ss.get("multiplex"), dict) else {}
            if mux.get("enabled") is not False:
                ss["multiplex"] = {"enabled": False}
                changed = True

            users_ss = ss.setdefault("users", [])
            if not isinstance(users_ss, list):
                raise RuntimeError("Invalid sing-box config: users must be lists.")

            inbounds = cfg.setdefault("inbounds", [])
            if not isinstance(inbounds, list):
                raise RuntimeError("Invalid sing-box config: inbounds must be a list.")

            desired_stls: list[dict] = []
            for idx, selected_port in enumerate(target_ports):
                stls_tag = "shadowtls-in" if idx == 0 else f"shadowtls-in-{selected_port}"
                users_copy = [dict(item) for item in users_ss if isinstance(item, dict)]
                desired_stls.append(
                    self._build_shadowtls_inbound(
                        tag=stls_tag,
                        listen_port=selected_port,
                        handshake_server=handshake_server,
                        users=users_copy,
                    )
                )

            passthrough_inbounds = [item for item in inbounds if isinstance(item, dict) and item.get("type") != "shadowtls"]
            desired_inbounds = desired_stls + passthrough_inbounds
            if inbounds != desired_inbounds:
                cfg["inbounds"] = desired_inbounds
                changed = True

            if any(isinstance(u, dict) and str(u.get("name") or "").strip() == name for u in users_ss):
                if changed:
                    self._write_config(cfg)
                for selected_port in target_ports:
                    self._ensure_firewall_port(int(selected_port))
                self._ensure_tcp_tuning()
                self._restart()
                exported = self.export_client(name)
                exported["listen_port"] = int(target_ports[0])
                exported["listen_ports"] = [int(item) for item in target_ports]
                exported["sni"] = handshake_server
                return exported

            user_password = self._random_b64(self.SS_KEY_LEN)
            users_ss.append({"name": name, "password": user_password})

            for inbound in cfg.get("inbounds") or []:
                if not isinstance(inbound, dict) or inbound.get("type") != "shadowtls":
                    continue
                users_stls = inbound.setdefault("users", [])
                if not isinstance(users_stls, list):
                    raise RuntimeError("Invalid sing-box config: users must be lists.")
                users_stls.append({"name": name, "password": user_password})

            self._write_config(cfg)
            for selected_port in target_ports:
                self._ensure_firewall_port(int(selected_port))
            self._ensure_tcp_tuning()
            self._restart()
            exported = self.export_client(name)
            exported["listen_port"] = int(target_ports[0])
            exported["listen_ports"] = [int(item) for item in target_ports]
            exported["sni"] = handshake_server
            return exported

        # Initial setup
        server_password = self._random_b64(self.SS_KEY_LEN)
        user_password = self._random_b64(self.SS_KEY_LEN)
        local_ss_port = 20000
        while self._is_port_busy(local_ss_port):
            local_ss_port += 1
            if local_ss_port > 40000:
                raise RuntimeError("Could not find a free local Shadowsocks port.")

        initial_users = [{"name": name, "password": user_password}]
        shadowtls_inbounds: list[dict] = []
        for idx, selected_port in enumerate(target_ports):
            stls_tag = "shadowtls-in" if idx == 0 else f"shadowtls-in-{selected_port}"
            shadowtls_inbounds.append(
                self._build_shadowtls_inbound(
                    tag=stls_tag,
                    listen_port=selected_port,
                    handshake_server=handshake_server,
                    users=[dict(item) for item in initial_users],
                )
            )

        cfg = {
            "log": {"level": "warn"},
            "inbounds": shadowtls_inbounds
            + [
                {
                    "type": "shadowsocks",
                    "tag": "ss-in",
                    "listen": "127.0.0.1",
                    "listen_port": local_ss_port,
                    "method": self.SS_METHOD,
                    "password": server_password,
                    "users": [dict(item) for item in initial_users],
                    "multiplex": {"enabled": False},
                },
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
        self.progress("Writing sing-box config (ShadowTLS + Shadowsocks)")
        self._write_config(cfg)
        for selected_port in target_ports:
            self._ensure_firewall_port(selected_port)
        self._ensure_tcp_tuning()
        self.progress("Restarting sing-box service")
        self._restart()
        exported = self.export_client(name)
        exported["listen_port"] = target_ports[0]
        exported["listen_ports"] = [int(item) for item in target_ports]
        exported["sni"] = handshake_server
        return exported

    def list_clients(self) -> list[dict]:
        cfg = self._read_config()
        if not cfg:
            return []
        ss = self._extract_inbound(cfg, "shadowsocks") or {}
        raw_users = ss.get("users") or []
        if not isinstance(raw_users, list):
            return []
        result: list[dict] = []
        for idx, item in enumerate(raw_users):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip() or f"client{idx + 1}"
            result.append({"name": name, "interface": "shadowtls-ss"})
        return result

    def export_client(self, client_name: str) -> dict:
        name = self._validate_name(client_name)
        cfg = self._read_config()
        if not cfg:
            raise RuntimeError("sing-box config not found.")
        _stls_list, ss, listen_ports, server_password, handshake_server = self._state(cfg)
        users = ss.get("users") or []
        if not isinstance(users, list):
            raise RuntimeError("Invalid sing-box config: users must be a list.")
        user_password = None
        for item in users:
            if not isinstance(item, dict):
                continue
            if str(item.get("name") or "").strip() == name:
                user_password = str(item.get("password") or "").strip()
                break
        if not user_password:
            raise RuntimeError("Client not found.")
        host = self._public_ip()
        fallback_ports = [int(item) for item in listen_ports[1:] if isinstance(item, int) and 1 <= int(item) <= 65535]
        auto_config = self.build_singbox_client_config(
            host=host,
            port=int(listen_ports[0]),
            # Include extra server ports so client can fail over when one port degrades.
            fallback_ports=fallback_ports,
            handshake_sni=handshake_server,
            server_password=server_password,
            user_password=user_password,
        )
        return {
            "name": name,
            "interface": "shadowtls-ss",
            "auto_config": auto_config,
            "listen_port": int(listen_ports[0]),
            "listen_ports": [int(item) for item in listen_ports],
            "sni": handshake_server,
        }

    def add_client(self, client_name: Optional[str]) -> dict:
        name = self._validate_name(client_name)
        cfg = self._read_config()
        if not cfg:
            raise RuntimeError("sing-box config not found. Run proxy setup first.")
        stls_list, ss, _listen_ports, _server_password, _handshake_server = self._state(cfg)
        users_ss = ss.setdefault("users", [])
        if not isinstance(users_ss, list):
            raise RuntimeError("Invalid sing-box config: users must be lists.")
        if any(isinstance(u, dict) and str(u.get("name") or "").strip() == name for u in users_ss):
            return self.export_client(name)
        user_password = self._random_b64(self.SS_KEY_LEN)
        users_ss.append({"name": name, "password": user_password})
        for stls in stls_list:
            users_stls = stls.setdefault("users", [])
            if not isinstance(users_stls, list):
                raise RuntimeError("Invalid sing-box config: users must be lists.")
            users_stls.append({"name": name, "password": user_password})
        self._write_config(cfg)
        self._restart()
        return self.export_client(name)

    def remove_client(self, client_name: str) -> bool:
        name = self._validate_name(client_name)
        cfg = self._read_config()
        if not cfg:
            return False
        stls_list, ss, _listen_ports, _server_password, _handshake_server = self._state(cfg)
        users_ss = ss.get("users") or []
        if not isinstance(users_ss, list):
            return False
        idx_ss = next(
            (i for i, u in enumerate(users_ss) if isinstance(u, dict) and str(u.get("name") or "").strip() == name),
            -1,
        )
        if idx_ss < 0:
            return False
        if idx_ss >= 0:
            del users_ss[idx_ss]
        for stls in stls_list:
            users_stls = stls.get("users") or []
            if not isinstance(users_stls, list):
                continue
            idx_stls = next(
                (i for i, u in enumerate(users_stls) if isinstance(u, dict) and str(u.get("name") or "").strip() == name),
                -1,
            )
            if idx_stls >= 0:
                del users_stls[idx_stls]
        self._write_config(cfg)
        self._restart()
        return True

    def build_singbox_client_config(
        self,
        *,
        host: str,
        port: int,
        fallback_ports: Optional[list[int]] = None,
        handshake_sni: str,
        server_password: str,
        user_password: str,
        # NOTE: Hiddify обычно управляет inbound'ами (mixed/tun) сам и подмешивает только outbounds из профиля.
        # Чтобы не "включать VPN" неожиданно, по умолчанию генерируем outbound-only конфиг.
        include_tun: bool = False,
        strict_route: bool = True,
        remote_doh: str = "https://dns.quad9.net/dns-query",
        direct_dns: str = "77.88.8.8",
    ) -> str:
        selected_ports: list[int] = []
        for item in [int(port)] + [int(p) for p in (fallback_ports or [])]:
            if 1 <= item <= 65535 and item not in selected_ports:
                selected_ports.append(item)
        if not selected_ports:
            selected_ports = [int(port)]

        # sing-box full config for Hiddify:
        # - ShadowTLS + SS2022 chain(s)
        # - route uses a selector pinned to the primary chain by default.
        #   (RU networks frequently block some non-standard ports; urltest-based auto failover is fragile.)
        outbounds: list[dict] = []
        chain_tags: list[str] = []
        for idx, selected_port in enumerate(selected_ports, start=1):
            ss_tag = f"p{idx}"
            st_tag = f"st-{selected_port}"
            chain_tags.append(ss_tag)
            outbounds.append(
                {
                    "type": "shadowsocks",
                    "tag": ss_tag,
                    "server": host,
                    "server_port": int(selected_port),
                    "method": self.SS_METHOD,
                    # Multi-user SS2022: client uses "<server_password>:<user_password>"
                    "password": f"{server_password}:{user_password}",
                    "detour": st_tag,
                    "multiplex": {"enabled": False},
                }
            )
            outbounds.append(
                {
                    "type": "shadowtls",
                    "tag": st_tag,
                    "server": host,
                    "server_port": int(selected_port),
                    "version": 3,
                    "password": str(user_password),
                    "tls": {"enabled": True, "server_name": str(handshake_sni)},
                }
            )

        primary_tag = chain_tags[0] if chain_tags else "direct"
        outbounds.append(
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": chain_tags or ["direct"],
                "default": primary_tag if chain_tags else "direct",
            }
        )
        if self.enable_urltest and len(chain_tags) > 1:
            outbounds.append(
                {
                    "type": "urltest",
                    "tag": "auto",
                    "outbounds": chain_tags,
                    "interval": "45s",
                    "tolerance": 200,
                    "interrupt_exist_connections": False,
                }
            )

        outbounds.append({"type": "direct", "tag": "direct", "domain_strategy": "ipv4_only"})
        outbounds.append({"type": "block", "tag": "block"})

        config: dict = {
            "log": {"level": "warn"},
            "outbounds": outbounds,
            "route": {"final": "proxy"},
        }

        # Optional full-tunnel mode for raw sing-box clients (not recommended as default for RU users in Hiddify).
        if include_tun:
            config["dns"] = {
                "servers": [
                    {"tag": "doh", "address": remote_doh, "detour": "proxy"},
                    {"tag": "local", "address": direct_dns, "detour": "direct"},
                ],
                "strategy": "ipv4_only",
            }
            config["inbounds"] = [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "address": ["172.19.0.1/30"],
                    "auto_route": True,
                    "strict_route": bool(strict_route),
                    "stack": "mixed",
                    "sniff": True,
                }
            ]
            config["route"] = {
                "auto_detect_interface": True,
                "rules": [
                    {"ip_version": 6, "outbound": "block"},
                    {"inbound": ["tun-in"], "ip_version": 6, "outbound": "block"},
                    {"inbound": ["tun-in"], "protocol": ["quic"], "outbound": "block"},
                    {"inbound": ["tun-in"], "network": ["udp"], "port": [443], "outbound": "block"},
                ],
                "final": "proxy",
            }
        return json.dumps(config, indent=2, ensure_ascii=False)
