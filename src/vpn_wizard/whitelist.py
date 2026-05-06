"""Whitelist-friendly proxy: VLESS-XHTTP+TLS inbound on the user's VPS,
fronted by Yandex Cloud API Gateway.

Architecture:
  client -> https://<gw>.apigw.yandexcloud.net (whitelisted in RU mobile networks)
         -> Yandex API Gateway (HTTP integration)
         -> https://<ip-dashes>.sslip.io:8443/<path>
         -> Xray VLESS-XHTTP+TLS inbound on the VPS
         -> internet

We add a SECOND Xray inbound alongside the existing Reality one. Cert for the
sslip.io domain is obtained via acme.sh in standalone mode (port 80, briefly).
"""

from __future__ import annotations

import base64
import re
import shlex
import uuid
from typing import Callable, Optional
from urllib.parse import quote

from vpn_wizard.core import SSHRunner
from vpn_wizard.proxy import ProxyProvisioner


# 8443 is the conventional fallback for Reality on hosts where 443 is taken by
# nginx/caddy. Default the WL inbound to 9443 so it doesn't collide with that.
WL_INBOUND_PORT_DEFAULT = 9443
WL_LOOPBACK_PORT_DEFAULT = 10000
WL_PATH_PREFIX = "/vpnw-wl-"
ACME_HOME = "/root/.acme.sh"
CERT_DIR = "/usr/local/etc/xray/wl-certs"
ACME_CHALLENGE_PORT = 80
ACME_WEBROOT = "/var/www/acme-webroot"
NGINX_CONFD = "/etc/nginx/conf.d"
ACME_MODES = ("auto", "webroot", "standalone")


def _nginx_acme_snippet(domain: str) -> str:
    """Hostname-scoped server block: ONLY answers requests with Host: <domain>.
    Existing vhosts (Rodnya etc.) are unaffected because their server_name doesn't
    match this one, and we deliberately do NOT use default_server.
    """
    return (
        f"# Managed by vpn-wizard for ACME HTTP-01 challenge of {domain}.\n"
        f"# Hostname-scoped: only answers requests with Host: {domain}.\n"
        f"server {{\n"
        f"    listen 80;\n"
        f"    listen [::]:80;\n"
        f"    server_name {domain};\n"
        f"\n"
        f"    location ^~ /.well-known/acme-challenge/ {{\n"
        f"        default_type \"text/plain\";\n"
        f"        root {ACME_WEBROOT};\n"
        f"        try_files $uri =404;\n"
        f"    }}\n"
        f"\n"
        f"    location / {{\n"
        f"        return 404;\n"
        f"    }}\n"
        f"}}\n"
    )


def derive_sslip_domain(public_ip: str) -> str:
    """1.2.3.4 -> 1-2-3-4.sslip.io. Caller is responsible for passing a real IPv4 string."""
    raw = (public_ip or "").strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw):
        raise RuntimeError(f"Cannot derive sslip.io domain from {raw!r} (expected IPv4).")
    return raw.replace(".", "-") + ".sslip.io"


class WhitelistProvisioner:
    """Adds and manages a VLESS-XHTTP+TLS inbound on the user's VPS for WL routing.

    Reuses the existing Xray installation that ProxyProvisioner manages, so the
    same xray service handles both Reality (port 443) and the WL inbound (port 8443).
    """

    def __init__(
        self,
        ssh: SSHRunner,
        progress: Optional[Callable[[str], None]] = None,
        listen_port: int = WL_INBOUND_PORT_DEFAULT,
        *,
        stop_port80_service: Optional[str] = None,
        acme_mode: str = "auto",
    ) -> None:
        self.ssh = ssh
        self.progress = progress or (lambda _msg: None)
        self.listen_port = int(listen_port)
        self._proxy = ProxyProvisioner(ssh, progress=progress)
        self._name_pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
        # auto:       prefer webroot if nginx is active, fall back to standalone otherwise
        # webroot:    require nginx, never touch other services on :80
        # standalone: take :80 directly via acme.sh; needs :80 free or stop_port80_service
        mode = (acme_mode or "auto").strip().lower()
        if mode not in ACME_MODES:
            mode = "auto"
        self.acme_mode = mode
        # Standalone-only escape hatch. NOT recommended on hosts where nginx serves
        # production traffic — webroot is preferred and zero-downtime.
        self.stop_port80_service = (stop_port80_service or "").strip() or None

    # ---------- helpers -------------------------------------------------

    def _validate_name(self, name: Optional[str]) -> str:
        value = (name or "wl1").strip()
        if not self._name_pattern.match(value):
            raise RuntimeError("WL client name must match [a-zA-Z0-9_-]{1,64}.")
        return value

    def _random_path(self) -> str:
        return f"{WL_PATH_PREFIX}{uuid.uuid4().hex[:12]}"

    def _public_ip(self) -> str:
        ip = self.ssh.run(
            "curl -4 -fsS https://ifconfig.co 2>/dev/null || "
            "curl -4 -fsS https://api.ipify.org 2>/dev/null || true",
            check=False,
        ).strip()
        if not ip:
            ip = getattr(self.ssh.config, "host", "") or ""
        return ip.strip()

    # ---------- system prereqs -----------------------------------------

    def _ensure_acme(self) -> None:
        installed = self.ssh.run(
            f"test -x {ACME_HOME}/acme.sh && echo ok || echo missing",
            sudo=True,
            check=False,
        ).strip()
        if installed == "ok":
            return
        self.progress("Installing acme.sh")
        self.ssh.run(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y curl socat cron >/dev/null 2>&1 || true",
            sudo=True,
            check=False,
        )
        self.ssh.run(
            "bash -lc " + shlex.quote(
                "curl -fsSL https://get.acme.sh | sh -s -- --no-cron --home " + ACME_HOME
            ),
            sudo=True,
        )
        self.ssh.run(
            f"{ACME_HOME}/acme.sh --set-default-ca --server letsencrypt --home {ACME_HOME} >/dev/null 2>&1 || true",
            sudo=True,
            check=False,
        )

    def _ensure_firewall_port(self, port: int) -> None:
        port = int(port)
        ufw_active = self.ssh.run(
            "command -v ufw >/dev/null 2>&1 && "
            "ufw status 2>/dev/null | head -n 1 | grep -qi 'Status: active' && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if ufw_active == "yes":
            self.ssh.run(f"ufw allow {port}/tcp", sudo=True, check=False)
            return
        firewalld_active = self.ssh.run(
            "command -v firewall-cmd >/dev/null 2>&1 && "
            "systemctl is-active firewalld >/dev/null 2>&1 && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if firewalld_active == "yes":
            self.ssh.run(f"firewall-cmd --add-port={port}/tcp --permanent", sudo=True, check=False)
            self.ssh.run("firewall-cmd --reload", sudo=True, check=False)

    def _free_port_80_for_acme(self) -> Optional[str]:
        """Returns the systemd unit currently bound to :80, if any (so we can resume it)."""
        owner = self.ssh.run(
            'ss -ltnpH "sport = :80" 2>/dev/null | head -n 1 || true',
            check=False,
        )
        match = re.search(r'users:\(\("([^"]+)"', owner or "")
        process = match.group(1) if match else ""
        if not process:
            return None
        # caller may want to stop the service; we only signal which one
        return process

    # ---------- cert issuance ------------------------------------------

    def _resolve_port80_service_to_stop(self, owner: str) -> Optional[str]:
        """Return the systemd unit name to stop (or None if we should leave :80 alone)."""
        configured = self.stop_port80_service
        if not configured:
            return None
        if configured.lower() in {"auto", "*"}:
            return owner or None
        # User pinned a specific unit (e.g. "nginx") — only stop if the actual process matches.
        if owner and (owner == configured or owner.startswith(configured)):
            return configured
        # Configured unit doesn't match what's actually on :80 — be conservative and bail.
        return None

    def _nginx_active(self) -> bool:
        state = self.ssh.run(
            "systemctl is-active nginx 2>/dev/null || true",
            sudo=True,
            check=False,
        ).strip()
        return state == "active"

    def _resolve_acme_mode(self) -> str:
        """Pick webroot vs standalone for this run, honoring explicit operator choice."""
        if self.acme_mode == "webroot":
            return "webroot"
        if self.acme_mode == "standalone":
            return "standalone"
        # auto: prefer zero-downtime webroot when nginx is around.
        return "webroot" if self._nginx_active() else "standalone"

    def _nginx_snippet_path(self, domain: str) -> str:
        safe = re.sub(r"[^a-z0-9.-]", "-", (domain or "").lower())
        return f"{NGINX_CONFD}/acme-vpnw-wl-{safe}.conf"

    def _find_nginx_server_for(self, domain: str) -> Optional[str]:
        """Return the path of an existing nginx config that already declares
        server_name <domain>, or None if nothing claims it.

        Excludes our own managed snippet so re-runs don't see themselves.
        """
        domain_re = re.escape(domain)
        # Match `server_name ... <domain> ...;` as a whole token, skip commented lines.
        # -P would be cleaner but isn't always available; use ERE with word-ish boundaries.
        cmd = (
            f"grep -rlE '^[[:space:]]*server_name[[:space:]][^#;]*(^|[[:space:]]){domain_re}([[:space:]]|;|$)' "
            f"/etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null "
            f"| grep -v '/acme-vpnw-wl-' "
            f"|| true"
        )
        out = self.ssh.run(f"bash -lc {shlex.quote(cmd)}", sudo=True, check=False).strip()
        if not out:
            return None
        return out.splitlines()[0].strip() or None

    def _nginx_serves_acme_for(self, config_path: str) -> bool:
        out = self.ssh.run(
            f"grep -F '/.well-known/acme-challenge/' {shlex.quote(config_path)} 2>/dev/null || true",
            sudo=True,
            check=False,
        ).strip()
        return bool(out)

    def _setup_nginx_webroot(self, domain: str) -> str:
        """Make /.well-known/acme-challenge/ on `domain` reach $ACME_WEBROOT.

        Three cases:
          1. Some other server block already claims `server_name <domain>` AND already
             serves /.well-known/acme-challenge/ from /var/www/acme-webroot. We do nothing
             and proceed to acme.sh — the existing config is correct.
          2. Some other server block claims `server_name <domain>` but does NOT serve the
             ACME location. We bail with explicit instructions; writing our own snippet
             would duplicate server_name and nginx would silently ignore one of them.
          3. No conflict — write a fresh hostname-scoped snippet, validate, reload.
        """
        self.progress(f"Preparing nginx ACME webroot at {ACME_WEBROOT}")
        self.ssh.run(f"mkdir -p {ACME_WEBROOT}/.well-known/acme-challenge", sudo=True)
        # nginx default user differs across distros (www-data on Debian/Ubuntu, nginx on RHEL).
        # 0755 + open ownership is enough — challenge files are public by design.
        self.ssh.run(f"chmod -R 755 {ACME_WEBROOT}", sudo=True, check=False)

        existing = self._find_nginx_server_for(domain)
        if existing:
            if self._nginx_serves_acme_for(existing):
                self.progress(
                    f"Reusing existing nginx server for {domain} at {existing} "
                    f"(already serves /.well-known/acme-challenge/ from {ACME_WEBROOT})."
                )
                return existing
            raise RuntimeError(
                f"nginx already declares `server_name {domain}` in {existing}, "
                f"but no /.well-known/acme-challenge/ location is present there. "
                f"Adding a separate conf.d snippet would duplicate the server_name and "
                f"nginx would silently ignore one of the blocks. "
                f"Add this to the existing :80 server block in {existing}:\n\n"
                f"  location ^~ /.well-known/acme-challenge/ {{\n"
                f"      default_type \"text/plain\";\n"
                f"      root {ACME_WEBROOT};\n"
                f"      try_files $uri =404;\n"
                f"  }}\n\n"
                f"Then `sudo nginx -t && sudo systemctl reload nginx`, and re-run /wl_add."
            )

        # No conflicting block — write a fresh hostname-scoped snippet (works for
        # sslip.io-style throwaway domains and any FQDN we control entirely).
        snippet_path = self._nginx_snippet_path(domain)
        snippet = _nginx_acme_snippet(domain)

        # Atomic write: render to /tmp, then mv into conf.d. Avoids leaving a half-written
        # file that nginx -t could trip on.
        encoded = base64.b64encode(snippet.encode()).decode()
        write_cmd = (
            f"set -e; "
            f"tmp=$(mktemp /tmp/acme-vpnw-wl.XXXXXX); "
            f"echo {shlex.quote(encoded)} | base64 -d > $tmp; "
            f"chmod 644 $tmp; "
            f"mv $tmp {shlex.quote(snippet_path)}"
        )
        self.ssh.run(f"bash -lc {shlex.quote(write_cmd)}", sudo=True)

        # Validate before touching the running nginx.
        test_out = self.ssh.run("nginx -t 2>&1", sudo=True, check=False)
        if "syntax is ok" not in (test_out or "").lower() and "test is successful" not in (test_out or "").lower():
            self.progress("nginx -t failed; rolling back ACME snippet")
            self.ssh.run(f"rm -f {shlex.quote(snippet_path)}", sudo=True, check=False)
            raise RuntimeError(
                f"nginx config validation failed after writing {snippet_path}. "
                f"Snippet rolled back. nginx -t output:\n{test_out}"
            )

        # reload (NOT restart): zero-downtime, existing connections survive.
        self.ssh.run("systemctl reload nginx", sudo=True)
        return snippet_path

    def _issue_via_webroot(self, domain: str, cert_path: str, key_path: str) -> dict:
        if not self._nginx_active():
            raise RuntimeError(
                "ACME webroot mode requires an active nginx (systemctl is-active nginx). "
                "Either start nginx, or set VPNW_WL_ACME_MODE=standalone."
            )
        self._setup_nginx_webroot(domain)
        self.progress(f"Requesting Let's Encrypt cert for {domain} (webroot via nginx)")
        # acme.sh writes challenge file under <webroot>/.well-known/acme-challenge/<token>;
        # nginx serves it on http://<domain>/.well-known/acme-challenge/<token>.
        self.ssh.run(
            f"{ACME_HOME}/acme.sh --issue --webroot {shlex.quote(ACME_WEBROOT)} "
            f"-d {shlex.quote(domain)} --keylength ec-256 --home {ACME_HOME}",
            sudo=True,
        )
        self.ssh.run(
            f"{ACME_HOME}/acme.sh --install-cert -d {shlex.quote(domain)} --ecc "
            f"--fullchain-file {shlex.quote(cert_path)} --key-file {shlex.quote(key_path)} "
            # On renewal, reload xray so it picks the freshly rotated cert without restart.
            f"--reloadcmd 'systemctl reload xray 2>/dev/null || systemctl restart xray' "
            f"--home {ACME_HOME}",
            sudo=True,
        )
        self.ssh.run(f"chmod 600 {shlex.quote(key_path)}", sudo=True, check=False)
        return {
            "domain": domain,
            "cert_path": cert_path,
            "key_path": key_path,
            "issued": True,
            "mode": "webroot",
        }

    def _issue_via_standalone(self, domain: str, cert_path: str, key_path: str) -> dict:
        owner = self._free_port_80_for_acme()
        stopped_service: Optional[str] = None
        if owner:
            unit = self._resolve_port80_service_to_stop(owner)
            if not unit:
                raise RuntimeError(
                    f"Port 80 is currently bound by {owner!r}; stop it before issuing a cert "
                    f"(e.g. `systemctl stop {owner}`), or set "
                    f"VPNW_WL_STOP_PORT80_SERVICE={owner} to let the bot stop+restart it. "
                    f"For zero-downtime, prefer VPNW_WL_ACME_MODE=webroot if nginx is in front."
                )
            self.progress(f"Stopping {unit} to free port 80 for acme.sh standalone")
            self.ssh.run(f"systemctl stop {shlex.quote(unit)}", sudo=True)
            stopped_service = unit

        try:
            self.progress(f"Requesting Let's Encrypt cert for {domain} (standalone)")
            self.ssh.run(
                f"{ACME_HOME}/acme.sh --issue --standalone -d {shlex.quote(domain)} "
                f"--httpport {ACME_CHALLENGE_PORT} --keylength ec-256 --home {ACME_HOME}",
                sudo=True,
            )
            self.ssh.run(
                f"{ACME_HOME}/acme.sh --install-cert -d {shlex.quote(domain)} --ecc "
                f"--fullchain-file {shlex.quote(cert_path)} --key-file {shlex.quote(key_path)} "
                f"--reloadcmd 'systemctl reload xray 2>/dev/null || systemctl restart xray' "
                f"--home {ACME_HOME}",
                sudo=True,
            )
            self.ssh.run(f"chmod 600 {shlex.quote(key_path)}", sudo=True, check=False)
        finally:
            # ALWAYS attempt to bring the service back, even if acme.sh failed mid-issue.
            # We use check=False so a failed restart surfaces in the log but doesn't
            # mask the original acme error.
            if stopped_service:
                self.progress(f"Restarting {stopped_service}")
                started = self.ssh.run(
                    f"systemctl start {shlex.quote(stopped_service)}; "
                    f"systemctl is-active {shlex.quote(stopped_service)} || echo INACTIVE",
                    sudo=True,
                    check=False,
                )
                if "INACTIVE" in (started or ""):
                    self.progress(
                        f"WARNING: {stopped_service} did not come back up — investigate "
                        f"with `journalctl -u {stopped_service} --since '5 minutes ago'`."
                    )
        return {
            "domain": domain,
            "cert_path": cert_path,
            "key_path": key_path,
            "issued": True,
            "mode": "standalone",
        }

    def issue_certificate(self, domain: str) -> dict:
        domain = (domain or "").strip().lower()
        if not domain:
            raise RuntimeError("Domain is required for cert issuance.")
        self._ensure_acme()
        self._ensure_firewall_port(ACME_CHALLENGE_PORT)

        self.ssh.run(f"mkdir -p {CERT_DIR}", sudo=True)
        cert_path = f"{CERT_DIR}/{domain}.fullchain.pem"
        key_path = f"{CERT_DIR}/{domain}.key.pem"
        already = self.ssh.run(
            f"test -s {cert_path} && test -s {key_path} && echo yes || echo no",
            sudo=True,
            check=False,
        ).strip()
        if already == "yes":
            self.progress(f"Reusing existing certificate for {domain}")
            return {
                "domain": domain,
                "cert_path": cert_path,
                "key_path": key_path,
                "issued": False,
                "mode": "cached",
            }

        mode = self._resolve_acme_mode()
        self.progress(f"ACME mode: {mode}")
        if mode == "webroot":
            return self._issue_via_webroot(domain, cert_path, key_path)
        return self._issue_via_standalone(domain, cert_path, key_path)

    # ---------- xray inbound -------------------------------------------

    def _read_xray_config(self) -> dict:
        cfg = self._proxy._read_config()
        if not cfg:
            raise RuntimeError(
                "Xray config not found. Provision Reality first so xray-core is installed and managed."
            )
        return cfg

    def _find_wl_inbound(self, cfg: dict) -> Optional[dict]:
        for inbound in cfg.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            if inbound.get("tag") == "vless-wl":
                return inbound
        return None

    def _build_wl_inbound(
        self,
        *,
        listen_port: int,
        domain: str,
        cert_path: str,
        key_path: str,
        client_uuid: str,
        client_name: str,
        path: str,
    ) -> dict:
        return {
            "tag": "vless-wl",
            "port": listen_port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": client_uuid, "email": client_name}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h2", "http/1.1"],
                    "certificates": [
                        {
                            "ocspStapling": 3600,
                            "certificateFile": cert_path,
                            "keyFile": key_path,
                        }
                    ],
                    "serverName": domain,
                },
                "xhttpSettings": {
                    "path": path,
                    # packet-up works through any HTTP proxy (incl. Yandex API Gateway HTTP integration).
                    "mode": "packet-up",
                },
                "sockopt": {
                    "tcpFastOpen": True,
                    "tcpKeepAliveIdle": 300,
                    "tcpKeepAliveInterval": 60,
                    "tcpUserTimeout": 30000,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }

    def setup_inbound(
        self,
        client_name: Optional[str] = None,
        *,
        domain: Optional[str] = None,
    ) -> dict:
        """Install the WL inbound on the VPS and return the public-facing parameters."""
        name = self._validate_name(client_name)
        cfg = self._read_xray_config()

        public_ip = self._public_ip()
        if not public_ip:
            raise RuntimeError("Failed to determine VPS public IPv4.")
        chosen_domain = (domain or derive_sslip_domain(public_ip)).strip().lower()

        cert = self.issue_certificate(chosen_domain)
        self._ensure_firewall_port(self.listen_port)

        inbound = self._find_wl_inbound(cfg)
        if inbound is None:
            client_uuid = str(uuid.uuid4())
            path = self._random_path()
            inbound = self._build_wl_inbound(
                listen_port=self.listen_port,
                domain=chosen_domain,
                cert_path=cert["cert_path"],
                key_path=cert["key_path"],
                client_uuid=client_uuid,
                client_name=name,
                path=path,
            )
            cfg.setdefault("inbounds", []).append(inbound)
            self.progress(f"Adding WL inbound on :{self.listen_port} for {chosen_domain}")
        else:
            stream = inbound.setdefault("streamSettings", {})
            tls = stream.setdefault("tlsSettings", {})
            certs = tls.setdefault("certificates", [{}])
            certs[0]["certificateFile"] = cert["cert_path"]
            certs[0]["keyFile"] = cert["key_path"]
            tls["serverName"] = chosen_domain
            inbound["port"] = self.listen_port
            settings = inbound.setdefault("settings", {})
            clients = settings.setdefault("clients", [])
            existing = next(
                (c for c in clients if isinstance(c, dict) and c.get("email") == name),
                None,
            )
            if existing is None:
                client_uuid = str(uuid.uuid4())
                clients.append({"id": client_uuid, "email": name})
            else:
                client_uuid = str(existing.get("id") or uuid.uuid4())
                existing["id"] = client_uuid
            xhttp = stream.setdefault("xhttpSettings", {})
            path = str(xhttp.get("path") or "").strip() or self._random_path()
            xhttp["path"] = path
            xhttp["mode"] = "packet-up"
            self.progress(f"Updating WL inbound on :{self.listen_port}")

        self._proxy._write_config(cfg)
        self._proxy._restart_xray()

        backend_url = f"https://{chosen_domain}:{self.listen_port}"
        return {
            "client_name": name,
            "client_uuid": client_uuid,
            "domain": chosen_domain,
            "listen_port": self.listen_port,
            "path": path,
            "cert_path": cert["cert_path"],
            "key_path": cert["key_path"],
            "backend_url": backend_url,
        }

    # ---------- client link generation ---------------------------------

    @staticmethod
    def build_client_link(
        *,
        gateway_domain: str,
        client_uuid: str,
        path: str,
        client_name: str,
        sni: Optional[str] = None,
    ) -> str:
        """Build the vless:// link the family member pastes into Hiddify / v2rayNG."""
        host = (gateway_domain or "").strip().rstrip("/")
        if not host:
            raise RuntimeError("gateway_domain is required for client link.")
        normalized_sni = (sni or host).strip()
        params = {
            "encryption": "none",
            "type": "xhttp",
            "security": "tls",
            "sni": normalized_sni,
            "fp": "chrome",
            "host": normalized_sni,
            "path": path,
            "mode": "packet-up",
        }
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        tag = quote(client_name or "wl", safe="-_.")
        # Gateway is reachable on standard 443; client uses that.
        return f"vless://{client_uuid}@{host}:443?{query}#{tag}"


__all__ = [
    "WhitelistProvisioner",
    "derive_sslip_domain",
    "WL_INBOUND_PORT_DEFAULT",
    "WL_PATH_PREFIX",
]
