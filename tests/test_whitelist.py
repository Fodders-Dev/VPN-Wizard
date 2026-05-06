from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from vpn_wizard.whitelist import (
    WhitelistProvisioner,
    _nginx_acme_snippet,
    derive_sslip_domain,
)


class FakeSSH:
    def __init__(self, scripted=None):
        self.config = SimpleNamespace(host="1.2.3.4", password=None)
        self.commands: list[str] = []
        self._scripted = list(scripted or [])

    def run(self, command: str, sudo: bool = False, check: bool = True) -> str:
        self.commands.append(command)
        for matcher, response in self._scripted:
            if matcher in command:
                return response
        # sensible defaults for prereq probes
        if "test -x" in command and "/acme.sh" in command:
            return "ok"
        if "ifconfig.co" in command or "ipify" in command:
            return "1.2.3.4"
        if "ufw status" in command or "firewall-cmd" in command or "is-active firewalld" in command:
            return "no"
        if "test -s" in command and "fullchain" in command:
            return "yes"  # cert reuse path by default
        if "users:((" in command or "ss -ltnpH" in command:
            return ""
        if "systemctl" in command:
            return ""
        return ""


def test_derive_sslip_domain_for_ipv4():
    assert derive_sslip_domain("1.2.3.4") == "1-2-3-4.sslip.io"
    assert derive_sslip_domain("203.0.113.7") == "203-0-113-7.sslip.io"


def test_derive_sslip_domain_rejects_non_ipv4():
    with pytest.raises(RuntimeError):
        derive_sslip_domain("example.com")
    with pytest.raises(RuntimeError):
        derive_sslip_domain("")


def test_build_client_link_targets_gateway_on_443_with_xhttp_packet_up():
    link = WhitelistProvisioner.build_client_link(
        gateway_domain="abcd.apigw.yandexcloud.net",
        client_uuid="22222222-2222-2222-2222-222222222222",
        path="/vpnw-wl-deadbeef",
        client_name="mom",
    )
    assert link.startswith("vless://22222222-2222-2222-2222-222222222222@abcd.apigw.yandexcloud.net:443?")
    assert "type=xhttp" in link
    assert "security=tls" in link
    assert "sni=abcd.apigw.yandexcloud.net" in link
    assert "host=abcd.apigw.yandexcloud.net" in link
    assert "mode=packet-up" in link
    assert "path=%2Fvpnw-wl-deadbeef" in link
    assert link.endswith("#mom")


def test_default_listen_port_avoids_reality_8443():
    prov = WhitelistProvisioner(FakeSSH())
    assert prov.listen_port == 9443


def test_setup_inbound_adds_new_inbound_when_missing(monkeypatch):
    cfg = {"inbounds": [{"protocol": "vless", "tag": "reality"}]}
    writes = []
    restarts = []

    ssh = FakeSSH()
    prov = WhitelistProvisioner(ssh, listen_port=9443)

    monkeypatch.setattr(prov._proxy, "_read_config", lambda: cfg)
    monkeypatch.setattr(prov._proxy, "_write_config", lambda payload: writes.append(copy.deepcopy(payload)))
    monkeypatch.setattr(prov._proxy, "_restart_xray", lambda: restarts.append(True))
    monkeypatch.setattr(prov, "_public_ip", lambda: "1.2.3.4")
    monkeypatch.setattr(
        prov,
        "issue_certificate",
        lambda domain: {
            "domain": domain,
            "cert_path": "/etc/wl/cert.pem",
            "key_path": "/etc/wl/key.pem",
            "issued": False,
        },
    )

    result = prov.setup_inbound("alice")
    assert result["client_name"] == "alice"
    assert result["domain"] == "1-2-3-4.sslip.io"
    assert result["listen_port"] == 9443
    assert result["backend_url"] == "https://1-2-3-4.sslip.io:9443"
    assert result["path"].startswith("/vpnw-wl-")
    assert restarts == [True]
    assert len(writes) == 1
    inbounds = writes[0]["inbounds"]
    wl = next(ib for ib in inbounds if ib.get("tag") == "vless-wl")
    assert wl["port"] == 9443
    assert wl["streamSettings"]["network"] == "xhttp"
    assert wl["streamSettings"]["security"] == "tls"
    assert wl["streamSettings"]["xhttpSettings"]["mode"] == "packet-up"
    assert wl["settings"]["clients"][0]["email"] == "alice"


def test_setup_inbound_appends_client_to_existing_inbound(monkeypatch):
    existing_uuid = "11111111-1111-1111-1111-111111111111"
    cfg = {
        "inbounds": [
            {
                "tag": "vless-wl",
                "port": 8443,
                "protocol": "vless",
                "settings": {"clients": [{"id": existing_uuid, "email": "alice"}]},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [{"certificateFile": "old", "keyFile": "old"}],
                        "serverName": "1-2-3-4.sslip.io",
                    },
                    "xhttpSettings": {"path": "/vpnw-wl-existing", "mode": "packet-up"},
                },
            }
        ]
    }
    writes = []
    ssh = FakeSSH()
    prov = WhitelistProvisioner(ssh, listen_port=9443)

    monkeypatch.setattr(prov._proxy, "_read_config", lambda: cfg)
    monkeypatch.setattr(prov._proxy, "_write_config", lambda payload: writes.append(copy.deepcopy(payload)))
    monkeypatch.setattr(prov._proxy, "_restart_xray", lambda: None)
    monkeypatch.setattr(prov, "_public_ip", lambda: "1.2.3.4")
    monkeypatch.setattr(
        prov,
        "issue_certificate",
        lambda domain: {
            "domain": domain,
            "cert_path": "/etc/wl/cert.pem",
            "key_path": "/etc/wl/key.pem",
            "issued": False,
        },
    )

    result = prov.setup_inbound("bob")
    assert result["client_name"] == "bob"
    assert result["path"] == "/vpnw-wl-existing"  # path preserved
    inbounds = writes[0]["inbounds"]
    wl = next(ib for ib in inbounds if ib.get("tag") == "vless-wl")
    emails = [c.get("email") for c in wl["settings"]["clients"]]
    assert "alice" in emails and "bob" in emails
    assert wl["streamSettings"]["tlsSettings"]["certificates"][0]["certificateFile"] == "/etc/wl/cert.pem"


def test_setup_inbound_rejects_invalid_client_name():
    prov = WhitelistProvisioner(FakeSSH())
    with pytest.raises(RuntimeError):
        prov.setup_inbound("bad name with spaces")


def test_setup_inbound_requires_existing_xray_config(monkeypatch):
    ssh = FakeSSH()
    prov = WhitelistProvisioner(ssh)
    monkeypatch.setattr(prov._proxy, "_read_config", lambda: None)
    with pytest.raises(RuntimeError) as exc:
        prov.setup_inbound("alice")
    assert "Provision Reality first" in str(exc.value)


def test_issue_certificate_aborts_when_port_80_in_use(monkeypatch):
    ssh = FakeSSH(
        scripted=[
            ("test -x", "ok"),  # acme.sh present
            ("test -s", "no"),  # no existing cert
            ("ss -ltnpH", 'tcp users:(("nginx",pid=42,fd=6))'),
        ]
    )
    prov = WhitelistProvisioner(ssh)
    with pytest.raises(RuntimeError) as exc:
        prov.issue_certificate("1-2-3-4.sslip.io")
    assert "nginx" in str(exc.value)
    assert "VPNW_WL_STOP_PORT80_SERVICE" in str(exc.value)


def test_issue_certificate_stops_and_restarts_pinned_service(monkeypatch):
    issued = []
    started_back = []

    ssh = FakeSSH(
        scripted=[
            ("test -x", "ok"),
            ("test -s", "no"),
            ("ss -ltnpH", 'tcp users:(("nginx",pid=42,fd=6))'),
        ]
    )
    original_run = ssh.run

    def tracking_run(command, sudo=False, check=True):
        if "acme.sh --issue" in command:
            issued.append(command)
            return ""
        if "systemctl start" in command:
            started_back.append(command)
            return ""
        return original_run(command, sudo=sudo, check=check)

    ssh.run = tracking_run  # type: ignore[assignment]
    prov = WhitelistProvisioner(ssh, stop_port80_service="nginx")
    result = prov.issue_certificate("1-2-3-4.sslip.io")
    assert result["issued"] is True
    assert issued, "acme.sh --issue must run after the conflicting service is stopped"
    assert any("nginx" in cmd for cmd in started_back), "nginx must be restarted afterwards"


def test_issue_certificate_auto_stops_whatever_owns_port_80(monkeypatch):
    started_back = []
    ssh = FakeSSH(
        scripted=[
            ("test -x", "ok"),
            ("test -s", "no"),
            ("ss -ltnpH", 'tcp users:(("apache2",pid=99,fd=8))'),
        ]
    )
    original_run = ssh.run

    def tracking_run(command, sudo=False, check=True):
        if "systemctl start" in command:
            started_back.append(command)
            return ""
        if "acme.sh --issue" in command:
            return ""
        return original_run(command, sudo=sudo, check=check)

    ssh.run = tracking_run  # type: ignore[assignment]
    prov = WhitelistProvisioner(ssh, stop_port80_service="auto")
    prov.issue_certificate("1-2-3-4.sslip.io")
    assert any("apache2" in cmd for cmd in started_back)


def test_issue_certificate_does_not_stop_when_service_does_not_match(monkeypatch):
    ssh = FakeSSH(
        scripted=[
            ("test -x", "ok"),
            ("test -s", "no"),
            ("ss -ltnpH", 'tcp users:(("apache2",pid=99,fd=8))'),
        ]
    )
    prov = WhitelistProvisioner(ssh, stop_port80_service="nginx", acme_mode="standalone")
    with pytest.raises(RuntimeError) as exc:
        prov.issue_certificate("1-2-3-4.sslip.io")
    # owner is apache2 but user pinned nginx — bot must not touch apache2
    assert "apache2" in str(exc.value)


# --- ACME webroot mode ------------------------------------------------------

def test_nginx_acme_snippet_is_hostname_scoped_and_no_default_server():
    snippet = _nginx_acme_snippet("1-2-3-4.sslip.io")
    assert "server_name 1-2-3-4.sslip.io" in snippet
    # MUST NOT use default_server — that would steal traffic from existing vhosts.
    assert "default_server" not in snippet
    # Challenge files must be served from the dedicated webroot.
    assert "/var/www/acme-webroot" in snippet
    assert "/.well-known/acme-challenge/" in snippet
    # Anything else returns 404 (no leakage of /).
    assert "return 404" in snippet


def test_resolve_acme_mode_auto_uses_webroot_when_nginx_active():
    ssh = FakeSSH(scripted=[("is-active nginx", "active")])
    prov = WhitelistProvisioner(ssh, acme_mode="auto")
    assert prov._resolve_acme_mode() == "webroot"


def test_resolve_acme_mode_auto_falls_back_to_standalone_without_nginx():
    ssh = FakeSSH(scripted=[("is-active nginx", "inactive")])
    prov = WhitelistProvisioner(ssh, acme_mode="auto")
    assert prov._resolve_acme_mode() == "standalone"


def test_resolve_acme_mode_honors_explicit_choice():
    ssh = FakeSSH(scripted=[("is-active nginx", "active")])  # would be webroot under auto
    prov = WhitelistProvisioner(ssh, acme_mode="standalone")
    assert prov._resolve_acme_mode() == "standalone"


def test_webroot_aborts_if_nginx_not_active():
    ssh = FakeSSH(scripted=[("is-active nginx", "inactive"), ("test -s", "no")])
    prov = WhitelistProvisioner(ssh, acme_mode="webroot")
    with pytest.raises(RuntimeError) as exc:
        prov.issue_certificate("1-2-3-4.sslip.io")
    assert "active nginx" in str(exc.value)


def test_webroot_writes_snippet_validates_and_reloads_nginx():
    runs: list[tuple[str, bool]] = []

    ssh = FakeSSH(scripted=[("is-active nginx", "active"), ("test -s", "no")])
    original_run = ssh.run

    def tracking_run(command, sudo=False, check=True):
        if "nginx -t" in command:
            return "nginx: configuration file /etc/nginx/nginx.conf test is successful"
        if "acme.sh --issue --webroot" in command:
            runs.append(("issue", True))
            return ""
        if "acme.sh --install-cert" in command:
            runs.append(("install", True))
            return ""
        if "systemctl reload nginx" in command:
            runs.append(("reload-nginx", True))
            return ""
        return original_run(command, sudo=sudo, check=check)

    ssh.run = tracking_run  # type: ignore[assignment]
    prov = WhitelistProvisioner(ssh, acme_mode="webroot")
    result = prov.issue_certificate("1-2-3-4.sslip.io")
    assert result["mode"] == "webroot"
    # webroot path runs in this exact order: write snippet, validate, reload, then issue.
    kinds = [k for k, _ in runs]
    assert kinds == ["reload-nginx", "issue", "install"]
    # The snippet write must have included the canonical config.d path for our domain.
    assert any(
        "acme-vpnw-wl-1-2-3-4.sslip.io.conf" in cmd for cmd in ssh.commands
    ), "snippet should be written to a hostname-scoped file in conf.d"


def test_webroot_rolls_back_snippet_when_nginx_t_fails():
    rollback_seen = {"hit": False}
    reloaded = {"hit": False}

    ssh = FakeSSH(scripted=[("is-active nginx", "active"), ("test -s", "no")])
    original_run = ssh.run

    def tracking_run(command, sudo=False, check=True):
        if "nginx -t" in command:
            return "nginx: [emerg] unknown directive in /etc/nginx/conf.d/acme-vpnw-wl-1-2-3-4.sslip.io.conf"
        if command.startswith("rm -f") and "acme-vpnw-wl-1-2-3-4.sslip.io.conf" in command:
            rollback_seen["hit"] = True
            return ""
        if "systemctl reload nginx" in command:
            reloaded["hit"] = True
            return ""
        if "acme.sh --issue" in command:
            raise AssertionError("acme.sh must NOT run if nginx -t failed")
        return original_run(command, sudo=sudo, check=check)

    ssh.run = tracking_run  # type: ignore[assignment]
    prov = WhitelistProvisioner(ssh, acme_mode="webroot")
    with pytest.raises(RuntimeError) as exc:
        prov.issue_certificate("1-2-3-4.sslip.io")
    assert "validation failed" in str(exc.value)
    assert rollback_seen["hit"], "snippet must be removed when nginx -t rejects it"
    assert not reloaded["hit"], "nginx must NOT be reloaded with broken config"


def test_auto_mode_picks_webroot_during_full_setup_inbound(monkeypatch):
    cfg = {"inbounds": []}
    ssh = FakeSSH(scripted=[("is-active nginx", "active")])
    prov = WhitelistProvisioner(ssh, listen_port=9443, acme_mode="auto")

    monkeypatch.setattr(prov._proxy, "_read_config", lambda: cfg)
    monkeypatch.setattr(prov._proxy, "_write_config", lambda payload: None)
    monkeypatch.setattr(prov._proxy, "_restart_xray", lambda: None)
    monkeypatch.setattr(prov, "_public_ip", lambda: "1.2.3.4")

    captured: dict = {}

    def fake_issue(domain: str) -> dict:
        captured["mode"] = prov._resolve_acme_mode()
        return {
            "domain": domain,
            "cert_path": "/etc/wl/cert.pem",
            "key_path": "/etc/wl/key.pem",
            "issued": False,
            "mode": "cached",
        }

    monkeypatch.setattr(prov, "issue_certificate", fake_issue)
    prov.setup_inbound("alice")
    assert captured["mode"] == "webroot"


def test_invalid_acme_mode_falls_back_to_auto():
    prov = WhitelistProvisioner(FakeSSH(), acme_mode="bogus")
    assert prov.acme_mode == "auto"


# --- Existing nginx server_name detection (rodnya-tree.ru style) ----------

def test_webroot_reuses_existing_nginx_server_with_acme_location():
    """An operator-managed nginx vhost already claims the domain AND already serves
    /.well-known/acme-challenge/ — we leave it alone and proceed to acme.sh."""
    snippet_writes: list[str] = []
    nginx_reloads: list[str] = []

    ssh = FakeSSH(scripted=[("is-active nginx", "active"), ("test -s", "no")])
    original_run = ssh.run

    def tracking_run(command, sudo=False, check=True):
        if "grep -rlE" in command and "server_name" in command:
            return "/etc/nginx/sites-enabled/rodnya.conf"
        if "grep -F '/.well-known/acme-challenge/'" in command:
            # The existing config already has the location.
            return "    location ^~ /.well-known/acme-challenge/ {"
        if "mv" in command and "/conf.d/acme-vpnw-wl-" in command:
            snippet_writes.append(command)
            return ""
        if "systemctl reload nginx" in command:
            nginx_reloads.append(command)
            return ""
        if "acme.sh --issue --webroot" in command:
            return ""
        if "acme.sh --install-cert" in command:
            return ""
        return original_run(command, sudo=sudo, check=check)

    ssh.run = tracking_run  # type: ignore[assignment]
    prov = WhitelistProvisioner(ssh, acme_mode="webroot")
    result = prov.issue_certificate("rodnya-tree.ru")
    assert result["mode"] == "webroot"
    # Crucial: we did NOT write a duplicate snippet, and we did NOT reload nginx
    # (the existing config is already serving the challenge location).
    assert snippet_writes == [], "must not duplicate server_name when nginx already owns it"
    assert nginx_reloads == [], "no reload when no config change"


def test_webroot_bails_when_existing_server_lacks_acme_location():
    """An nginx vhost claims the domain but has no acme-challenge location.
    Writing our snippet would duplicate server_name → silent ignore. Bail loudly."""
    snippet_writes: list[str] = []

    ssh = FakeSSH(scripted=[("is-active nginx", "active"), ("test -s", "no")])
    original_run = ssh.run

    def tracking_run(command, sudo=False, check=True):
        if "grep -rlE" in command and "server_name" in command:
            return "/etc/nginx/sites-enabled/rodnya.conf"
        if "grep -F '/.well-known/acme-challenge/'" in command:
            return ""  # no location present
        if "mv" in command and "/conf.d/acme-vpnw-wl-" in command:
            snippet_writes.append(command)
            return ""
        if "acme.sh --issue" in command or "acme.sh --install-cert" in command:
            raise AssertionError("acme.sh issuance must NOT run when nginx isn't routed yet")
        return original_run(command, sudo=sudo, check=check)

    ssh.run = tracking_run  # type: ignore[assignment]
    prov = WhitelistProvisioner(ssh, acme_mode="webroot")
    with pytest.raises(RuntimeError) as exc:
        prov.issue_certificate("rodnya-tree.ru")
    msg = str(exc.value)
    assert "rodnya-tree.ru" in msg
    assert "duplicate" in msg.lower()
    assert "rodnya.conf" in msg
    # The bail-out prints the exact location block to paste.
    assert "location ^~ /.well-known/acme-challenge/" in msg
    assert snippet_writes == [], "must not write a duplicate snippet"


def test_webroot_writes_fresh_snippet_when_no_conflict():
    """sslip.io / fresh FQDN with no existing server_name → write+reload as before."""
    snippet_paths_written: list[str] = []
    nginx_reloads: list[str] = []

    ssh = FakeSSH(scripted=[("is-active nginx", "active"), ("test -s", "no")])
    original_run = ssh.run

    def tracking_run(command, sudo=False, check=True):
        if "grep -rlE" in command and "server_name" in command:
            return ""  # no existing server_name claims this domain
        if "nginx -t" in command:
            return "nginx: the configuration file ... test is successful"
        if "mv" in command and "/conf.d/acme-vpnw-wl-" in command:
            snippet_paths_written.append(command)
            return ""
        if "systemctl reload nginx" in command:
            nginx_reloads.append(command)
            return ""
        if "acme.sh" in command:
            return ""
        return original_run(command, sudo=sudo, check=check)

    ssh.run = tracking_run  # type: ignore[assignment]
    prov = WhitelistProvisioner(ssh, acme_mode="webroot")
    prov.issue_certificate("1-2-3-4.sslip.io")
    assert snippet_paths_written, "should write a fresh snippet when there's no conflict"
    assert nginx_reloads == ["systemctl reload nginx"], "reload exactly once after fresh snippet"
