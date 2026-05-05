from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from vpn_wizard.whitelist import WhitelistProvisioner, derive_sslip_domain


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


def test_setup_inbound_adds_new_inbound_when_missing(monkeypatch):
    cfg = {"inbounds": [{"protocol": "vless", "tag": "reality"}]}
    writes = []
    restarts = []

    ssh = FakeSSH()
    prov = WhitelistProvisioner(ssh, listen_port=8443)

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
    assert result["listen_port"] == 8443
    assert result["backend_url"] == "https://1-2-3-4.sslip.io:8443"
    assert result["path"].startswith("/vpnw-wl-")
    assert restarts == [True]
    assert len(writes) == 1
    inbounds = writes[0]["inbounds"]
    wl = next(ib for ib in inbounds if ib.get("tag") == "vless-wl")
    assert wl["port"] == 8443
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
    prov = WhitelistProvisioner(ssh, listen_port=8443)

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
    assert "stop" in str(exc.value)
