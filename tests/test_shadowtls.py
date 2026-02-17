from __future__ import annotations

import copy
import json
from types import SimpleNamespace

from vpn_wizard.shadowtls import ShadowTLSSSProvisioner


class DummySSH:
    def __init__(self) -> None:
        self.config = SimpleNamespace(host="1.2.3.4", password=None)

    def run(self, command: str, sudo: bool = False, check: bool = True) -> str:
        if "systemctl is-active sing-box" in command:
            return "active"
        return ""


def _base_server_config() -> dict:
    return {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "shadowtls",
                "tag": "shadowtls-in",
                "listen": "::",
                "listen_port": 443,
                "detour": "ss-in",
                "version": 3,
                "users": [{"name": "client1", "password": "USER1"}],
                "handshake": {"server": "www.microsoft.com", "server_port": 443},
                "strict_mode": True,
            },
            {
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "127.0.0.1",
                "listen_port": 20000,
                "method": "2022-blake3-aes-256-gcm",
                "password": "SERVERPASS",
                "users": [{"name": "client1", "password": "USER1"}],
                "multiplex": {"enabled": True},
            },
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }


def test_build_singbox_client_config_contains_shadowtls_and_ss_chain() -> None:
    prov = ShadowTLSSSProvisioner(DummySSH())
    cfg = json.loads(
        prov.build_singbox_client_config(
            host="1.2.3.4",
            port=443,
            fallback_ports=[],
            handshake_sni="www.microsoft.com",
            server_password="SERVERPASS",
            user_password="USER1",
        )
    )
    outbounds = cfg.get("outbounds") or []
    selector = next((o for o in outbounds if o.get("type") == "selector"), None)
    ss_outbounds = [o for o in outbounds if o.get("type") == "shadowsocks"]
    st_outbounds = [o for o in outbounds if o.get("type") == "shadowtls"]
    assert selector is None
    assert len(ss_outbounds) == 1
    assert len(st_outbounds) == 1
    for ss in ss_outbounds:
        assert ss.get("server") == "1.2.3.4"
        assert ss.get("password") == "SERVERPASS:USER1"
        assert str(ss.get("detour") or "").startswith("st-")
    for st in st_outbounds:
        assert st.get("server") == "1.2.3.4"
        assert st.get("password") == "USER1"
        assert (st.get("tls") or {}).get("server_name") == "www.microsoft.com"

    # RU defaults: block IPv6 and QUIC/UDP443 inside tunnel.
    rules = (cfg.get("route") or {}).get("rules") or []
    assert (cfg.get("route") or {}).get("final") == "p1"
    dns = cfg.get("dns") or {}
    doh = next((item for item in (dns.get("servers") or []) if item.get("tag") == "doh"), {})
    assert doh.get("detour") == "p1"
    assert any(r.get("ip_version") == 6 and r.get("outbound") == "block" for r in rules)
    assert any(r.get("protocol") == ["quic"] and r.get("outbound") == "block" for r in rules)
    assert any(r.get("network") == ["udp"] and r.get("port") == [443] and r.get("outbound") == "block" for r in rules)


def test_detect_status_reads_shadowtls_shape(monkeypatch) -> None:
    prov = ShadowTLSSSProvisioner(DummySSH())
    cfg = _base_server_config()
    monkeypatch.setattr(prov, "_read_config", lambda: copy.deepcopy(cfg))
    status = prov.detect_status()
    assert status["configured"] is True
    assert status["protocol"] == "shadowtls_ss"
    assert status["listen_port"] == 443
    assert status["clients_count"] == 1
    assert status["sni"] == "www.microsoft.com"


def test_add_client_updates_both_inbound_user_lists(monkeypatch) -> None:
    prov = ShadowTLSSSProvisioner(DummySSH())
    cfg = _base_server_config()
    writes: list[dict] = []
    restarts: list[bool] = []

    monkeypatch.setattr(prov, "_read_config", lambda: cfg)
    monkeypatch.setattr(prov, "_write_config", lambda payload: writes.append(copy.deepcopy(payload)))
    monkeypatch.setattr(prov, "_restart", lambda: restarts.append(True))
    monkeypatch.setattr(prov, "_public_ip", lambda: "1.2.3.4")

    monkeypatch.setattr(prov, "_random_b64", lambda _n: "USER2")

    result = prov.add_client("client2")
    assert result["name"] == "client2"
    assert writes
    assert restarts == [True]


def test_setup_reuses_existing_config_and_adds_fallback_ports(monkeypatch) -> None:
    prov = ShadowTLSSSProvisioner(DummySSH())
    cfg = _base_server_config()
    writes: list[dict] = []
    restarts: list[bool] = []

    monkeypatch.setattr(prov, "_ensure_prereqs", lambda: None)
    monkeypatch.setattr(prov, "_read_config", lambda: cfg)
    monkeypatch.setattr(prov, "_write_config", lambda payload: writes.append(copy.deepcopy(payload)))
    monkeypatch.setattr(prov, "_restart", lambda: restarts.append(True))
    monkeypatch.setattr(prov, "_ensure_firewall_port", lambda port: None)
    monkeypatch.setattr(prov, "_ensure_tcp_tuning", lambda: None)
    monkeypatch.setattr(prov, "_public_ip", lambda: "1.2.3.4")
    monkeypatch.setattr(prov, "_is_port_busy", lambda port: port == 443)

    result = prov.setup("client1", listen_port=443, sni="www.microsoft.com")
    assert result["listen_port"] == 443
    assert len(result["listen_ports"]) >= 2
    shadowtls_inbounds = [item for item in (cfg.get("inbounds") or []) if item.get("type") == "shadowtls"]
    assert len(shadowtls_inbounds) >= 2
    assert writes
    assert restarts == [True]
