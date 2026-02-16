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
            handshake_sni="www.microsoft.com",
            server_password="SERVERPASS",
            user_password="USER1",
        )
    )
    outbounds = cfg.get("outbounds") or []
    ss = next((o for o in outbounds if o.get("type") == "shadowsocks"), None)
    st = next((o for o in outbounds if o.get("type") == "shadowtls"), None)
    assert ss and st
    assert ss.get("detour") == "st-out"
    assert ss.get("server") == "1.2.3.4"
    assert ss.get("server_port") == 443
    assert ss.get("password") == "SERVERPASS:USER1"
    assert st.get("server") == "1.2.3.4"
    assert st.get("server_port") == 443
    assert st.get("password") == "USER1"
    assert (st.get("tls") or {}).get("server_name") == "www.microsoft.com"

    # RU defaults: block IPv6 and QUIC/UDP443 inside tunnel.
    rules = (cfg.get("route") or {}).get("rules") or []
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
