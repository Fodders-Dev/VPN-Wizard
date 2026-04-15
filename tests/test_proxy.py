from __future__ import annotations

import copy
import json
from types import SimpleNamespace

from vpn_wizard.proxy import ProxyProvisioner, rewrite_vless_alternatives, rewrite_vless_endpoint


class DummySSH:
    def __init__(self) -> None:
        self.config = SimpleNamespace(host="1.2.3.4", password=None)

    def run(self, command: str, sudo: bool = False, check: bool = True) -> str:
        if "systemctl is-active xray" in command:
            return "active"
        if "x25519 -i" in command:
            return "PrivateKey: PRIV\nPassword: PUB_FROM_PRIVATE\nHash32: HASH"
        if "x25519" in command:
            return "PrivateKey: PRIV\nPassword: PUB\nHash32: HASH"
        return ""


def test_build_link_contains_required_reality_params() -> None:
    prov = ProxyProvisioner(DummySSH())
    link = prov._build_link(
        client_uuid="11111111-1111-1111-1111-111111111111",
        host="1.2.3.4",
        port=443,
        sni="www.cloudflare.com",
        public_key="PUBKEY",
        short_id="abcd1234abcd1234",
        path="/vpnw-xh-test",
        name="client1",
    )
    assert link.startswith("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?")
    assert "security=reality" in link
    assert "type=xhttp" in link
    assert "path=%2Fvpnw-xh-test" in link
    assert "pbk=PUBKEY" in link
    assert "sid=abcd1234abcd1234" in link
    assert "spx=" not in link
    assert link.endswith("#client1")


def test_rewrite_vless_endpoint_swaps_host_and_port() -> None:
    link = (
        "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
        "?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUB&sid=abcd&type=xhttp&path=%2Fvpnw#c1"
    )
    rewritten = rewrite_vless_endpoint(link, "relay.example.com", 7443)
    assert "@relay.example.com:7443?" in rewritten
    assert "sni=www.microsoft.com" in rewritten
    assert rewritten.endswith("#c1")


def test_rewrite_vless_alternatives_updates_every_link() -> None:
    alternatives = [
        {"sni": "www.microsoft.com", "fp": "chrome", "link": "vless://uuid@1.2.3.4:443?pbk=A&sid=B&type=xhttp#one"},
        {"sni": "www.apple.com", "fp": "safari", "link": "vless://uuid@1.2.3.4:443?pbk=A&sid=B&type=xhttp#two"},
    ]
    rewritten = rewrite_vless_alternatives(alternatives, "10.20.30.40", 9443)
    assert rewritten is not None
    assert all("@10.20.30.40:9443?" in item["link"] for item in rewritten)


def test_detect_status_reads_xray_shape(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())
    monkeypatch.setattr(
        prov,
        "_read_config",
        lambda: {
            "inbounds": [
                {
                    "port": 443,
                    "protocol": "vless",
                    "settings": {"clients": [{"email": "client1"}, {"email": "client2"}]},
                    "streamSettings": {
                        "security": "reality",
                        "realitySettings": {"serverNames": ["www.cloudflare.com"]},
                    },
                }
            ]
        },
    )
    status = prov.detect_status()
    assert status["configured"] is True
    assert status["protocol"] == "xray"
    assert status["listen_port"] == 443
    assert status["clients_count"] == 2
    assert status["sni"] == "www.cloudflare.com"


def test_validate_name_rejects_invalid_chars() -> None:
    prov = ProxyProvisioner(DummySSH())
    try:
        prov._validate_name("bad name")
    except RuntimeError as exc:
        assert "Proxy client name" in str(exc)
        return
    raise AssertionError("Expected RuntimeError for invalid client name")


def test_reality_key_parsers_use_xray_output() -> None:
    prov = ProxyProvisioner(DummySSH())
    private_key, public_key = prov._generate_reality_keypair()
    assert private_key == "PRIV"
    assert public_key == "PUB"
    assert prov._derive_public_key("PRIV") == "PUB_FROM_PRIVATE"


def test_reality_key_parsers_support_legacy_public_key(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())

    def fake_run(command: str, sudo: bool = False, check: bool = True) -> str:
        if "x25519 -i" in command:
            return "Public key: LEGACY_DERIVED"
        if "x25519" in command:
            return "Private key: LEGACY_PRIV\nPublic key: LEGACY_PUB"
        return ""

    monkeypatch.setattr(prov.ssh, "run", fake_run)
    private_key, public_key = prov._generate_reality_keypair()
    assert private_key == "LEGACY_PRIV"
    assert public_key == "LEGACY_PUB"
    assert prov._derive_public_key("LEGACY_PRIV") == "LEGACY_DERIVED"


def test_reality_key_parsers_support_equals_separator(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())

    def fake_run(command: str, sudo: bool = False, check: bool = True) -> str:
        if "x25519 -i" in command:
            return "PublicKey = EQUALS_DERIVED"
        if "x25519" in command:
            return "PrivateKey = EQUALS_PRIV\nPublicKey = EQUALS_PUB"
        return ""

    monkeypatch.setattr(prov.ssh, "run", fake_run)
    private_key, public_key = prov._generate_reality_keypair()
    assert private_key == "EQUALS_PRIV"
    assert public_key == "EQUALS_PUB"
    assert prov._derive_public_key("EQUALS_PRIV") == "EQUALS_DERIVED"


def test_reality_key_parsers_support_password_public_key_alias(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())

    def fake_run(command: str, sudo: bool = False, check: bool = True) -> str:
        if "x25519 -i" in command:
            return "Password (PublicKey): ALIAS_DERIVED"
        if "x25519" in command:
            return "PrivateKey: ALIAS_PRIV\nPassword (PublicKey): ALIAS_PUB\nHash32: HASH"
        return ""

    monkeypatch.setattr(prov.ssh, "run", fake_run)
    private_key, public_key = prov._generate_reality_keypair()
    assert private_key == "ALIAS_PRIV"
    assert public_key == "ALIAS_PUB"
    assert prov._derive_public_key("ALIAS_PRIV") == "ALIAS_DERIVED"


def test_choose_free_port_uses_fallback_candidates(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())
    monkeypatch.setattr(prov, "_is_port_busy", lambda port: port in {443, 2053})
    assert prov.choose_free_port(443) == 8443


def test_choose_best_sni_prefers_non_avoided_candidate_when_reachable(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())
    monkeypatch.setattr(prov, "_probe_sni", lambda host: host == "www.microsoft.com")
    selected = prov._choose_best_sni(None, "www.cloudflare.com")
    assert selected == "www.microsoft.com"


def test_choose_best_sni_keeps_existing_when_probes_fail(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())
    monkeypatch.setattr(prov, "_probe_sni", lambda host: False)
    selected = prov._choose_best_sni(None, "www.cloudflare.com")
    assert selected == "www.cloudflare.com"


def _base_reality_config() -> dict:
    return {
        "inbounds": [
            {
                "port": 2053,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {"id": "client-1-id", "email": "client1"}
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "reality",
                    "xhttpSettings": {"path": "/vpnw-xh-fixed"},
                    "sockopt": {
                        "tcpFastOpen": True,
                        "tcpKeepAliveIdle": 300,
                        "tcpKeepAliveInterval": 60,
                        "tcpUserTimeout": 30000,
                    },
                    "realitySettings": {
                        "target": "www.cloudflare.com:443",
                        "dest": "www.cloudflare.com:443",
                        "serverNames": ["www.cloudflare.com", "www.apple.com"],
                        "privateKey": "PRIVKEY",
                        "shortIds": ["sid-client-1"],
                    },
                },
            }
        ],
        "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}],
    }


def test_setup_reuses_existing_reality_without_rotating_keys(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())
    cfg = _base_reality_config()
    writes: list[dict] = []
    restarts: list[bool] = []

    monkeypatch.setattr(prov, "_ensure_prereqs", lambda: None)
    monkeypatch.setattr(prov, "_read_config", lambda: cfg)
    monkeypatch.setattr(prov, "_write_config", lambda payload: writes.append(copy.deepcopy(payload)))
    monkeypatch.setattr(prov, "_restart_xray", lambda: restarts.append(True))
    monkeypatch.setattr(prov, "_derive_public_key", lambda private: "PUBKEY")
    monkeypatch.setattr(prov, "_public_ip", lambda: "1.2.3.4")
    monkeypatch.setattr(
        prov,
        "_generate_reality_keypair",
        lambda: (_ for _ in ()).throw(AssertionError("must not generate new keys")),
    )

    result = prov.setup("client1", listen_port=2053, sni=None)
    assert result["listen_port"] == 2053
    assert result["sni"] == "www.cloudflare.com"
    assert "sid=sid-client-1" in result["link"]
    assert "pbk=PUBKEY" in result["link"]
    assert "type=xhttp" in result["link"]
    assert not writes
    assert not restarts


def test_setup_adds_client_to_existing_reality_config(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())
    cfg = _base_reality_config()
    writes: list[dict] = []
    restarts: list[bool] = []

    monkeypatch.setattr(prov, "_ensure_prereqs", lambda: None)
    monkeypatch.setattr(prov, "_read_config", lambda: cfg)
    monkeypatch.setattr(prov, "_write_config", lambda payload: writes.append(copy.deepcopy(payload)))
    monkeypatch.setattr(prov, "_restart_xray", lambda: restarts.append(True))
    monkeypatch.setattr(prov, "_derive_public_key", lambda private: "PUBKEY")
    monkeypatch.setattr(prov, "_public_ip", lambda: "1.2.3.4")
    monkeypatch.setattr(
        prov,
        "_generate_reality_keypair",
        lambda: (_ for _ in ()).throw(AssertionError("must not generate new keys")),
    )

    result = prov.setup("client2", listen_port=2053, sni="www.cloudflare.com")
    assert result["listen_port"] == 2053
    assert len(cfg["inbounds"][0]["settings"]["clients"]) == 2
    assert len(cfg["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"]) == 2
    assert writes
    assert restarts == [True]


def test_setup_initial_config_uses_ipv4_domain_strategy(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())
    writes: list[dict] = []

    monkeypatch.setattr(prov, "_ensure_prereqs", lambda: None)
    monkeypatch.setattr(prov, "_read_config", lambda: None)
    monkeypatch.setattr(prov, "_write_config", lambda payload: writes.append(copy.deepcopy(payload)))
    monkeypatch.setattr(prov, "_restart_xray", lambda: None)
    monkeypatch.setattr(prov, "_ensure_firewall_port", lambda port: None)
    monkeypatch.setattr(prov, "_ensure_tcp_tuning", lambda: None)
    monkeypatch.setattr(prov, "_public_ip", lambda: "1.2.3.4")
    monkeypatch.setattr(prov, "_choose_best_sni", lambda preferred, existing: "www.microsoft.com")
    monkeypatch.setattr(prov, "_generate_reality_keypair", lambda: ("PRIV", "PUB"))

    result = prov.setup("client1", listen_port=443)
    assert result["listen_port"] == 443
    assert writes
    outbounds = writes[0].get("outbounds") or []
    assert isinstance(outbounds, list)
    assert outbounds and outbounds[0].get("protocol") == "freedom"
    assert outbounds[0].get("settings", {}).get("domainStrategy") == "UseIPv4"
    stream = writes[0]["inbounds"][0]["streamSettings"]
    assert stream.get("network") == "xhttp"
    assert (stream.get("xhttpSettings") or {}).get("path")


def test_singbox_auto_config_keeps_udp_enabled_and_sets_xudp_packet_encoding() -> None:
    prov = ProxyProvisioner(DummySSH())
    link = (
        "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:2083"
        "?encryption=none&security=reality"
        "&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=abcd1234abcd1234&type=xhttp&path=%2Fvpnw-xh-test#client1"
    )
    cfg = json.loads(prov.build_singbox_auto_config(primary_link=link, alternatives=None, include_tun=True))

    # Ensure QUIC is blocked (avoids slow page loads when HTTP/3 is flaky)
    route_rules = (cfg.get("route") or {}).get("rules") or []
    assert any(rule.get("protocol") == ["quic"] and rule.get("outbound") == "block" for rule in route_rules)
    assert any(rule.get("network") == ["udp"] and rule.get("port") == [443] and rule.get("outbound") == "block" for rule in route_rules)

    outbounds = cfg.get("outbounds") or []
    vless_outbounds = [o for o in outbounds if o.get("type") == "vless"]
    assert vless_outbounds, "Expected vless outbounds in sing-box auto config"
    for o in vless_outbounds:
        # Must not force TCP-only; otherwise UDP is disabled in sing-box.
        assert o.get("network") != "tcp"
        assert o.get("packet_encoding") == "xudp"
        assert (o.get("transport") or {}).get("type") == "xhttp"
        assert (o.get("transport") or {}).get("path") == "/vpnw-xh-test"

    # Default: route should be pinned to a selector tagged "proxy".
    selector = next((o for o in outbounds if o.get("type") == "selector"), None)
    assert selector and selector.get("tag") == "proxy"
    assert (cfg.get("route") or {}).get("final") == "proxy"
    dns = cfg.get("dns") or {}
    doh = next((item for item in (dns.get("servers") or []) if item.get("tag") == "doh"), {})
    assert doh.get("detour") == "proxy"

    # Optional: urltest can be enabled via env; if present, it must not use Google endpoints.
    urltest = next((o for o in outbounds if o.get("type") == "urltest"), None)
    if urltest:
        assert urltest.get("tag") == "auto"
        assert "msftconnecttest" in (urltest.get("url") or "")
