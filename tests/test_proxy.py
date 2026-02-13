from __future__ import annotations

import copy
from types import SimpleNamespace

from vpn_wizard.proxy import ProxyProvisioner


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
        name="client1",
    )
    assert link.startswith("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?")
    assert "security=reality" in link
    assert "flow=xtls-rprx-vision" in link
    assert "pbk=PUBKEY" in link
    assert "sid=abcd1234abcd1234" in link
    assert link.endswith("#client1")


def test_detect_status_reads_vless_reality_shape(monkeypatch) -> None:
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
    assert status["protocol"] == "vless_reality"
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
                        {"id": "client-1-id", "flow": "xtls-rprx-vision", "email": "client1"}
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "www.cloudflare.com:443",
                        "serverNames": ["www.cloudflare.com", "www.apple.com"],
                        "privateKey": "PRIVKEY",
                        "shortIds": ["sid-client-1"],
                    },
                },
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
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
