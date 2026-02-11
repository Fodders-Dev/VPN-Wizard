from __future__ import annotations

from types import SimpleNamespace

from vpn_wizard.proxy import ProxyProvisioner


class DummySSH:
    def __init__(self) -> None:
        self.config = SimpleNamespace(host="1.2.3.4", password=None)

    def run(self, command: str, sudo: bool = False, check: bool = True) -> str:
        if "systemctl is-active xray" in command:
            return "active"
        if "x25519 -i" in command:
            return "Public key: PUB_FROM_PRIVATE"
        if "x25519" in command:
            return "Private key: PRIV\nPublic key: PUB"
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


def test_choose_free_port_uses_fallback_candidates(monkeypatch) -> None:
    prov = ProxyProvisioner(DummySSH())
    monkeypatch.setattr(prov, "_is_port_busy", lambda port: port in {443, 2053})
    assert prov.choose_free_port(443) == 2083
