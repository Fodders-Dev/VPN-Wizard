"""Presentation promotion must not move old users onto another key/interface."""
import importlib.util
import json
from pathlib import Path

import pytest

from vpn_wizard.awg_servers import AwgRegistry


path = Path(__file__).resolve().parents[1] / "deploy/scripts/prefer-nl-3478.py"
spec = importlib.util.spec_from_file_location("prefer_nl", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def environment() -> str:
    return "VPNW_AWG_DEFAULT_SERVER=nl\nVPNW_AWG_FALLBACK_LISTEN_PORT=443\nOTHER_SECRET=fixture\nVPNW_AWG_SERVERS='" + json.dumps([
        {"id": "nl", "host": "127.0.0.1", "listen_port": 443, "key_path": "fixture"},
        {"id": "nl-alt", "host": "127.0.0.1", "listen_port": 3478,
         "key_path": "fixture", "alt_port": True, "alt_of": "nl"},
        {"id": "us", "host": "example.test", "listen_port": 3478, "key_path": "fixture"},
    ]) + "'\n"


def test_promote_existing_port_is_idempotent_and_preserves_legacy(monkeypatch):
    original = environment()
    updated = module.promote(original)
    assert module.promote(updated) == updated
    assert updated.split("VPNW_AWG_SERVERS=")[0] == original.split("VPNW_AWG_SERVERS=")[0]
    raw = updated.split("VPNW_AWG_SERVERS=", 1)[1].strip().strip("'")
    monkeypatch.setenv("VPNW_AWG_SERVERS", raw)
    monkeypatch.setenv("VPNW_AWG_DEFAULT_SERVER", "nl")
    registry = AwgRegistry.from_env()
    assert registry.default_server.id == "nl"
    assert registry.default_server.listen_port == 443
    primary = registry.servers[0]
    assert primary.id == "nl-alt" and primary.listen_port == 3478
    assert not primary.alt_port and primary.alt_of is None
    assert registry.get_server("nl").alt_of == "nl-alt"
    assert registry.get_server("nl").alt_port is True
    before = {n["id"]: n for n in json.loads(original.split("VPNW_AWG_SERVERS=", 1)[1].strip().strip("'"))}
    for node in json.loads(raw):
        assert {k: v for k, v in node.items() if k not in {"alt_port", "alt_of"}} == {
            k: v for k, v in before[node["id"]].items() if k not in {"alt_port", "alt_of"}}


@pytest.mark.parametrize("replacement", ["4500", "null"])
def test_wrong_existing_port_is_rejected(replacement):
    with pytest.raises(ValueError):
        module.promote(environment().replace('"listen_port": 3478', '"listen_port": ' + replacement))


@pytest.mark.parametrize("default", ["", "VPNW_AWG_DEFAULT_SERVER=nl-alt\n"])
def test_implicit_or_different_storage_default_is_rejected(default):
    with pytest.raises(ValueError):
        module.promote(environment().replace("VPNW_AWG_DEFAULT_SERVER=nl\n", default))
