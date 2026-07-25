from __future__ import annotations

import json

import pytest

from vpn_wizard.awg_servers import (
    DEFAULT_PRESETS,
    INTERFACE_WIDE_PARAMS,
    PER_CLIENT_PARAMS,
    AwgRegistry,
    AwgRegistryError,
    AwgServer,
)


_ENV_VARS = (
    "VPNW_AWG_SERVERS",
    "VPNW_AWG_PRESETS",
    "VPNW_AWG_DEFAULT_SERVER",
    "VPNW_AWG_FALLBACK_HOST",
    "VPNW_AWG_FALLBACK_ID",
    "VPNW_AWG_FALLBACK_LABEL",
    "VPNW_AWG_FALLBACK_FLAG",
    "VPNW_AWG_FALLBACK_SSH_USER",
    "VPNW_AWG_FALLBACK_SSH_PORT",
    "VPNW_AWG_FALLBACK_SSH_PASSWORD",
    "VPNW_AWG_FALLBACK_SSH_KEY",
    "VPNW_AWG_FALLBACK_SSH_KEY_CONTENT",
    "VPNW_AWG_FALLBACK_LISTEN_PORT",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _servers_json(*entries: dict) -> str:
    return json.dumps(list(entries))


# --- legacy single-server compatibility ---------------------------------------

def test_legacy_env_yields_one_server(monkeypatch: pytest.MonkeyPatch) -> None:
    # An existing deployment has no VPNW_AWG_SERVERS. It must keep working, and
    # its already-issued configs must keep resolving to the same machine.
    monkeypatch.setenv("VPNW_AWG_FALLBACK_HOST", "212.69.84.167")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_SSH_PASSWORD", "hunter2")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_LISTEN_PORT", "443")

    registry = AwgRegistry.from_env()

    assert registry.configured is True
    assert [s.id for s in registry.servers] == ["main"]
    assert registry.default_server.host == "212.69.84.167"
    assert registry.default_server.listen_port == 443
    assert registry.default_server.user == "root"  # documented default


def test_no_configuration_at_all_is_not_configured() -> None:
    registry = AwgRegistry.from_env()
    assert registry.servers == ()
    assert registry.configured is False
    assert registry.default_server is None


def test_legacy_server_without_credentials_is_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VPNW_AWG_FALLBACK_HOST", "10.0.0.1")
    registry = AwgRegistry.from_env()
    assert registry.servers[0].usable is False
    assert registry.configured is False


# --- multi-server registry -----------------------------------------------------

def test_json_registry_parses_all_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        _servers_json(
            {"id": "nl", "label": "Нидерланды", "flag": "🇳🇱", "host": "1.1.1.1", "password": "p", "listen_port": 443},
            {"id": "fi", "label": "Финляндия", "flag": "🇫🇮", "host": "2.2.2.2", "password": "p"},
            {"id": "tr", "label": "Турция", "flag": "🇹🇷", "host": "3.3.3.3", "password": "p"},
            {"id": "us", "label": "США", "flag": "🇺🇸", "host": "4.4.4.4", "password": "p"},
        ),
    )
    registry = AwgRegistry.from_env()

    assert [s.id for s in registry.servers] == ["nl", "fi", "tr", "us"]
    assert registry.get_server("fi").host == "2.2.2.2"
    assert registry.get_server("FI").host == "2.2.2.2"  # ids are case-insensitive
    assert registry.get_server("tr").display == "🇹🇷 Турция"


def test_unknown_server_id_is_rejected_not_silently_defaulted(monkeypatch: pytest.MonkeyPatch) -> None:
    # A typo must surface, not quietly hand the user a different country.
    monkeypatch.setenv("VPNW_AWG_SERVERS", _servers_json({"id": "nl", "host": "1.1.1.1", "password": "p"}))
    registry = AwgRegistry.from_env()
    assert registry.get_server("de") is None
    assert registry.get_server("") is registry.default_server  # omitted -> default


def test_default_server_prefers_explicit_then_first(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = _servers_json(
        {"id": "nl", "host": "1.1.1.1", "password": "p"},
        {"id": "fi", "host": "2.2.2.2", "password": "p"},
    )
    monkeypatch.setenv("VPNW_AWG_SERVERS", entries)
    assert AwgRegistry.from_env().default_server.id == "nl"  # first wins by default

    monkeypatch.setenv("VPNW_AWG_DEFAULT_SERVER", "fi")
    assert AwgRegistry.from_env().default_server.id == "fi"

    # A bogus default must not blow up the whole service — fall back to first.
    monkeypatch.setenv("VPNW_AWG_DEFAULT_SERVER", "nope")
    assert AwgRegistry.from_env().default_server.id == "nl"


def test_duplicate_and_malformed_ids_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        _servers_json({"id": "nl", "host": "1.1.1.1"}, {"id": "nl", "host": "2.2.2.2"}),
    )
    with pytest.raises(AwgRegistryError, match="Duplicate"):
        AwgRegistry.from_env()

    # Ids land in filenames and URLs, so keep them boring.
    monkeypatch.setenv("VPNW_AWG_SERVERS", _servers_json({"id": "nl/../etc", "host": "1.1.1.1"}))
    with pytest.raises(AwgRegistryError, match="Invalid server id"):
        AwgRegistry.from_env()


def test_server_without_host_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VPNW_AWG_SERVERS", _servers_json({"id": "nl"}))
    with pytest.raises(AwgRegistryError, match="no host"):
        AwgRegistry.from_env()


def test_malformed_json_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VPNW_AWG_SERVERS", "{not json")
    with pytest.raises(AwgRegistryError, match="not valid JSON"):
        AwgRegistry.from_env()

    monkeypatch.setenv("VPNW_AWG_SERVERS", '{"id": "nl"}')
    with pytest.raises(AwgRegistryError, match="list of objects"):
        AwgRegistry.from_env()


# --- presets -------------------------------------------------------------------

def test_default_presets_start_with_plain_profile() -> None:
    registry = AwgRegistry.from_env()
    assert registry.presets == DEFAULT_PRESETS
    assert registry.presets[0].id == "default"
    assert registry.presets[0].overrides == {}  # plain profile pins nothing
    assert registry.get_preset(None).id == "default"


def test_preset_overrides_only_include_pinned_params() -> None:
    registry = AwgRegistry.from_env()
    mts = registry.get_preset("mts")
    assert mts.overrides == {"jc": 3, "i1": "<r 48>"}
    assert "jmin" not in mts.overrides  # unset -> keep the server default

    megafon = registry.get_preset("megafon")
    assert megafon.overrides == {"jc": 3, "jmin": 80, "jmax": 268}
    assert "i1" not in megafon.overrides  # Megafon blocks the CPS packet


def test_unknown_preset_is_rejected() -> None:
    assert AwgRegistry.from_env().get_preset("beeline-xyz") is None


def test_builtin_presets_only_touch_per_client_safe_params() -> None:
    # S1-S4/H1-H4 are per-device and enforced on receive by exact packet size and
    # header range. A preset that varied one would be dropped before any crypto
    # runs, so the user sees a dead server with no error anywhere.
    for preset in DEFAULT_PRESETS:
        assert set(preset.overrides).issubset(PER_CLIENT_PARAMS), preset.id
        assert not INTERFACE_WIDE_PARAMS.intersection(preset.overrides), preset.id


@pytest.mark.parametrize("param", sorted(INTERFACE_WIDE_PARAMS))
def test_preset_with_interface_wide_param_is_refused(
    monkeypatch: pytest.MonkeyPatch, param: str
) -> None:
    monkeypatch.setenv(
        "VPNW_AWG_PRESETS",
        json.dumps([{"id": "bad", "label": "Bad", param: 100}]),
    )
    with pytest.raises(AwgRegistryError, match="interface-wide"):
        AwgRegistry.from_env()


def test_preset_supports_all_five_signature_packets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "VPNW_AWG_PRESETS",
        json.dumps([{"id": "mimic", "label": "Mimic", "i1": "<r 48>", "i5": "<t>"}]),
    )
    preset = AwgRegistry.from_env().get_preset("mimic")
    assert preset.overrides == {"i1": "<r 48>", "i5": "<t>"}


def test_preset_drops_blank_signature_packets(monkeypatch: pytest.MonkeyPatch) -> None:
    # awg-quick strips empty I-keys and then fails at `awg setconf`, so a blank
    # value must never reach the rendered config.
    monkeypatch.setenv(
        "VPNW_AWG_PRESETS",
        json.dumps([{"id": "blank", "label": "Blank", "i1": "", "i2": "   ", "jc": 3}]),
    )
    assert AwgRegistry.from_env().get_preset("blank").overrides == {"jc": 3}


def test_custom_presets_replace_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VPNW_AWG_PRESETS", json.dumps([{"id": "plain", "label": "Plain"}]))
    registry = AwgRegistry.from_env()
    assert [p.id for p in registry.presets] == ["plain"]
    assert registry.get_preset(None).id == "plain"


# --- what we hand to the bot / website -----------------------------------------

def test_public_payload_never_leaks_hosts_or_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        _servers_json(
            {"id": "nl", "label": "Нидерланды", "flag": "🇳🇱", "host": "212.69.84.167",
             "user": "root", "password": "hunter2", "listen_port": 443},
            {"id": "fi", "label": "Финляндия", "flag": "🇫🇮", "host": "2.2.2.2",
             "key_content": "-----BEGIN OPENSSH PRIVATE KEY-----"},
        ),
    )
    payload = AwgRegistry.from_env().public()
    blob = json.dumps(payload, ensure_ascii=False)

    for secret in ("212.69.84.167", "hunter2", "root", "2.2.2.2", "BEGIN OPENSSH"):
        assert secret not in blob, f"{secret!r} leaked into the public payload"

    assert [s["id"] for s in payload["servers"]] == ["nl", "fi"]
    assert payload["servers"][0]["display"] == "🇳🇱 Нидерланды"
    assert payload["default_server"] == "nl"
    assert payload["default_preset"] == "default"


def test_public_payload_hides_servers_missing_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    # A half-configured box must not be offered to users as a choice.
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        _servers_json(
            {"id": "nl", "host": "1.1.1.1", "password": "p"},
            {"id": "us", "host": "4.4.4.4"},  # no credential yet
        ),
    )
    payload = AwgRegistry.from_env().public()
    assert [s["id"] for s in payload["servers"]] == ["nl"]


def test_server_from_dict_defaults() -> None:
    server = AwgServer.from_dict({"id": "us", "host": "4.4.4.4", "password": "p"})
    assert server.user == "root"
    assert server.port == 22
    assert server.listen_port is None  # provisioner picks its own default
    # An unlabelled server falls back to its id, NEVER its host: /api/awg/servers
    # is unauthenticated, so a missing label must not publish the IP.
    assert server.label == "us"
    assert server.display == "us"
    assert "4.4.4.4" not in json.dumps(server.public())


def test_unlabelled_servers_never_publish_their_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        _servers_json({"id": "nl", "host": "212.69.84.167", "password": "p"}),
    )
    assert "212.69.84.167" not in json.dumps(AwgRegistry.from_env().public())

    # ...and the same for the legacy single-server path.
    monkeypatch.delenv("VPNW_AWG_SERVERS")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_HOST", "212.69.84.167")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_SSH_PASSWORD", "p")
    registry = AwgRegistry.from_env()
    assert registry.default_server.label == "main"
    assert "212.69.84.167" not in json.dumps(registry.public())


# --- applying an operator preset to a client config -------------------------------

from vpn_wizard.awg_servers import apply_preset  # noqa: E402

BASE_CONFIG = """# Fodder VPN — 🇳🇱 Нидерланды
# server: nl
[Interface]
PrivateKey = secret
Address = 10.10.0.5/32
DNS = 1.1.1.1
MTU = 1280
Jc = 2
Jmin = 40
Jmax = 70
S1 = 65
S2 = 130
H1 = 1949841359

[Peer]
PublicKey = serverkey
Endpoint = 1.2.3.4:443
AllowedIPs = 0.0.0.0/0
"""


def _values(config: str) -> dict:
    out = {}
    for line in config.splitlines():
        if "=" in line and not line.strip().startswith("#") and not line.startswith("["):
            key, value = line.split("=", 1)
            out[key.strip().lower()] = value.strip()
    return out


def test_preset_rewrites_only_the_sender_side_knobs() -> None:
    registry = AwgRegistry.from_env()
    applied = apply_preset(BASE_CONFIG, registry.get_preset("mts"))
    values = _values(applied)

    assert values["jc"] == "3"          # pinned by the preset
    assert values["i1"] == "<r 48>"     # signature packet added
    # Interface-wide parameters must survive untouched, or the tunnel silently
    # stops handshaking: they are matched byte-for-byte against the server.
    assert values["s1"] == "65"
    assert values["s2"] == "130"
    assert values["h1"] == "1949841359"
    # Everything else is preserved.
    assert values["privatekey"] == "secret"
    assert values["mtu"] == "1280"
    assert values["endpoint"] == "1.2.3.4:443"


def test_preset_replaces_in_place_and_keeps_the_peer_section_intact() -> None:
    registry = AwgRegistry.from_env()
    applied = apply_preset(BASE_CONFIG, registry.get_preset("megafon"))
    values = _values(applied)
    assert (values["jc"], values["jmin"], values["jmax"]) == ("3", "80", "268")
    # Megafon's CPS packet triggers blocks, so this preset must add no I1 at all.
    assert "i1" not in values
    # The added keys must land in [Interface], never after [Peer].
    interface, peer = applied.split("[Peer]")
    assert "Jmax" in interface and "Jmax" not in peer
    assert applied.count("[Peer]") == 1


def test_default_preset_and_none_leave_the_config_byte_identical() -> None:
    registry = AwgRegistry.from_env()
    assert apply_preset(BASE_CONFIG, registry.get_preset("default")) == BASE_CONFIG
    assert apply_preset(BASE_CONFIG, None) == BASE_CONFIG


def test_preset_adds_missing_parameters_without_duplicating_them() -> None:
    bare = "[Interface]\nPrivateKey = k\nAddress = 10.10.0.5/32\n\n[Peer]\nPublicKey = s\n"
    registry = AwgRegistry.from_env()
    applied = apply_preset(bare, registry.get_preset("tele2"))
    assert applied.count("Jc =") == 1
    assert applied.count("I1 =") == 1
    values = _values(applied)
    assert values["jc"] == "3" and values["jmax"] == "70" and values["i1"] == "<r 48>"
