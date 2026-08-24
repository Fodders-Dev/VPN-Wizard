from __future__ import annotations

from pathlib import Path

import pytest

from vpn_wizard.account import AccountStore
from vpn_wizard.awg_devices import (
    FAMILY_SLOT,
    collect_usage,
    config_address,
    default_label,
    list_devices,
    parse_awg_show,
    parse_handshake_age,
    revoke_device,
    slot_of_peer,
)
from vpn_wizard.awg_fallback import device_peer_id, family_guest_id


OWNER = 449066726


def _store(tmp_path: Path) -> AccountStore:
    return AccountStore(tmp_path / "state.db", secret_key="unit-test-secret")


# --- parsing what the exits report --------------------------------------------

AWG_SHOW = """interface: awg0
  public key: serverkey
  listening port: 443

peer: aaa=
  endpoint: 1.2.3.4:51820
  allowed ips: 10.10.0.5/32
  latest handshake: 1 minute, 20 seconds ago
  transfer: 49.00 MiB received, 2.47 GiB sent

peer: bbb=
  allowed ips: 10.10.0.9/32

peer: ccc=
  allowed ips: 10.10.0.12/32
  latest handshake: 1 day, 7 hours, 23 minutes, 55 seconds ago
  transfer: 564 B received, 6.92 KiB sent
"""


def test_parse_awg_show_extracts_last_seen_and_traffic() -> None:
    parsed = parse_awg_show(AWG_SHOW)
    assert set(parsed) == {"10.10.0.5", "10.10.0.9", "10.10.0.12"}

    busy = parsed["10.10.0.5"]
    assert busy["last_handshake_age"] == 80
    assert busy["rx_bytes"] == 49 * 1024**2
    assert busy["tx_bytes"] == int(2.47 * 1024**3)

    # A provisioned but never-connected peer must read as "never", not as zero
    # seconds ago — that difference is the whole point of the screen.
    assert parsed["10.10.0.9"]["last_handshake_age"] is None
    assert parsed["10.10.0.9"]["rx_bytes"] == 0

    stale = parsed["10.10.0.12"]
    assert stale["last_handshake_age"] == 86400 + 7 * 3600 + 23 * 60 + 55


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Now", 0),
        ("8 seconds ago", 8),
        ("2 minutes, 5 seconds ago", 125),
        ("3 hours ago", 10800),
        ("", None),
        ("never", None),
    ],
)
def test_parse_handshake_age(text, expected) -> None:
    assert parse_handshake_age(text) == expected


def test_config_address_reads_the_tunnel_ip() -> None:
    config = "# Fodder VPN\n[Interface]\nPrivateKey = x\nAddress = 10.10.0.12/32\nMTU = 1280\n"
    assert config_address(config) == "10.10.0.12"
    assert config_address(None) is None
    assert config_address("[Interface]\nPrivateKey = x\n") is None


# --- slot identity --------------------------------------------------------------

def test_slot_of_peer_round_trips_every_slot() -> None:
    assert slot_of_peer(OWNER, OWNER) == 1
    assert slot_of_peer(family_guest_id(OWNER), OWNER) == FAMILY_SLOT
    for slot in (3, 4, 5, 12):
        assert slot_of_peer(device_peer_id(OWNER, slot), OWNER) == slot
    # Someone else's peers must never be attributed to this owner.
    assert slot_of_peer(device_peer_id(123456, 3), OWNER) is None
    assert slot_of_peer(999, OWNER) is None


def test_default_label_names_the_family_slot_distinctly() -> None:
    assert default_label(1, False) == "Устройство 1"
    assert default_label(FAMILY_SLOT, True) == "Для близкого"


# --- the list a subscriber sees ---------------------------------------------------

def _issue(store: AccountStore, peer_id: int, server_id: str | None, address: str, status="active"):
    config = f"[Interface]\nPrivateKey = k\nAddress = {address}/32\n"
    if server_id is None:
        store.awg_save_peer(peer_id, client_name=f"sub-{peer_id}", remnawave_uuid=None,
                            config=config, status=status)
    else:
        store.awg_save_server_peer(peer_id, server_id, client_name=f"sub-{peer_id}-{server_id}",
                                   remnawave_uuid=None, config=config, status=status)


def test_list_devices_shows_every_paid_slot_even_when_unused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    devices = list_devices(store, OWNER, device_limit=3, legacy_server_id="nl")
    assert [device.slot for device in devices] == [1, 2, 3]
    assert all(not device.used for device in devices)
    assert devices[1].label == "Для близкого"


def test_list_devices_groups_countries_and_usage_per_slot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, None, "10.10.0.5")            # slot 1 on the default exit
    _issue(store, OWNER, "fi", "10.20.0.5")            # same slot, second country
    _issue(store, family_guest_id(OWNER), "fi", "10.20.0.9", status="suspended")

    store.awg_record_usage("nl", OWNER, last_handshake_at=1000, rx_bytes=100, tx_bytes=200)
    store.awg_record_usage("fi", OWNER, last_handshake_at=5000, rx_bytes=1, tx_bytes=2)

    devices = list_devices(store, OWNER, device_limit=3, legacy_server_id="nl")
    first = devices[0]
    assert sorted(first.servers) == ["fi", "nl"]
    assert first.total_bytes == 303
    assert first.last_seen_at == 5000       # most recent across countries wins

    family = devices[1]
    assert family.is_family
    assert family.suspended_servers == ["fi"]
    assert family.servers == []


def test_list_devices_still_shows_slots_left_over_after_a_downgrade(tmp_path: Path) -> None:
    # Dropping to a smaller plan must not hide a key that is still out there.
    store = _store(tmp_path)
    _issue(store, device_peer_id(OWNER, 5), "fi", "10.20.0.30")
    devices = list_devices(store, OWNER, device_limit=1, legacy_server_id="nl")
    assert [d.slot for d in devices] == [1, 5]
    assert devices[1].servers == ["fi"]


def test_list_devices_ignores_other_subscribers(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, 7938373718, None, "10.10.0.77")
    devices = list_devices(store, OWNER, device_limit=2, legacy_server_id="nl")
    assert all(not device.used for device in devices)


# --- usage collection -------------------------------------------------------------

def test_collect_usage_matches_peers_by_tunnel_address(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, None, "10.10.0.5")
    _issue(store, family_guest_id(OWNER), None, "10.10.0.9")

    written = collect_usage(store, "nl", store.awg_list_peers(), AWG_SHOW, now=10_000)
    assert written == 2

    usage = store.awg_get_usage([OWNER, family_guest_id(OWNER)])
    assert usage[("nl", OWNER)]["last_handshake_at"] == 10_000 - 80
    assert usage[("nl", OWNER)]["rx_bytes"] == 49 * 1024**2
    # Never connected -> no timestamp, rather than "connected at epoch".
    assert usage[("nl", family_guest_id(OWNER))]["last_handshake_at"] is None


def test_collect_usage_skips_peers_absent_from_the_interface(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, None, "10.99.99.99")
    assert collect_usage(store, "nl", store.awg_list_peers(), AWG_SHOW, now=1) == 0


# --- naming -----------------------------------------------------------------------

def test_labels_belong_to_the_slot_not_the_country(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, None, "10.10.0.5")
    _issue(store, OWNER, "fi", "10.20.0.5")
    store.awg_set_device_label(OWNER, 1, "  Мамин телефон  ")

    devices = list_devices(store, OWNER, device_limit=2, legacy_server_id="nl")
    assert devices[0].label == "Мамин телефон"      # one rename, both countries
    assert sorted(devices[0].servers) == ["fi", "nl"]

    store.awg_set_device_label(OWNER, 1, "   ")      # cleared -> back to default
    assert list_devices(store, OWNER, 2, legacy_server_id="nl")[0].label == "Устройство 1"


def test_label_is_capped_and_scoped_to_its_owner(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.awg_set_device_label(OWNER, 1, "x" * 200)
    assert len(store.awg_get_device_labels(OWNER)[1]) == 40
    assert store.awg_get_device_labels(7938373718) == {}


# --- revoking ---------------------------------------------------------------------

class _Service:
    def __init__(self, server_id, revoked, fail=False):
        self.server_id = server_id
        self._revoked = revoked
        self._fail = fail

    def revoke(self, peer_id: int) -> bool:
        if self._fail:
            raise RuntimeError("exit unreachable")
        self._revoked.append((self.server_id, peer_id))
        return True


def test_revoke_device_kills_the_slot_on_every_exit() -> None:
    revoked: list[tuple[str, int]] = []
    services = [_Service("nl", revoked), _Service("fi", revoked)]
    assert revoke_device(OWNER, 3, services) == 2
    expected = device_peer_id(OWNER, 3)
    assert revoked == [("nl", expected), ("fi", expected)]


def test_revoke_device_survives_one_dead_exit() -> None:
    revoked: list[tuple[str, int]] = []
    errors: list[str] = []
    services = [_Service("nl", revoked, fail=True), _Service("fi", revoked)]
    removed = revoke_device(OWNER, 1, services, on_error=lambda s, e: errors.append(s.server_id))
    # The reachable exit is still cleaned up; the failure is reported, not swallowed.
    assert removed == 1
    assert revoked == [("fi", OWNER)]
    assert errors == ["nl"]


# --- the periodic refresh ---------------------------------------------------------

def test_refresh_usage_reads_each_exit_once(tmp_path: Path) -> None:
    from vpn_wizard.awg_reconcile import refresh_usage

    store = _store(tmp_path)
    _issue(store, OWNER, None, "10.10.0.5")          # default exit
    _issue(store, OWNER, "fi", "10.10.0.12")         # second exit

    class Registry:
        default_server = type("S", (), {"id": "nl"})()

    reads: list[str] = []

    def fake_read(service):
        reads.append(service.server_id)
        return AWG_SHOW

    legacy = type("L", (), {"server_id": "nl"})()
    services = {"fi": type("F", (), {"server_id": "fi"})()}
    rows = refresh_usage(store, legacy, services, Registry(), read=fake_read)

    assert rows == 2
    assert reads == ["nl", "fi"]
    usage = store.awg_get_usage([OWNER])
    assert usage[("nl", OWNER)]["rx_bytes"] == 49 * 1024**2
    assert usage[("fi", OWNER)]["last_handshake_at"] is not None


def test_refresh_usage_survives_an_unreachable_exit(tmp_path: Path) -> None:
    from vpn_wizard.awg_reconcile import refresh_usage

    store = _store(tmp_path)
    _issue(store, OWNER, None, "10.10.0.5")
    _issue(store, OWNER, "fi", "10.10.0.12")

    class Registry:
        default_server = type("S", (), {"id": "nl"})()

    def fake_read(service):
        if service.server_id == "nl":
            raise RuntimeError("ssh timeout")
        return AWG_SHOW

    legacy = type("L", (), {"server_id": "nl"})()
    services = {"fi": type("F", (), {"server_id": "fi"})()}
    # The healthy exit is still refreshed.
    assert refresh_usage(store, legacy, services, Registry(), read=fake_read) == 1


# --- измерение подключений переживает перезапуск интерфейса --------------------

def test_interface_restart_does_not_erase_that_a_peer_ever_connected(tmp_path: Path) -> None:
    """AmneziaWG забывает хендшейки при рестарте интерфейса, а выдача профиля
    его перезапускает. Из-за этого «последний раз» обнулялся у всех, стоило
    кому-то одному получить профиль, и статистика показывала горстку живых
    вместо реальной картины."""
    store = _store(tmp_path)
    _issue(store, OWNER, "nl", "10.10.0.5")

    store.awg_record_usage("nl", OWNER, last_handshake_at=1000, rx_bytes=10, tx_bytes=20)
    # Кто-то другой получил профиль → awg-quick перезапущен → wg рапортует "never".
    store.awg_record_usage("nl", OWNER, last_handshake_at=None, rx_bytes=0, tx_bytes=0)

    row = store.awg_get_usage([OWNER])[("nl", OWNER)]
    assert row["last_handshake_at"] == 1000, "последний раз не должен стираться"
    assert row["first_handshake_at"] == 1000, "факт подключения запоминается навсегда"

    # Человек снова включил VPN — «последний раз» двигается вперёд, «впервые» нет.
    store.awg_record_usage("nl", OWNER, last_handshake_at=9000, rx_bytes=5, tx_bytes=5)
    row = store.awg_get_usage([OWNER])[("nl", OWNER)]
    assert row["last_handshake_at"] == 9000
    assert row["first_handshake_at"] == 1000


def test_a_peer_that_never_connected_stays_empty(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, "nl", "10.10.0.5")
    store.awg_record_usage("nl", OWNER, last_handshake_at=None, rx_bytes=0, tx_bytes=0)

    row = store.awg_get_usage([OWNER])[("nl", OWNER)]
    assert row["last_handshake_at"] is None
    assert row["first_handshake_at"] is None
