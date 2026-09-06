"""A fallback for people whose network will not carry the tunnel on UDP 443.

A friend on Rostelecom in Tyumen could not get the VPN up on his router until
the port moved to 3478 — that is STUN, and a provider who blocks it breaks
video calls for its own subscribers, so it tends to be left alone. UDP 443 is
QUIC and gets meddled with far more.

Of 108 profiles handed out, 43 never completed a handshake. Some of those are
people who never installed anything. Some are almost certainly this, and they
had no way out except messaging the owner personally, so they left instead.
"""
from __future__ import annotations

import pytest

from vpn_wizard.awg_servers import AwgServer


def make(**extra) -> dict:
    base = {"id": "nl", "host": "203.0.113.9", "password": "p"}
    base.update(extra)
    return base


# --- реестр --------------------------------------------------------------------

def test_an_exit_can_be_declared_a_fallback_port() -> None:
    server = AwgServer.from_dict(make(id="nl-alt", listen_port=3478, alt_port=True))
    assert server.alt_port is True
    assert server.listen_port == 3478


def test_ordinary_exits_are_not_fallbacks() -> None:
    assert AwgServer.from_dict(make()).alt_port is False


def test_the_website_is_told_which_exit_is_the_fallback() -> None:
    # Без этого страница не может предложить его — она знает только то, что
    # отдаёт /api/awg/servers, а хосты и ключи туда не попадают.
    public = AwgServer.from_dict(make(id="nl-alt", alt_port=True)).public()
    assert public["alt_port"] is True
    assert "host" not in public and "password" not in public


# --- кому он доступен ----------------------------------------------------------

@pytest.fixture()
def server_module():
    from vpn_wizard import server as module

    return module


def _registry_with(monkeypatch, server_module, servers: dict) -> None:
    class Registry:
        def get_server(self, server_id):
            return servers.get(server_id)

    monkeypatch.setattr(server_module, "_awg_registry", lambda: Registry())


def test_a_fallback_exit_is_recognised(monkeypatch, server_module) -> None:
    _registry_with(
        monkeypatch,
        server_module,
        {
            "nl": AwgServer.from_dict(make()),
            "nl-alt": AwgServer.from_dict(make(id="nl-alt", alt_port=True)),
        },
    )
    assert server_module._awg_is_alt_port("nl-alt") is True
    assert server_module._awg_is_alt_port("nl") is False
    assert server_module._awg_is_alt_port(None) is False
    assert server_module._awg_is_alt_port("nope") is False


def test_a_broken_registry_does_not_turn_into_a_500(monkeypatch, server_module) -> None:
    def boom():
        raise RuntimeError("registry is invalid")

    monkeypatch.setattr(server_module, "_awg_registry", boom)
    assert server_module._awg_is_alt_port("nl-alt") is False


def _free_entitlement(server_module, assigned: str | None):
    return server_module._AwgEntitlement(
        paid_user=None,
        free=server_module.ChannelAccessStatus(
            configured=True, active=True, kind="member", server_id=assigned
        ),
    )


def test_a_pinned_free_user_may_still_reach_the_fallback(monkeypatch, server_module) -> None:
    _registry_with(
        monkeypatch,
        server_module,
        {
            "nl": AwgServer.from_dict(make()),
            "nl-alt": AwgServer.from_dict(make(id="nl-alt", alt_port=True)),
        },
    )
    limit, kind = server_module._awg_authorise_entitlement(
        _free_entitlement(server_module, "nl"),
        server_id="nl-alt",
        required_device_slot=1,
    )
    assert (limit, kind) == (1, "member")


def test_the_pin_still_holds_for_another_country(monkeypatch, server_module) -> None:
    # Закрепление существует, чтобы разводить нагрузку по странам. Запасной порт
    # — не страна, а обычная Финляндия по-прежнему закрыта.
    _registry_with(
        monkeypatch,
        server_module,
        {
            "nl": AwgServer.from_dict(make()),
            "fi": AwgServer.from_dict(make(id="fi")),
            "nl-alt": AwgServer.from_dict(make(id="nl-alt", alt_port=True)),
        },
    )
    with pytest.raises(Exception) as excinfo:
        server_module._awg_authorise_entitlement(
            _free_entitlement(server_module, "nl"),
            server_id="fi",
            required_device_slot=1,
        )
    assert getattr(excinfo.value, "status_code", None) == 403


def test_the_fallback_does_not_hand_out_a_second_device(monkeypatch, server_module) -> None:
    _registry_with(
        monkeypatch,
        server_module,
        {"nl-alt": AwgServer.from_dict(make(id="nl-alt", alt_port=True))},
    )
    with pytest.raises(Exception) as excinfo:
        server_module._awg_authorise_entitlement(
            _free_entitlement(server_module, "nl"),
            server_id="nl-alt",
            required_device_slot=2,
        )
    assert getattr(excinfo.value, "status_code", None) == 403
