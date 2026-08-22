"""HTTP surface of the AmneziaWG delivery path.

Regression home for the client-side constraints that are invisible from Python:
the AmneziaWG Android client derives the tunnel name from the downloaded file's
base name and rejects anything outside ``[a-zA-Z0-9_=+.-]{1,15}`` instead of
truncating it, so a long filename silently makes a config unimportable.
"""
from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import re

import pytest
from fastapi.testclient import TestClient

import vpn_wizard.server as server_module
from vpn_wizard.account import AccountStore
from vpn_wizard.awg_fallback import (
    device_peer_id,
    family_guest_id,
    family_issue_token,
    issue_token,
)
from vpn_wizard.awg_servers import AwgServer
from vpn_wizard.server import _awg_file_slug, _awg_label_config, app


# Mirrors Tunnel.NAME_PATTERN in the AmneziaWG Android client.
ANDROID_TUNNEL_NAME = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")

_AWG_ENV = (
    "VPNW_AWG_SERVERS",
    "VPNW_AWG_PRESETS",
    "VPNW_AWG_DEFAULT_SERVER",
    "VPNW_AWG_FALLBACK_HOST",
    "VPNW_AWG_FALLBACK_ID",
    "VPNW_AWG_FALLBACK_LABEL",
    "VPNW_AWG_FALLBACK_FLAG",
    "VPNW_AWG_FALLBACK_SSH_PASSWORD",
    "VPNW_AWG_LINK_SECRET",
    "VPNW_CHANNEL_ACCESS_ENABLED",
    "VPNW_CHANNEL_ACCESS_CHANNEL_ID",
    "VPNW_CHANNEL_ACCESS_SERVER_ID",
    "VPNW_CHANNEL_ACCESS_WEB_GRACE_HOURS",
    "VPNW_BOT_TOKEN",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    for name in _AWG_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VPNW_STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("VPNW_SECRET_KEY", "test-secret-key")


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


def _configure_single_server(monkeypatch: pytest.MonkeyPatch, secret: str = "link-secret") -> None:
    monkeypatch.setenv("VPNW_AWG_FALLBACK_HOST", "212.69.84.167")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_SSH_PASSWORD", "hunter2")
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)


def _configure_channel_access(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VPNW_CHANNEL_ACCESS_ENABLED", "true")
    monkeypatch.setenv("VPNW_CHANNEL_ACCESS_CHANNEL_ID", "-1002358992995")
    monkeypatch.setenv("VPNW_CHANNEL_ACCESS_SERVER_ID", "nl")
    monkeypatch.setenv("VPNW_CHANNEL_ACCESS_WEB_GRACE_HOURS", "12")
    monkeypatch.setenv("VPNW_BOT_TOKEN", "123:test-token")


# --- tunnel name (the live import bug) ----------------------------------------

@pytest.mark.parametrize(
    "server_id",
    ["nl", "main", "us", "a-very-long-server-identifier", "..//etc/passwd", "🇳🇱", "", None],
)
def test_file_slug_always_importable_on_android(server_id) -> None:
    slug = _awg_file_slug(server_id)
    assert ANDROID_TUNNEL_NAME.match(slug), f"{slug!r} would be rejected by AmneziaWG Android"


def test_file_slug_names_the_server() -> None:
    assert _awg_file_slug("nl") == "FVPN-nl"
    assert _awg_file_slug("us") == "FVPN-us"
    # Different servers must yield different files, or a second download
    # overwrites the first instead of adding a tunnel.
    assert _awg_file_slug("nl") != _awg_file_slug("fi")
    assert _awg_file_slug("nl", device_slot=2) == "FVPN-nl-D2"
    assert _awg_file_slug("nl", family=True) == "FVPN-nl-F"


def test_file_slug_falls_back_when_id_is_unusable() -> None:
    assert _awg_file_slug("🇳🇱") == "FVPN"
    assert _awg_file_slug(None) == "FVPN"


# --- config labelling ----------------------------------------------------------

def _server(**kwargs) -> AwgServer:
    base = {
        "id": "nl", "label": "Нидерланды", "flag": "🇳🇱", "host": "1.1.1.1",
        "user": "root", "port": 22, "password": "p", "key_path": None,
        "key_content": None, "listen_port": 443,
    }
    return AwgServer(**{**base, **kwargs})


def test_label_is_whole_line_comments_above_interface() -> None:
    original = "[Interface]\nPrivateKey = abc\nAddress = 10.10.0.5/32\n"
    labelled = _awg_label_config(original, _server())

    lines = labelled.splitlines()
    assert lines[0] == "# Fodder VPN — 🇳🇱 Нидерланды"
    assert lines[1] == "# server: nl"
    assert lines[2] == "[Interface]"
    # Every comment must be a whole line: an inline one would be captured by the
    # `grep '^Address'` parsing that rebuilds server-side peer blocks.
    for line in lines:
        assert "#" not in line or line.startswith("#")
    # The original config must survive byte-for-byte after the header.
    assert labelled.endswith(original)


def test_label_adds_no_directives_that_break_import() -> None:
    labelled = _awg_label_config("[Interface]\nPrivateKey = abc\n", _server())
    keys = [
        line.split("=")[0].strip()
        for line in labelled.splitlines()
        if "=" in line and not line.startswith("#")
    ]
    # A non-whitelisted key such as `Name` or `Server` fails the whole import.
    assert keys == ["PrivateKey"]


def test_label_is_a_noop_without_a_server() -> None:
    original = "[Interface]\nPrivateKey = abc\n"
    assert _awg_label_config(original, None) == original


# --- endpoint behaviour --------------------------------------------------------

def test_config_download_filename_is_importable(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    # Guards the regression directly: the endpoint must never emit a name the
    # Android client refuses (the old one was `fodder-awg-<telegram_id>.conf`).
    monkeypatch.setattr(
        server_module,
        "_awg_issue_config",
        lambda telegram_id, token, server_id=None, device_slot=1, preset_id=None: (
            "[Interface]\nPrivateKey = k\n",
            _server(),
        ),
    )
    response = client.get("/api/awg/449066726/config", params={"token": "whatever"})

    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    name = re.search(r'filename="([^"]+)"', disposition).group(1)
    assert name.endswith(".conf")
    assert ANDROID_TUNNEL_NAME.match(name[: -len(".conf")])
    assert name == "FVPN-nl.conf"
    # Not text/plain, or the browser appends .txt and Android stops offering
    # "open with AmneziaWG".
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["cache-control"] == "no-store"


def test_config_requires_configuration_then_a_valid_token(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    unconfigured = client.get("/api/awg/1/config", params={"token": "x"})
    assert unconfigured.status_code == 503

    _configure_single_server(monkeypatch)
    assert client.get("/api/awg/1/config", params={"token": "wrong"}).status_code == 403
    # A token minted for a different user must not work either.
    other = issue_token("link-secret", 2)
    assert client.get("/api/awg/1/config", params={"token": other}).status_code == 403


def test_family_config_uses_owner_entitlement_and_separate_peer(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner_id = 449066726
    _configure_single_server(monkeypatch, secret)
    entitlement_lookups: list[int] = []
    issued_peers: list[int] = []

    class ActiveRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        def active_user(self, telegram_id: int):
            entitlement_lookups.append(telegram_id)
            return {"uuid": "owner-active", "hwidDeviceLimit": 2}

    def issue(self, telegram_id: int, *, remnawave_uuid=None):
        issued_peers.append(telegram_id)
        return {
            "config": "[Interface]\nPrivateKey = family-key\n",
            "client_name": "family",
            "reused": False,
        }

    monkeypatch.setattr(server_module, "RemnawaveClient", ActiveRemnawave)
    monkeypatch.setattr(server_module.AwgFallbackService, "issue", issue)
    token = family_issue_token(secret, owner_id)

    config = client.get(
        f"/api/awg/family/{owner_id}/config",
        params={"token": token},
    )
    qr = client.get(
        f"/api/awg/family/{owner_id}/qr",
        params={"token": token},
    )

    assert config.status_code == 200
    assert config.headers["content-disposition"] == 'attachment; filename="FVPN-main-F.conf"'
    assert config.headers["cache-control"] == "no-store"
    assert config.headers["referrer-policy"] == "no-referrer"
    assert qr.status_code == 200
    assert qr.headers["content-type"] == "image/png"
    assert qr.headers["cache-control"] == "no-store"
    assert entitlement_lookups == [owner_id, owner_id]
    assert issued_peers == [family_guest_id(owner_id), family_guest_id(owner_id)]


def test_family_endpoint_rejects_personal_or_wrong_owner_token(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    _configure_single_server(monkeypatch, secret)

    personal = issue_token(secret, 1)
    assert (
        client.get("/api/awg/family/1/config", params={"token": personal}).status_code
        == 403
    )
    other_family = family_issue_token(secret, 2)
    assert (
        client.get("/api/awg/family/1/config", params={"token": other_family}).status_code
        == 403
    )


def test_personal_device_slot_is_capped_by_paid_limit(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner_id = 449066726
    _configure_single_server(monkeypatch, secret)
    issued_peers: list[int] = []

    class ActiveRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        def active_user(self, telegram_id: int):
            assert telegram_id == owner_id
            return {
                "uuid": "active-user",
                "status": "ACTIVE",
                "hwidDeviceLimit": 2,
                "expireAt": "2999-01-01T00:00:00Z",
            }

    def issue(self, telegram_id: int, *, remnawave_uuid=None):
        issued_peers.append(telegram_id)
        return {"config": "[Interface]\nPrivateKey = k\n", "client_name": "x", "reused": False}

    monkeypatch.setattr(server_module, "RemnawaveClient", ActiveRemnawave)
    monkeypatch.setattr(server_module.AwgFallbackService, "issue", issue)
    token = issue_token(secret, owner_id)

    access = client.get(f"/api/awg/{owner_id}/access", params={"token": token})
    second = client.get(
        f"/api/awg/{owner_id}/config",
        params={"token": token, "device": 2},
    )
    third = client.get(
        f"/api/awg/{owner_id}/config",
        params={"token": token, "device": 3},
    )

    assert access.status_code == 200
    assert access.json() == {
        "ok": True,
        "active": True,
        "device_limit": 2,
        "family": False,
        "expires_at": "2999-01-01T00:00:00Z",
    }
    assert second.status_code == 200
    assert second.headers["content-disposition"] == 'attachment; filename="FVPN-main-D2.conf"'
    assert third.status_code == 403
    assert issued_peers == [device_peer_id(owner_id, 2)]


def test_webhook_applies_expiry_and_renewal_to_owner_and_family(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "webhook-secret"
    owner_id = 449066726
    calls: list[tuple[str, int]] = []

    class Service:
        server_id = "nl"

        @staticmethod
        def suspend(peer_id: int) -> None:
            calls.append(("suspend", peer_id))

        @staticmethod
        def resume(peer_id: int) -> None:
            calls.append(("resume", peer_id))

    monkeypatch.setenv("VPNW_REMNAWAVE_WEBHOOK_SECRET", secret)
    monkeypatch.setattr(server_module, "_awg_all_services", lambda: [Service()])

    for event in ("user.expired", "user.enabled"):
        raw = json.dumps(
            {"event": event, "data": {"telegramId": owner_id}},
            separators=(",", ":"),
        ).encode()
        signature = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        response = client.post(
            "/api/integrations/remnawave/webhook",
            content=raw,
            headers={"x-remnawave-signature": signature},
        )
        assert response.status_code == 200

    guest_id = family_guest_id(owner_id)
    assert calls == [
        ("suspend", owner_id),
        ("suspend", guest_id),
        ("resume", owner_id),
        ("resume", guest_id),
    ]


def test_paid_expiry_keeps_only_the_free_netherlands_owner_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner_id = 449066726
    calls: list[tuple[str, str, int]] = []

    class Service:
        def __init__(self, server_id: str) -> None:
            self.server_id = server_id

        def suspend(self, peer_id: int) -> None:
            calls.append(("suspend", self.server_id, peer_id))

        def resume(self, peer_id: int) -> None:
            calls.append(("resume", self.server_id, peer_id))

    _configure_channel_access(monkeypatch)
    server_module.build_account_store().channel_access_grant_member(owner_id)
    monkeypatch.setattr(
        server_module,
        "_awg_entitlement",
        lambda _tid: server_module._AwgEntitlement(
            paid_user=None,
            free=server_module.ChannelAccessStatus(configured=True, active=True, kind="member"),
        ),
    )
    monkeypatch.setattr(
        server_module, "_awg_all_services", lambda: [Service("nl"), Service("fi")]
    )

    server_module._awg_webhook_apply("policy", owner_id)

    guest_id = family_guest_id(owner_id)
    assert calls == [
        ("resume", "nl", owner_id),
        ("suspend", "nl", guest_id),
        ("suspend", "fi", owner_id),
        ("suspend", "fi", guest_id),
    ]


# --- server picker -------------------------------------------------------------

def test_servers_endpoint_lists_choices_without_leaking_secrets(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "flag": "🇳🇱", "host": "212.69.84.167", "password": "hunter2"},
            {"id": "fi", "label": "Финляндия", "flag": "🇫🇮", "host": "2.2.2.2", "password": "hunter2"},
        ]),
    )
    response = client.get("/api/awg/servers")
    assert response.status_code == 200

    body = response.json()
    assert [s["id"] for s in body["servers"]] == ["nl", "fi"]
    assert body["default_server"] == "nl"
    raw = response.text
    for secret in ("212.69.84.167", "hunter2", "2.2.2.2"):
        assert secret not in raw


def test_servers_endpoint_reports_unconfigured_and_invalid(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    assert client.get("/api/awg/servers").status_code == 503

    monkeypatch.setenv("VPNW_AWG_SERVERS", "{not json")
    assert client.get("/api/awg/servers").status_code == 500


def test_servers_route_does_not_shadow_the_config_route(client: TestClient) -> None:
    # "/api/awg/servers" and "/api/awg/{telegram_id}/config" must stay distinct;
    # a greedy int path param would otherwise swallow it.
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/awg/servers" in paths
    assert "/api/awg/{telegram_id}/config" in paths
    assert "/api/awg/{telegram_id}/access" in paths
    assert "/api/awg/family/{owner_telegram_id}/config" in paths
    assert "/api/awg/family/{owner_telegram_id}/qr" in paths
    assert "/api/awg/family/{owner_telegram_id}/access" in paths


def test_selected_server_controls_real_provisioning(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "host": "127.0.0.1", "password": "p", "listen_port": 443},
            {"id": "fi", "label": "Финляндия", "host": "151.245.139.63", "password": "p", "listen_port": 3478},
        ]),
    )

    class ActiveRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        def active_user(self, telegram_id: int):
            return {"uuid": "active-user"}

    captured: dict[str, object] = {}

    def issue(self, telegram_id: int, *, remnawave_uuid=None):
        captured.update(
            host=self.config.host,
            listen_port=self.config.listen_port,
            server_id=self.server_id,
            telegram_id=telegram_id,
        )
        return {"config": "[Interface]\nPrivateKey = k\n", "client_name": "x", "reused": False}

    monkeypatch.setattr(server_module, "RemnawaveClient", ActiveRemnawave)
    monkeypatch.setattr(server_module.AwgFallbackService, "issue", issue)
    token = issue_token(secret, 449066726)
    response = client.get(
        "/api/awg/449066726/config",
        params={"token": token, "server": "fi"},
    )

    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="FVPN-fi.conf"'
    assert captured == {
        "host": "151.245.139.63",
        "listen_port": 3478,
        "server_id": "fi",
        "telegram_id": 449066726,
    }
    assert "# server: fi" in response.text


def test_unknown_selected_server_is_rejected_before_provisioning(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "host": "127.0.0.1", "password": "p"},
        ]),
    )
    token = issue_token(secret, 1)
    response = client.get("/api/awg/1/config", params={"token": token, "server": "moon"})
    assert response.status_code == 404


# --- blocker 1: the read endpoints must not block the single event loop --------

def test_awg_read_endpoints_run_off_the_event_loop() -> None:
    # These make a blocking Remnawave HTTP call + a blocking SSH provision. As
    # `async def` on a single uvicorn worker, one slow exit froze config/QR/portal
    # AND the billing webhook for everyone. Plain `def` offloads them to a thread.
    for fn in (
        server_module.awg_config,
        server_module.awg_qr,
        server_module.awg_access,
        server_module.awg_family_config,
        server_module.awg_family_qr,
        server_module.awg_family_access,
    ):
        assert not inspect.iscoroutinefunction(fn), f"{fn.__name__} must be sync"
    # The webhook stays async: it awaits the request body, then offloads the
    # blocking suspend/resume to a thread itself.
    assert inspect.iscoroutinefunction(server_module.remnawave_webhook)


# --- multi-country: a slot may hold every exit at once -------------------------

def test_issuing_a_country_does_not_disturb_the_others(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # The bot advertises "download several countries, each becomes its own tunnel".
    # Issuing one must therefore never suspend the same slot elsewhere.
    secret = "link-secret"
    owner = 449066726
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "host": "127.0.0.1", "password": "p", "listen_port": 443},
            {"id": "fi", "label": "Финляндия", "host": "2.2.2.2", "password": "p", "listen_port": 3478},
        ]),
    )

    class ActiveRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        def active_user(self, telegram_id: int):
            return {"uuid": "u", "hwidDeviceLimit": 1}

    issued: list[tuple[object, int]] = []
    suspended: list[tuple[object, int]] = []

    def issue(self, telegram_id: int, *, remnawave_uuid=None):
        issued.append((self.server_id, telegram_id))
        return {"config": "[Interface]\nPrivateKey = k\n", "client_name": "x", "reused": False}

    def suspend(self, telegram_id: int) -> bool:
        suspended.append((self.server_id, telegram_id))
        return True

    monkeypatch.setattr(server_module, "RemnawaveClient", ActiveRemnawave)
    monkeypatch.setattr(server_module.AwgFallbackService, "issue", issue)
    monkeypatch.setattr(server_module.AwgFallbackService, "suspend", suspend)
    token = issue_token(secret, owner)

    assert client.get(f"/api/awg/{owner}/config", params={"token": token, "server": "nl"}).status_code == 200
    assert client.get(f"/api/awg/{owner}/config", params={"token": token, "server": "fi"}).status_code == 200

    assert issued == [(None, owner), ("fi", owner)]  # nl is default -> legacy storage
    assert suspended == []  # nothing revoked behind the user's back


def test_channel_member_can_issue_only_the_free_netherlands_server(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    _configure_channel_access(monkeypatch)
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "host": "127.0.0.1", "password": "p"},
            {"id": "us", "label": "США", "host": "2.2.2.2", "password": "p"},
        ]),
    )

    class InactiveRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        @staticmethod
        def active_user(_telegram_id: int):
            return None

    monkeypatch.setattr(server_module, "RemnawaveClient", InactiveRemnawave)
    server_module.build_account_store().channel_access_grant_member(owner)
    monkeypatch.setattr(
        server_module.AwgFallbackService,
        "issue",
        lambda self, telegram_id, **kwargs: {
            "config": "[Interface]\nPrivateKey = k\n",
            "client_name": "x",
            "reused": False,
        },
    )
    token = issue_token(secret, owner)

    denied = client.get(
        f"/api/awg/{owner}/config", params={"token": token, "server": "us"}
    )
    allowed = client.get(
        f"/api/awg/{owner}/config", params={"token": token, "server": "nl"}
    )
    assert denied.status_code == 403
    assert "Нидерланды" in denied.text
    assert allowed.status_code == 200


# --- disabled exits: hidden from choice, still managed -------------------------

def test_disabled_server_is_hidden_and_refuses_new_configs(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # An exit whose provider blocks its UDP port must not be offered, and must not
    # hand out a config we know cannot connect — but it stays in the registry so
    # peers already issued there keep being suspended/resumed on expiry.
    secret = "link-secret"
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "host": "127.0.0.1", "password": "p"},
            {"id": "tr", "label": "Турция", "host": "3.3.3.3", "password": "p", "enabled": False},
        ]),
    )

    listed = client.get("/api/awg/servers")
    assert [s["id"] for s in listed.json()["servers"]] == ["nl"]

    token = issue_token(secret, 7)
    blocked = client.get("/api/awg/7/config", params={"token": token, "server": "tr"})
    assert blocked.status_code == 503

    # Still resolvable internally, so suspend/resume can reach its existing peers.
    registry = server_module.AwgRegistry.from_env()
    assert registry.get_server("tr") is not None
    assert registry.get_server("tr").enabled is False


def test_disabled_default_server_falls_through_to_a_live_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNW_AWG_DEFAULT_SERVER", "tr")
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "tr", "host": "3.3.3.3", "password": "p", "enabled": False},
            {"id": "nl", "host": "127.0.0.1", "password": "p"},
        ]),
    )
    # Disabling the default must not strand every no-server-param link on it.
    assert server_module.AwgRegistry.from_env().default_server.id == "nl"


# --- HTML freshness ------------------------------------------------------------

def test_html_is_never_cached(client: TestClient) -> None:
    # Telegram's in-app browser holds on to HTML aggressively. Without no-store
    # a redesign silently never reaches users, and bumping a ?v= query by hand
    # only covers links that carry one — family links point straight at the page.
    for path in ("/portal/", "/connect/awg.html", "/connect/index.html"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "text/html" in response.headers["content-type"], path
        assert response.headers.get("cache-control") == "no-store, max-age=0", path


def test_json_responses_keep_their_own_caching(client: TestClient) -> None:
    # The blanket rule must apply to HTML only.
    response = client.get("/api/awg/servers")
    assert "text/html" not in response.headers.get("content-type", "")


# --- device control -------------------------------------------------------------

def _active_remnawave(limit: int):
    class ActiveRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        def active_user(self, telegram_id: int):
            return {"uuid": "u", "hwidDeviceLimit": limit, "status": "ACTIVE",
                    "expireAt": "2999-01-01T00:00:00Z"}
    return ActiveRemnawave


def test_device_list_reports_every_paid_slot(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(3))

    response = client.get(f"/api/awg/{owner}/devices", params={"token": issue_token(secret, owner)})
    assert response.status_code == 200
    body = response.json()
    assert body["device_limit"] == 3
    assert [d["slot"] for d in body["devices"]] == [1, 2, 3]
    assert body["devices"][1]["family"] is True
    assert all(d["in_use"] is False for d in body["devices"])


def test_device_endpoints_reject_a_family_token(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # A family guest holds one slot; it must never see or revoke the owner's others.
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(5))
    family = family_issue_token(secret, owner)

    assert client.get(f"/api/awg/{owner}/devices", params={"token": family}).status_code == 403
    assert client.post(
        f"/api/awg/{owner}/devices/3/revoke", params={"token": family}
    ).status_code == 403
    assert client.post(
        f"/api/awg/{owner}/devices/3/label", params={"token": family}, json={"label": "x"}
    ).status_code == 403


def test_device_endpoints_require_an_active_subscription(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)

    class Expired:
        def __init__(self, config) -> None:
            self.config = config

        def active_user(self, telegram_id: int):
            return None

    monkeypatch.setattr(server_module, "RemnawaveClient", Expired)
    token = issue_token(secret, owner)
    assert client.get(f"/api/awg/{owner}/devices", params={"token": token}).status_code == 403


def test_renaming_a_slot_persists_and_can_be_cleared(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(2))
    token = issue_token(secret, owner)

    named = client.post(
        f"/api/awg/{owner}/devices/1/label", params={"token": token}, json={"label": "Мамин телефон"}
    )
    assert named.status_code == 200
    assert named.json()["label"] == "Мамин телефон"

    listed = client.get(f"/api/awg/{owner}/devices", params={"token": token}).json()
    assert listed["devices"][0]["label"] == "Мамин телефон"

    cleared = client.post(
        f"/api/awg/{owner}/devices/1/label", params={"token": token}, json={"label": ""}
    )
    assert cleared.json()["label"] is None


def test_revoke_reports_failure_when_a_location_cannot_be_cleared(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # Reporting success while a shared key still works somewhere would be worse
    # than an error: the owner believes access is cut when it is not.
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(3))

    class DeadService:
        server_id = "fi"

        @staticmethod
        def revoke(peer_id: int) -> bool:
            raise RuntimeError("exit unreachable")

    monkeypatch.setattr(server_module, "_awg_all_services", lambda: [DeadService()])
    response = client.post(
        f"/api/awg/{owner}/devices/3/revoke", params={"token": issue_token(secret, owner)}
    )
    assert response.status_code == 502


def test_revoke_clears_the_slot_on_all_locations(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(3))
    calls: list[tuple[str, int]] = []

    class Service:
        def __init__(self, server_id):
            self.server_id = server_id

        def revoke(self, peer_id: int) -> bool:
            calls.append((self.server_id, peer_id))
            return True

    monkeypatch.setattr(server_module, "_awg_all_services", lambda: [Service("nl"), Service("fi")])
    response = client.post(
        f"/api/awg/{owner}/devices/3/revoke", params={"token": issue_token(secret, owner)}
    )
    assert response.status_code == 200
    assert response.json()["revoked_from"] == 2
    assert calls == [("nl", device_peer_id(owner, 3)), ("fi", device_peer_id(owner, 3))]


# --- invites: getting a VPN without Telegram ------------------------------------

def test_invite_endpoints_require_the_owner_token(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))

    assert client.get(f"/api/awg/{owner}/invites", params={"token": "bad"}).status_code == 403
    family = family_issue_token(secret, owner)
    assert client.post(f"/api/awg/{owner}/invites", params={"token": family}).status_code == 403


def test_owner_can_mint_and_withdraw_invites(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))
    token = issue_token(secret, owner)

    created = client.post(f"/api/awg/{owner}/invites", params={"token": token})
    assert created.status_code == 200
    code = created.json()["code"]

    listed = client.get(f"/api/awg/{owner}/invites", params={"token": token}).json()
    assert [i["code"] for i in listed["invites"]] == [code]

    dropped = client.delete(f"/api/awg/{owner}/invites/{code}", params={"token": token})
    assert dropped.status_code == 200
    assert client.get(f"/api/awg/{owner}/invites", params={"token": token}).json()["invites"] == []


def test_a_visitor_can_check_a_code_before_committing(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))
    code = client.post(
        f"/api/awg/{owner}/invites", params={"token": issue_token(secret, owner)}
    ).json()["code"]

    # No token of any kind: this is the whole point — the visitor has no Telegram.
    good = client.get(f"/api/web/invite/{code}").json()
    assert good["valid"] is True

    bad = client.get("/api/web/invite/ZZZZ-9999").json()
    assert bad["valid"] is False and bad["detail"]


def test_redeeming_creates_an_account_and_hands_back_a_working_link(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)

    class OwnerOnlyRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        @staticmethod
        def active_user(telegram_id: int):
            return {"uuid": "owner", "hwidDeviceLimit": 1} if telegram_id == owner else None

    monkeypatch.setattr(server_module, "RemnawaveClient", OwnerOnlyRemnawave)
    code = client.post(
        f"/api/awg/{owner}/invites", params={"token": issue_token(secret, owner)}
    ).json()["code"]

    response = client.post(f"/api/web/invite/{code}/redeem")
    assert response.status_code == 200
    body = response.json()

    # The synthetic id must be outside Telegram's range, and the token must be the
    # real signed one, so the connect page works with no further setup.
    from vpn_wizard.web_signup import is_web_account

    assert is_web_account(body["telegram_id"])
    assert body["token"] == issue_token(secret, body["telegram_id"])
    assert body["grace_hours"] == 12
    assert body["server_id"] == "nl"
    assert body["bind_url"].endswith(f"?start=web_{code}")
    assert body["grace_expires_at"] > 0
    assert client.get(
        f"/api/awg/{body['telegram_id']}/access", params={"token": body["token"]}
    ).status_code == 200

    # Single use: the same SMS cannot onboard two people.
    assert client.post(f"/api/web/invite/{code}/redeem").status_code == 400


def test_redeem_does_not_burn_the_code_when_signup_fails(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))
    code = client.post(
        f"/api/awg/{owner}/invites", params={"token": issue_token(secret, owner)}
    ).json()["code"]

    monkeypatch.setattr(
        AccountStore,
        "channel_access_grant_grace",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("disk full")),
    )
    with pytest.raises(RuntimeError, match="disk full"):
        client.post(f"/api/web/invite/{code}/redeem")
    # The invite survives, so the person can retry instead of losing their only code.
    assert client.get(f"/api/web/invite/{code}").json()["valid"] is True


def test_one_shared_code_onboards_the_whole_chat_until_the_limit(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))
    server_module._shared_redeem_log.clear()

    from vpn_wizard.web_signup import create_shared_invite

    code = create_shared_invite(
        server_module.build_account_store(), owner, max_uses=2
    )["code"]
    assert client.get(f"/api/web/invite/{code}").json()["valid"] is True

    first = client.post(f"/api/web/invite/{code}/redeem")
    second = client.post(f"/api/web/invite/{code}/redeem")
    assert first.status_code == 200 and second.status_code == 200
    one, two = first.json(), second.json()

    # Two different people: separate accounts, separate hidden bind codes — the
    # shared code itself never becomes anyone's identity.
    assert one["telegram_id"] != two["telegram_id"]
    assert one["bind_url"] != two["bind_url"]
    assert f"web_{code}" not in one["bind_url"]
    for body in (one, two):
        assert client.get(
            f"/api/awg/{body['telegram_id']}/access", params={"token": body["token"]}
        ).status_code == 200

    # The third neighbour is politely refused, and the check endpoint agrees.
    refused = client.post(f"/api/web/invite/{code}/redeem")
    assert refused.status_code == 400 and "Лимит" in refused.json()["detail"]
    checked = client.get(f"/api/web/invite/{code}").json()
    assert checked["valid"] is False and "Лимит" in checked["detail"]


def test_zero_grace_hours_issues_a_profile_without_a_deadline(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # The first profile is a gift: no countdown, nothing ever suspends it.
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)
    monkeypatch.setenv("VPNW_CHANNEL_ACCESS_WEB_GRACE_HOURS", "0")
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))
    code = client.post(
        f"/api/awg/{owner}/invites", params={"token": issue_token(secret, owner)}
    ).json()["code"]

    body = client.post(f"/api/web/invite/{code}/redeem").json()
    assert body["grace_hours"] == 0
    assert body["grace_expires_at"] == 0
    assert client.get(
        f"/api/awg/{body['telegram_id']}/access", params={"token": body["token"]}
    ).status_code == 200


def test_shared_redeems_from_one_address_are_rate_limited(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # One person refresh-clicking must not drain the family's counter.
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)
    server_module._shared_redeem_log.clear()

    from vpn_wizard.web_signup import create_shared_invite

    code = create_shared_invite(
        server_module.build_account_store(), owner, max_uses=50
    )["code"]
    for _ in range(server_module._SHARED_REDEEM_PER_IP):
        assert client.post(f"/api/web/invite/{code}/redeem").status_code == 200
    throttled = client.post(f"/api/web/invite/{code}/redeem")
    assert throttled.status_code == 429

    # The brake spends no uses, so the family still has the rest of the pool.
    shared = server_module.build_account_store().shared_invite_get(code)
    assert shared["used_count"] == server_module._SHARED_REDEEM_PER_IP
    server_module._shared_redeem_log.clear()


def test_operator_preset_rewrites_the_config_it_serves(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # A subscriber whose operator drops the default junk profile has no way to
    # tell — the tunnel simply never handshakes. The preset is their only lever.
    secret = "link-secret"
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))

    def issue(self, telegram_id: int, *, remnawave_uuid=None):
        return {
            "config": "[Interface]\nPrivateKey = k\nJc = 2\nS1 = 65\nH1 = 7\n\n[Peer]\nPublicKey = s\n",
            "client_name": "x",
            "reused": False,
        }

    monkeypatch.setattr(server_module.AwgFallbackService, "issue", issue)
    token = issue_token(secret, 1)

    plain = client.get("/api/awg/1/config", params={"token": token}).text
    assert "Jc = 2" in plain and "I1" not in plain

    mts = client.get("/api/awg/1/config", params={"token": token, "preset": "mts"}).text
    assert "Jc = 3" in mts
    assert "I1 = <r 48>" in mts
    # Interface-wide values must never be rewritten, or the tunnel dies silently.
    assert "S1 = 65" in mts and "H1 = 7" in mts

    unknown = client.get("/api/awg/1/config", params={"token": token, "preset": "nope"})
    assert unknown.status_code == 404


def test_a_website_trial_cannot_mint_its_own_invites(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # A redeemed trial passes the same active-subscription check as a payer, so
    # without this gate one leaked code would let free access replicate itself.
    from vpn_wizard.web_signup import web_account_id

    secret = "link-secret"
    guest = web_account_id(11)
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))
    token = issue_token(secret, guest)

    assert client.post(f"/api/awg/{guest}/invites", params={"token": token}).status_code == 403
    assert client.get(f"/api/awg/{guest}/invites", params={"token": token}).status_code == 403
    # A real Telegram subscriber is unaffected.
    owner_token = issue_token(secret, 449066726)
    assert client.post("/api/awg/449066726/invites", params={"token": owner_token}).status_code == 200


def test_website_profile_links_to_verified_telegram_member(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)

    class OwnerOnlyRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        @staticmethod
        def active_user(telegram_id: int):
            return {"uuid": "owner", "hwidDeviceLimit": 1} if telegram_id == owner else None

    monkeypatch.setattr(server_module, "RemnawaveClient", OwnerOnlyRemnawave)
    code = client.post(
        f"/api/awg/{owner}/invites", params={"token": issue_token(secret, owner)}
    ).json()["code"]

    redeemed = client.post(f"/api/web/invite/{code}/redeem").json()
    real_id = 777001
    monkeypatch.setattr(server_module, "telegram_channel_member", lambda *_args: True)
    applied: list[tuple[str, int]] = []
    monkeypatch.setattr(
        server_module, "_awg_webhook_apply", lambda action, tid: applied.append((action, tid))
    )

    linked = client.post(
        f"/api/web/invite/{code}/link",
        params={"telegram_id": real_id, "token": issue_token(secret, real_id)},
    )

    assert linked.status_code == 200
    assert linked.json()["linked"] is True
    assert server_module.build_account_store().channel_access_get(redeemed["telegram_id"]) is None
    assert server_module.build_account_store().channel_access_by_telegram(real_id) is not None
    assert applied == [("policy", real_id)]


def test_website_profile_cannot_be_linked_after_12_hour_window(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    _configure_channel_access(monkeypatch)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(1))
    code = client.post(
        f"/api/awg/{owner}/invites", params={"token": issue_token(secret, owner)}
    ).json()["code"]

    monkeypatch.setattr(server_module.time, "time", lambda: 1_000)
    client.post(f"/api/web/invite/{code}/redeem").raise_for_status()
    monkeypatch.setattr(server_module.time, "time", lambda: 44_201)
    monkeypatch.setattr(server_module, "telegram_channel_member", lambda *_args: True)

    linked = client.post(
        f"/api/web/invite/{code}/link",
        params={"telegram_id": 777001, "token": issue_token(secret, 777001)},
    )
    assert linked.status_code == 410
    assert "Срок временного профиля" in linked.json()["detail"]


def test_revoking_the_family_slot_kills_the_link_already_handed_out(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # Both confirm dialogs promise the relative loses access. Before the epoch,
    # their old URL simply re-provisioned the same guest peer on the next request.
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(3))

    def issue(self, telegram_id: int, *, remnawave_uuid=None):
        return {"config": "[Interface]\nPrivateKey = k\n", "client_name": "x", "reused": False}

    class Service:
        server_id = None

        @staticmethod
        def revoke(peer_id: int) -> bool:
            return True

    monkeypatch.setattr(server_module.AwgFallbackService, "issue", issue)
    monkeypatch.setattr(server_module, "_awg_all_services", lambda: [Service()])

    old_link = family_issue_token(secret, owner)
    assert client.get(f"/api/awg/family/{owner}/config", params={"token": old_link}).status_code == 200

    revoked = client.post(
        f"/api/awg/{owner}/devices/2/revoke", params={"token": issue_token(secret, owner)}
    )
    assert revoked.status_code == 200

    # The link the relative already holds is now dead...
    assert client.get(
        f"/api/awg/family/{owner}/config", params={"token": old_link}
    ).status_code == 403
    # ...and a freshly issued one works again, so the owner can re-share.
    new_link = family_issue_token(secret, owner, 1)
    assert client.get(
        f"/api/awg/family/{owner}/config", params={"token": new_link}
    ).status_code == 200


def test_a_failed_family_revoke_leaves_the_link_alive(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    # Bumping the epoch on a partial failure would tell the owner nothing changed
    # while silently breaking a link whose key is still installed somewhere.
    secret = "link-secret"
    owner = 449066726
    _configure_single_server(monkeypatch, secret)
    monkeypatch.setattr(server_module, "RemnawaveClient", _active_remnawave(3))

    class DeadService:
        server_id = "fi"

        @staticmethod
        def revoke(peer_id: int) -> bool:
            raise RuntimeError("exit unreachable")

    monkeypatch.setattr(server_module, "_awg_all_services", lambda: [DeadService()])
    assert client.post(
        f"/api/awg/{owner}/devices/2/revoke", params={"token": issue_token(secret, owner)}
    ).status_code == 502

    from vpn_wizard.account import build_account_store

    assert build_account_store().awg_family_epoch(owner) == 0
