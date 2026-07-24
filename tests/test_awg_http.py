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
        lambda telegram_id, token, server_id=None, device_slot=1: ("[Interface]\nPrivateKey = k\n", _server()),
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
