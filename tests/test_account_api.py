from __future__ import annotations

import hashlib
import hmac
import json
from contextlib import contextmanager
import time
from urllib.parse import parse_qs, urlencode, urlparse

from fastapi.testclient import TestClient

import vpn_wizard.server as server
from vpn_wizard.awg_fallback import family_issue_token, issue_token


def _configure_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VPNW_STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("VPNW_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("VPNW_BOT_TOKEN", "123456:telegram-test-token")
    monkeypatch.setenv("VPNW_BOT_USERNAME", "vpn_wizard_test_bot")


def _web_auth_payload(bot_token: str) -> dict[str, object]:
    now = int(time.time())
    payload = {
        "id": 10101,
        "first_name": "Fodder",
        "last_name": "Test",
        "username": "fodder_test",
        "photo_url": "https://example.com/avatar.png",
        "auth_date": now,
    }
    data_check = "\n".join(f"{key}={payload[key]}" for key in sorted(payload))
    digest = hmac.new(hashlib.sha256(bot_token.encode("utf-8")).digest(), data_check.encode("utf-8"), "sha256").hexdigest()
    return {**payload, "hash": digest}


def _miniapp_init_data(bot_token: str) -> str:
    now = int(time.time())
    user = {"id": 10101, "first_name": "Fodder", "username": "fodder_test", "language_code": "ru"}
    payload = {
        "auth_date": str(now),
        "query_id": "AAEAAAE",
        "user": json.dumps(user, separators=(",", ":")),
    }
    data_check = "\n".join(f"{key}={payload[key]}" for key in sorted(payload))
    secret = hmac.new(b"WebAppData", bot_token.encode("utf-8"), "sha256").digest()
    digest = hmac.new(secret, data_check.encode("utf-8"), "sha256").hexdigest()
    return urlencode({**payload, "hash": digest})


def test_browser_and_miniapp_auth_endpoints_accept_valid_telegram_payloads(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    client = TestClient(server.app)

    web_response = client.post("/api/auth/telegram/web", json=_web_auth_payload("123456:telegram-test-token"))
    assert web_response.status_code == 200
    assert web_response.json()["authenticated"] is True
    assert client.get("/api/auth/me").json()["authenticated"] is True

    client.post("/api/auth/logout")
    mini_response = client.post(
        "/api/auth/telegram/miniapp",
        json={"init_data": _miniapp_init_data("123456:telegram-test-token")},
    )
    assert mini_response.status_code == 200
    assert mini_response.json()["authenticated"] is True


def test_miniapp_auth_works_without_legacy_bot_poller(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    monkeypatch.delenv("VPNW_BOT_TOKEN")
    monkeypatch.setenv("VPNW_TELEGRAM_AUTH_TOKEN", "123456:telegram-test-token")
    client = TestClient(server.app)

    config = client.get("/api/auth/config")
    assert config.status_code == 200
    assert config.json()["miniapp_login_enabled"] is True

    response = client.post(
        "/api/auth/telegram/miniapp",
        json={"init_data": _miniapp_init_data("123456:telegram-test-token")},
    )
    assert response.status_code == 200
    assert response.json()["authenticated"] is True


def test_portal_links_require_telegram_session_and_keep_tokens_separate(
    monkeypatch, tmp_path
) -> None:
    _configure_env(monkeypatch, tmp_path)
    secret = "portal-link-secret"
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", "https://vpn.example.test")
    client = TestClient(server.app)

    assert client.get("/api/portal/links").status_code == 401
    login = client.post(
        "/api/auth/telegram/miniapp",
        json={"init_data": _miniapp_init_data("123456:telegram-test-token")},
    )
    assert login.status_code == 200

    response = client.get("/api/portal/links")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    body = response.json()
    personal = urlparse(body["personal_vpn_url"])
    family = urlparse(body["family_vpn_url"])
    assert personal.path == "/connect/awg.html"
    assert family.path == "/connect/awg.html"
    assert parse_qs(personal.query) == {
        "tid": ["10101"],
        "token": [issue_token(secret, 10101)],
    }
    assert parse_qs(family.query) == {
        "family": ["10101"],
        "token": [family_issue_token(secret, 10101)],
    }
    assert body["server_wizard_url"] == "https://vpn.example.test/wizard/?v=20260722-3"


def test_legacy_miniapp_entry_redirects_to_uncached_portal() -> None:
    client = TestClient(server.app, follow_redirects=False)

    response = client.get("/miniapp/")

    assert response.status_code == 307
    assert response.headers["location"] == "/portal/?v=20260722-3"
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    portal = client.get("/portal/")
    wizard = client.get("/wizard/")
    assert portal.status_code == 200
    assert wizard.status_code == 200
    assert portal.headers["cache-control"] == "no-store, max-age=0"
    assert wizard.headers["cache-control"] == "no-store, max-age=0"


def test_saved_server_roundtrip_works_for_authenticated_user(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    client = TestClient(server.app)
    client.post("/api/auth/telegram/web", json=_web_auth_payload("123456:telegram-test-token"))

    save_response = client.post(
        "/api/account/servers",
        json={
            "ssh": {"host": "1.2.3.4", "user": "root", "port": 2222, "password": "secret"},
            "protocol": "xray",
            "listen_port": 443,
            "proxy_sni": "www.microsoft.com",
            "relay": {
                "ssh": {"host": "10.20.30.40", "user": "root", "port": 22, "password": "relay-secret"},
                "public_host": "relay.example.com",
                "listen_port": 7443,
            },
        },
    )
    assert save_response.status_code == 200
    payload = save_response.json()
    assert payload["ok"] is True
    assert payload["server"]["host"] == "1.2.3.4"
    assert payload["server"]["ssh_port"] == 2222
    assert payload["server"]["relay_enabled"] is True
    assert payload["server"]["relay_public_host"] == "relay.example.com"

    list_response = client.get("/api/account/servers")
    assert list_response.status_code == 200
    servers = list_response.json()["servers"]
    assert len(servers) == 1
    assert servers[0]["has_password"] is True
    assert servers[0]["mode"] == "xray"
    assert servers[0]["relay_enabled"] is True


def test_saved_server_access_requires_pin_unlock(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    client = TestClient(server.app)
    client.post("/api/auth/telegram/web", json=_web_auth_payload("123456:telegram-test-token"))
    save_response = client.post(
        "/api/account/servers",
        json={
            "ssh": {"host": "1.2.3.4", "user": "root", "port": 22, "password": "secret"},
            "protocol": "amneziawg",
        },
    )
    server_id = save_response.json()["server"]["id"]

    pin_response = client.post("/api/account/pin", json={"enabled": True, "pin": "1234"})
    assert pin_response.status_code == 200
    assert pin_response.json()["pin_enabled"] is True
    assert client.get("/api/auth/me").json()["pin_required"] is True

    locked_status = client.post("/api/server/status", json={"saved_server_id": server_id, "protocol": "amneziawg"})
    assert locked_status.status_code == 200
    assert locked_status.json()["ok"] is False
    assert "PIN" in locked_status.json()["error"]

    observed: dict[str, str] = {}

    @contextmanager
    def fake_ssh_connection(ssh_payload, session_id=None, saved_server_id=None, request=None, logger=None):
        observed["host"] = ssh_payload.host
        observed["user"] = ssh_payload.user
        observed["password"] = ssh_payload.password
        yield object(), ssh_payload

    monkeypatch.setattr(server, "_ssh_connection", fake_ssh_connection)
    monkeypatch.setattr(
        server,
        "_detect_server_status",
        lambda _ssh: {"configured": True, "protocol": "amneziawg", "listen_port": 51820, "clients_count": 2},
    )

    unlock_response = client.post("/api/account/pin/unlock", json={"pin": "1234"})
    assert unlock_response.status_code == 200
    assert unlock_response.json()["pin_required"] is False

    ready_status = client.post("/api/server/status", json={"saved_server_id": server_id, "protocol": "amneziawg"})
    assert ready_status.status_code == 200
    assert ready_status.json()["ok"] is True
    assert ready_status.json()["configured"] is True
    assert observed == {"host": "1.2.3.4", "user": "root", "password": "secret"}


def test_session_login_requires_authenticated_account(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    client = TestClient(server.app)

    response = client.post(
        "/api/sessions/login",
        json={"ssh": {"host": "1.2.3.4", "user": "root", "password": "secret", "port": 22}},
    )

    assert response.status_code == 401
    assert "Telegram login required" in response.text


def test_clients_export_retries_after_transient_ssh_failure(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    client = TestClient(server.app)
    client.post("/api/auth/telegram/web", json=_web_auth_payload("123456:telegram-test-token"))
    attempts = {"count": 0}

    @contextmanager
    def flaky_ssh_connection(ssh_payload, session_id=None, saved_server_id=None, request=None, logger=None):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise EOFError()
        if logger is not None:
            logger("connected")
        yield object(), ssh_payload

    class FakeWGProvisioner:
        def __init__(self, ssh, **kwargs):
            self.ssh = ssh

        def export_client(self, client_name: str) -> dict[str, str]:
            assert client_name == "Alina-Iphone"
            return {
                "name": client_name,
                "config": "[Interface]\nPrivateKey = test\n",
                "ip": "10.11.0.23/32",
                "interface": "awg1",
            }

    monkeypatch.setattr(server, "_ssh_connection", flaky_ssh_connection)
    monkeypatch.setattr(server, "WireGuardProvisioner", FakeWGProvisioner)

    response = client.post(
        "/api/clients/export",
        json={
            "ssh": {"host": "1.2.3.4", "user": "root", "password": "secret", "port": 22},
            "protocol": "amneziawg",
            "client_name": "Alina-Iphone",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["client_name"] == "Alina-Iphone"
    assert payload["client_ip"] == "10.11.0.23/32"
    assert payload["config"].startswith("[Interface]")
    assert payload["download_id"]
    assert payload["qr_png_base64"]
    assert attempts["count"] == 2
