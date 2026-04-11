from __future__ import annotations

import hashlib
import hmac
import paramiko
import time

from fastapi.testclient import TestClient

import vpn_wizard.server as server_module
from vpn_wizard.server import (
    DOWNLOAD_STORE,
    JobStore,
    SSHPayload,
    SessionStore,
    _discover_ssh_port,
    _error_message,
    _is_retryable_ssh_error,
    _split_host_port,
)


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
        "username": "fodder_test",
        "auth_date": now,
    }
    data_check = "\n".join(f"{key}={payload[key]}" for key in sorted(payload))
    digest = hmac.new(hashlib.sha256(bot_token.encode("utf-8")).digest(), data_check.encode("utf-8"), "sha256").hexdigest()
    return {**payload, "hash": digest}


def test_job_store_create_update_and_progress() -> None:
    store = JobStore()
    job = store.create()
    store.append_progress(job.job_id, "step 1")
    store.update(job.job_id, status="running")
    stored = store.get(job.job_id)
    assert stored is not None
    assert stored.status == "running"
    assert stored.progress == ["step 1"]
    assert stored.alternatives is None


def test_download_config_returns_attachment(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    client = TestClient(server_module.app)
    client.post("/api/auth/telegram/web", json=_web_auth_payload("123456:telegram-test-token"))
    download_id = DOWNLOAD_STORE.create("config data", b"png", "demo-profile", owner_user_id=1)
    response = client.get(f"/api/download/{download_id}/config")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.content == b"config data"
    assert response.headers["content-disposition"].endswith('filename="demo-profile.conf"')


def test_download_config_respects_custom_suffix(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    client = TestClient(server_module.app)
    client.post("/api/auth/telegram/web", json=_web_auth_payload("123456:telegram-test-token"))
    download_id = DOWNLOAD_STORE.create("vless://demo", b"png", "demo-profile", suffix="txt", owner_user_id=1)
    response = client.get(f"/api/download/{download_id}/config")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.content == b"vless://demo"
    assert response.headers["content-disposition"].endswith('filename="demo-profile.txt"')


def test_download_qr_returns_png(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)
    client = TestClient(server_module.app)
    client.post("/api/auth/telegram/web", json=_web_auth_payload("123456:telegram-test-token"))
    download_id = DOWNLOAD_STORE.create("config data", b"png", "client 01", owner_user_id=1)
    response = client.get(f"/api/download/{download_id}/qr")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/png")
    assert response.content == b"png"
    assert response.headers["content-disposition"].endswith('filename="client01.png"')


def test_split_host_port_handles_common_formats() -> None:
    assert _split_host_port("example.com:2222") == ("example.com", 2222)
    assert _split_host_port("[2001:db8::1]:2200") == ("2001:db8::1", 2200)
    assert _split_host_port("2001:db8::1") == ("2001:db8::1", None)
    assert _split_host_port("1.2.3.4") == ("1.2.3.4", None)


def test_ssh_payload_normalizes_host_port() -> None:
    payload = SSHPayload(host="example.com:2222", user="root")
    assert payload.host == "example.com"
    assert payload.port == 2222

    explicit_port = SSHPayload(host="example.com:2222", user="root", port=2022)
    assert explicit_port.port == 2022


def test_session_store_create_get_and_revoke() -> None:
    store = SessionStore(ttl_seconds=600, limit=10)
    source = SSHPayload(host="1.2.3.4", user="root", password="secret")
    session_id = store.create(source)
    restored = store.get(session_id)
    assert restored is not None
    assert restored.host == "1.2.3.4"
    assert restored.password == "secret"
    assert store.revoke(session_id) is True
    assert store.get(session_id) is None


def test_discover_ssh_port_prefers_preferred_port(monkeypatch) -> None:
    checked: list[int] = []

    def fake_probe(host: str, port: int, timeout: float = 1.8) -> bool:
        checked.append(port)
        return port == 2200

    monkeypatch.setattr("vpn_wizard.server._probe_ssh_port", fake_probe)
    found, order = _discover_ssh_port("example.com", preferred_port=2200)
    assert found == 2200
    assert checked[0] == 2200
    assert order[0] == 2200


def test_discover_ssh_port_parses_host_embedded_port(monkeypatch) -> None:
    checked: list[int] = []

    def fake_probe(host: str, port: int, timeout: float = 1.8) -> bool:
        checked.append(port)
        return port == 2022

    monkeypatch.setattr("vpn_wizard.server._probe_ssh_port", fake_probe)
    found, order = _discover_ssh_port("example.com:2022")
    assert found == 2022
    assert checked[0] == 2022
    assert order[0] == 2022


def test_ssh_discover_endpoint_returns_error_when_not_found(monkeypatch, tmp_path) -> None:
    _configure_env(monkeypatch, tmp_path)

    def fake_discover(host: str, preferred_port: int | None = None) -> tuple[int | None, list[int]]:
        return None, [22, 2222]

    monkeypatch.setattr("vpn_wizard.server._discover_ssh_port", fake_discover)
    client = TestClient(server_module.app)
    client.post("/api/auth/telegram/web", json=_web_auth_payload("123456:telegram-test-token"))
    response = client.post("/api/ssh/discover-port", json={"host": "example.com"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is False
    assert payload["checked_ports"] == [22, 2222]
    assert payload["error"] is not None


def test_error_message_maps_empty_auth_exception() -> None:
    exc = paramiko.AuthenticationException()
    assert "SSH authentication failed." in _error_message(exc)


def test_error_message_maps_eoferror_to_server_closed_text() -> None:
    exc = EOFError()
    assert "closed by the server before authentication completed" in _error_message(exc)


def test_error_message_preserves_non_empty_text() -> None:
    exc = RuntimeError("custom failure")
    assert _error_message(exc) == "custom failure"


def test_retryable_ssh_error_treats_eof_as_transient() -> None:
    assert _is_retryable_ssh_error(EOFError()) is True


def test_retryable_ssh_error_does_not_retry_auth_failures() -> None:
    assert _is_retryable_ssh_error(paramiko.AuthenticationException()) is False
