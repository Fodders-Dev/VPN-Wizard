from __future__ import annotations

import asyncio

from vpn_wizard.server import (
    DOWNLOAD_STORE,
    JobStore,
    SSHPayload,
    SSHDiscoverRequest,
    ssh_discover_port,
    _discover_ssh_port,
    SessionStore,
    _split_host_port,
    download_config,
    download_qr,
)


def test_job_store_create_update_and_progress() -> None:
    store = JobStore()
    job = store.create()
    store.append_progress(job.job_id, "step 1")
    store.update(job.job_id, status="running")
    stored = store.get(job.job_id)
    assert stored is not None
    assert stored.status == "running"
    assert stored.progress == ["step 1"]


def test_download_config_returns_attachment() -> None:
    download_id = DOWNLOAD_STORE.create("config data", b"png", "demo-profile")
    response = download_config(download_id)
    assert response.media_type == "text/plain"
    assert response.body == b"config data"
    assert response.headers["content-disposition"].endswith('filename="demo-profile.conf"')


def test_download_qr_returns_png() -> None:
    download_id = DOWNLOAD_STORE.create("config data", b"png", "client 01")
    response = download_qr(download_id)
    assert response.media_type == "image/png"
    assert response.body == b"png"
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


def test_ssh_discover_endpoint_returns_error_when_not_found(monkeypatch) -> None:
    def fake_discover(host: str, preferred_port: int | None = None) -> tuple[int | None, list[int]]:
        return None, [22, 2222]

    monkeypatch.setattr("vpn_wizard.server._discover_ssh_port", fake_discover)
    response = asyncio.run(ssh_discover_port(SSHDiscoverRequest(host="example.com")))
    assert response.ok is False
    assert response.checked_ports == [22, 2222]
    assert response.error is not None
