from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from vpn_wizard import server
from vpn_wizard.public_access import RateLimitExceeded


class PublicStub:
    def __init__(self):
        self.selected = SimpleNamespace(id="nl", host="localhost")
        self.registry = SimpleNamespace(get_server=lambda name: self.selected if name == "nl" else None,
                                        offerable=[self.selected])
        self.requests = []

    def bootstrap_device(self, **kwargs):
        return "test-device-cookie"

    def issue(self, **kwargs):
        self.requests.append(kwargs)
        return SimpleNamespace(config="[Interface]\nPrivateKey = test-fixture\n",
                               filename="FVPN-nl.conf", device_cookie="test-device-cookie")


@pytest.fixture
def public_client(monkeypatch):
    stub = PublicStub()
    monkeypatch.setattr(server, "_public_service", lambda: stub)
    return TestClient(server.app, base_url="https://vpn.example"), stub


@pytest.mark.parametrize("format", ["config", "qr"])
def test_public_config_requires_same_origin_and_bootstrap(public_client, format):
    client, stub = public_client
    assert client.post(f"/api/public/awg/{format}", json={"server_id": "nl"}).status_code == 403
    assert client.post(f"/api/public/awg/{format}", json={"server_id": "nl"},
                       headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post(f"/api/public/awg/{format}", json={"server_id": "nl"},
                       headers={"Origin": "https://vpn.example"}).status_code == 428
    assert not stub.requests


def test_anonymous_download_is_private_and_does_not_need_code_or_account(public_client):
    client, stub = public_client
    headers = {"Origin": "https://vpn.example"}
    boot = client.post("/api/public/awg/device", json={}, headers=headers)
    assert boot.status_code == 200
    assert boot.json() == {"ok": True}
    assert all(flag in boot.headers["set-cookie"].lower() for flag in ["secure", "httponly", "samesite=lax"])
    for _ in range(2):
        result = client.post("/api/public/awg/config", json={"server_id": "nl"}, headers=headers)
        assert result.status_code == 200
        assert result.headers["cache-control"] == "no-store"
        assert result.headers["content-type"] == "application/octet-stream"
        assert result.headers["content-disposition"] == 'attachment; filename="FVPN-nl.conf"'
    assert stub.requests[0]["device_token"] == stub.requests[1]["device_token"]


def test_public_qr_returns_private_png_for_same_device_profile(public_client, monkeypatch):
    client, stub = public_client
    headers = {"Origin": "https://vpn.example"}
    client.post("/api/public/awg/device", json={}, headers=headers)
    generated = []
    config_response = client.post("/api/public/awg/config", json={"server_id": "nl"}, headers=headers)

    def build_png(config):
        generated.append(config)
        return b"\x89PNG\r\n\x1a\nfixture"

    monkeypatch.setattr(server, "_build_qr_png", build_png)
    response = client.post("/api/public/awg/qr", json={"server_id": "nl"}, headers=headers)
    assert response.status_code == 200
    assert response.content == b"\x89PNG\r\n\x1a\nfixture"
    assert response.headers["content-type"] == "image/png"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "privatekey" not in response.text.lower()
    assert generated == [config_response.text]
    assert len(stub.requests) == 2
    assert stub.requests[0]["device_token"] == stub.requests[1]["device_token"]
    assert stub.requests[0]["server_id"] == "nl"
    assert stub.requests[0]["device_token"] == client.cookies[server.PUBLIC_DEVICE_COOKIE]


def test_public_qr_rejects_bad_origin_and_unknown_server(public_client):
    client, stub = public_client
    headers = {"Origin": "https://vpn.example"}
    assert client.post("/api/public/awg/qr", json={"server_id": "nl"}).status_code == 403
    assert client.post("/api/public/awg/qr", json={"server_id": "nl"},
                       headers={"Origin": "https://evil.example"}).status_code == 403
    client.post("/api/public/awg/device", json={}, headers=headers)
    response = client.post("/api/public/awg/qr", json={"server_id": "missing"}, headers=headers)
    assert response.status_code == 503
    assert not stub.requests


@pytest.mark.parametrize("format", ["config", "qr"])
def test_public_rate_limit_and_failures_do_not_leak_secrets(public_client, monkeypatch, format):
    client, stub = public_client
    headers = {"Origin": "https://vpn.example"}
    client.post("/api/public/awg/device", json={}, headers=headers)
    def limited(**kwargs):
        raise RateLimitExceeded(15)
    monkeypatch.setattr(stub, "issue", limited)
    response = client.post(f"/api/public/awg/{format}", json={"server_id": "nl"}, headers=headers)
    assert response.status_code == 429 and response.headers["retry-after"] == "15"
    def failure(**kwargs):
        raise RuntimeError("PrivateKey = do-not-expose")
    monkeypatch.setattr(stub, "issue", failure)
    response = client.post(f"/api/public/awg/{format}", json={"server_id": "nl"}, headers=headers)
    assert response.status_code == 502
    assert "PrivateKey" not in response.text


@pytest.mark.parametrize("format", ["config", "qr"])
def test_new_device_and_disabled_servers_cannot_bypass_bootstrap(public_client, format):
    client, _ = public_client
    headers = {"Origin": "https://vpn.example"}
    client.post("/api/public/awg/device", json={}, headers=headers)
    assert client.post(f"/api/public/awg/{format}", json={"server_id": "nl", "new_device": True},
                       headers=headers).status_code == 400
    assert client.post(f"/api/public/awg/{format}", json={"server_id": "off"}, headers=headers).status_code == 503
    assert client.post("/api/public/awg/device", json={}, headers={**headers, "Sec-Fetch-Site": "cross-site"}).status_code == 403
