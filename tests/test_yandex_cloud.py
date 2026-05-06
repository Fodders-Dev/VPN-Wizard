from __future__ import annotations

import json

import pytest

from vpn_wizard.yandex_cloud import (
    IamTokenManager,
    YandexCloudClient,
    YandexCloudError,
    build_proxy_openapi_spec,
    provision_wl_gateway,
)


class FakeHttp:
    """Records request/response cycles. Each handler is keyed by (method, url)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict, bytes]] = []
        self._handlers: list[tuple[str, str, callable]] = []

    def on(self, method: str, url_substring: str, responder):
        self._handlers.append((method.upper(), url_substring, responder))
        return self

    def __call__(self, method: str, url: str, headers, body):
        self.calls.append((method, url, dict(headers or {}), body or b""))
        for m, sub, responder in self._handlers:
            if m == method.upper() and sub in url:
                status, payload = responder(method, url, headers or {}, body or b"")
                raw = payload if isinstance(payload, (bytes, bytearray)) else json.dumps(payload).encode()
                return status, raw
        return 404, json.dumps({"message": f"unmatched {method} {url}"}).encode()


def test_iam_token_manager_caches_until_near_expiry():
    clock = [1_000_000.0]
    http = FakeHttp().on(
        "POST",
        "/iam/v1/tokens",
        lambda *_: (200, {"iamToken": "iam-1", "expiresAt": "2099-01-01T00:00:00Z"}),
    )
    iam = IamTokenManager("oauth-x", http=http, clock=lambda: clock[0])

    assert iam.get() == "iam-1"
    assert iam.get() == "iam-1"
    assert len(http.calls) == 1, "second get() should be cached"


def test_iam_token_manager_refreshes_after_expiry():
    clock = [1_000_000.0]
    http = FakeHttp()
    counter = {"n": 0}

    def respond(*_):
        counter["n"] += 1
        return 200, {"iamToken": f"iam-{counter['n']}", "expiresAt": "2099-01-01T00:00:00Z"}

    http.on("POST", "/iam/v1/tokens", respond)
    iam = IamTokenManager("oauth-x", refresh_buffer_seconds=60, http=http, clock=lambda: clock[0])
    assert iam.get() == "iam-1"
    iam.invalidate()
    assert iam.get() == "iam-2"


def test_iam_token_manager_raises_on_failure():
    http = FakeHttp().on("POST", "/iam/v1/tokens", lambda *_: (401, {"message": "bad token"}))
    iam = IamTokenManager("oauth-x", http=http)
    with pytest.raises(YandexCloudError) as exc:
        iam.get()
    assert exc.value.status == 401
    assert "bad token" in str(exc.value)


def test_client_list_clouds_and_folders():
    http = (
        FakeHttp()
        .on("POST", "/iam/v1/tokens", lambda *_: (200, {"iamToken": "iam-X", "expiresAt": "2099-01-01T00:00:00Z"}))
        .on(
            "GET",
            "/resource-manager/v1/clouds",
            lambda *_: (200, {"clouds": [{"id": "cl-1", "name": "main"}]}),
        )
        .on(
            "GET",
            "/resource-manager/v1/folders?cloudId=cl-1",
            lambda *_: (
                200,
                {"folders": [{"id": "fl-1", "name": "default", "status": "ACTIVE", "cloudId": "cl-1"}]},
            ),
        )
    )
    client = YandexCloudClient(IamTokenManager("oauth", http=http), http=http)
    assert [c["id"] for c in client.list_clouds()] == ["cl-1"]
    assert [f["id"] for f in client.list_folders("cl-1")] == ["fl-1"]


def test_resolve_folder_picks_first_active_when_no_id_given():
    http = (
        FakeHttp()
        .on("POST", "/iam/v1/tokens", lambda *_: (200, {"iamToken": "iam-X", "expiresAt": "2099-01-01T00:00:00Z"}))
        .on("GET", "/resource-manager/v1/clouds", lambda *_: (200, {"clouds": [{"id": "cl-1"}]}))
        .on(
            "GET",
            "/resource-manager/v1/folders?cloudId=cl-1",
            lambda *_: (
                200,
                {
                    "folders": [
                        {"id": "fl-deleted", "name": "old", "status": "DELETING", "cloudId": "cl-1"},
                        {"id": "fl-active", "name": "default", "status": "ACTIVE", "cloudId": "cl-1"},
                    ]
                },
            ),
        )
    )
    client = YandexCloudClient(IamTokenManager("oauth", http=http), http=http)
    folder = client.resolve_folder()
    assert folder["id"] == "fl-active"


def test_resolve_folder_raises_when_no_clouds():
    http = (
        FakeHttp()
        .on("POST", "/iam/v1/tokens", lambda *_: (200, {"iamToken": "iam-X", "expiresAt": "2099-01-01T00:00:00Z"}))
        .on("GET", "/resource-manager/v1/clouds", lambda *_: (200, {"clouds": []}))
    )
    client = YandexCloudClient(IamTokenManager("oauth", http=http), http=http)
    with pytest.raises(YandexCloudError) as exc:
        client.resolve_folder()
    assert "Activate Yandex Cloud" in str(exc.value)


def test_build_proxy_openapi_spec_targets_backend_with_path_capture():
    raw = build_proxy_openapi_spec(backend_url="https://1-2-3-4.sslip.io:8443")
    spec = json.loads(raw)
    paths = spec["paths"]
    assert "/{path+}" in paths
    integration = paths["/{path+}"]["x-yc-apigateway-any-method"]["x-yc-apigateway-integration"]
    assert integration["type"] == "http"
    assert integration["url"] == "https://1-2-3-4.sslip.io:8443/{path}"
    assert integration["headers"] == {"*": "*", "Host": "1-2-3-4.sslip.io"}
    assert integration["query"] == {"*": "*"}
    assert integration["timeouts"]["read"] >= 30


def test_build_proxy_openapi_spec_rejects_non_http_url():
    with pytest.raises(YandexCloudError):
        build_proxy_openapi_spec(backend_url="ssh://example.com")


def test_build_proxy_openapi_spec_rejects_url_without_hostname():
    # Without a hostname we can't compute the Host header override that
    # makes the upstream TLS validation pass. Bail loudly.
    with pytest.raises(YandexCloudError):
        build_proxy_openapi_spec(backend_url="https:///some/path")


def test_build_proxy_openapi_spec_host_header_pins_backend_hostname_not_port():
    # Host header must be just the hostname (no :port). curl/Go/Node TLS
    # validation strips the port too, but explicit is safer than implicit.
    raw = build_proxy_openapi_spec(backend_url="https://rodnya-tree.ru:9443")
    spec = json.loads(raw)
    integration = spec["paths"]["/{path+}"]["x-yc-apigateway-any-method"]["x-yc-apigateway-integration"]
    assert integration["headers"]["Host"] == "rodnya-tree.ru"


def test_provision_wl_gateway_creates_when_missing(monkeypatch):
    operation_state = {"done": False}

    def respond_create(method, url, headers, body):
        payload = json.loads(body)
        assert payload["folderId"] == "fl-1"
        assert payload["name"] == "vpn-wl"
        assert "openapi" in payload["openapiSpec"]
        return 200, {"id": "op-1", "done": False}

    def respond_op(*_):
        if not operation_state["done"]:
            operation_state["done"] = True
            return 200, {"id": "op-1", "done": False}
        return 200, {
            "id": "op-1",
            "done": True,
            "response": {
                "id": "gw-1",
                "name": "vpn-wl",
                "domain": "abcd.apigw.yandexcloud.net",
                "status": "ACTIVE",
            },
        }

    http = (
        FakeHttp()
        .on("POST", "/iam/v1/tokens", lambda *_: (200, {"iamToken": "iam-X", "expiresAt": "2099-01-01T00:00:00Z"}))
        .on("GET", "/resource-manager/v1/clouds", lambda *_: (200, {"clouds": [{"id": "cl-1"}]}))
        .on(
            "GET",
            "/resource-manager/v1/folders?cloudId=cl-1",
            lambda *_: (200, {"folders": [{"id": "fl-1", "status": "ACTIVE", "cloudId": "cl-1"}]}),
        )
        .on(
            "GET",
            "/apigateways/v1/apigateways?folderId=fl-1",
            lambda *_: (200, {"apiGateways": []}),
        )
        .on("POST", "/apigateways/v1/apigateways", respond_create)
        .on("GET", "/operations/op-1", respond_op)
    )

    # short-circuit time.sleep so tests stay fast
    import vpn_wizard.yandex_cloud as yc

    monkeypatch.setattr(yc.time, "sleep", lambda _s: None)

    result = provision_wl_gateway(
        oauth_token="oauth",
        backend_url="https://1-2-3-4.sslip.io:8443",
        http=http,
    )
    assert result["gateway_id"] == "gw-1"
    assert result["domain"] == "abcd.apigw.yandexcloud.net"
    assert result["public_url"].startswith("https://abcd.apigw")
    assert result["folder_id"] == "fl-1"


def test_provision_wl_gateway_updates_when_existing(monkeypatch):
    def respond_patch(*_):
        return 200, {
            "id": "op-2",
            "done": True,
            "response": {
                "id": "gw-existing",
                "name": "vpn-wl",
                "domain": "existing.apigw.yandexcloud.net",
                "status": "ACTIVE",
            },
        }

    http = (
        FakeHttp()
        .on("POST", "/iam/v1/tokens", lambda *_: (200, {"iamToken": "iam-X", "expiresAt": "2099-01-01T00:00:00Z"}))
        .on("GET", "/resource-manager/v1/clouds", lambda *_: (200, {"clouds": [{"id": "cl-1"}]}))
        .on(
            "GET",
            "/resource-manager/v1/folders?cloudId=cl-1",
            lambda *_: (200, {"folders": [{"id": "fl-1", "status": "ACTIVE", "cloudId": "cl-1"}]}),
        )
        .on(
            "GET",
            "/apigateways/v1/apigateways?folderId=fl-1",
            lambda *_: (
                200,
                {"apiGateways": [{"id": "gw-existing", "name": "vpn-wl", "domain": "existing.apigw.yandexcloud.net"}]},
            ),
        )
        .on("PATCH", "/apigateways/v1/apigateways/gw-existing", respond_patch)
    )

    import vpn_wizard.yandex_cloud as yc
    monkeypatch.setattr(yc.time, "sleep", lambda _s: None)

    result = provision_wl_gateway(
        oauth_token="oauth",
        backend_url="https://1-2-3-4.sslip.io:8443",
        http=http,
    )
    assert result["gateway_id"] == "gw-existing"
    assert result["domain"] == "existing.apigw.yandexcloud.net"


def test_provision_wl_gateway_propagates_operation_error(monkeypatch):
    http = (
        FakeHttp()
        .on("POST", "/iam/v1/tokens", lambda *_: (200, {"iamToken": "iam-X", "expiresAt": "2099-01-01T00:00:00Z"}))
        .on("GET", "/resource-manager/v1/clouds", lambda *_: (200, {"clouds": [{"id": "cl-1"}]}))
        .on(
            "GET",
            "/resource-manager/v1/folders?cloudId=cl-1",
            lambda *_: (200, {"folders": [{"id": "fl-1", "status": "ACTIVE", "cloudId": "cl-1"}]}),
        )
        .on(
            "GET",
            "/apigateways/v1/apigateways?folderId=fl-1",
            lambda *_: (200, {"apiGateways": []}),
        )
        .on("POST", "/apigateways/v1/apigateways", lambda *_: (200, {"id": "op-bad", "done": False}))
        .on(
            "GET",
            "/operations/op-bad",
            lambda *_: (
                200,
                {
                    "id": "op-bad",
                    "done": True,
                    "error": {"code": 13, "message": "OpenAPI spec validation failed"},
                },
            ),
        )
    )

    import vpn_wizard.yandex_cloud as yc
    monkeypatch.setattr(yc.time, "sleep", lambda _s: None)

    with pytest.raises(YandexCloudError) as exc:
        provision_wl_gateway(
            oauth_token="oauth",
            backend_url="https://1-2-3-4.sslip.io:8443",
            http=http,
        )
    assert "OpenAPI spec validation failed" in str(exc.value)
