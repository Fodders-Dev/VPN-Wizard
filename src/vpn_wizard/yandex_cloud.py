"""Yandex Cloud REST client for whitelist-friendly proxy provisioning.

Exchanges a Yandex passport OAuth token for an IAM token (cached, auto-refreshed)
and creates an API Gateway that forwards HTTPS traffic from a *.apigw.yandexcloud.net
domain (whitelisted by most RU mobile networks) to a user-controlled VPS endpoint.

Stdlib-only on purpose: no new runtime dependency.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib import error, parse, request


IAM_TOKENS_URL = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
RESOURCE_MANAGER_BASE = "https://resource-manager.api.cloud.yandex.net/resource-manager/v1"
API_GATEWAY_BASE = "https://serverless-apigateway.api.cloud.yandex.net/apigateways/v1"
OPERATION_BASE = "https://operation.api.cloud.yandex.net/operations"


HttpFn = Callable[[str, str, Optional[dict[str, str]], Optional[bytes]], tuple[int, bytes]]


def _default_http(method: str, url: str, headers: Optional[dict[str, str]], body: Optional[bytes]) -> tuple[int, bytes]:
    req = request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except error.HTTPError as exc:
        return exc.code, exc.read()


class YandexCloudError(RuntimeError):
    def __init__(self, status: int, message: str, *, payload: Optional[dict] = None):
        super().__init__(f"Yandex Cloud API error {status}: {message}")
        self.status = status
        self.payload = payload or {}


def _parse_iam_expires_at(value: Optional[str]) -> float:
    """Parse RFC 3339 timestamp returned by IAM into a unix epoch (seconds)."""
    if not value:
        return time.time() + 3600
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    if "." in raw:
        head, tail = raw.split(".", 1)
        # Python's fromisoformat accepts up to 6 fractional digits; trim extras.
        tz_marker = ""
        for marker in ("+", "-"):
            idx = tail.find(marker, 1)
            if idx > 0:
                tz_marker = tail[idx:]
                tail = tail[:idx]
                break
        tail = tail[:6]
        raw = f"{head}.{tail}{tz_marker}"
    try:
        return datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return time.time() + 3600


class IamTokenManager:
    """Caches and auto-refreshes IAM tokens minted from a Yandex passport OAuth token."""

    def __init__(
        self,
        oauth_token: str,
        *,
        refresh_buffer_seconds: int = 300,
        http: Optional[HttpFn] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        token = (oauth_token or "").strip()
        if not token:
            raise YandexCloudError(0, "OAuth token is empty.")
        self._oauth = token
        self._http = http or _default_http
        self._clock = clock
        self._buffer = max(60, int(refresh_buffer_seconds))
        self._cached_token: Optional[str] = None
        self._cached_expires_at: float = 0.0

    def get(self) -> str:
        if self._cached_token and self._clock() + self._buffer < self._cached_expires_at:
            return self._cached_token
        body = json.dumps({"yandexPassportOauthToken": self._oauth}).encode()
        status, raw = self._http(
            "POST", IAM_TOKENS_URL, {"Content-Type": "application/json"}, body
        )
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            payload = {}
        if status != 200 or not payload.get("iamToken"):
            message = (payload.get("message") if isinstance(payload, dict) else None) or raw[:200].decode(
                "utf-8", errors="replace"
            )
            raise YandexCloudError(status, f"IAM exchange failed: {message}", payload=payload if isinstance(payload, dict) else None)
        self._cached_token = str(payload["iamToken"])
        self._cached_expires_at = _parse_iam_expires_at(payload.get("expiresAt"))
        return self._cached_token

    def invalidate(self) -> None:
        self._cached_token = None
        self._cached_expires_at = 0.0


class YandexCloudClient:
    """Thin REST wrapper for the Yandex Cloud surfaces we need."""

    def __init__(
        self,
        iam: IamTokenManager,
        *,
        http: Optional[HttpFn] = None,
        progress: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._iam = iam
        self._http = http or _default_http
        self._progress = progress or (lambda _msg: None)

    def _request(self, method: str, url: str, *, body: Any = None) -> dict:
        headers = {"Authorization": f"Bearer {self._iam.get()}"}
        raw_body: Optional[bytes] = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw_body = json.dumps(body).encode()
        status, raw = self._http(method, url, headers, raw_body)
        try:
            payload = json.loads(raw or b"{}") if raw else {}
        except json.JSONDecodeError:
            payload = {}
        if status >= 400:
            message = (payload.get("message") if isinstance(payload, dict) else None) or raw[:200].decode(
                "utf-8", errors="replace"
            )
            raise YandexCloudError(status, message, payload=payload if isinstance(payload, dict) else None)
        if not isinstance(payload, dict):
            return {}
        return payload

    def list_clouds(self) -> list[dict]:
        return list(self._request("GET", f"{RESOURCE_MANAGER_BASE}/clouds").get("clouds") or [])

    def list_folders(self, cloud_id: str) -> list[dict]:
        cid = (cloud_id or "").strip()
        if not cid:
            raise YandexCloudError(0, "cloud_id is required to list folders.")
        url = f"{RESOURCE_MANAGER_BASE}/folders?cloudId={parse.quote(cid)}"
        return list(self._request("GET", url).get("folders") or [])

    def resolve_folder(self, *, folder_id: Optional[str] = None, cloud_id: Optional[str] = None) -> dict:
        """Pick a usable folder. Honors explicit folder_id; otherwise first ACTIVE folder in the first cloud."""
        if folder_id:
            return self._request("GET", f"{RESOURCE_MANAGER_BASE}/folders/{parse.quote(folder_id)}")

        clouds = self.list_clouds()
        if not clouds:
            raise YandexCloudError(0, "No Yandex Cloud organizations linked to this account. Activate Yandex Cloud at https://console.yandex.cloud/.")
        candidate_cloud_id = (cloud_id or clouds[0]["id"]).strip()
        folders = self.list_folders(candidate_cloud_id)
        active = [f for f in folders if str(f.get("status", "")).upper() == "ACTIVE"]
        if not active:
            raise YandexCloudError(0, f"No ACTIVE folders in cloud {candidate_cloud_id}.")
        return active[0]

    def list_api_gateways(self, folder_id: str) -> list[dict]:
        url = f"{API_GATEWAY_BASE}/apigateways?folderId={parse.quote(folder_id)}"
        return list(self._request("GET", url).get("apiGateways") or [])

    def find_api_gateway_by_name(self, folder_id: str, name: str) -> Optional[dict]:
        target = (name or "").strip()
        for gw in self.list_api_gateways(folder_id):
            if str(gw.get("name") or "").strip() == target:
                return gw
        return None

    def create_api_gateway(self, *, folder_id: str, name: str, openapi_spec: str, description: str = "") -> dict:
        body = {
            "folderId": folder_id,
            "name": name,
            "description": description or "vpn-wizard whitelist proxy",
            "openapiSpec": openapi_spec,
        }
        operation = self._request("POST", f"{API_GATEWAY_BASE}/apigateways", body=body)
        return self.wait_operation(operation)

    def update_api_gateway(self, *, gateway_id: str, openapi_spec: str) -> dict:
        body = {"openapiSpec": openapi_spec, "updateMask": "openapiSpec"}
        operation = self._request("PATCH", f"{API_GATEWAY_BASE}/apigateways/{parse.quote(gateway_id)}", body=body)
        return self.wait_operation(operation)

    def get_api_gateway(self, gateway_id: str) -> dict:
        return self._request("GET", f"{API_GATEWAY_BASE}/apigateways/{parse.quote(gateway_id)}")

    def wait_operation(self, operation: dict, *, timeout_seconds: int = 180, poll_interval: float = 2.0) -> dict:
        if not isinstance(operation, dict):
            return {}
        if operation.get("done"):
            return operation
        op_id = str(operation.get("id") or "").strip()
        if not op_id:
            return operation
        deadline = time.time() + max(10, int(timeout_seconds))
        last = operation
        while time.time() < deadline:
            time.sleep(poll_interval)
            last = self._request("GET", f"{OPERATION_BASE}/{parse.quote(op_id)}")
            if last.get("done"):
                if isinstance(last.get("error"), dict):
                    raise YandexCloudError(
                        int(last["error"].get("code") or 0) or 0,
                        str(last["error"].get("message") or "operation failed"),
                        payload=last,
                    )
                return last
            self._progress(f"operation {op_id}: still running")
        raise YandexCloudError(0, f"Timed out waiting for operation {op_id}.")


def build_proxy_openapi_spec(
    *,
    backend_url: str,
    title: str = "vpn-wl",
    connect_timeout_s: float = 1.0,
    read_timeout_s: float = 60.0,
) -> str:
    """OpenAPI 3 spec that forwards every path/method to backend_url with the same path appended."""
    base = (backend_url or "").rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise YandexCloudError(0, "backend_url must start with http:// or https://")
    spec = {
        "openapi": "3.0.0",
        "info": {"title": title, "version": "1.0.0"},
        "paths": {
            "/{path+}": {
                "x-yc-apigateway-any-method": {
                    "x-yc-apigateway-integration": {
                        "type": "http",
                        "url": f"{base}/{{path}}",
                        "timeouts": {
                            "connect": float(connect_timeout_s),
                            "read": float(read_timeout_s),
                        },
                    },
                    "parameters": [
                        {
                            "name": "path",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                }
            }
        },
    }
    return json.dumps(spec, ensure_ascii=False, indent=2)


def provision_wl_gateway(
    *,
    oauth_token: str,
    backend_url: str,
    name: str = "vpn-wl",
    folder_id: Optional[str] = None,
    cloud_id: Optional[str] = None,
    progress: Optional[Callable[[str], None]] = None,
    http: Optional[HttpFn] = None,
) -> dict:
    """End-to-end: token → IAM → resolve folder → create-or-update gateway → return public URL.

    Returns: {"gateway_id", "domain", "folder_id", "cloud_id", "operation_id"}
    """
    notify = progress or (lambda _msg: None)
    iam = IamTokenManager(oauth_token, http=http)
    client = YandexCloudClient(iam, http=http, progress=notify)

    notify("Resolving Yandex Cloud folder")
    folder = client.resolve_folder(folder_id=folder_id, cloud_id=cloud_id)
    resolved_folder_id = str(folder.get("id") or "").strip()
    resolved_cloud_id = str(folder.get("cloudId") or cloud_id or "").strip()
    if not resolved_folder_id:
        raise YandexCloudError(0, "Failed to resolve folder id.")

    spec = build_proxy_openapi_spec(backend_url=backend_url, title=name)
    existing = client.find_api_gateway_by_name(resolved_folder_id, name)
    if existing:
        notify(f"Updating existing API gateway {existing.get('id')}")
        result = client.update_api_gateway(gateway_id=str(existing["id"]), openapi_spec=spec)
    else:
        notify(f"Creating API gateway {name!r}")
        result = client.create_api_gateway(folder_id=resolved_folder_id, name=name, openapi_spec=spec)

    response = (result.get("response") or {}) if isinstance(result, dict) else {}
    gateway = response if response.get("id") else client.find_api_gateway_by_name(resolved_folder_id, name) or {}
    domain = str(gateway.get("domain") or "").strip()
    return {
        "gateway_id": str(gateway.get("id") or ""),
        "domain": domain,
        "public_url": f"https://{domain}" if domain else "",
        "folder_id": resolved_folder_id,
        "cloud_id": resolved_cloud_id,
        "operation_id": str(result.get("id") or "") if isinstance(result, dict) else "",
        "status": str(gateway.get("status") or ""),
    }


__all__ = [
    "YandexCloudError",
    "IamTokenManager",
    "YandexCloudClient",
    "build_proxy_openapi_spec",
    "provision_wl_gateway",
    "IAM_TOKENS_URL",
    "RESOURCE_MANAGER_BASE",
    "API_GATEWAY_BASE",
]
