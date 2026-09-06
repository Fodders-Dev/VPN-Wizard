from __future__ import annotations

from dataclasses import dataclass, field
import base64
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from io import BytesIO
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import time
from urllib.parse import urlencode, urlparse
import tempfile
from typing import Any, Callable, Optional
import threading
import re
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import paramiko
from pydantic import BaseModel, Field, model_validator
import qrcode
import uvicorn

from urllib import request as _owner_notify_request

import vpn_wizard.proxy as proxy_module
from vpn_wizard.account import (
    build_account_store,
    verify_telegram_login,
    verify_telegram_webapp_init_data,
)
from vpn_wizard.core import SSHConfig, SSHRunner, WireGuardProvisioner
from vpn_wizard.awg_fallback import (
    MAX_DEVICE_SLOT,
    AwgFallbackConfig,
    AwgFallbackService,
    device_owner_slot,
    device_peer_id,
    family_guest_id,
    family_issue_token,
    family_owner_id,
    issue_token,
    verify_family_issue_token,
    verify_issue_token,
)
from vpn_wizard.awg_devices import (
    FAMILY_SLOT,
    list_devices,
    peer_id_for_slot,
    revoke_device,
)
from vpn_wizard.awg_servers import AwgRegistry, AwgRegistryError, apply_preset
from vpn_wizard.bot_api import BotApiClient, referral_link, subscription_facts_of
from vpn_wizard.console_proxy import (
    ConsoleProxyConfig,
    normalize_ip,
    sync_ips_file,
)
from vpn_wizard.channel_access import (
    ChannelAccessConfig,
    ChannelAccessError,
    ChannelAccessStatus,
    access_status as channel_access_status,
    telegram_channel_member,
)
from vpn_wizard.metrics import collect as collect_metrics, owner_ids
from vpn_wizard.web_signup import (
    InviteConfig,
    is_web_account,
    InviteError,
    create_invite,
    mint_shared_redemption,
    normalize_code,
    outstanding_invites,
    resolve_invite,
    web_account_id,
)
from vpn_wizard.proxy import ProxyProvisioner, rewrite_vless_alternatives, rewrite_vless_endpoint
from vpn_wizard.relay import RelayProvisioner
from vpn_wizard.remnawave import (
    RemnawaveClient,
    RemnawaveConfig,
    RemnawaveError,
    device_limit_of,
    event_action,
    parse_event,
    telegram_id_of,
    verify_webhook_signature,
)
from vpn_wizard.shadowtls import ShadowTLSSSProvisioner
from vpn_wizard.urls import resolve_public_miniapp_url


app = FastAPI(title="VPN Wizard API")
logger = logging.getLogger("vpn_wizard.server")
APP_STARTED_AT = datetime.now(timezone.utc)
raw_origins = os.getenv("VPNW_CORS_ORIGINS", "")
cors_origins: list[str] = []
if raw_origins:
    for origin in raw_origins.split(","):
        clean = origin.strip().strip("'").strip('"')
        if not clean:
            continue
        if clean == "*":
            cors_origins.append("*")
            continue
        if "://" in clean:
            parsed = urlparse(clean)
            if parsed.scheme and parsed.netloc:
                cors_origins.append(f"{parsed.scheme}://{parsed.netloc}")
                continue
        clean = clean.split("?", 1)[0].split("/", 1)[0]
        if clean:
            cors_origins.append(f"https://{clean}")
            cors_origins.append(f"http://{clean}")

if cors_origins and "*" not in cors_origins:
    cors_origins = list(dict.fromkeys(cors_origins))

print(f"VPN Wizard: Loaded CORS origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _no_store_html(request: Request, call_next):
    """Never let a Telegram WebView keep serving a stale HTML document.

    The /portal and /wizard entry routes set no-store, but the StaticFiles mounts
    covering the same prefixes answer first, so their responses carried only an
    ETag. Telegram's in-app browser caches aggressively and a bumped ?v= query
    only helps the links that carry one — family links point straight at
    awg.html with no version at all. Set it on every HTML response instead;
    hashed assets and API payloads keep their own caching.
    """
    response = await call_next(request)
    if "text/html" in (response.headers.get("content-type") or ""):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

XRAY_PROTOCOLS = {"xray", "vless_reality"}
LEGACY_PROXY_PROTOCOLS = {"shadowtls_ss", "vless_reality"}


def _is_xray_protocol(protocol: Optional[str]) -> bool:
    return (protocol or "").strip() in XRAY_PROTOCOLS


def _is_legacy_proxy_protocol(protocol: Optional[str]) -> bool:
    return (protocol or "").strip() in LEGACY_PROXY_PROTOCOLS


class SSHPayload(BaseModel):
    host: str = Field(..., examples=["1.2.3.4"])
    user: str = Field(..., examples=["root"])
    port: int = 22
    password: Optional[str] = None
    key_path: Optional[str] = None
    key_content: Optional[str] = None

    @model_validator(mode="after")
    def normalize(self) -> "SSHPayload":
        host, parsed_port = _split_host_port(self.host)
        self.host = host
        self.user = (self.user or "").strip()
        if parsed_port is not None and self.port == 22:
            self.port = parsed_port
        if not self.host:
            raise ValueError("SSH host is required.")
        if not self.user:
            raise ValueError("SSH user is required.")
        if not 1 <= self.port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535.")
        return self


class RelayPayload(BaseModel):
    ssh: SSHPayload
    public_host: Optional[str] = None
    listen_port: Optional[int] = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def normalize(self) -> "RelayPayload":
        clean_public_host, parsed_port = _split_host_port(self.public_host or "")
        if clean_public_host:
            self.public_host = clean_public_host
            if parsed_port is not None and self.listen_port is None:
                self.listen_port = parsed_port
        else:
            self.public_host = self.ssh.host
        return self


def _split_host_port(raw_host: str) -> tuple[str, Optional[int]]:
    host = (raw_host or "").strip()
    if not host:
        return "", None
    if host.startswith("["):
        closing = host.find("]")
        if closing != -1:
            inner = host[1:closing].strip()
            tail = host[closing + 1 :].strip()
            if tail.startswith(":") and tail[1:].isdigit():
                return inner, int(tail[1:])
            return inner, None
    if host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if left and right.isdigit():
            return left.strip(), int(right)
    return host, None


def _parse_discovery_ports(raw: str) -> tuple[int, ...]:
    values: list[int] = []
    for chunk in (raw or "").split(","):
        item = chunk.strip()
        if not item:
            continue
        if not item.isdigit():
            continue
        port = int(item)
        if 1 <= port <= 65535:
            values.append(port)
    deduped = list(dict.fromkeys(values))
    if not deduped:
        deduped = [22, 2222, 22022, 2200, 2022, 10022]
    return tuple(deduped)


SSH_DISCOVERY_PORTS = _parse_discovery_ports(
    os.getenv("VPNW_SSH_DISCOVERY_PORTS", "22,2222,22022,2200,2022,10022")
)
SSH_DISCOVERY_TIMEOUT = float(os.getenv("VPNW_SSH_DISCOVERY_TIMEOUT", "1.8"))


def _ordered_discovery_ports(preferred_port: Optional[int] = None) -> list[int]:
    ports = list(SSH_DISCOVERY_PORTS)
    if preferred_port is not None and 1 <= preferred_port <= 65535:
        ports = [preferred_port] + [port for port in ports if port != preferred_port]
    return ports


def _probe_ssh_port(host: str, port: int, timeout: float = SSH_DISCOVERY_TIMEOUT) -> bool:
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(128).decode("ascii", "ignore").strip()
        return banner.startswith("SSH-")
    except Exception:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _discover_ssh_port(host: str, preferred_port: Optional[int] = None) -> tuple[Optional[int], list[int]]:
    checked: list[int] = []
    clean_host, parsed = _split_host_port(host)
    if not clean_host:
        raise ValueError("SSH host is required.")
    first_port = preferred_port if preferred_port is not None else parsed
    for port in _ordered_discovery_ports(first_port):
        checked.append(port)
        if _probe_ssh_port(clean_host, port):
            return port, checked
    return None, checked


def _error_message(exc: Exception) -> str:
    message = str(exc).strip()
    if message:
        return message
    if isinstance(exc, EOFError):
        return (
            "SSH login was closed by the server before authentication completed. "
            "This usually means root/password login is being rejected for the app backend IP, "
            "or the server is rate-limiting or filtering this connection."
        )
    if isinstance(exc, paramiko.AuthenticationException):
        return (
            "SSH authentication failed. Check the password or key and make sure the server allows "
            "password login for this user from the app backend."
        )
    if isinstance(exc, paramiko.BadHostKeyException):
        return "SSH host key verification failed."
    if isinstance(exc, paramiko.ssh_exception.NoValidConnectionsError):
        return "Could not open an SSH connection to the server on the selected port."
    if isinstance(exc, paramiko.SSHException):
        return (
            "SSH session could not be established. The server may be rejecting this connection, "
            "rate-limiting the backend IP, or requiring a different auth method."
        )
    if isinstance(exc, TimeoutError):
        return "The SSH connection timed out."
    return exc.__class__.__name__.replace("_", " ")


def _ssh_target_label(payload: Optional[SSHPayload]) -> str:
    if payload is None:
        return "session-or-saved-server"
    return f"{payload.user}@{payload.host}:{payload.port}"


def _is_retryable_ssh_error(exc: Exception) -> bool:
    if isinstance(exc, paramiko.AuthenticationException):
        return False
    if isinstance(exc, (EOFError, TimeoutError, paramiko.SSHException, paramiko.ssh_exception.NoValidConnectionsError)):
        return True
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "ssh login was closed by the server before authentication completed",
            "connection closed by remote host",
            "connection reset by peer",
            "the ssh connection timed out",
            "could not open an ssh connection",
        )
    )


def _run_ssh_action_with_retries(
    *,
    action_name: str,
    request_id: str,
    target: str,
    operation: Callable[[int], object],
) -> object:
    last_exc: Optional[Exception] = None
    for attempt in range(1, 4):
        try:
            result = operation(attempt)
            last_exc = None
            return result
        except Exception as exc:
            last_exc = exc
            if attempt >= 3 or not _is_retryable_ssh_error(exc):
                raise
            logger.info(
                "%s.retry req=%s attempt=%s target=%s error=%s",
                action_name,
                request_id,
                attempt,
                target,
                _error_message(exc),
            )
            time.sleep(1.2 * attempt)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"{action_name} did not produce a result")


class AuthRequest(BaseModel):
    ssh: Optional[SSHPayload] = None
    session_id: Optional[str] = None
    saved_server_id: Optional[str] = None
    protocol: Optional[str] = None
    relay: Optional[RelayPayload] = None


class SSHDiscoverRequest(BaseModel):
    host: str = Field(..., examples=["1.2.3.4"])
    port: Optional[int] = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def normalize(self) -> "SSHDiscoverRequest":
        self.host = (self.host or "").strip()
        if not self.host:
            raise ValueError("SSH host is required.")
        return self


class SSHDiscoverResponse(BaseModel):
    ok: bool
    host: Optional[str] = None
    port: Optional[int] = None
    checked_ports: list[int] = Field(default_factory=list)
    error: Optional[str] = None


class ProvisionOptions(BaseModel):
    client_name: str = "client1"
    client_ip: Optional[str] = None
    server_cidr: str = "10.10.0.1/24"
    listen_port: Optional[int] = None
    dns: str = "1.1.1.1, 1.0.0.1"
    mtu: Optional[int] = None
    auto_mtu: bool = True
    tune: bool = True
    check: bool = True
    protocol: str = "amneziawg"
    proxy_sni: Optional[str] = None


class ProvisionRequest(BaseModel):
    ssh: Optional[SSHPayload] = None
    session_id: Optional[str] = None
    saved_server_id: Optional[str] = None
    relay: Optional[RelayPayload] = None
    options: ProvisionOptions = Field(default_factory=ProvisionOptions)


class CheckItem(BaseModel):
    name: str
    ok: bool
    details: Optional[str] = None


class ProvisionResponse(BaseModel):
    ok: bool
    config: Optional[str] = None
    alternatives: Optional[list[dict]] = None
    auto_config: Optional[str] = None
    qr_png_base64: Optional[str] = None
    download_id: Optional[str] = None
    auto_download_id: Optional[str] = None
    checks: list[CheckItem] = Field(default_factory=list)
    error: Optional[str] = None


class RollbackRequest(AuthRequest):
    pass


class RollbackResponse(BaseModel):
    ok: bool
    backup: Optional[str] = None
    error: Optional[str] = None


class ClientRequest(AuthRequest):
    client_name: Optional[str] = None
    client_ip: Optional[str] = None
    listen_port: Optional[int] = None


class ClientRemoveRequest(AuthRequest):
    client_name: str
    listen_port: Optional[int] = None


class ClientListResponse(BaseModel):
    ok: bool
    clients: list[dict] = Field(default_factory=list)
    error: Optional[str] = None


class ClientAddResponse(BaseModel):
    ok: bool
    client_name: Optional[str] = None
    client_ip: Optional[str] = None
    config: Optional[str] = None
    alternatives: Optional[list[dict]] = None
    auto_config: Optional[str] = None
    qr_png_base64: Optional[str] = None
    download_id: Optional[str] = None
    auto_download_id: Optional[str] = None
    interface: Optional[str] = None
    error: Optional[str] = None


class ClientExportResponse(BaseModel):
    ok: bool
    client_name: Optional[str] = None
    client_ip: Optional[str] = None
    config: Optional[str] = None
    alternatives: Optional[list[dict]] = None
    auto_config: Optional[str] = None
    qr_png_base64: Optional[str] = None
    download_id: Optional[str] = None
    auto_download_id: Optional[str] = None
    interface: Optional[str] = None
    error: Optional[str] = None


class JobCreateResponse(BaseModel):
    job_id: str


class JobStatus(BaseModel):
    job_id: str
    status: str
    progress: list[str] = Field(default_factory=list)
    checks: list[CheckItem] = Field(default_factory=list)
    error: Optional[str] = None
    config_ready: bool = False
    alternatives: Optional[list[dict]] = None
    auto_config_ready: bool = False


class SessionLoginRequest(BaseModel):
    ssh: SSHPayload


class SessionRevokeRequest(BaseModel):
    session_id: str


class SessionLoginResponse(BaseModel):
    ok: bool
    session_id: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    port: Optional[int] = None
    error: Optional[str] = None


class TelegramMiniAppAuthRequest(BaseModel):
    init_data: str


class TelegramWebAuthRequest(BaseModel):
    id: int
    auth_date: int
    hash: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    photo_url: Optional[str] = None
    language_code: Optional[str] = None


class AuthConfigResponse(BaseModel):
    ok: bool
    browser_login_enabled: bool
    miniapp_login_enabled: bool
    telegram_bot_username: Optional[str] = None
    canonical_miniapp_url: str


class CurrentUserResponse(BaseModel):
    ok: bool
    authenticated: bool
    user: Optional[dict] = None
    pin_enabled: bool = False
    pin_required: bool = False
    error: Optional[str] = None


class PortalLinksResponse(BaseModel):
    ok: bool
    personal_vpn_url: str
    family_vpn_url: str
    server_wizard_url: str
    subscription_active: bool = False
    device_limit: int = 1
    referral_url: Optional[str] = None
    # Remnawave knows the entitlement but not whether anyone paid for it. Only
    # the billing bot knows a trial is a trial, and a cabinet that cannot tell
    # the difference says "подписка активна" to someone whose free week ends
    # tonight — and never mentions money.
    is_trial: bool = False
    expires_at: Optional[str] = None
    traffic_limit_gb: Optional[float] = None
    traffic_used_gb: Optional[float] = None
    channel_access_enabled: bool = False
    channel_access_active: bool = False
    channel_access_available: bool = False
    channel_access_kind: Optional[str] = None
    channel_access_channel_url: Optional[str] = None
    channel_access_server_id: Optional[str] = None
    channel_access_grace_expires_at: Optional[int] = None


class ConsoleProxyResponse(BaseModel):
    ok: bool
    enabled: bool = False
    entitled: bool = False
    host: Optional[str] = None
    port: Optional[int] = None
    ips: list[dict[str, Any]] = []
    limit: int = 2
    bound_ip: Optional[str] = None


class ChannelAccessVerifyResponse(BaseModel):
    ok: bool
    active: bool
    personal_vpn_url: str
    server_id: str


class AwgAccessResponse(BaseModel):
    ok: bool
    active: bool
    device_limit: int
    family: bool = False
    expires_at: Optional[str] = None


class InviteCreateResponse(BaseModel):
    ok: bool
    code: str
    expires_at: Optional[int] = None
    url: Optional[str] = None


class InviteListResponse(BaseModel):
    ok: bool
    max_outstanding: int
    grace_hours: int
    invites: list[dict[str, Any]]


class InviteCheckResponse(BaseModel):
    ok: bool
    valid: bool
    grace_hours: int = 0
    detail: Optional[str] = None


class InviteRedeemResponse(BaseModel):
    ok: bool
    telegram_id: int
    token: str
    grace_hours: int
    grace_expires_at: int
    server_id: str
    bind_url: str


class InviteLinkResponse(BaseModel):
    ok: bool
    linked: bool
    personal_vpn_url: str
    server_id: str


class AwgDeviceListResponse(BaseModel):
    ok: bool
    device_limit: int
    devices: list[dict[str, Any]]


class AwgDeviceLabelRequest(BaseModel):
    label: Optional[str] = None


class AwgDeviceActionResponse(BaseModel):
    ok: bool
    slot: int
    revoked_from: int = 0
    label: Optional[str] = None


class SavedServerRequest(BaseModel):
    label: Optional[str] = None
    server_id: Optional[str] = None
    ssh: SSHPayload
    protocol: Optional[str] = None
    listen_port: Optional[int] = None
    proxy_sni: Optional[str] = None
    relay: Optional[RelayPayload] = None


class SavedServerRenameRequest(BaseModel):
    label: Optional[str] = None


class SavedServerListResponse(BaseModel):
    ok: bool
    servers: list[dict] = Field(default_factory=list)
    error: Optional[str] = None


class SavedServerResponse(BaseModel):
    ok: bool
    server: Optional[dict] = None
    error: Optional[str] = None


class PinConfigureRequest(BaseModel):
    enabled: bool
    pin: Optional[str] = None


class PinUnlockRequest(BaseModel):
    pin: str


class PinResponse(BaseModel):
    ok: bool
    pin_enabled: bool = False
    pin_required: bool = False
    error: Optional[str] = None


@dataclass
class TempKey:
    path: Optional[str] = None

    def cleanup(self) -> None:
        if self.path and Path(self.path).exists():
            try:
                Path(self.path).unlink()
            except OSError:
                pass


def _write_temp_key(content: str) -> TempKey:
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
    tmp.write(content)
    tmp.flush()
    tmp.close()
    os.chmod(tmp.name, 0o600)
    return TempKey(path=tmp.name)


def _build_qr_base64(config: str) -> str:
    return base64.b64encode(_build_qr_png(config)).decode("ascii")


def _build_qr_png(config: str) -> bytes:
    img = qrcode.make(config)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@dataclass
class Job:
    job_id: str
    owner_user_id: Optional[int] = None
    status: str = "queued"
    progress: list[str] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    config: Optional[str] = None
    alternatives: Optional[list[dict]] = None
    auto_config: Optional[str] = None
    qr_png_base64: Optional[str] = None
    download_id: Optional[str] = None
    auto_download_id: Optional[str] = None
    client_name: Optional[str] = None
    error: Optional[str] = None
    created_at: float = 0.0
    expires_at: float = 0.0


class JobStore:
    def __init__(self, ttl_seconds: int = 1800) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._ttl_seconds = max(300, ttl_seconds)

    def _cleanup(self, now: float) -> None:
        expired = [job_id for job_id, job in self._jobs.items() if job.expires_at and job.expires_at <= now]
        for job_id in expired:
            self._jobs.pop(job_id, None)

    def create(self, owner_user_id: Optional[int] = None) -> Job:
        job_id = uuid.uuid4().hex
        now = time.time()
        job = Job(
            job_id=job_id,
            owner_user_id=owner_user_id,
            created_at=now,
            expires_at=now + self._ttl_seconds,
        )
        with self._lock:
            self._cleanup(now)
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str, owner_user_id: Optional[int] = None) -> Optional[Job]:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            job = self._jobs.get(job_id)
            if not job:
                return None
            if owner_user_id is not None and job.owner_user_id != owner_user_id:
                return None
            return Job(
                job_id=job.job_id,
                owner_user_id=job.owner_user_id,
                status=job.status,
                progress=list(job.progress),
                checks=list(job.checks),
                config=job.config,
                alternatives=job.alternatives,
                auto_config=job.auto_config,
                qr_png_base64=job.qr_png_base64,
                download_id=job.download_id,
                auto_download_id=job.auto_download_id,
                client_name=job.client_name,
                error=job.error,
                created_at=job.created_at,
                expires_at=job.expires_at,
            )

    def update(self, job_id: str, **kwargs) -> None:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            job = self._jobs.get(job_id)
            if not job:
                return
            for key, value in kwargs.items():
                setattr(job, key, value)
            job.expires_at = now + self._ttl_seconds

    def append_progress(self, job_id: str, message: str) -> None:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            job = self._jobs.get(job_id)
            if not job:
                return
            job.progress.append(message)
            if len(job.progress) > 50:
                job.progress = job.progress[-50:]
            job.expires_at = now + self._ttl_seconds


JOB_STORE = JobStore(ttl_seconds=int(os.getenv("VPNW_JOB_TTL_SECONDS", "1800")))


@dataclass
class DownloadItem:
    config: str
    qr_png: bytes
    name: str
    suffix: str = "conf"
    owner_user_id: Optional[int] = None
    created_at: float = 0.0
    expires_at: float = 0.0


class DownloadStore:
    def __init__(self, limit: int = 200, ttl_seconds: int = 1800) -> None:
        self._items: "OrderedDict[str, DownloadItem]" = OrderedDict()
        self._lock = threading.Lock()
        self._limit = limit
        self._ttl_seconds = max(300, ttl_seconds)

    def _cleanup(self, now: float) -> None:
        expired = [download_id for download_id, item in self._items.items() if item.expires_at and item.expires_at <= now]
        for download_id in expired:
            self._items.pop(download_id, None)
        while len(self._items) > self._limit:
            self._items.popitem(last=False)

    def create(
        self,
        config: str,
        qr_png: bytes,
        name: Optional[str],
        suffix: str = "conf",
        *,
        owner_user_id: Optional[int] = None,
        download_id: Optional[str] = None,
    ) -> str:
        download_id = (download_id or uuid.uuid4().hex).strip() or uuid.uuid4().hex
        safe_name = _safe_name(name)
        safe_suffix = (suffix or "conf").strip().lstrip(".") or "conf"
        now = time.time()
        with self._lock:
            self._cleanup(now)
            self._items[download_id] = DownloadItem(
                config=config,
                qr_png=qr_png,
                name=safe_name,
                suffix=safe_suffix,
                owner_user_id=owner_user_id,
                created_at=now,
                expires_at=now + self._ttl_seconds,
            )
        return download_id

    def get(self, download_id: str, owner_user_id: Optional[int] = None) -> Optional[DownloadItem]:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            item = self._items.get(download_id)
            if item is None:
                return None
            if owner_user_id is not None and item.owner_user_id != owner_user_id:
                return None
            return item


DOWNLOAD_STORE = DownloadStore(
    ttl_seconds=int(os.getenv("VPNW_DOWNLOAD_TTL_SECONDS", "1800")),
)


@dataclass
class SessionItem:
    ssh: SSHPayload
    expires_at: float
    created_at: float
    touched_at: float
    owner_user_id: Optional[int] = None


class SessionStore:
    def __init__(self, ttl_seconds: int = 86400, limit: int = 512) -> None:
        self._items: "OrderedDict[str, SessionItem]" = OrderedDict()
        self._lock = threading.Lock()
        self._ttl_seconds = max(60, ttl_seconds)
        self._limit = max(16, limit)

    def _cleanup(self, now: float) -> None:
        expired = [sid for sid, item in self._items.items() if item.expires_at <= now]
        for sid in expired:
            self._items.pop(sid, None)
        while len(self._items) > self._limit:
            self._items.popitem(last=False)

    def create(self, ssh: SSHPayload, owner_user_id: Optional[int] = None) -> str:
        session_id = uuid.uuid4().hex
        now = time.time()
        item = SessionItem(
            ssh=ssh.model_copy(deep=True),
            expires_at=now + self._ttl_seconds,
            created_at=now,
            touched_at=now,
            owner_user_id=owner_user_id,
        )
        with self._lock:
            self._cleanup(now)
            self._items[session_id] = item
        return session_id

    def get(self, session_id: str, owner_user_id: Optional[int] = None) -> Optional[SSHPayload]:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            item = self._items.get(session_id)
            if not item:
                return None
            if owner_user_id is not None and item.owner_user_id != owner_user_id:
                return None
            item.touched_at = now
            item.expires_at = now + self._ttl_seconds
            self._items.move_to_end(session_id)
            return item.ssh.model_copy(deep=True)

    def revoke(self, session_id: str, owner_user_id: Optional[int] = None) -> bool:
        with self._lock:
            item = self._items.get(session_id)
            if item is None:
                return False
            if owner_user_id is not None and item.owner_user_id != owner_user_id:
                return False
            self._items.pop(session_id, None)
            return True


SESSION_STORE = SessionStore(
    ttl_seconds=int(os.getenv("VPNW_SESSION_TTL_SECONDS", "86400")),
    limit=int(os.getenv("VPNW_SESSION_LIMIT", "512")),
)


class PinUnlockLimiter:
    def __init__(self, threshold: int = 5, window_seconds: int = 600, lockout_seconds: int = 300) -> None:
        self._threshold = max(1, threshold)
        self._window_seconds = max(60, window_seconds)
        self._lockout_seconds = max(60, lockout_seconds)
        self._items: dict[str, dict[str, float | int]] = {}
        self._lock = threading.Lock()

    def _cleanup(self, now: float) -> None:
        expired = [
            session_id
            for session_id, item in self._items.items()
            if float(item.get("locked_until", 0)) <= now and float(item.get("last_failure_at", 0)) + self._window_seconds <= now
        ]
        for session_id in expired:
            self._items.pop(session_id, None)

    def remaining(self, session_id: str) -> int:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            item = self._items.get(session_id)
            if not item:
                return 0
            locked_until = float(item.get("locked_until", 0))
            if locked_until <= now:
                return 0
            return max(1, int(locked_until - now))

    def record_failure(self, session_id: str) -> int:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            item = self._items.get(session_id)
            if item is None or float(item.get("last_failure_at", 0)) + self._window_seconds <= now:
                item = {"count": 0, "last_failure_at": now, "locked_until": 0.0}
            item["count"] = int(item.get("count", 0)) + 1
            item["last_failure_at"] = now
            if int(item["count"]) >= self._threshold:
                item["count"] = 0
                item["locked_until"] = now + self._lockout_seconds
            self._items[session_id] = item
            locked_until = float(item.get("locked_until", 0))
            if locked_until > now:
                return max(1, int(locked_until - now))
            return 0

    def reset(self, session_id: str) -> None:
        with self._lock:
            self._items.pop(session_id, None)


PIN_UNLOCK_LIMITER = PinUnlockLimiter(
    threshold=int(os.getenv("VPNW_PIN_UNLOCK_THRESHOLD", "5")),
    window_seconds=int(os.getenv("VPNW_PIN_UNLOCK_WINDOW_SECONDS", "600")),
    lockout_seconds=int(os.getenv("VPNW_PIN_UNLOCK_LOCKOUT_SECONDS", "300")),
)

APP_SESSION_COOKIE = "vpnw_app_session"


def _account_store():
    return build_account_store()


def _browser_login_enabled() -> bool:
    return bool(_telegram_bot_token(required=False) and (os.getenv("VPNW_BOT_USERNAME") or "").strip())


def _miniapp_login_enabled() -> bool:
    return bool(_telegram_bot_token(required=False))


def _telegram_bot_username() -> Optional[str]:
    value = (os.getenv("VPNW_BOT_USERNAME") or "").strip()
    return value or None


def _app_session_token(request: Request) -> Optional[str]:
    return (request.cookies.get(APP_SESSION_COOKIE) or "").strip() or None


def _current_account(request: Request, *, required: bool = False) -> Optional[dict]:
    session_id = _app_session_token(request)
    if not session_id:
        if required:
            raise HTTPException(status_code=401, detail="Telegram login required.")
        return None
    session = _account_store().get_auth_session(session_id)
    if session is None:
        if required:
            raise HTTPException(status_code=401, detail="Account session expired.")
        return None
    return session


def _require_account(request: Request) -> dict:
    account = _current_account(request, required=True)
    assert account is not None
    return account


def _cookie_secure(request: Request) -> bool:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").split(",")[0].strip().lower()
    return proto == "https"


def _set_auth_cookie(response: Response, request: Request, session_id: str) -> None:
    response.set_cookie(
        APP_SESSION_COOKIE,
        session_id,
        httponly=True,
        max_age=int(os.getenv("VPNW_APP_SESSION_TTL_SECONDS", str(60 * 60 * 24 * 30))),
        samesite="lax",
        secure=_cookie_secure(request),
        path="/",
    )


def _clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(APP_SESSION_COOKIE, path="/")

def _safe_subprocess(args: list[str], timeout_s: float = 0.35) -> str:
    try:
        out = subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=timeout_s)
        return out.decode("utf-8", "ignore").strip()
    except Exception:
        return ""


def _detect_commit_sha() -> Optional[str]:
    # CI/CD environments usually expose one of these.
    for key in (
        "RAILWAY_GIT_COMMIT_SHA",
        "VERCEL_GIT_COMMIT_SHA",
        "GITHUB_SHA",
        "COMMIT_SHA",
        "SOURCE_VERSION",
        "RENDER_GIT_COMMIT",
    ):
        value = (os.getenv(key) or "").strip()
        if value:
            return value

    # Best-effort fallback for environments that keep the git checkout.
    sha = _safe_subprocess(["git", "rev-parse", "HEAD"])
    return sha or None


def _detect_package_version() -> str:
    explicit = (os.getenv("VPNW_VERSION") or "").strip()
    if explicit:
        return explicit

    try:
        return importlib.metadata.version("vpn-wizard")
    except Exception:
        pass

    # When running from source (e.g. Railway Nixpacks with PYTHONPATH=src),
    # package metadata might not be available. Fall back to pyproject.toml.
    candidates: list[Path] = []
    try:
        candidates.append(Path.cwd() / "pyproject.toml")
    except Exception:
        pass
    candidates.append(Path("/app/pyproject.toml"))
    try:
        here = Path(__file__).resolve()
        candidates.extend(root / "pyproject.toml" for root in list(here.parents)[:8])
    except Exception:
        pass

    for pyproject in candidates:
        try:
            if not pyproject.exists():
                continue
            text = pyproject.read_text(encoding="utf-8", errors="ignore")
            match = re.search(r'(?m)^version\\s*=\\s*\"([^\"]+)\"\\s*$', text)
            if match:
                return match.group(1).strip()
        except Exception:
            continue

    # Keep the string stable for UIs; a commit SHA is still returned separately.
    return "dev"


def _iso_utc(ts: datetime) -> str:
    # Always emit an explicit UTC marker to avoid confusion across regions.
    return ts.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class VersionResponse(BaseModel):
    ok: bool
    name: str = "vpn-wizard"
    version: str
    commit_sha: Optional[str] = None
    started_at_utc: str
    now_utc: str


@app.get("/api/version", response_model=VersionResponse)
def api_version() -> Response:
    payload = VersionResponse(
        ok=True,
        version=_detect_package_version(),
        commit_sha=_detect_commit_sha(),
        started_at_utc=_iso_utc(APP_STARTED_AT),
        now_utc=_iso_utc(datetime.now(timezone.utc)),
    ).model_dump()
    # Avoid confusion during rollouts.
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


def _telegram_bot_token(*, required: bool = True) -> str:
    # A combined deployment may hand polling to another process while this API
    # still validates Telegram Login Widget and Mini App initData signatures.
    token = (os.getenv("VPNW_TELEGRAM_AUTH_TOKEN") or os.getenv("VPNW_BOT_TOKEN") or "").strip()
    if not token and required:
        raise HTTPException(status_code=503, detail="Telegram auth is not configured.")
    return token


def _current_user_payload(request: Request) -> CurrentUserResponse:
    account = _current_account(request, required=False)
    if account is None:
        return CurrentUserResponse(ok=True, authenticated=False)
    return CurrentUserResponse(
        ok=True,
        authenticated=True,
        user=account["user"],
        pin_enabled=bool(account["user"].get("pin_enabled")),
        pin_required=bool(account["user"].get("pin_enabled")) and not bool(account["pin_unlocked"]),
    )


@app.get("/api/auth/config", response_model=AuthConfigResponse)
def auth_config(request: Request) -> AuthConfigResponse:
    public_base_url = (os.getenv("VPNW_PUBLIC_BASE_URL") or "").strip().rstrip("/") or None
    resolved_miniapp_url = resolve_public_miniapp_url(
        (os.getenv("VPNW_MINIAPP_URL") or "").strip() or (f"{public_base_url}/miniapp" if public_base_url else None)
    )
    return AuthConfigResponse(
        ok=True,
        browser_login_enabled=_browser_login_enabled(),
        miniapp_login_enabled=_miniapp_login_enabled(),
        telegram_bot_username=_telegram_bot_username(),
        canonical_miniapp_url=resolved_miniapp_url,
    )


@app.get("/api/auth/me", response_model=CurrentUserResponse)
def auth_me(request: Request) -> CurrentUserResponse:
    return _current_user_payload(request)


@app.post("/api/auth/telegram/web", response_model=CurrentUserResponse)
def auth_telegram_web(payload: TelegramWebAuthRequest, request: Request, response: Response) -> CurrentUserResponse:
    try:
        user_payload = verify_telegram_login(payload.model_dump(exclude_none=True), _telegram_bot_token())
        store = _account_store()
        user = store.upsert_user_from_telegram(user_payload)
        session_id = store.create_auth_session(user["id"])
        _set_auth_cookie(response, request, session_id)
        session = store.get_auth_session(session_id)
        assert session is not None
        return CurrentUserResponse(
            ok=True,
            authenticated=True,
            user=session["user"],
            pin_enabled=bool(session["user"].get("pin_enabled")),
            pin_required=bool(session["user"].get("pin_enabled")) and not bool(session["pin_unlocked"]),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _clear_auth_cookie(response)
        return CurrentUserResponse(ok=False, authenticated=False, error=_error_message(exc))


@app.post("/api/auth/telegram/miniapp", response_model=CurrentUserResponse)
def auth_telegram_miniapp(payload: TelegramMiniAppAuthRequest, request: Request, response: Response) -> CurrentUserResponse:
    try:
        user_payload = verify_telegram_webapp_init_data(payload.init_data, _telegram_bot_token())
        store = _account_store()
        user = store.upsert_user_from_telegram(user_payload)
        session_id = store.create_auth_session(user["id"])
        _set_auth_cookie(response, request, session_id)
        session = store.get_auth_session(session_id)
        assert session is not None
        return CurrentUserResponse(
            ok=True,
            authenticated=True,
            user=session["user"],
            pin_enabled=bool(session["user"].get("pin_enabled")),
            pin_required=bool(session["user"].get("pin_enabled")) and not bool(session["pin_unlocked"]),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _clear_auth_cookie(response)
        return CurrentUserResponse(ok=False, authenticated=False, error=_error_message(exc))


@app.post("/api/auth/logout", response_model=CurrentUserResponse)
def auth_logout(request: Request, response: Response) -> CurrentUserResponse:
    session_id = _app_session_token(request)
    if session_id:
        _account_store().revoke_auth_session(session_id)
        PIN_UNLOCK_LIMITER.reset(session_id)
    _clear_auth_cookie(response)
    return CurrentUserResponse(ok=True, authenticated=False)


def _channel_access_personal_url(
    base: str, telegram_id: int, secret: str, server_id: str, *, web: bool = False
) -> str:
    query = urlencode(
        {
            "tid": int(telegram_id),
            "token": issue_token(secret, telegram_id),
            "server": server_id,
            "free": 1,
            **({"web": 1} if web else {}),
        }
    )
    return f"{base}/connect/awg.html?{query}"


@app.get("/api/portal/links", response_model=PortalLinksResponse)
def portal_links(request: Request) -> Response:
    """Return private navigation for the authenticated Telegram user.

    Telegram initData is exchanged for an HttpOnly session before this endpoint
    is called. Tokens are returned only in a no-store response and are never put
    in localStorage by the portal.
    """
    account = _require_account(request)
    telegram_id = int(account["user"]["telegram_id"])
    config = AwgFallbackConfig.from_env()
    if not config.link_secret:
        raise HTTPException(status_code=503, detail="AWG links are not configured.")
    base = _public_base_url_from_request(request)
    if not base:
        raise HTTPException(status_code=503, detail="Public URL is not configured.")
    personal_query = urlencode(
        {"tid": telegram_id, "token": issue_token(config.link_secret, telegram_id)}
    )
    family_query = urlencode(
        {
            "family": telegram_id,
            "token": family_issue_token(
                config.link_secret,
                telegram_id,
                _account_store().awg_family_epoch(telegram_id),
            ),
        }
    )
    channel = ChannelAccessConfig.from_env()
    payload = PortalLinksResponse(
        ok=True,
        personal_vpn_url=f"{base}/connect/awg.html?{personal_query}",
        family_vpn_url=f"{base}/connect/awg.html?{family_query}",
        server_wizard_url=f"{base}/wizard/",
        channel_access_enabled=channel.configured,
        channel_access_channel_url=channel.channel_url if channel.configured else None,
        channel_access_server_id=channel.free_server_id if channel.configured else None,
    )
    try:
        active_user = RemnawaveClient(RemnawaveConfig.from_env()).active_user(telegram_id)
    except RemnawaveError:
        active_user = None
    if active_user:
        payload.subscription_active = True
        payload.device_limit = device_limit_of(active_user)
    try:
        free_access = channel_access_status(
            _account_store(), telegram_id, channel, refresh_membership=False
        )
    except ChannelAccessError:
        free_access = ChannelAccessStatus(configured=channel.configured, active=False)
    payload.channel_access_active = free_access.active
    payload.channel_access_available = bool(channel.configured and not free_access.active)
    payload.channel_access_kind = free_access.kind
    payload.channel_access_grace_expires_at = free_access.grace_expires_at
    if free_access.active and not active_user:
        payload.device_limit = 1
        payload.personal_vpn_url = _channel_access_personal_url(
            base,
            telegram_id,
            config.link_secret,
            free_access.server_id or channel.free_server_id,
        )
    # The invite link must be personal, or nobody is credited for bringing
    # anyone in. The code lives in the bot's database; if it is unreachable the
    # portal simply shows no invite rather than a shared link that rewards no one.
    # One fetch: the referral code and the subscription facts come from the same
    # user object, and this call is already on the portal's critical path.
    bot_user = BotApiClient().user_by_telegram_id(telegram_id)
    code = str((bot_user or {}).get("referral_code") or "").strip() or None
    payload.referral_url = referral_link(os.getenv("VPNW_BOT_USERNAME") or "", code)
    # An unreachable bot must degrade to "we don't know" — the defaults above —
    # never to a confident claim that a trial is a paid subscription.
    facts = subscription_facts_of(bot_user)
    payload.is_trial = bool(facts["is_trial"])
    payload.expires_at = facts["expires_at"]
    payload.traffic_limit_gb = facts["traffic_limit_gb"]
    payload.traffic_used_gb = facts["traffic_used_gb"]
    return JSONResponse(
        payload.model_dump(),
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@app.post("/api/portal/channel-access/verify", response_model=ChannelAccessVerifyResponse)
def verify_channel_access(request: Request) -> ChannelAccessVerifyResponse:
    """Turn verified Fodder's Dev membership into permanent one-device NL access."""
    account = _require_account(request)
    telegram_id = int(account["user"]["telegram_id"])
    channel = ChannelAccessConfig.from_env()
    if not channel.configured:
        raise HTTPException(status_code=404, detail="Бесплатный доступ пока не включён.")
    awg = AwgFallbackConfig.from_env()
    base = _public_base_url_from_request(request)
    if not awg.link_secret or not base:
        raise HTTPException(status_code=503, detail="VPN links are not configured.")
    try:
        status = channel_access_status(
            _account_store(),
            telegram_id,
            channel,
            refresh_membership=True,
            create_member=True,
        )
    except ChannelAccessError as exc:
        raise HTTPException(status_code=502, detail="Не удалось проверить подписку. Попробуйте ещё раз.") from exc
    if not status.active:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "channel_membership_required",
                "message": "Сначала подпишитесь на Fodder’s Dev.",
                "channel_url": channel.channel_url,
            },
        )
    _awg_webhook_apply("policy", telegram_id)
    return ChannelAccessVerifyResponse(
        ok=True,
        active=True,
        personal_vpn_url=_channel_access_personal_url(
            base, telegram_id, awg.link_secret, channel.free_server_id
        ),
        server_id=channel.free_server_id,
    )


@app.get("/api/account/servers", response_model=SavedServerListResponse)
def account_servers(request: Request) -> SavedServerListResponse:
    account = _current_account(request, required=True)
    assert account is not None
    servers = _account_store().list_servers(account["user"]["id"])
    return SavedServerListResponse(ok=True, servers=servers)


@app.post("/api/account/servers", response_model=SavedServerResponse)
def account_save_server(payload: SavedServerRequest, request: Request) -> SavedServerResponse:
    try:
        account = _current_account(request, required=True)
        assert account is not None
        server = _account_store().save_server(
            user_id=account["user"]["id"],
            host=payload.ssh.host,
            ssh_user=payload.ssh.user,
            ssh_port=payload.ssh.port,
            password=payload.ssh.password,
            key_content=payload.ssh.key_content,
            mode=payload.protocol,
            listen_port=payload.listen_port,
            proxy_sni=payload.proxy_sni,
            label=payload.label,
            relay=_relay_payload_to_store(payload.relay),
            server_id=payload.server_id,
        )
        return SavedServerResponse(ok=True, server=server)
    except HTTPException:
        raise
    except Exception as exc:
        return SavedServerResponse(ok=False, error=_error_message(exc))


@app.delete("/api/account/servers/{server_id}", response_model=RollbackResponse)
def account_delete_server(server_id: str, request: Request) -> RollbackResponse:
    account = _current_account(request, required=True)
    assert account is not None
    removed = _account_store().delete_server(account["user"]["id"], server_id)
    if not removed:
        return RollbackResponse(ok=False, error="Saved server not found.")
    return RollbackResponse(ok=True)


@app.patch("/api/account/servers/{server_id}", response_model=SavedServerResponse)
def account_rename_server(server_id: str, payload: SavedServerRenameRequest, request: Request) -> SavedServerResponse:
    try:
        account = _current_account(request, required=True)
        assert account is not None
        server = _account_store().rename_server(account["user"]["id"], server_id, payload.label)
        return SavedServerResponse(ok=True, server=server)
    except HTTPException:
        raise
    except Exception as exc:
        return SavedServerResponse(ok=False, error=_error_message(exc))


@app.post("/api/account/pin", response_model=PinResponse)
def account_configure_pin(payload: PinConfigureRequest, request: Request) -> PinResponse:
    try:
        account = _current_account(request, required=True)
        assert account is not None
        user = _account_store().configure_pin(account["user"]["id"], payload.pin, payload.enabled)
        refreshed = _account_store().get_auth_session(account["session_id"])
        pin_required = bool(refreshed and refreshed["user"].get("pin_enabled") and not refreshed["pin_unlocked"])
        return PinResponse(ok=True, pin_enabled=bool(user.get("pin_enabled")), pin_required=pin_required)
    except HTTPException:
        raise
    except Exception as exc:
        return PinResponse(ok=False, error=_error_message(exc))


@app.post("/api/account/pin/unlock", response_model=PinResponse)
def account_unlock_pin(payload: PinUnlockRequest, request: Request) -> PinResponse:
    try:
        account = _current_account(request, required=True)
        assert account is not None
        remaining = PIN_UNLOCK_LIMITER.remaining(account["session_id"])
        if remaining:
            return PinResponse(
                ok=False,
                pin_enabled=True,
                pin_required=True,
                error=f"Too many wrong PIN attempts. Try again in {remaining}s.",
            )
        ok = _account_store().unlock_pin(account["session_id"], payload.pin)
        if not ok:
            remaining = PIN_UNLOCK_LIMITER.record_failure(account["session_id"])
            if remaining:
                return PinResponse(
                    ok=False,
                    pin_enabled=True,
                    pin_required=True,
                    error=f"Too many wrong PIN attempts. Try again in {remaining}s.",
                )
            return PinResponse(ok=False, pin_enabled=True, pin_required=True, error="Wrong PIN.")
        PIN_UNLOCK_LIMITER.reset(account["session_id"])
        refreshed = _account_store().get_auth_session(account["session_id"])
        pin_enabled = bool(refreshed and refreshed["user"].get("pin_enabled"))
        pin_required = bool(refreshed and refreshed["user"].get("pin_enabled") and not refreshed["pin_unlocked"])
        return PinResponse(ok=True, pin_enabled=pin_enabled, pin_required=pin_required)
    except HTTPException:
        raise
    except Exception as exc:
        return PinResponse(ok=False, error=_error_message(exc))


def _safe_name(name: Optional[str]) -> str:
    if not name:
        return "client1"
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in {"-", "_"})
    return cleaned or "client1"


def _download_filename(name: Optional[str], suffix: str) -> str:
    safe = _safe_name(name)
    return f"{safe}.{suffix}"


def _relay_payload_to_store(relay: Optional[RelayPayload]) -> Optional[dict]:
    if relay is None:
        return None
    return {
        "host": relay.ssh.host,
        "user": relay.ssh.user,
        "port": relay.ssh.port,
        "password": relay.ssh.password,
        "key_content": relay.ssh.key_content,
        "public_host": relay.public_host or relay.ssh.host,
        "listen_port": relay.listen_port,
    }


def _relay_payload_from_creds(relay: Optional[dict]) -> Optional[dict]:
    if not relay:
        return None
    host = str(relay.get("host") or "").strip()
    user = str(relay.get("user") or "").strip()
    port = relay.get("port")
    if not host or not user or not port:
        return None
    return {
        "ssh": {
            "host": host,
            "user": user,
            "port": int(port),
            "password": relay.get("password"),
            "key_content": relay.get("key_content"),
        },
        "public_host": relay.get("public_host") or host,
        "listen_port": relay.get("listen_port"),
    }


def _rewrite_xray_links_for_relay(
    *,
    link: Optional[str],
    alternatives: Optional[list[dict]],
    auto_config: Optional[str],
    relay: Optional[RelayPayload],
    fallback_port: Optional[int] = None,
) -> tuple[Optional[str], Optional[list[dict]], Optional[str]]:
    if relay is None or not link:
        return link, alternatives, auto_config
    relay_host = str(relay.public_host or relay.ssh.host or "").strip()
    relay_port = int(relay.listen_port or fallback_port or 0)
    if not relay_host or relay_port < 1 or relay_port > 65535:
        return link, alternatives, auto_config
    primary_link = rewrite_vless_endpoint(link, relay_host, relay_port)
    rewritten_alternatives = rewrite_vless_alternatives(alternatives, relay_host, relay_port)
    proxy = proxy_module.ProxyProvisioner.__new__(proxy_module.ProxyProvisioner)
    proxy.enable_urltest = False
    proxy.fingerprint = "chrome"
    auto = proxy.build_singbox_auto_config(primary_link=primary_link, alternatives=rewritten_alternatives)
    return primary_link, rewritten_alternatives, auto


def _public_base_url_from_request(request: Optional[Request]) -> Optional[str]:
    """
    Build a public-facing base URL for QR codes.

    We prefer an explicit env override because some reverse proxies may mangle request.url.
    """
    explicit = (os.getenv("VPNW_PUBLIC_BASE_URL") or "").strip().rstrip("/")
    if explicit:
        return explicit
    if not request:
        return None
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.netloc
        or ""
    ).split(",")[0].strip()
    if not host:
        return None
    return f"{proto}://{host}".rstrip("/")


def _resolve_ssh_payload(
    ssh_payload: Optional[SSHPayload],
    session_id: Optional[str],
    saved_server_id: Optional[str] = None,
    request: Optional[Request] = None,
) -> SSHPayload:
    if ssh_payload is not None:
        return ssh_payload
    if session_id:
        if request is None:
            raise RuntimeError("Session access requires an authenticated request.")
        account = _require_account(request)
        session_ssh = SESSION_STORE.get(session_id, owner_user_id=account["user"]["id"])
        if session_ssh is not None:
            return session_ssh
        raise RuntimeError("Session expired. Please log in again.")
    if saved_server_id:
        if request is None:
            raise RuntimeError("Saved server access requires an authenticated request.")
        account = _require_account(request)
        creds = _account_store().resolve_server_credentials(
            user_id=account["user"]["id"],
            server_id=saved_server_id,
            require_pin_unlocked=True,
            auth_session_id=account["session_id"],
        )
        return SSHPayload(
            host=creds["host"],
            user=creds["user"],
            port=creds["port"],
            password=creds.get("password"),
            key_content=creds.get("key_content"),
        )
    raise RuntimeError("SSH credentials are required.")


@contextmanager
def _ssh_connection(
    ssh_payload: Optional[SSHPayload],
    session_id: Optional[str] = None,
    saved_server_id: Optional[str] = None,
    request: Optional[Request] = None,
    logger: Optional[Callable[[str], None]] = None,
):
    resolved = _resolve_ssh_payload(ssh_payload, session_id, saved_server_id, request)
    temp_key = TempKey()
    key_path = resolved.key_path
    if resolved.key_content:
        temp_key = _write_temp_key(resolved.key_content)
        key_path = temp_key.path
    cfg = SSHConfig(
        host=resolved.host,
        user=resolved.user,
        port=resolved.port,
        password=resolved.password,
        key_path=key_path,
    )
    try:
        with SSHRunner(cfg, logger=logger) as ssh:
            yield ssh, resolved
    finally:
        temp_key.cleanup()


def _materialize_saved_server(payload: BaseModel, request: Request) -> BaseModel:
    session_id = getattr(payload, "session_id", None)
    if session_id and getattr(payload, "ssh", None) is None:
        account = _require_account(request)
        session_ssh = SESSION_STORE.get(session_id, owner_user_id=account["user"]["id"])
        if session_ssh is None:
            raise RuntimeError("Session expired. Please connect again.")
        updated = payload.model_dump()
        updated["ssh"] = session_ssh.model_dump(exclude_none=True)
        updated["session_id"] = None
        payload = payload.__class__(**updated)

    saved_server_id = getattr(payload, "saved_server_id", None)
    if not saved_server_id:
        return payload
    account = _require_account(request)
    creds = _account_store().resolve_server_credentials(
        user_id=account["user"]["id"],
        server_id=saved_server_id,
        require_pin_unlocked=True,
        auth_session_id=account["session_id"],
    )
    _account_store().touch_server(account["user"]["id"], saved_server_id)
    updated = payload.model_dump()
    updated["ssh"] = {
        "host": creds["host"],
        "user": creds["user"],
        "port": creds["port"],
        "password": creds.get("password"),
        "key_content": creds.get("key_content"),
    }
    if creds.get("relay"):
        updated["relay"] = _relay_payload_from_creds(creds.get("relay"))
    updated["saved_server_id"] = None
    if "protocol" in updated and not updated.get("protocol") and creds.get("mode"):
        updated["protocol"] = creds["mode"]
    if "listen_port" in updated and not updated.get("listen_port") and creds.get("listen_port"):
        updated["listen_port"] = creds["listen_port"]
    if "options" in updated and isinstance(updated["options"], dict):
        if not updated["options"].get("protocol") and creds.get("mode"):
            updated["options"]["protocol"] = creds["mode"]
        if not updated["options"].get("listen_port") and creds.get("listen_port"):
            updated["options"]["listen_port"] = creds["listen_port"]
        if not updated["options"].get("proxy_sni") and creds.get("proxy_sni"):
            updated["options"]["proxy_sni"] = creds["proxy_sni"]
    return payload.__class__(**updated)


def _run_provision(
    job_id: str,
    payload: ProvisionRequest,
    owner_user_id: Optional[int],
    public_base_url: Optional[str] = None,
) -> None:
    try:
        JOB_STORE.update(job_id, status="running")

        def progress(msg: str) -> None:
            JOB_STORE.append_progress(job_id, msg)

        progress("Connecting over SSH")
        with _ssh_connection(payload.ssh, payload.session_id, logger=progress) as (ssh, _resolved):
            opts = payload.options
            JOB_STORE.update(job_id, client_name=opts.client_name)
            config = None
            alternatives = None
            auto_config = None
            checks: list[dict] = []
            suffix = "conf"

            if _is_xray_protocol(opts.protocol):
                proxy = ProxyProvisioner(ssh, progress=progress)
                proxy_port = opts.listen_port
                if not proxy_port:
                    status = proxy.detect_status()
                    existing = status.get("listen_port") if isinstance(status, dict) else None
                    if status.get("configured") and isinstance(existing, int) and 1 <= int(existing) <= 65535:
                        proxy_port = int(existing)
                        progress(f"Proxy already configured. Reusing existing port: {proxy_port}.")
                    else:
                        auto_port = proxy.choose_free_port()
                        if not auto_port:
                            JOB_STORE.update(
                                job_id,
                                status="error",
                                error="Could not find a free proxy TCP port automatically. Set it manually.",
                            )
                            return
                        proxy_port = auto_port
                        progress(f"Proxy port selected automatically: {proxy_port}.")
                pre_checks = proxy.pre_check(proxy_port)
                port_check = next((item for item in pre_checks if item.get("name") == "port_available"), None)
                if port_check and not port_check.get("ok"):
                    fallback_port = proxy.choose_free_port(proxy_port)
                    if fallback_port and fallback_port != proxy_port:
                        progress(f"Proxy port {proxy_port} is busy. Switching to free port {fallback_port}.")
                        proxy_port = fallback_port
                        pre_checks = proxy.pre_check(proxy_port)
                for item in pre_checks:
                    progress(
                        f"precheck {item.get('name')}: {'ok' if item.get('ok') else 'fail'} ({item.get('details')})"
                    )
                critical = {"os_supported", "sudo", "port_available"}
                if any(item.get("name") in critical and not item.get("ok") for item in pre_checks):
                    JOB_STORE.update(job_id, status="error", error="Precheck failed.", checks=pre_checks)
                    return
                result = proxy.setup(
                    client_name=opts.client_name or "client1",
                    listen_port=proxy_port,
                    sni=opts.proxy_sni,
                )
                config = result["link"]
                alternatives = result.get("alternatives")
                auto_config = proxy.build_singbox_auto_config(primary_link=config, alternatives=alternatives)
                if payload.relay is not None:
                    parsed_origin = urlparse(config or "")
                    origin_host = parsed_origin.hostname
                    origin_port = parsed_origin.port
                    if not origin_host or not origin_port:
                        JOB_STORE.update(job_id, status="error", error="Could not determine XRay endpoint for relay setup.")
                        return
                    relay_port = int(payload.relay.listen_port or origin_port)
                    progress("Connecting to relay over SSH")
                    with _ssh_connection(payload.relay.ssh, logger=progress) as (relay_ssh, _relay_resolved):
                        relay_info = RelayProvisioner(relay_ssh, progress=progress).setup(
                            origin_host=origin_host,
                            origin_port=origin_port,
                            listen_port=relay_port,
                        )
                    payload.relay.listen_port = int(relay_info["listen_port"])
                    config, alternatives, auto_config = _rewrite_xray_links_for_relay(
                        link=config,
                        alternatives=alternatives,
                        auto_config=auto_config,
                        relay=payload.relay,
                        fallback_port=int(relay_info["listen_port"]),
                    )
                    progress(
                        f"Relay ready on {payload.relay.public_host or payload.relay.ssh.host}:{int(relay_info['listen_port'])}"
                    )
                checks = pre_checks if opts.check else []
                suffix = "txt"
                JOB_STORE.update(job_id, client_name=result.get("name") or opts.client_name)

            elif opts.protocol == "shadowtls_ss":
                proxy = ShadowTLSSSProvisioner(ssh, progress=progress)
                proxy_port = opts.listen_port
                if not proxy_port:
                    # Reuse the existing listen port when already configured.
                    # Rotating the public port can noticeably change RU ISP behavior (throttling / filtering).
                    status = proxy.detect_status()
                    existing = status.get("listen_port") if isinstance(status, dict) else None
                    if status.get("configured") and isinstance(existing, int) and 1 <= int(existing) <= 65535:
                        proxy_port = int(existing)
                        progress(f"Proxy already configured. Reusing existing port: {proxy_port}.")
                    else:
                        auto_port = proxy.choose_free_port()
                        if not auto_port:
                            JOB_STORE.update(
                                job_id,
                                status="error",
                                error="Could not find a free proxy TCP port automatically. Set it manually.",
                            )
                            return
                        proxy_port = auto_port
                        progress(f"Proxy port selected automatically: {proxy_port}.")
                pre_checks = proxy.pre_check(int(proxy_port))
                port_check = next((item for item in pre_checks if item.get("name") == "port_available"), None)
                if port_check and not port_check.get("ok"):
                    fallback_port = proxy.choose_free_port(int(proxy_port))
                    if fallback_port and fallback_port != proxy_port:
                        progress(f"Proxy port {proxy_port} is busy. Switching to free port {fallback_port}.")
                        proxy_port = fallback_port
                        pre_checks = proxy.pre_check(int(proxy_port))
                for item in pre_checks:
                    progress(
                        f"precheck {item.get('name')}: {'ok' if item.get('ok') else 'fail'} ({item.get('details')})"
                    )
                critical = {"os_supported", "sudo", "port_available"}
                if any(item.get("name") in critical and not item.get("ok") for item in pre_checks):
                    JOB_STORE.update(job_id, status="error", error="Precheck failed.", checks=pre_checks)
                    return
                result = proxy.setup(
                    client_name=opts.client_name or "client1",
                    listen_port=int(proxy_port),
                    sni=opts.proxy_sni,
                )
                auto_config = result.get("auto_config")
                checks = pre_checks if opts.check else []
                suffix = "txt"
                JOB_STORE.update(job_id, client_name=result.get("name") or opts.client_name)

            else:
                prov = WireGuardProvisioner(
                    ssh,
                    client_name=opts.client_name,
                    client_ip=opts.client_ip,
                    server_cidr=opts.server_cidr,
                    listen_port=opts.listen_port or 3478,
                    dns=opts.dns,
                    mtu=opts.mtu,
                    auto_mtu=opts.auto_mtu,
                    tune=opts.tune,
                    progress=progress,
                    protocol=opts.protocol,
                )
                pre_checks = prov.pre_check()
                for item in pre_checks:
                    progress(
                        f"precheck {item.get('name')}: {'ok' if item.get('ok') else 'fail'} ({item.get('details')})"
                    )
                critical = {"os_supported", "sudo", "port_available"}
                if any(item.get("name") in critical and not item.get("ok") for item in pre_checks):
                    JOB_STORE.update(job_id, status="error", error="Precheck failed.", checks=pre_checks)
                    return
                prov.provision()
                config = prov.export_client_config()
                checks = prov.post_check() if opts.check else []

        # QR:
        # - WG / vless: QR encodes the config payload (small enough, import-friendly).
        # - ShadowTLS+SS: QR encodes the auto-profile URL (much smaller than JSON; works well for mobile).
        base_url = (public_base_url or os.getenv("VPNW_PUBLIC_BASE_URL") or "").strip().rstrip("/") or None

        qr_png = None
        qr_b64 = None
        download_id = None
        auto_download_id = None

        if opts.protocol == "shadowtls_ss" and auto_config:
            auto_download_id = uuid.uuid4().hex
            auto_url = f"{base_url}/api/download/{auto_download_id}/config" if base_url else None
            qr_seed = auto_url or "VPN Wizard"
            qr_png = _build_qr_png(qr_seed)
            qr_b64 = base64.b64encode(qr_png).decode("ascii")
            DOWNLOAD_STORE.create(
                auto_config,
                qr_png,
                f"{opts.client_name}-auto",
                suffix="json",
                owner_user_id=owner_user_id,
                download_id=auto_download_id,
            )
            # For proxy profiles we treat the auto profile as the primary artifact.
            download_id = auto_download_id
        else:
            qr_seed = config if config else "VPN Wizard"
            qr_png = _build_qr_png(qr_seed) if (config or auto_config) else None
            qr_b64 = base64.b64encode(qr_png).decode("ascii") if qr_png else None
            if config and qr_png:
                download_id = DOWNLOAD_STORE.create(
                    config,
                    qr_png,
                    opts.client_name,
                    suffix=suffix,
                    owner_user_id=owner_user_id,
                )
            if (_is_xray_protocol(opts.protocol) or opts.protocol == "shadowtls_ss") and auto_config and qr_png:
                auto_download_id = DOWNLOAD_STORE.create(
                    auto_config,
                    qr_png,
                    f"{opts.client_name}-auto",
                    suffix="json",
                    owner_user_id=owner_user_id,
                )
        JOB_STORE.update(
            job_id,
            status="done",
            config=config,
            alternatives=alternatives if _is_xray_protocol(opts.protocol) else None,
            auto_config=auto_config if (_is_xray_protocol(opts.protocol) or opts.protocol == "shadowtls_ss") else None,
            qr_png_base64=qr_b64,
            download_id=download_id,
            auto_download_id=auto_download_id,
            checks=checks,
            error=None,
        )
    except Exception as exc:
        JOB_STORE.update(job_id, status="error", error=_error_message(exc))


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/api/ssh/discover-port", response_model=SSHDiscoverResponse)
async def ssh_discover_port(payload: SSHDiscoverRequest, request: Request) -> SSHDiscoverResponse:
    try:
        _require_account(request)
        clean_host, parsed_port = _split_host_port(payload.host)
        preferred = payload.port if payload.port is not None else parsed_port
        found_port, checked = _discover_ssh_port(clean_host, preferred_port=preferred)
        if found_port is None:
            return SSHDiscoverResponse(
                ok=False,
                host=clean_host,
                checked_ports=checked,
                error="Could not find a reachable SSH port. Set SSH port manually in advanced settings.",
            )
        return SSHDiscoverResponse(
            ok=True,
            host=clean_host,
            port=found_port,
            checked_ports=checked,
        )
    except HTTPException:
        raise
    except Exception as exc:
        return SSHDiscoverResponse(ok=False, error=_error_message(exc))


@app.post("/api/sessions/login", response_model=SessionLoginResponse)
async def session_login(payload: SessionLoginRequest, request: Request) -> SessionLoginResponse:
    request_id = uuid.uuid4().hex[:8]
    logger.info("ssh.login.start req=%s target=%s", request_id, _ssh_target_label(payload.ssh))
    last_exc: Optional[Exception] = None
    try:
        account = _require_account(request)
        for attempt in range(1, 4):
            try:
                with _ssh_connection(
                    payload.ssh,
                    logger=lambda message: logger.info("ssh.login.trace req=%s attempt=%s %s", request_id, attempt, message),
                ):
                    pass
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if attempt >= 3 or not _is_retryable_ssh_error(exc):
                    raise
                logger.info("ssh.login.retry req=%s attempt=%s error=%s", request_id, attempt, _error_message(exc))
                time.sleep(1.2 * attempt)
        if last_exc is not None:
            raise last_exc
        session_id = SESSION_STORE.create(payload.ssh, owner_user_id=account["user"]["id"])
        logger.info("ssh.login.ok req=%s target=%s", request_id, _ssh_target_label(payload.ssh))
        return SessionLoginResponse(
            ok=True,
            session_id=session_id,
            host=payload.ssh.host,
            user=payload.ssh.user,
            port=payload.ssh.port,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "ssh.login.fail req=%s target=%s error=%s",
            request_id,
            _ssh_target_label(payload.ssh),
            _error_message(exc),
            exc_info=True,
        )
        return SessionLoginResponse(ok=False, error=_error_message(exc))


@app.post("/api/sessions/revoke", response_model=RollbackResponse)
async def session_revoke(payload: SessionRevokeRequest, request: Request) -> RollbackResponse:
    account = _require_account(request)
    removed = SESSION_STORE.revoke(payload.session_id, owner_user_id=account["user"]["id"])
    if not removed:
        return RollbackResponse(ok=False, error="Session not found.")
    return RollbackResponse(ok=True)


@app.post("/api/provision", response_model=JobCreateResponse)
async def provision(payload: ProvisionRequest, background_tasks: BackgroundTasks, request: Request) -> JobCreateResponse:
    account = _require_account(request)
    payload = _materialize_saved_server(payload, request)
    job = JOB_STORE.create(owner_user_id=account["user"]["id"])
    background_tasks.add_task(
        _run_provision,
        job.job_id,
        payload,
        account["user"]["id"],
        _public_base_url_from_request(request),
    )
    return JobCreateResponse(job_id=job.job_id)


@app.get("/api/jobs/{job_id}", response_model=JobStatus)
def job_status(job_id: str, request: Request) -> JobStatus:
    account = _require_account(request)
    job = JOB_STORE.get(job_id, owner_user_id=account["user"]["id"])
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatus(
        job_id=job.job_id,
        status=job.status,
        progress=job.progress,
        checks=job.checks,
        error=job.error,
        config_ready=bool(job.config),
        alternatives=job.alternatives,
        auto_config_ready=bool(job.auto_config),
    )


@app.get("/api/jobs/{job_id}/result", response_model=ProvisionResponse)
def job_result(job_id: str, request: Request) -> ProvisionResponse:
    account = _require_account(request)
    job = JOB_STORE.get(job_id, owner_user_id=account["user"]["id"])
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == "error":
        return ProvisionResponse(ok=False, error=job.error)
    if job.status != "done":
        raise HTTPException(status_code=409, detail="Job not finished")
    return ProvisionResponse(
        ok=True,
        config=job.config,
        alternatives=job.alternatives,
        auto_config=job.auto_config,
        qr_png_base64=job.qr_png_base64,
        download_id=job.download_id,
        auto_download_id=job.auto_download_id,
        checks=job.checks,
        error=None,
    )


@app.get("/api/download/{download_id}/config")
def download_config(download_id: str) -> Response:
    item = DOWNLOAD_STORE.get(download_id)
    if not item:
        raise HTTPException(status_code=404, detail="Download not found")
    filename = _download_filename(item.name, item.suffix or "conf")
    media_type = "application/json" if (item.suffix or "").lower() == "json" else "text/plain"
    return Response(
        content=item.config,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/download/{download_id}/qr")
def download_qr(download_id: str) -> Response:
    item = DOWNLOAD_STORE.get(download_id)
    if not item:
        raise HTTPException(status_code=404, detail="Download not found")
    filename = _download_filename(item.name, "png")
    return Response(
        content=item.qr_png,
        media_type="image/png",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/rollback", response_model=RollbackResponse)
async def rollback(payload: RollbackRequest, request: Request) -> RollbackResponse:
    try:
        _require_account(request)
        payload = _materialize_saved_server(payload, request)
        with _ssh_connection(payload.ssh, payload.session_id, request=request) as (ssh, _resolved):
            prov = WireGuardProvisioner(ssh)
            backup = prov.rollback_last_backup()
        if not backup:
            return RollbackResponse(ok=False, error="No backup found.")
        return RollbackResponse(ok=True, backup=backup)
    except HTTPException:
        raise
    except Exception as exc:
        return RollbackResponse(ok=False, error=_error_message(exc))


@app.post("/api/clients/list", response_model=ClientListResponse)
async def client_list(payload: RollbackRequest, request: Request) -> ClientListResponse:
    request_id = uuid.uuid4().hex[:8]
    target = _ssh_target_label(payload.ssh) if payload.ssh else (payload.session_id or payload.saved_server_id or "unknown")
    logger.info("ssh.clients.list.start req=%s target=%s protocol=%s", request_id, target, payload.protocol or "auto")
    try:
        _require_account(request)
        payload = _materialize_saved_server(payload, request)
        def _operation(attempt: int) -> list[dict]:
            with _ssh_connection(
                payload.ssh,
                payload.session_id,
                request=request,
                logger=lambda message: logger.info(
                    "ssh.clients.list.trace req=%s attempt=%s %s",
                    request_id,
                    attempt,
                    message,
                ),
            ) as (ssh, _resolved):
                if _is_xray_protocol(payload.protocol):
                    return ProxyProvisioner(ssh).list_clients()
                if payload.protocol == "shadowtls_ss":
                    return ShadowTLSSSProvisioner(ssh).list_clients()
                return WireGuardProvisioner(ssh).list_clients()

        clients = _run_ssh_action_with_retries(
            action_name="ssh.clients.list",
            request_id=request_id,
            target=target,
            operation=_operation,
        )
        logger.info("ssh.clients.list.ok req=%s target=%s count=%s", request_id, target, len(clients))
        return ClientListResponse(ok=True, clients=clients)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "ssh.clients.list.fail req=%s target=%s error=%s",
            request_id,
            target,
            _error_message(exc),
            exc_info=True,
        )
        return ClientListResponse(ok=False, error=_error_message(exc))


@app.post("/api/clients/add", response_model=ClientAddResponse)
async def client_add(payload: ClientRequest, request: Request) -> ClientAddResponse:
    request_id = uuid.uuid4().hex[:8]
    target = _ssh_target_label(payload.ssh) if payload.ssh else (payload.session_id or payload.saved_server_id or "unknown")
    logger.info(
        "ssh.clients.add.start req=%s target=%s protocol=%s client=%s",
        request_id,
        target,
        payload.protocol or "auto",
        payload.client_name or "client1",
    )
    try:
        account = _require_account(request)
        payload = _materialize_saved_server(payload, request)
        def _operation(attempt: int) -> dict:
            with _ssh_connection(
                payload.ssh,
                payload.session_id,
                request=request,
                logger=lambda message: logger.info(
                    "ssh.clients.add.trace req=%s attempt=%s %s",
                    request_id,
                    attempt,
                    message,
                ),
            ) as (ssh, _resolved):
                if _is_xray_protocol(payload.protocol):
                    proxy = ProxyProvisioner(ssh)
                    result = proxy.add_client(payload.client_name or "client1")
                    return {
                        "client_name": result["name"],
                        "config_value": result["link"],
                        "alternatives": result.get("alternatives"),
                        "auto_config": proxy.build_singbox_auto_config(
                            primary_link=result["link"],
                            alternatives=result.get("alternatives"),
                        ),
                        "client_ip": None,
                        "iface": result.get("interface"),
                        "suffix": "txt",
                    }
                if payload.protocol == "shadowtls_ss":
                    proxy = ShadowTLSSSProvisioner(ssh)
                    result = proxy.add_client(payload.client_name or "client1")
                    return {
                        "client_name": result["name"],
                        "config_value": None,
                        "alternatives": None,
                        "auto_config": result.get("auto_config"),
                        "client_ip": None,
                        "iface": result.get("interface"),
                        "suffix": "txt",
                    }
                prov_kwargs = {}
                if payload.listen_port:
                    prov_kwargs["listen_port"] = payload.listen_port
                prov = WireGuardProvisioner(ssh, **prov_kwargs)
                result = prov.add_client(client_name=payload.client_name, client_ip=payload.client_ip)
                return {
                    "client_name": result["name"],
                    "config_value": result["config"],
                    "alternatives": None,
                    "auto_config": None,
                    "client_ip": result["ip"],
                    "iface": result.get("interface"),
                    "suffix": "conf",
                }

        result = _run_ssh_action_with_retries(
            action_name="ssh.clients.add",
            request_id=request_id,
            target=target,
            operation=_operation,
        )
        client_name = result["client_name"]
        config_value = result["config_value"]
        alternatives = result["alternatives"]
        auto_config = result["auto_config"]
        if _is_xray_protocol(payload.protocol):
            config_value, alternatives, auto_config = _rewrite_xray_links_for_relay(
                link=config_value,
                alternatives=alternatives,
                auto_config=auto_config,
                relay=payload.relay,
            )
        client_ip = result["client_ip"]
        iface = result["iface"]
        suffix = result["suffix"]
        base_url = _public_base_url_from_request(request)
        qr_png = None
        qr_b64 = None
        download_id = None
        auto_download_id = None

        if payload.protocol == "shadowtls_ss" and auto_config:
            auto_download_id = uuid.uuid4().hex
            auto_url = f"{base_url}/api/download/{auto_download_id}/config" if base_url else None
            qr_seed = auto_url or "VPN Wizard"
            qr_png = _build_qr_png(qr_seed)
            qr_b64 = base64.b64encode(qr_png).decode("ascii")
            DOWNLOAD_STORE.create(
                auto_config,
                qr_png,
                f"{client_name}-auto",
                suffix="json",
                owner_user_id=account["user"]["id"],
                download_id=auto_download_id,
            )
            download_id = auto_download_id
        else:
            qr_seed = config_value if config_value else "VPN Wizard"
            qr_png = _build_qr_png(qr_seed) if (config_value or auto_config) else None
            qr_b64 = base64.b64encode(qr_png).decode("ascii") if qr_png else None
            if config_value and qr_png:
                download_id = DOWNLOAD_STORE.create(
                    config_value,
                    qr_png,
                    client_name,
                    suffix=suffix,
                    owner_user_id=account["user"]["id"],
                )
            if (_is_xray_protocol(payload.protocol) or payload.protocol == "shadowtls_ss") and auto_config and qr_png:
                auto_download_id = DOWNLOAD_STORE.create(
                    auto_config,
                    qr_png,
                    f"{client_name}-auto",
                    suffix="json",
                    owner_user_id=account["user"]["id"],
                )
        logger.info("ssh.clients.add.ok req=%s target=%s client=%s", request_id, target, client_name)
        return ClientAddResponse(
            ok=True,
            client_name=client_name,
            client_ip=client_ip,
            config=config_value,
            alternatives=alternatives,
            auto_config=auto_config,
            qr_png_base64=qr_b64,
            download_id=download_id,
            auto_download_id=auto_download_id,
            interface=iface,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "ssh.clients.add.fail req=%s target=%s error=%s",
            request_id,
            target,
            _error_message(exc),
            exc_info=True,
        )
        return ClientAddResponse(ok=False, error=_error_message(exc))


@app.post("/api/clients/remove", response_model=RollbackResponse)
async def client_remove(payload: ClientRemoveRequest, request: Request) -> RollbackResponse:
    request_id = uuid.uuid4().hex[:8]
    target = _ssh_target_label(payload.ssh) if payload.ssh else (payload.session_id or payload.saved_server_id or "unknown")
    logger.info(
        "ssh.clients.remove.start req=%s target=%s protocol=%s client=%s",
        request_id,
        target,
        payload.protocol or "auto",
        payload.client_name,
    )
    try:
        _require_account(request)
        payload = _materialize_saved_server(payload, request)
        def _operation(attempt: int) -> bool:
            with _ssh_connection(
                payload.ssh,
                payload.session_id,
                request=request,
                logger=lambda message: logger.info(
                    "ssh.clients.remove.trace req=%s attempt=%s %s",
                    request_id,
                    attempt,
                    message,
                ),
            ) as (ssh, _resolved):
                if _is_xray_protocol(payload.protocol):
                    return ProxyProvisioner(ssh).remove_client(payload.client_name)
                if payload.protocol == "shadowtls_ss":
                    return ShadowTLSSSProvisioner(ssh).remove_client(payload.client_name)
                return WireGuardProvisioner(ssh).remove_client(payload.client_name)

        ok = _run_ssh_action_with_retries(
            action_name="ssh.clients.remove",
            request_id=request_id,
            target=target,
            operation=_operation,
        )
        if not ok:
            return RollbackResponse(ok=False, error="Client not found.")
        logger.info("ssh.clients.remove.ok req=%s target=%s client=%s", request_id, target, payload.client_name)
        return RollbackResponse(ok=True, backup=None)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "ssh.clients.remove.fail req=%s target=%s error=%s",
            request_id,
            target,
            _error_message(exc),
            exc_info=True,
        )
        return RollbackResponse(ok=False, error=_error_message(exc))


@app.post("/api/clients/rotate", response_model=ClientAddResponse)
async def client_rotate(payload: ClientRemoveRequest, request: Request) -> ClientAddResponse:
    request_id = uuid.uuid4().hex[:8]
    target = _ssh_target_label(payload.ssh) if payload.ssh else (payload.session_id or payload.saved_server_id or "unknown")
    logger.info(
        "ssh.clients.rotate.start req=%s target=%s protocol=%s client=%s",
        request_id,
        target,
        payload.protocol or "auto",
        payload.client_name,
    )
    try:
        account = _require_account(request)
        if _is_legacy_proxy_protocol(payload.protocol) or _is_xray_protocol(payload.protocol):
            return ClientAddResponse(ok=False, error="Rotate is not supported for proxy profiles.")
        payload = _materialize_saved_server(payload, request)
        def _operation(attempt: int) -> dict:
            with _ssh_connection(
                payload.ssh,
                payload.session_id,
                request=request,
                logger=lambda message: logger.info(
                    "ssh.clients.rotate.trace req=%s attempt=%s %s",
                    request_id,
                    attempt,
                    message,
                ),
            ) as (ssh, _resolved):
                prov_kwargs = {}
                if payload.listen_port:
                    prov_kwargs["listen_port"] = payload.listen_port
                prov = WireGuardProvisioner(ssh, **prov_kwargs)
                return prov.rotate_client(payload.client_name)

        result = _run_ssh_action_with_retries(
            action_name="ssh.clients.rotate",
            request_id=request_id,
            target=target,
            operation=_operation,
        )
        qr_png = _build_qr_png(result["config"])
        qr_b64 = base64.b64encode(qr_png).decode("ascii")
        download_id = DOWNLOAD_STORE.create(
            result["config"],
            qr_png,
            result.get("name"),
            owner_user_id=account["user"]["id"],
        )
        logger.info("ssh.clients.rotate.ok req=%s target=%s client=%s", request_id, target, result.get("name"))
        return ClientAddResponse(
            ok=True,
            client_name=result["name"],
            client_ip=result["ip"],
            config=result["config"],
            qr_png_base64=qr_b64,
            download_id=download_id,
            interface=result.get("interface"),
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "ssh.clients.rotate.fail req=%s target=%s error=%s",
            request_id,
            target,
            _error_message(exc),
            exc_info=True,
        )
        return ClientAddResponse(ok=False, error=_error_message(exc))


@app.post("/api/clients/export", response_model=ClientExportResponse)
async def client_export(payload: ClientRemoveRequest, request: Request) -> ClientExportResponse:
    request_id = uuid.uuid4().hex[:8]
    target = _ssh_target_label(payload.ssh) if payload.ssh else (payload.session_id or payload.saved_server_id or "unknown")
    logger.info(
        "ssh.clients.export.start req=%s target=%s protocol=%s client=%s",
        request_id,
        target,
        payload.protocol or "auto",
        payload.client_name,
    )
    try:
        account = _require_account(request)
        payload = _materialize_saved_server(payload, request)
        def _operation(attempt: int) -> dict:
            with _ssh_connection(
                payload.ssh,
                payload.session_id,
                request=request,
                logger=lambda message: logger.info(
                    "ssh.clients.export.trace req=%s attempt=%s %s",
                    request_id,
                    attempt,
                    message,
                ),
            ) as (ssh, _resolved):
                if _is_xray_protocol(payload.protocol):
                    proxy = ProxyProvisioner(ssh)
                    result = proxy.export_client(payload.client_name)
                    return {
                        "client_name": result["name"],
                        "config_value": result["link"],
                        "alternatives": result.get("alternatives"),
                        "auto_config": proxy.build_singbox_auto_config(
                            primary_link=result["link"],
                            alternatives=result.get("alternatives"),
                        ),
                        "client_ip": None,
                        "iface": result.get("interface"),
                        "suffix": "txt",
                    }
                if payload.protocol == "shadowtls_ss":
                    proxy = ShadowTLSSSProvisioner(ssh)
                    result = proxy.export_client(payload.client_name)
                    return {
                        "client_name": result["name"],
                        "config_value": None,
                        "alternatives": None,
                        "auto_config": result.get("auto_config"),
                        "client_ip": None,
                        "iface": result.get("interface"),
                        "suffix": "txt",
                    }
                prov = WireGuardProvisioner(ssh)
                result = prov.export_client(payload.client_name)
                return {
                    "client_name": result["name"],
                    "config_value": result["config"],
                    "alternatives": None,
                    "auto_config": None,
                    "client_ip": result["ip"],
                    "iface": result.get("interface"),
                    "suffix": "conf",
                }

        result = _run_ssh_action_with_retries(
            action_name="ssh.clients.export",
            request_id=request_id,
            target=target,
            operation=_operation,
        )
        client_name = result["client_name"]
        config_value = result["config_value"]
        alternatives = result["alternatives"]
        auto_config = result["auto_config"]
        if _is_xray_protocol(payload.protocol):
            config_value, alternatives, auto_config = _rewrite_xray_links_for_relay(
                link=config_value,
                alternatives=alternatives,
                auto_config=auto_config,
                relay=payload.relay,
            )
        client_ip = result["client_ip"]
        iface = result["iface"]
        suffix = result["suffix"]
        base_url = _public_base_url_from_request(request)
        qr_png = None
        qr_b64 = None
        download_id = None
        auto_download_id = None

        if payload.protocol == "shadowtls_ss" and auto_config:
            auto_download_id = uuid.uuid4().hex
            auto_url = f"{base_url}/api/download/{auto_download_id}/config" if base_url else None
            qr_seed = auto_url or "VPN Wizard"
            qr_png = _build_qr_png(qr_seed)
            qr_b64 = base64.b64encode(qr_png).decode("ascii")
            DOWNLOAD_STORE.create(
                auto_config,
                qr_png,
                f"{client_name}-auto",
                suffix="json",
                owner_user_id=account["user"]["id"],
                download_id=auto_download_id,
            )
            download_id = auto_download_id
        else:
            qr_seed = config_value if config_value else "VPN Wizard"
            qr_png = _build_qr_png(qr_seed) if (config_value or auto_config) else None
            qr_b64 = base64.b64encode(qr_png).decode("ascii") if qr_png else None
            if config_value and qr_png:
                download_id = DOWNLOAD_STORE.create(
                    config_value,
                    qr_png,
                    client_name,
                    suffix=suffix,
                    owner_user_id=account["user"]["id"],
                )
            if (_is_xray_protocol(payload.protocol) or payload.protocol == "shadowtls_ss") and auto_config and qr_png:
                auto_download_id = DOWNLOAD_STORE.create(
                    auto_config,
                    qr_png,
                    f"{client_name}-auto",
                    suffix="json",
                    owner_user_id=account["user"]["id"],
                )
        logger.info("ssh.clients.export.ok req=%s target=%s client=%s", request_id, target, client_name)
        return ClientExportResponse(
            ok=True,
            client_name=client_name,
            client_ip=client_ip,
            config=config_value,
            alternatives=alternatives,
            auto_config=auto_config,
            qr_png_base64=qr_b64,
            download_id=download_id,
            auto_download_id=auto_download_id,
            interface=iface,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "ssh.clients.export.fail req=%s target=%s error=%s",
            request_id,
            target,
            _error_message(exc),
            exc_info=True,
        )
        return ClientExportResponse(ok=False, error=_error_message(exc))


class LogsResponse(BaseModel):
    ok: bool
    logs: Optional[str] = None
    error: Optional[str] = None


class ServerStatusResponse(BaseModel):
    ok: bool
    configured: bool
    protocol: Optional[str] = None
    listen_port: Optional[int] = None
    server_cidr: Optional[str] = None
    clients_count: int = 0
    tyumen_port: Optional[int] = None
    proxy_sni: Optional[str] = None
    error: Optional[str] = None


class PrecheckResponse(BaseModel):
    ok: bool
    checks: list[CheckItem] = Field(default_factory=list)
    error: Optional[str] = None


def _detect_server_status(ssh: SSHRunner) -> dict:
    awg_conf = "/etc/amnezia/amneziawg/awg0.conf"
    wg_conf = "/etc/wireguard/wg0.conf"
    has_awg = ssh.run(f"test -f {awg_conf} && echo yes || echo no", sudo=True, check=False).strip() == "yes"
    has_wg = ssh.run(f"test -f {wg_conf} && echo yes || echo no", sudo=True, check=False).strip() == "yes"
    if not has_awg and not has_wg:
        return {"configured": False}

    protocol = "amneziawg" if has_awg else "wireguard"
    conf_path = awg_conf if has_awg else wg_conf
    clients_dir = "/etc/amnezia/amneziawg/clients" if has_awg else "/etc/wireguard/clients"

    listen_port_raw = ssh.run(
        f"awk -F'= ' '/^ListenPort/{{print $2; exit}}' {conf_path} 2>/dev/null || true",
        sudo=True,
        check=False,
    ).strip()
    listen_port = int(listen_port_raw) if listen_port_raw.isdigit() else None

    server_cidr = ssh.run(
        f"awk -F'= ' '/^Address/{{print $2; exit}}' {conf_path} 2>/dev/null || true",
        sudo=True,
        check=False,
    ).strip() or None

    clients_count_raw = ssh.run(
        f"ls -1 {clients_dir}/*.conf 2>/dev/null | wc -l",
        sudo=True,
        check=False,
    ).strip()
    clients_count = int(clients_count_raw) if clients_count_raw.isdigit() else 0
    if has_awg:
        tyumen_count_raw = ssh.run(
            "ls -1 /etc/amnezia/amneziawg/clients_tyumen/*.conf 2>/dev/null | wc -l",
            sudo=True,
            check=False,
        ).strip()
        if tyumen_count_raw.isdigit():
            clients_count += int(tyumen_count_raw)

    tyumen_port_raw = ssh.run(
        "awk -F'= ' '/^ListenPort/{{print $2; exit}}' /etc/amnezia/amneziawg/awg1.conf 2>/dev/null || true",
        sudo=True,
        check=False,
    ).strip()
    tyumen_port = int(tyumen_port_raw) if tyumen_port_raw.isdigit() else None

    return {
        "configured": True,
        "protocol": protocol,
        "listen_port": listen_port,
        "server_cidr": server_cidr,
        "clients_count": clients_count,
        "tyumen_port": tyumen_port,
    }

@app.post("/api/logs", response_model=LogsResponse)
async def get_logs(payload: RollbackRequest, request: Request) -> LogsResponse:
    try:
        _require_account(request)
        payload = _materialize_saved_server(payload, request)
        with _ssh_connection(payload.ssh, payload.session_id, request=request) as (ssh, _resolved):
            prov = WireGuardProvisioner(ssh)
            report = prov.get_system_report()
        return LogsResponse(ok=True, logs=report)
    except HTTPException:
        raise
    except Exception as exc:
        return LogsResponse(ok=False, error=_error_message(exc))


@app.post("/api/server/status", response_model=ServerStatusResponse)
async def server_status(payload: RollbackRequest, request: Request) -> ServerStatusResponse:
    request_id = uuid.uuid4().hex[:8]
    target = _ssh_target_label(payload.ssh) if payload.ssh else (payload.session_id or payload.saved_server_id or "unknown")
    logger.info("ssh.status.start req=%s target=%s protocol=%s", request_id, target, payload.protocol or "auto")
    try:
        _require_account(request)
        payload = _materialize_saved_server(payload, request)
        last_exc: Optional[Exception] = None
        status: dict = {}
        for attempt in range(1, 4):
            try:
                with _ssh_connection(
                    payload.ssh,
                    payload.session_id,
                    request=request,
                    logger=lambda message: logger.info("ssh.status.trace req=%s attempt=%s %s", request_id, attempt, message),
                ) as (ssh, _resolved):
                    if _is_xray_protocol(payload.protocol):
                        status = ProxyProvisioner(ssh).detect_status()
                    elif payload.protocol == "shadowtls_ss":
                        status = ShadowTLSSSProvisioner(ssh).detect_status()
                    elif payload.protocol:
                        status = _detect_server_status(ssh)
                    else:
                        status = _detect_server_status(ssh)
                        if not status.get("configured"):
                            status = ShadowTLSSSProvisioner(ssh).detect_status()
                        if not status.get("configured"):
                            status = ProxyProvisioner(ssh).detect_status()
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if attempt >= 3 or not _is_retryable_ssh_error(exc):
                    raise
                logger.info("ssh.status.retry req=%s attempt=%s error=%s", request_id, attempt, _error_message(exc))
                time.sleep(1.2 * attempt)
        if last_exc is not None:
            raise last_exc

        if not status.get("configured"):
            logger.info("ssh.status.ok req=%s configured=false", request_id)
            return ServerStatusResponse(ok=True, configured=False)

        logger.info(
            "ssh.status.ok req=%s configured=true protocol=%s clients=%s",
            request_id,
            status.get("protocol"),
            status.get("clients_count", 0),
        )
        return ServerStatusResponse(
            ok=True,
            configured=True,
            protocol=status.get("protocol"),
            listen_port=status.get("listen_port"),
            server_cidr=status.get("server_cidr"),
            clients_count=status.get("clients_count", 0),
            tyumen_port=status.get("tyumen_port"),
            proxy_sni=status.get("sni"),
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "ssh.status.fail req=%s target=%s error=%s",
            request_id,
            target,
            _error_message(exc),
            exc_info=True,
        )
        return ServerStatusResponse(ok=False, configured=False, error=_error_message(exc))


@app.post("/api/server/precheck", response_model=PrecheckResponse)
async def server_precheck(payload: ProvisionRequest, request: Request) -> PrecheckResponse:
    try:
        _require_account(request)
        payload = _materialize_saved_server(payload, request)
        with _ssh_connection(payload.ssh, payload.session_id, request=request) as (ssh, _resolved):
            opts = payload.options
            if _is_xray_protocol(opts.protocol):
                proxy = ProxyProvisioner(ssh)
                proxy_port = opts.listen_port
                auto_selected = False
                if not proxy_port:
                    status = proxy.detect_status()
                    existing = status.get("listen_port") if isinstance(status, dict) else None
                    if status.get("configured") and isinstance(existing, int) and 1 <= int(existing) <= 65535:
                        proxy_port = int(existing)
                        auto_selected = True
                    else:
                        proxy_port = proxy.choose_free_port() or 10443
                        auto_selected = True
                checks = proxy.pre_check(proxy_port)
                if auto_selected:
                    checks.append(
                        {
                            "name": "proxy_port_selected",
                            "ok": True,
                            "details": str(proxy_port),
                        }
                    )
            elif opts.protocol == "shadowtls_ss":
                proxy = ShadowTLSSSProvisioner(ssh)
                proxy_port = opts.listen_port
                auto_selected = False
                if not proxy_port:
                    status = proxy.detect_status()
                    existing = status.get("listen_port") if isinstance(status, dict) else None
                    if status.get("configured") and isinstance(existing, int) and 1 <= int(existing) <= 65535:
                        proxy_port = int(existing)
                        auto_selected = True
                    else:
                        proxy_port = proxy.choose_free_port() or 10443
                        auto_selected = True
                checks = proxy.pre_check(int(proxy_port))
                if auto_selected:
                    checks.append(
                        {
                            "name": "proxy_port_selected",
                            "ok": True,
                            "details": str(proxy_port),
                        }
                    )
            else:
                prov = WireGuardProvisioner(
                    ssh,
                    client_name=opts.client_name,
                    client_ip=opts.client_ip,
                    server_cidr=opts.server_cidr,
                    listen_port=opts.listen_port or 3478,
                    dns=opts.dns,
                    mtu=opts.mtu,
                    auto_mtu=opts.auto_mtu,
                    tune=opts.tune,
                    protocol=opts.protocol,
                )
                checks = prov.pre_check()
        return PrecheckResponse(ok=True, checks=checks)
    except HTTPException:
        raise
    except Exception as exc:
        return PrecheckResponse(ok=False, error=_error_message(exc))


@app.post("/api/repair", response_model=JobCreateResponse)
async def run_repair(payload: RollbackRequest, background_tasks: BackgroundTasks, request: Request) -> JobCreateResponse:
    account = _require_account(request)
    payload = _materialize_saved_server(payload, request)
    job = JOB_STORE.create(owner_user_id=account["user"]["id"])

    def _do_repair(job_id: str, payload: RollbackRequest):
        try:
            JOB_STORE.update(job_id, status="running")

            def progress(msg: str) -> None:
                JOB_STORE.append_progress(job_id, msg)

            with _ssh_connection(payload.ssh, payload.session_id, logger=progress) as (ssh, _resolved):
                prov = WireGuardProvisioner(ssh, progress=progress)
                logs = prov.repair_network()

            JOB_STORE.update(job_id, status="done", progress=logs, error=None)
        except Exception as exc:
            JOB_STORE.update(job_id, status="error", error=_error_message(exc))

    background_tasks.add_task(_do_repair, job.job_id, payload)
    return JobCreateResponse(job_id=job.job_id)


# --- AmneziaWG fallback (tied to a Remnawave subscription) -----------------


def _awg_service() -> AwgFallbackService:
    """Original single-server service retained for already-issued NL profiles."""
    return AwgFallbackService(build_account_store(), AwgFallbackConfig.from_env())


def _awg_service_for(server: object, registry: AwgRegistry) -> AwgFallbackService:
    """Route an exit server to either legacy or per-server peer storage."""
    legacy = AwgFallbackConfig.from_env()
    config = AwgFallbackConfig.from_server(server, link_secret=legacy.link_secret)
    default = registry.default_server
    storage_server_id = None if default is not None and server.id == default.id else server.id
    return AwgFallbackService(
        build_account_store(),
        config,
        server_id=storage_server_id,
    )


def _awg_all_services() -> list[AwgFallbackService]:
    """Every configured exit, with the default mapped to the legacy peer row."""
    registry = _awg_registry()
    return [
        _awg_service_for(server, registry)
        for server in registry.servers
        if server.usable
    ]


# NOTE (deliberate product decision, not an oversight): a device slot may hold a
# peer on EVERY exit at once, so "download several countries and switch freely" —
# which the bot advertises — works without a round trip through the bot. The cost
# is that each (slot, server) pair is an independent keypair usable in parallel, so
# a subscriber could hand different countries to different people. Device count is
# capped by slot number alone (see required_device_slot below). Revisit if sharing
# shows up in the numbers.


# The AmneziaWG Android client takes the tunnel name from the file's base name and
# validates it against [a-zA-Z0-9_=+.-]{1,15}. It raises instead of truncating, so an
# over-long name makes the config unimportable on the most common client.
_AWG_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_=+.-]")
_AWG_NAME_MAX = 15


def _awg_file_slug(
    server_id: Optional[str],
    *,
    device_slot: int = 1,
    family: bool = False,
) -> str:
    """Base filename == the tunnel name the user will see in the app."""
    suffix = _AWG_UNSAFE_NAME_RE.sub("", (server_id or "").strip())[:6]
    name = f"FVPN-{suffix}" if suffix else "FVPN"
    if family:
        name += "-F"
    elif int(device_slot) > 1:
        name += f"-D{int(device_slot)}"
    return name[:_AWG_NAME_MAX]


def _awg_label_config(config_text: str, server: Optional[object]) -> str:
    """Stamp which exit server issued this config.

    Whole-line ``#`` comments only, and only above ``[Interface]``: clients strip
    them, but an inline comment would be swallowed by the ``grep '^Address'``
    parsing that rebuilds server-side peer blocks. A non-comment key such as
    ``Name =`` would make the whole import fail, so never add one.
    """
    if server is None:
        return config_text
    display = getattr(server, "display", "") or getattr(server, "id", "")
    header = f"# Fodder VPN — {display}\n# server: {getattr(server, 'id', '')}\n"
    return header + config_text.lstrip("\n")


def _awg_registry() -> AwgRegistry:
    try:
        return AwgRegistry.from_env()
    except AwgRegistryError as exc:
        # A typo in the registry must not read as "no servers configured".
        raise HTTPException(status_code=500, detail=f"AWG registry is invalid: {exc}") from exc


@dataclass(frozen=True)
class _AwgEntitlement:
    paid_user: Optional[dict[str, Any]]
    free: ChannelAccessStatus
    billing_error: Optional[Exception] = None
    free_error: Optional[Exception] = None


def _awg_entitlement(telegram_id: int) -> _AwgEntitlement:
    """Resolve paid and channel access independently so either can keep NL alive."""
    paid_user: Optional[dict[str, Any]] = None
    billing_error: Optional[Exception] = None
    # Website bridge ids are deliberately outside Telegram's id range and can
    # never own a paid subscription. Some panel versions reject such a lookup;
    # treating that rejection as an outage would fail open after the 12h grace.
    if not is_web_account(telegram_id):
        try:
            paid_user = RemnawaveClient(RemnawaveConfig.from_env()).active_user(telegram_id)
        except RemnawaveError as exc:
            billing_error = exc
    free_error: Optional[Exception] = None
    try:
        free = channel_access_status(build_account_store(), telegram_id)
    except ChannelAccessError as exc:
        free_error = exc
        free = ChannelAccessStatus(configured=True, active=False)
    return _AwgEntitlement(
        paid_user=paid_user,
        free=free,
        billing_error=billing_error,
        free_error=free_error,
    )


def _awg_same_place(assigned: Optional[str], requested: Optional[str]) -> bool:
    """Are these two exits the same country reached over different ports?

    Paired exits are interchangeable for a free account. The pin to one exit
    exists to spread load across countries, and a second port is not another
    country — it is the same one reached over a port the person's network does
    not break. The pairing works both ways: whichever port someone was given,
    the other one has to remain available when the first fails them.
    """
    if not assigned or not requested or assigned == requested:
        return False
    try:
        registry = _awg_registry()
        one = registry.get_server(assigned)
        two = registry.get_server(requested)
    except Exception:  # a broken registry must not turn into a 500 here
        return False
    if one is None or two is None:
        return False
    return (
        getattr(two, "alt_of", None) == one.id
        or getattr(one, "alt_of", None) == two.id
    )


def _awg_authorise_entitlement(
    entitlement: _AwgEntitlement,
    *,
    server_id: Optional[str],
    required_device_slot: Optional[int],
) -> tuple[int, str]:
    """Return (device limit, access kind) or explain why this request is denied."""
    if entitlement.paid_user:
        limit = device_limit_of(entitlement.paid_user)
        if required_device_slot is None or required_device_slot <= limit:
            return limit, "paid"

    channel = ChannelAccessConfig.from_env()
    free_slot = required_device_slot == 1
    # Each free account is pinned to the exit assigned at signup, so load stays
    # spread instead of everyone drifting to one server.
    assigned = entitlement.free.server_id or channel.free_server_id
    # The pin exists to spread load across countries. A fallback-port exit is
    # not another country — it is the same one reached over a port the person's
    # network does not break, so the pin must not stand in the way of someone
    # whose only alternative is no VPN at all.
    free_location = (
        server_id is None
        or server_id == assigned
        or _awg_same_place(assigned, server_id)
    )
    if entitlement.free.active and free_slot and free_location:
        return 1, entitlement.free.kind or "member"

    if entitlement.billing_error is not None:
        raise HTTPException(status_code=502, detail=str(entitlement.billing_error))
    if entitlement.free_error is not None:
        raise HTTPException(
            status_code=502,
            detail="Не удалось проверить подписку на канал. Попробуйте ещё раз.",
        )
    if entitlement.free.active and not free_location:
        raise HTTPException(
            status_code=403,
            detail="Бесплатный профиль работает только на закреплённой за вами стране.",
        )
    if entitlement.free.active and not free_slot:
        raise HTTPException(
            status_code=403,
            detail="Бесплатный профиль доступен только для одного устройства.",
        )
    raise HTTPException(status_code=403, detail="Нет активного доступа к VPN.")


def _awg_issue_config(
    telegram_id: int,
    token: str,
    server_id: Optional[str] = None,
    device_slot: int = 1,
    preset_id: Optional[str] = None,
) -> tuple[str, Optional[object]]:
    """Verify the link token + active subscription, then return (config, server)."""
    awg_cfg = AwgFallbackConfig.from_env()
    if not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="AWG fallback is not configured.")
    if not verify_issue_token(awg_cfg.link_secret, telegram_id, token):
        raise HTTPException(status_code=403, detail="Invalid or missing token.")
    try:
        peer_id = device_peer_id(telegram_id, device_slot)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _awg_issue_entitled_config(
        peer_id,
        telegram_id,
        server_id,
        required_device_slot=device_slot,
        preset_id=preset_id,
    )


def _awg_issue_family_config(
    owner_telegram_id: int,
    token: str,
    server_id: Optional[str] = None,
) -> tuple[str, Optional[object]]:
    """Issue the owner's independent, single family slot."""
    awg_cfg = AwgFallbackConfig.from_env()
    if not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="AWG fallback is not configured.")
    epoch = build_account_store().awg_family_epoch(owner_telegram_id)
    if not verify_family_issue_token(awg_cfg.link_secret, owner_telegram_id, token, epoch):
        raise HTTPException(status_code=403, detail="Invalid or missing family token.")
    try:
        peer_id = family_guest_id(owner_telegram_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _awg_issue_entitled_config(
        peer_id,
        owner_telegram_id,
        server_id,
        required_device_slot=2,
    )


def _awg_issue_entitled_config(
    peer_id: int,
    entitlement_telegram_id: int,
    server_id: Optional[str] = None,
    *,
    required_device_slot: Optional[int] = None,
    preset_id: Optional[str] = None,
) -> tuple[str, Optional[object]]:
    """Provision ``peer_id`` using another Telegram account's entitlement."""
    registry = _awg_registry()
    requested_server = registry.get_server(server_id) if server_id else None
    if server_id and requested_server is None:
        raise HTTPException(status_code=404, detail="Unknown AWG server.")
    if requested_server is not None and not requested_server.enabled:
        raise HTTPException(
            status_code=503,
            detail="This location is temporarily unavailable. Please pick another one.",
        )
    entitlement = _awg_entitlement(entitlement_telegram_id)
    channel = ChannelAccessConfig.from_env()
    effective_server_id = server_id
    if not entitlement.paid_user and entitlement.free.active and not effective_server_id:
        effective_server_id = channel.free_server_id
    _limit, access_kind = _awg_authorise_entitlement(
        entitlement,
        server_id=effective_server_id,
        required_device_slot=required_device_slot,
    )
    server = requested_server or registry.get_server(effective_server_id)
    if server_id and server is None:
        raise HTTPException(status_code=404, detail="Unknown AWG server.")
    if server is None or not server.usable:
        raise HTTPException(status_code=503, detail="AWG fallback is not configured.")
    if not server.enabled:
        # Disabled exits stay registered so their existing peers keep being
        # suspended/resumed, but handing out a NEW config there would give the
        # user a tunnel we already know cannot connect.
        raise HTTPException(
            status_code=503,
            detail="This location is temporarily unavailable. Please pick another one.",
        )
    try:
        result = _awg_service_for(server, registry).issue(
            peer_id,
            remnawave_uuid=(entitlement.paid_user or {}).get("uuid"),
        )
    except Exception as exc:  # provisioning/SSH failure
        raise HTTPException(status_code=502, detail=f"AWG provisioning failed: {_error_message(exc)}") from exc
    # The preset only rewrites sender-side knobs, so it never touches the server:
    # a different operator profile is a different file, not a different peer.
    preset = registry.get_preset(preset_id) if preset_id else None
    if preset_id and preset is None:
        raise HTTPException(status_code=404, detail="Unknown profile.")
    logger.info(
        "awg.issue tid=%s peer=%s server=%s access=%s",
        entitlement_telegram_id,
        peer_id,
        server.id,
        access_kind,
    )
    return _awg_label_config(apply_preset(result["config"], preset), server), server


def _awg_access(
    telegram_id: int,
    token: str,
    *,
    family: bool = False,
) -> AwgAccessResponse:
    """Validate a signed installer link and expose only its paid slot count."""
    awg_cfg = AwgFallbackConfig.from_env()
    if not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="AWG fallback is not configured.")
    valid = (
        verify_family_issue_token(
            awg_cfg.link_secret,
            telegram_id,
            token,
            build_account_store().awg_family_epoch(telegram_id),
        )
        if family
        else verify_issue_token(awg_cfg.link_secret, telegram_id, token)
    )
    if not valid:
        raise HTTPException(status_code=403, detail="Invalid or missing token.")
    entitlement = _awg_entitlement(telegram_id)
    paid_limit, access_kind = _awg_authorise_entitlement(
        entitlement,
        server_id=None,
        required_device_slot=2 if family else 1,
    )
    return AwgAccessResponse(
        ok=True,
        active=True,
        device_limit=1 if family else paid_limit,
        family=family,
        expires_at=(
            str((entitlement.paid_user or {}).get("expireAt") or "") or None
            if access_kind == "paid"
            else (
                datetime.fromtimestamp(
                    int(entitlement.free.grace_expires_at), timezone.utc
                ).isoformat()
                if entitlement.free.grace_expires_at
                else None
            )
        ),
    )


def _awg_peer_ids_for_owner(service: object, owner_telegram_id: int) -> list[int]:
    """Existing personal, extra-device and family peers owned by one subscriber."""
    owner_telegram_id = int(owner_telegram_id)
    try:
        account = service.account
        if service.server_id is None:
            peers = account.awg_list_peers()
        else:
            peers = [
                peer
                for peer in account.awg_list_server_peers()
                if str(peer.get("server_id")) == str(service.server_id)
            ]
        owned: list[int] = []
        for peer in peers:
            peer_id = int(peer["telegram_id"])
            device_owner = device_owner_slot(peer_id)
            resolved_owner = family_owner_id(peer_id) or (
                device_owner[0] if device_owner else peer_id
            )
            if resolved_owner == owner_telegram_id:
                owned.append(peer_id)
        return sorted(set(owned))
    except (AttributeError, KeyError, TypeError, ValueError):
        # Compatibility for injected/custom services: preserve the original two
        # well-known slots. Real services always enumerate their persisted peers.
        return [owner_telegram_id, family_guest_id(owner_telegram_id)]


def _awg_webhook_apply(action: str, telegram_id: int) -> None:
    """Suspend/resume every AWG peer a user owns, across all exit servers.

    Blocking (SSH per server): the caller offloads it to a worker thread so a slow
    exit does not stall the event loop while Remnawave waits on the webhook.
    """
    try:
        raw_services = _awg_all_services()
        default_id = None
        if any(service.server_id is None for service in raw_services):
            registry = _awg_registry()
            default_id = getattr(registry.default_server, "id", None)
        services = [
            (service.server_id or default_id or "default", service)
            for service in raw_services
        ]
    except Exception as exc:
        logger.warning(
            "awg.webhook.registry_failed action=%s tid=%s err=%s",
            action,
            telegram_id,
            _error_message(exc),
        )
        return
    entitlement = _awg_entitlement(telegram_id) if action == "policy" else None
    paid_active = action == "enable" or bool(entitlement and entitlement.paid_user)
    billing_unknown = bool(entitlement and entitlement.billing_error)
    free_unknown = False
    try:
        free = channel_access_status(build_account_store(), telegram_id)
    except ChannelAccessError:
        free_unknown = True
        free = ChannelAccessStatus(configured=True, active=False)
    # A free account lives on the exit assigned at signup, not on a global one.
    free_server_id = free.server_id or ChannelAccessConfig.from_env().free_server_id
    for logical_server_id, service in services:
        try:
            peer_ids = _awg_peer_ids_for_owner(service, telegram_id)
        except ValueError:
            peer_ids = [telegram_id]
            logger.warning("awg.webhook.invalid_telegram_id tid=%s", telegram_id)
        for peer_id in peer_ids:
            try:
                free_allowed = bool(
                    free.active
                    and peer_id == int(telegram_id)
                    and logical_server_id == free_server_id
                )
                if paid_active or free_allowed:
                    service.resume(peer_id)
                elif billing_unknown or (
                    free_unknown
                    and peer_id == int(telegram_id)
                    and logical_server_id == free_server_id
                ):
                    # A failed policy lookup is not evidence that access expired.
                    continue
                else:
                    service.suspend(peer_id)
            except Exception as exc:
                logger.warning(
                    "awg.webhook.sync_failed action=%s tid=%s peer=%s server=%s err=%s",
                    action,
                    telegram_id,
                    peer_id,
                    logical_server_id,
                    _error_message(exc),
                )


@app.post("/api/integrations/remnawave/webhook")
async def remnawave_webhook(request: Request) -> JSONResponse:
    cfg = RemnawaveConfig.from_env()
    raw = await request.body()
    signature = request.headers.get("x-remnawave-signature")
    if not verify_webhook_signature(cfg.webhook_secret, raw, signature):
        raise HTTPException(status_code=401, detail="Invalid signature.")
    try:
        event, user = parse_event(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Malformed payload.") from exc
    action = event_action(event)
    telegram_id = telegram_id_of(user)
    # Keep the peer keys/config on disk. Disabling only removes its public key from
    # the live interface; enabling restores the same key so imported configs recover.
    if action in {"disable", "enable"} and telegram_id is not None:
        await run_in_threadpool(_awg_webhook_apply, action, telegram_id)
    return JSONResponse({"ok": True, "event": event, "action": action})


@app.get("/api/awg/{telegram_id}/config")
def awg_config(
    telegram_id: int,
    token: str,
    server: Optional[str] = None,
    device: int = 1,
    preset: Optional[str] = None,
) -> Response:
    # Plain `def`, not `async`: _awg_issue_config makes a blocking Remnawave HTTP
    # call and a blocking SSH provision. FastAPI runs sync path-ops in a worker
    # thread, so one slow/dead exit can no longer freeze every other request (and
    # the billing webhook) on the single uvicorn worker.
    config_text, selected_server = _awg_issue_config(telegram_id, token, server, device, preset)
    # The body carries a private key: never let a proxy/browser/link-preview cache it.
    # octet-stream (not text/plain) so browsers/Telegram keep the ".conf" name as-is
    # instead of appending ".txt" (which breaks "open with AmneziaWG" on Android).
    slug = _awg_file_slug(getattr(selected_server, "id", None), device_slot=device)
    return Response(
        content=config_text,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{slug}.conf"',
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
        },
    )


@app.get("/api/awg/{telegram_id}/qr")
def awg_qr(
    telegram_id: int,
    token: str,
    server: Optional[str] = None,
    device: int = 1,
    preset: Optional[str] = None,
) -> Response:
    config_text, _server = _awg_issue_config(telegram_id, token, server, device, preset)
    return Response(
        content=_build_qr_png(config_text),
        media_type="image/png",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@app.get("/api/awg/{telegram_id}/access", response_model=AwgAccessResponse)
def awg_access(telegram_id: int, token: str) -> AwgAccessResponse:
    return _awg_access(telegram_id, token)


@app.get("/api/awg/family/{owner_telegram_id}/config")
def awg_family_config(
    owner_telegram_id: int,
    token: str,
    server: Optional[str] = None,
) -> Response:
    config_text, selected_server = _awg_issue_family_config(
        owner_telegram_id,
        token,
        server,
    )
    slug = _awg_file_slug(getattr(selected_server, "id", None), family=True)
    return Response(
        content=config_text,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{slug}.conf"',
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
        },
    )


@app.get(
    "/api/awg/family/{owner_telegram_id}/access",
    response_model=AwgAccessResponse,
)
def awg_family_access(owner_telegram_id: int, token: str) -> AwgAccessResponse:
    return _awg_access(owner_telegram_id, token, family=True)


@app.get("/api/awg/family/{owner_telegram_id}/qr")
def awg_family_qr(
    owner_telegram_id: int,
    token: str,
    server: Optional[str] = None,
) -> Response:
    config_text, _server = _awg_issue_family_config(
        owner_telegram_id,
        token,
        server,
    )
    return Response(
        content=_build_qr_png(config_text),
        media_type="image/png",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


def _awg_owner_access(telegram_id: int, token: str) -> tuple[int, AwgRegistry]:
    """Authorise a device-management call. Personal token only — a family guest
    holds one slot and must not be able to see or revoke the owner's others."""
    awg_cfg = AwgFallbackConfig.from_env()
    if not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="AWG fallback is not configured.")
    if not verify_issue_token(awg_cfg.link_secret, telegram_id, token):
        raise HTTPException(status_code=403, detail="Invalid or missing token.")
    entitlement = _awg_entitlement(telegram_id)
    limit, _kind = _awg_authorise_entitlement(
        entitlement, server_id=None, required_device_slot=1
    )
    return limit, _awg_registry()


def _awg_legacy_server_id() -> Optional[str]:
    default = _awg_registry().default_server
    return getattr(default, "id", None)


@app.get("/api/awg/{telegram_id}/devices", response_model=AwgDeviceListResponse)
def awg_devices(telegram_id: int, token: str) -> AwgDeviceListResponse:
    """Which device slots exist, where their keys live, and when last used."""
    limit, _registry = _awg_owner_access(telegram_id, token)
    devices = list_devices(
        build_account_store(),
        telegram_id,
        limit,
        legacy_server_id=_awg_legacy_server_id(),
    )
    return AwgDeviceListResponse(
        ok=True,
        device_limit=limit,
        devices=[device.public() for device in devices],
    )


@app.post("/api/awg/{telegram_id}/devices/{slot}/revoke", response_model=AwgDeviceActionResponse)
def awg_device_revoke(telegram_id: int, slot: int, token: str) -> AwgDeviceActionResponse:
    """Destroy a slot's keys everywhere, so a shared config stops working."""
    _limit, registry = _awg_owner_access(telegram_id, token)
    try:
        peer_id_for_slot(telegram_id, slot)  # validates the slot number
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    failures: list[str] = []
    removed = revoke_device(
        telegram_id,
        slot,
        _awg_all_services(),
        on_error=lambda service, exc: failures.append(service.server_id or "default"),
    )
    if slot == FAMILY_SLOT and not failures:
        # The confirm dialog promises the relative loses access. Without bumping
        # the epoch their old link would just re-provision the same guest peer.
        build_account_store().awg_bump_family_epoch(telegram_id)
    if failures:
        logger.warning(
            "awg.device.revoke_partial tid=%s slot=%s failed_on=%s",
            telegram_id,
            slot,
            ",".join(failures),
        )
        # Partial revocation is a security problem, not a cosmetic one: say so
        # instead of reporting success while a key is still live somewhere.
        raise HTTPException(
            status_code=502,
            detail="Could not revoke on every location. Please try again.",
        )
    return AwgDeviceActionResponse(ok=True, slot=slot, revoked_from=removed)


@app.post("/api/awg/{telegram_id}/devices/{slot}/label", response_model=AwgDeviceActionResponse)
def awg_device_label(
    telegram_id: int, slot: int, token: str, payload: AwgDeviceLabelRequest
) -> AwgDeviceActionResponse:
    _limit, _registry = _awg_owner_access(telegram_id, token)
    if slot < 1 or slot > MAX_DEVICE_SLOT:
        raise HTTPException(status_code=400, detail="Unknown device slot.")
    store = build_account_store()
    store.awg_set_device_label(telegram_id, slot, payload.label)
    return AwgDeviceActionResponse(
        ok=True,
        slot=slot,
        label=store.awg_get_device_labels(telegram_id).get(slot),
    )


@app.get("/api/awg/{telegram_id}/family-link")
def awg_family_link(telegram_id: int, token: str) -> JSONResponse:
    """The family link signed with the owner's current epoch.

    Callers must not build this themselves: a locally signed link would use a
    stale epoch after a revoke and be dead on arrival.
    """
    limit, _registry = _awg_owner_access(telegram_id, token)
    if limit < 2:
        raise HTTPException(
            status_code=403,
            detail="Семейная ссылка доступна на тарифах от 3 устройств.",
        )
    config = AwgFallbackConfig.from_env()
    base = (os.getenv("VPNW_PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
    store = build_account_store()
    query = urlencode(
        {
            "family": telegram_id,
            "token": family_issue_token(
                config.link_secret, telegram_id, store.awg_family_epoch(telegram_id)
            ),
        }
    )
    return JSONResponse(
        {"ok": True, "url": f"{base}/connect/awg.html?{query}" if base else None},
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@app.get("/api/awg/{telegram_id}/invites", response_model=InviteListResponse)
def awg_invites(telegram_id: int, token: str) -> InviteListResponse:
    _limit, _registry = _awg_owner_access(telegram_id, token)
    channel = ChannelAccessConfig.from_env()
    if not channel.configured:
        raise HTTPException(status_code=503, detail="Приглашения пока не включены.")
    if is_web_account(telegram_id):
        raise HTTPException(
            status_code=403,
            detail="Приглашения доступны после привязки Telegram.",
        )

    store = build_account_store()
    config = InviteConfig.from_env()
    live = outstanding_invites(store, telegram_id)
    base = os.getenv("VPNW_PUBLIC_BASE_URL", "").strip().rstrip("/")
    return InviteListResponse(
        ok=True,
        max_outstanding=config.max_outstanding,
        grace_hours=channel.web_grace_hours,
        invites=[
            {
                "code": invite["code"],
                "expires_at": invite["expires_at"],
                "url": f"{base}/connect/join.html?code={invite['code']}" if base else None,
            }
            for invite in live
        ],
    )


@app.post("/api/awg/{telegram_id}/invites", response_model=InviteCreateResponse)
def awg_invite_create(telegram_id: int, token: str) -> InviteCreateResponse:
    """Mint an invite an existing subscriber can pass on outside Telegram.

    A website signup must never reach here: its own grace passes the same
    access check, so one leaked code would let temporary access
    replicate itself without limit.
    """
    _limit, _registry = _awg_owner_access(telegram_id, token)
    if not ChannelAccessConfig.from_env().configured:
        raise HTTPException(status_code=503, detail="Приглашения пока не включены.")
    if is_web_account(telegram_id):
        raise HTTPException(
            status_code=403,
            detail="Приглашения доступны после привязки Telegram.",
        )

    config = InviteConfig.from_env()
    owners = owner_ids()
    if owners and telegram_id in owners:
        # Владелец раздаёт промокоды сам: его лимитирует только здравый смысл,
        # а не потолок в три неиспользованных кода.
        config = InviteConfig(max_outstanding=10_000, ttl_days=config.ttl_days)
    try:
        invite = create_invite(build_account_store(), telegram_id, config)
    except InviteError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    base = os.getenv("VPNW_PUBLIC_BASE_URL", "").strip().rstrip("/")
    return InviteCreateResponse(
        ok=True,
        code=invite["code"],
        expires_at=invite["expires_at"],
        url=f"{base}/connect/join.html?code={invite['code']}" if base else None,
    )


@app.delete("/api/awg/{telegram_id}/invites/{code}", response_model=InviteCreateResponse)
def awg_invite_delete(telegram_id: int, code: str, token: str) -> InviteCreateResponse:
    _limit, _registry = _awg_owner_access(telegram_id, token)
    normalized = normalize_code(code) or code
    if not build_account_store().invite_delete(normalized, telegram_id):
        raise HTTPException(status_code=404, detail="Приглашение не найдено или уже активировано.")
    return InviteCreateResponse(ok=True, code=normalized)


@app.get("/api/web/invite/{code}", response_model=InviteCheckResponse)
def web_invite_check(code: str) -> InviteCheckResponse:
    """Tell a visitor whether their code will work, before they commit."""
    channel = ChannelAccessConfig.from_env()
    if not channel.configured:
        return InviteCheckResponse(
            ok=False,
            valid=False,
            detail="Бесплатная выдача пока не включена.",
        )
    try:
        resolve_invite(build_account_store(), code)
    except InviteError as exc:
        return InviteCheckResponse(ok=False, valid=False, detail=str(exc))
    return InviteCheckResponse(
        ok=True, valid=True, grace_hours=channel.web_grace_hours
    )


def _notify_owner(text: str) -> None:
    """Telegram message to the first VPNW_OWNER_IDS entry, via the product bot."""
    token = (
        os.getenv("VPNW_TELEGRAM_AUTH_TOKEN") or os.getenv("VPNW_BOT_TOKEN") or ""
    ).strip()
    owner = (os.getenv("VPNW_OWNER_IDS") or "").split(",")[0].strip()
    if not token or not owner:
        return
    body = urlencode({"chat_id": owner, "text": text}).encode()
    with _owner_notify_request.urlopen(
        _owner_notify_request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=body
        ),
        timeout=10,
    ) as response:
        response.read()


def _notify_owner_async(text: str) -> None:
    """Fire-and-forget: a dead Telegram must never slow down or fail a signup."""

    def _run() -> None:
        try:
            _notify_owner(text)
        except Exception:
            logging.getLogger("vpn_wizard").warning("owner notify failed", exc_info=True)

    threading.Thread(target=_run, daemon=True).start()


def _pick_free_server(store: AccountStore, channel: ChannelAccessConfig) -> str:
    """Least-loaded exit among the configured free ones.

    Filtered through the registry so a disabled exit never receives new people;
    NULL assignments in the ledger count toward the default exit.
    """
    candidates = list(channel.free_server_ids)
    caps: dict[str, int] = {}
    try:
        registry = _awg_registry()
        offerable = {server.id for server in registry.offerable}
        caps = {
            server.id: int(server.max_free)
            for server in registry.servers
            if getattr(server, "max_free", None)
        }
    except Exception:
        offerable = set()
    if offerable:
        alive = [sid for sid in candidates if sid in offerable]
        candidates = alive or candidates
    if len(candidates) == 1:
        return candidates[0]
    counts = store.channel_access_counts_by_server(channel.free_server_id)
    # A capped exit drops out of the running once it is full, but never blocks a
    # signup: if every exit is at its ceiling we still pick the emptiest one.
    room = [sid for sid in candidates if counts.get(sid, 0) < caps.get(sid, 1 << 30)]
    pool = room or candidates
    return min(pool, key=lambda sid: (counts.get(sid, 0), candidates.index(sid)))


# A shared code sits in a chat where anyone can refresh-click, and every redeem
# mints a real peer. A small per-IP hourly brake keeps one bored person from
# draining the family's counter; honest retries fit far under it.
_SHARED_REDEEM_WINDOW_SECONDS = 3600
_SHARED_REDEEM_PER_IP = 6
_shared_redeem_log: dict[str, list[float]] = {}
_shared_redeem_lock = threading.Lock()


def _shared_redeem_allowed(ip: str, *, now: Optional[float] = None) -> bool:
    if not ip:
        return True
    stamp = float(now if now is not None else time.time())
    horizon = stamp - _SHARED_REDEEM_WINDOW_SECONDS
    with _shared_redeem_lock:
        seen = [t for t in _shared_redeem_log.get(ip, []) if t > horizon]
        if len(seen) >= _SHARED_REDEEM_PER_IP:
            _shared_redeem_log[ip] = seen
            return False
        seen.append(stamp)
        _shared_redeem_log[ip] = seen
        if len(_shared_redeem_log) > 4096:
            stale = [key for key, hits in _shared_redeem_log.items() if not hits or max(hits) <= horizon]
            for key in stale:
                _shared_redeem_log.pop(key, None)
    return True


def _client_ip(request: Optional[Request]) -> str:
    if request is None:
        return ""
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.client.host if request.client else ""


@app.post("/api/web/invite/{code}/redeem", response_model=InviteRedeemResponse)
def web_invite_redeem(code: str, request: Request) -> InviteRedeemResponse:
    """Issue one NL profile for 12 hours so Telegram can become reachable."""
    store = build_account_store()
    channel = ChannelAccessConfig.from_env()
    awg_cfg = AwgFallbackConfig.from_env()
    if not channel.configured or not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="Сервис временно недоступен.")
    try:
        resolved = resolve_invite(store, code)
    except InviteError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Claim first: this endpoint is public and unthrottled, so provisioning before
    # claiming let N parallel requests each create a working grace row while only
    # one won the code. Reserving the code makes the race harmless, and a failed
    # local grant releases it so nobody loses their only way in.
    account_id = web_account_id()
    shared_code: Optional[str] = None
    if resolved["kind"] == "shared":
        shared = resolved["invite"]
        if not _shared_redeem_allowed(_client_ip(request)):
            raise HTTPException(
                status_code=429,
                detail="Слишком много попыток с этого адреса — попробуйте через час.",
            )
        if not store.shared_invite_consume(shared["code"]):
            raise HTTPException(
                status_code=409,
                detail="Лимит этого приглашения исчерпан — попросите новое.",
            )
        try:
            invite = mint_shared_redemption(store, shared)
        except Exception:
            store.shared_invite_release(shared["code"])
            raise
        shared_code = str(shared["code"])
    else:
        invite = resolved["invite"]
    if not store.invite_redeem(invite["code"], account_id):
        if shared_code:
            store.invite_delete(invite["code"], invite["issuer_telegram_id"])
            store.shared_invite_release(shared_code)
        raise HTTPException(status_code=409, detail="Это приглашение только что активировал кто-то другой.")
    stamp = int(time.time())
    # 0 = issued for good; the countdown UI stays off and nothing ever suspends it.
    expires_at = stamp + channel.web_grace_hours * 3600 if channel.web_grace_hours else 0
    assigned_server = _pick_free_server(store, channel)
    try:
        store.channel_access_grant_grace(
            account_id,
            invite["code"],
            expires_at=expires_at,
            server_id=assigned_server,
            now=stamp,
        )
    except Exception:
        store.invite_release(invite["code"], account_id)
        if shared_code:
            # The hidden per-use invite must not survive as a spare working code.
            store.invite_delete(invite["code"], invite["issuer_telegram_id"])
            store.shared_invite_release(shared_code)
        store.channel_access_delete(account_id)
        raise
    if shared_code:
        spent = store.shared_invite_get(shared_code) or {}
        _notify_owner_async(
            f"🎁 Выдан бесплатный профиль ({assigned_server}) по общему коду "
            f"{shared_code}: {spent.get('used_count', '?')}/{spent.get('max_uses', '?')}."
        )
    else:
        _notify_owner_async(
            f"🎟 Активирован код {invite['code']}: профиль на {assigned_server}."
        )
    bot_username = (os.getenv("VPNW_BOT_USERNAME") or "foddervpnbot").strip().lstrip("@")
    return InviteRedeemResponse(
        ok=True,
        telegram_id=account_id,
        token=issue_token(awg_cfg.link_secret, account_id),
        grace_hours=channel.web_grace_hours,
        grace_expires_at=expires_at,
        server_id=assigned_server,
        bind_url=f"https://t.me/{bot_username}?start=web_{invite['code']}",
    )


@app.post("/api/web/invite/{code}/link", response_model=InviteLinkResponse)
def web_invite_link(
    code: str,
    telegram_id: int,
    token: str,
    request: Request,
) -> InviteLinkResponse:
    """Bind a temporary website peer to its verified Telegram channel member."""
    channel = ChannelAccessConfig.from_env()
    awg_cfg = AwgFallbackConfig.from_env()
    if not channel.configured or not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="Сервис временно недоступен.")
    if not verify_issue_token(awg_cfg.link_secret, telegram_id, token):
        raise HTTPException(status_code=403, detail="Invalid or missing token.")
    normalized = normalize_code(code)
    store = build_account_store()
    invite = store.invite_get(normalized or "")
    grace = store.channel_access_by_invite(normalized or "")
    if (
        not normalized
        or not invite
        or not grace
        or int(invite.get("used_by") or 0) != int(grace["access_id"])
    ):
        raise HTTPException(status_code=404, detail="Временный профиль не найден.")
    expires_at = int(grace.get("grace_expires_at") or 0)
    if grace.get("status") != "active" or (expires_at and expires_at <= int(time.time())):
        raise HTTPException(
            status_code=410,
            detail="Срок временного профиля прошёл. Попросите новый код.",
        )
    try:
        member = telegram_channel_member(channel, telegram_id)
    except ChannelAccessError as exc:
        raise HTTPException(status_code=502, detail="Не удалось проверить подписку.") from exc
    if not member:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "channel_membership_required",
                "message": "Сначала подпишитесь на Fodder’s Dev.",
                "channel_url": channel.channel_url,
            },
        )

    web_id = int(grace["access_id"])
    migrated = store.channel_access_link_owner(
        web_id, telegram_id, invite_code=normalized
    )
    if not migrated:
        failures: list[str] = []
        for service in _awg_all_services():
            try:
                service.revoke(web_id)
            except Exception as exc:
                failures.append(_error_message(exc))
        if failures:
            raise HTTPException(
                status_code=502,
                detail="Не удалось безопасно удалить временный дубликат.",
            )
        store.channel_access_delete(web_id)
        store.channel_access_grant_member(telegram_id)

    _awg_webhook_apply("policy", telegram_id)
    base = _public_base_url_from_request(request)
    if not base:
        raise HTTPException(status_code=503, detail="Public URL is not configured.")
    # The person keeps the exit that was assigned at signup — the migrated row
    # carries it; the fallback re-grant path starts fresh on the default.
    assigned_server = (
        (store.channel_access_by_telegram(telegram_id) or {}).get("server_id")
        or channel.free_server_id
    )
    return InviteLinkResponse(
        ok=True,
        linked=migrated,
        personal_vpn_url=_channel_access_personal_url(
            base, telegram_id, awg_cfg.link_secret, assigned_server
        ),
        server_id=assigned_server,
    )


# --- прокси для приставок -------------------------------------------------------
# Приставки не умеют пароль у прокси, поэтому доступ по домашнему IP: кнопка в
# кабинете добавляет адрес запроса в allowlist squid'а на отдельном порту.

def _console_proxy_context(telegram_id: int, token: str):
    awg_cfg = AwgFallbackConfig.from_env()
    if not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="Сервис временно недоступен.")
    if not verify_issue_token(awg_cfg.link_secret, telegram_id, token):
        raise HTTPException(status_code=403, detail="Invalid or missing token.")
    config = ConsoleProxyConfig.from_env()
    entitlement = _awg_entitlement(telegram_id)
    if entitlement.billing_error is not None:
        raise HTTPException(status_code=502, detail=str(entitlement.billing_error))
    return config, bool(entitlement.paid_user)


def _console_proxy_payload(config, entitled: bool, telegram_id: int, **extra) -> ConsoleProxyResponse:
    store = build_account_store()
    return ConsoleProxyResponse(
        ok=True,
        enabled=config.configured,
        entitled=entitled,
        host=config.host or None,
        port=config.port if config.configured else None,
        ips=store.console_ips(telegram_id) if entitled else [],
        limit=config.max_ips,
        **extra,
    )


@app.get("/api/console-proxy/{telegram_id}", response_model=ConsoleProxyResponse)
def console_proxy_access(telegram_id: int, token: str) -> ConsoleProxyResponse:
    config, entitled = _console_proxy_context(telegram_id, token)
    return _console_proxy_payload(config, entitled, telegram_id)


@app.post("/api/console-proxy/{telegram_id}/bind", response_model=ConsoleProxyResponse)
def console_proxy_bind(telegram_id: int, token: str, request: Request) -> ConsoleProxyResponse:
    """Разрешить прокси домашней сети, из которой пришёл этот запрос."""
    config, entitled = _console_proxy_context(telegram_id, token)
    if not config.configured:
        raise HTTPException(status_code=503, detail="Прокси пока не включён.")
    if not entitled:
        raise HTTPException(
            status_code=403, detail="Прокси для приставок входит в платный тариф."
        )
    ip = normalize_ip(_client_ip(request))
    if not ip:
        raise HTTPException(status_code=400, detail="Не удалось определить ваш адрес.")
    store = build_account_store()
    store.console_ip_bind(telegram_id, ip, ttl_seconds=config.ttl_days * 86400)
    store.console_ips_trim(telegram_id, config.max_ips)
    sync_ips_file(config, store)
    return _console_proxy_payload(config, entitled, telegram_id, bound_ip=ip)


@app.delete("/api/console-proxy/{telegram_id}/bind", response_model=ConsoleProxyResponse)
def console_proxy_unbind(telegram_id: int, token: str, ip: str) -> ConsoleProxyResponse:
    config, entitled = _console_proxy_context(telegram_id, token)
    clean = normalize_ip(ip)
    if clean:
        store = build_account_store()
        store.console_ip_unbind(telegram_id, clean)
        sync_ips_file(config, store)
    return _console_proxy_payload(config, entitled, telegram_id)


@app.get("/api/metrics")
def owner_metrics(telegram_id: int, token: str) -> JSONResponse:
    """Business metrics, for the owner only.

    Signed with the same per-user token as everything else, but additionally
    restricted to VPNW_OWNER_IDS: a valid subscriber token must not open the
    books. Aggregate figures only — no per-user behaviour is recorded anywhere.
    """
    awg_cfg = AwgFallbackConfig.from_env()
    if not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="Not configured.")
    if not verify_issue_token(awg_cfg.link_secret, telegram_id, token):
        raise HTTPException(status_code=403, detail="Invalid or missing token.")
    owners = owner_ids()
    if not owners or telegram_id not in owners:
        raise HTTPException(status_code=403, detail="Not an owner.")

    bot = BotApiClient()
    # The bot holds signups and money; if it is down we still report our own side
    # rather than showing nothing.
    bot_stats = bot._get("/stats/full") if bot.config.configured else None
    try:
        registry = _awg_registry()
        legacy = getattr(registry.default_server, "id", None)
    except HTTPException:
        registry, legacy = None, None

    store = build_account_store()
    report = collect_metrics(
        store,
        registry,
        bot_stats,
        legacy_server_id=legacy,
        history=store.metrics_history(30),
    )
    return JSONResponse(report, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@app.get("/api/awg/servers")
async def awg_servers() -> JSONResponse:
    """Exit servers and obfuscation profiles offered to the bot/website picker.

    Public on purpose: it carries labels only. ``AwgRegistry.public()`` is what
    keeps hostnames and SSH credentials out of the response.
    """
    try:
        registry = AwgRegistry.from_env()
    except AwgRegistryError as exc:
        # Misconfigured registry: say so instead of pretending we have no servers.
        raise HTTPException(status_code=500, detail=f"AWG registry is invalid: {exc}") from exc
    if not registry.configured:
        raise HTTPException(status_code=503, detail="AWG fallback is not configured.")
    return JSONResponse(registry.public())


PORTAL_ENTRY_URL = "/portal/"
STATIC_ENTRY_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
}


@app.get("/miniapp", include_in_schema=False)
@app.get("/miniapp/", include_in_schema=False)
def legacy_miniapp_entry() -> RedirectResponse:
    """Move stale Telegram Wizard buttons onto a fresh, uncached portal URL."""
    return RedirectResponse(
        url=PORTAL_ENTRY_URL,
        status_code=307,
        headers=STATIC_ENTRY_HEADERS,
    )


def _entry_file(directory: str, filename: str = "index.html") -> FileResponse:
    root = Path(__file__).resolve().parents[2]
    return FileResponse(root / "web" / directory / filename, headers=STATIC_ENTRY_HEADERS)


@app.get("/portal", include_in_schema=False)
@app.get("/portal/", include_in_schema=False)
def portal_entry() -> FileResponse:
    # The liquid-glass cabinet. The previous portal keeps living at
    # /connect/index.html as a reachable fallback while this one settles in.
    return _entry_file("connect", "next.html")


@app.get("/wizard", include_in_schema=False)
@app.get("/wizard/", include_in_schema=False)
def wizard_entry() -> FileResponse:
    return _entry_file("miniapp")


def _mount_miniapp() -> None:
    root = Path(__file__).resolve().parents[2]
    connect_dir = root / "web" / "connect"
    miniapp_dir = root / "web" / "miniapp"
    # A distinct /portal URL avoids Telegram WebView reusing the old Wizard
    # document cached under /miniapp. Exact legacy entry routes below redirect
    # without caching; nested /miniapp assets remain available during rollout.
    if connect_dir.exists():
        app.mount("/portal", StaticFiles(directory=str(connect_dir), html=True), name="portal")
        app.mount("/miniapp", StaticFiles(directory=str(connect_dir), html=True), name="miniapp")
    if miniapp_dir.exists():
        app.mount("/wizard", StaticFiles(directory=str(miniapp_dir), html=True), name="wizard")
    # The portal also has a normal-browser address; family links use awg.html here.
    if connect_dir.exists():
        app.mount("/connect", StaticFiles(directory=str(connect_dir), html=True), name="connect")


_mount_miniapp()


def main() -> None:
    host = os.getenv("VPNW_HOST", "0.0.0.0")
    port = int(os.getenv("VPNW_PORT") or os.getenv("PORT", "8000"))
    uvicorn.run(
        "vpn_wizard.server:app",
        host=host,
        port=port,
        reload=False,
        access_log=False,
    )


if __name__ == "__main__":
    main()
