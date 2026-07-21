from __future__ import annotations

from dataclasses import dataclass, field
import base64
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from io import BytesIO
import importlib.metadata
import logging
import os
from pathlib import Path
import socket
import subprocess
import time
from urllib.parse import urlparse
import tempfile
from typing import Callable, Optional
import threading
import re
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import paramiko
from pydantic import BaseModel, Field, model_validator
import qrcode
import uvicorn

import vpn_wizard.proxy as proxy_module
from vpn_wizard.account import (
    build_account_store,
    verify_telegram_login,
    verify_telegram_webapp_init_data,
)
from vpn_wizard.core import SSHConfig, SSHRunner, WireGuardProvisioner
from vpn_wizard.awg_fallback import AwgFallbackConfig, AwgFallbackService, verify_issue_token
from vpn_wizard.awg_servers import AwgRegistry, AwgRegistryError
from vpn_wizard.proxy import ProxyProvisioner, rewrite_vless_alternatives, rewrite_vless_endpoint
from vpn_wizard.relay import RelayProvisioner
from vpn_wizard.remnawave import (
    RemnawaveClient,
    RemnawaveConfig,
    RemnawaveError,
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


# The AmneziaWG Android client takes the tunnel name from the file's base name and
# validates it against [a-zA-Z0-9_=+.-]{1,15}. It raises instead of truncating, so an
# over-long name makes the config unimportable on the most common client.
_AWG_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_=+.-]")
_AWG_NAME_MAX = 15


def _awg_file_slug(server_id: Optional[str]) -> str:
    """Base filename == the tunnel name the user will see in the app."""
    suffix = _AWG_UNSAFE_NAME_RE.sub("", (server_id or "").strip())[: _AWG_NAME_MAX - 5]
    return f"FVPN-{suffix}" if suffix else "FVPN"


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


def _awg_issue_config(
    telegram_id: int,
    token: str,
    server_id: Optional[str] = None,
) -> tuple[str, Optional[object]]:
    """Verify the link token + active subscription, then return (config, server)."""
    awg_cfg = AwgFallbackConfig.from_env()
    if not awg_cfg.link_secret:
        raise HTTPException(status_code=503, detail="AWG fallback is not configured.")
    if not verify_issue_token(awg_cfg.link_secret, telegram_id, token):
        raise HTTPException(status_code=403, detail="Invalid or missing token.")
    registry = _awg_registry()
    server = registry.get_server(server_id)
    if server_id and server is None:
        raise HTTPException(status_code=404, detail="Unknown AWG server.")
    if server is None or not server.usable:
        raise HTTPException(status_code=503, detail="AWG fallback is not configured.")
    try:
        user = RemnawaveClient(RemnawaveConfig.from_env()).active_user(telegram_id)
    except RemnawaveError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if not user:
        raise HTTPException(status_code=403, detail="No active subscription.")
    try:
        result = _awg_service_for(server, registry).issue(
            telegram_id,
            remnawave_uuid=user.get("uuid"),
        )
    except Exception as exc:  # provisioning/SSH failure
        raise HTTPException(status_code=502, detail=f"AWG provisioning failed: {_error_message(exc)}") from exc
    return _awg_label_config(result["config"], server), server


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
        try:
            services = _awg_all_services()
        except Exception as exc:
            services = []
            logger.warning(
                "awg.webhook.registry_failed action=%s tid=%s err=%s",
                action,
                telegram_id,
                _error_message(exc),
            )
        for service in services:
            try:
                if action == "disable":
                    service.suspend(telegram_id)
                else:
                    service.resume(telegram_id)
            except Exception as exc:
                logger.warning(
                    "awg.webhook.sync_failed action=%s tid=%s server=%s err=%s",
                    action,
                    telegram_id,
                    service.server_id or "default",
                    _error_message(exc),
                )
    return JSONResponse({"ok": True, "event": event, "action": action})


@app.get("/api/awg/{telegram_id}/config")
async def awg_config(telegram_id: int, token: str, server: Optional[str] = None) -> Response:
    config_text, selected_server = _awg_issue_config(telegram_id, token, server)
    # The body carries a private key: never let a proxy/browser/link-preview cache it.
    # octet-stream (not text/plain) so browsers/Telegram keep the ".conf" name as-is
    # instead of appending ".txt" (which breaks "open with AmneziaWG" on Android).
    slug = _awg_file_slug(getattr(selected_server, "id", None))
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
async def awg_qr(telegram_id: int, token: str, server: Optional[str] = None) -> Response:
    config_text, _server = _awg_issue_config(telegram_id, token, server)
    return Response(
        content=_build_qr_png(config_text),
        media_type="image/png",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


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


def _mount_miniapp() -> None:
    root = Path(__file__).resolve().parents[2]
    miniapp_dir = root / "web" / "miniapp"
    if miniapp_dir.exists():
        app.mount("/miniapp", StaticFiles(directory=str(miniapp_dir), html=True), name="miniapp")
    # Public "how to connect" page — reachable without Telegram, safe to send to new users.
    connect_dir = root / "web" / "connect"
    if connect_dir.exists():
        app.mount("/connect", StaticFiles(directory=str(connect_dir), html=True), name="connect")


_mount_miniapp()


def main() -> None:
    host = os.getenv("VPNW_HOST", "0.0.0.0")
    port = int(os.getenv("VPNW_PORT") or os.getenv("PORT", "8000"))
    uvicorn.run("vpn_wizard.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
