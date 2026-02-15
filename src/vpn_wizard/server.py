from __future__ import annotations

from dataclasses import dataclass, field
import base64
from collections import OrderedDict
from contextlib import contextmanager
from io import BytesIO
import os
from pathlib import Path
import socket
import time
from urllib.parse import urlparse
import tempfile
from typing import Callable, Optional
import threading
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator
import qrcode
import uvicorn

from vpn_wizard.core import SSHConfig, SSHRunner, WireGuardProvisioner
from vpn_wizard.proxy import ProxyProvisioner
from vpn_wizard.shadowtls import ShadowTLSSSProvisioner


app = FastAPI(title="VPN Wizard API")
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

if not cors_origins:
    cors_origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


class AuthRequest(BaseModel):
    ssh: Optional[SSHPayload] = None
    session_id: Optional[str] = None
    protocol: Optional[str] = None


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
    protocol: str = "amneziawg"  # "wireguard" or "amneziawg"
    proxy_sni: Optional[str] = None


class ProvisionRequest(BaseModel):
    ssh: Optional[SSHPayload] = None
    session_id: Optional[str] = None
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


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self) -> Job:
        job_id = uuid.uuid4().hex
        job = Job(job_id=job_id)
        with self._lock:
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return Job(
                job_id=job.job_id,
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
            )

    def update(self, job_id: str, **kwargs) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            for key, value in kwargs.items():
                setattr(job, key, value)

    def append_progress(self, job_id: str, message: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.progress.append(message)
            if len(job.progress) > 50:
                job.progress = job.progress[-50:]


JOB_STORE = JobStore()


@dataclass
class DownloadItem:
    config: str
    qr_png: bytes
    name: str
    suffix: str = "conf"


class DownloadStore:
    def __init__(self, limit: int = 200) -> None:
        self._items: "OrderedDict[str, DownloadItem]" = OrderedDict()
        self._lock = threading.Lock()
        self._limit = limit

    def create(self, config: str, qr_png: bytes, name: Optional[str], suffix: str = "conf") -> str:
        download_id = uuid.uuid4().hex
        safe_name = _safe_name(name)
        safe_suffix = (suffix or "conf").strip().lstrip(".") or "conf"
        with self._lock:
            self._items[download_id] = DownloadItem(
                config=config,
                qr_png=qr_png,
                name=safe_name,
                suffix=safe_suffix,
            )
            if len(self._items) > self._limit:
                self._items.popitem(last=False)
        return download_id

    def get(self, download_id: str) -> Optional[DownloadItem]:
        with self._lock:
            return self._items.get(download_id)


DOWNLOAD_STORE = DownloadStore()


@dataclass
class SessionItem:
    ssh: SSHPayload
    expires_at: float
    created_at: float
    touched_at: float


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

    def create(self, ssh: SSHPayload) -> str:
        session_id = uuid.uuid4().hex
        now = time.time()
        item = SessionItem(
            ssh=ssh.model_copy(deep=True),
            expires_at=now + self._ttl_seconds,
            created_at=now,
            touched_at=now,
        )
        with self._lock:
            self._cleanup(now)
            self._items[session_id] = item
        return session_id

    def get(self, session_id: str) -> Optional[SSHPayload]:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            item = self._items.get(session_id)
            if not item:
                return None
            item.touched_at = now
            item.expires_at = now + self._ttl_seconds
            self._items.move_to_end(session_id)
            return item.ssh.model_copy(deep=True)

    def revoke(self, session_id: str) -> bool:
        with self._lock:
            return self._items.pop(session_id, None) is not None


SESSION_STORE = SessionStore(
    ttl_seconds=int(os.getenv("VPNW_SESSION_TTL_SECONDS", "86400")),
    limit=int(os.getenv("VPNW_SESSION_LIMIT", "512")),
)


def _safe_name(name: Optional[str]) -> str:
    if not name:
        return "client1"
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in {"-", "_"})
    return cleaned or "client1"


def _download_filename(name: Optional[str], suffix: str) -> str:
    safe = _safe_name(name)
    return f"{safe}.{suffix}"


def _resolve_ssh_payload(
    ssh_payload: Optional[SSHPayload],
    session_id: Optional[str],
) -> SSHPayload:
    if ssh_payload is not None:
        return ssh_payload
    if session_id:
        session_ssh = SESSION_STORE.get(session_id)
        if session_ssh is not None:
            return session_ssh
        raise RuntimeError("Session expired. Please log in again.")
    raise RuntimeError("SSH credentials are required.")


@contextmanager
def _ssh_connection(
    ssh_payload: Optional[SSHPayload],
    session_id: Optional[str] = None,
    logger: Optional[Callable[[str], None]] = None,
):
    resolved = _resolve_ssh_payload(ssh_payload, session_id)
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


def _run_provision(job_id: str, payload: ProvisionRequest) -> None:
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

            if opts.protocol == "vless_reality":
                proxy = ProxyProvisioner(ssh, progress=progress)
                proxy_port = opts.listen_port
                if not proxy_port:
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
                checks = pre_checks if opts.check else []
                suffix = "txt"
                JOB_STORE.update(job_id, client_name=result.get("name") or opts.client_name)

            elif opts.protocol == "shadowtls_ss":
                proxy = ShadowTLSSSProvisioner(ssh, progress=progress)
                proxy_port = opts.listen_port
                if not proxy_port:
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

        # We store a QR for every downloadable item (store schema requirement), but only show
        # a meaningful QR to the user when `config` is actually a QR-friendly payload (WG config / vless://).
        qr_seed = config if config else "VPN Wizard"
        qr_png = _build_qr_png(qr_seed) if (config or auto_config) else None
        qr_b64 = base64.b64encode(qr_png).decode("ascii") if (qr_png and config) else None
        download_id = DOWNLOAD_STORE.create(config, qr_png, opts.client_name, suffix=suffix) if (config and qr_png) else None
        auto_download_id = None
        if opts.protocol in {"vless_reality", "shadowtls_ss"} and auto_config and qr_png:
            auto_download_id = DOWNLOAD_STORE.create(auto_config, qr_png, f"{opts.client_name}-auto", suffix="json")
        JOB_STORE.update(
            job_id,
            status="done",
            config=config,
            alternatives=alternatives if opts.protocol == "vless_reality" else None,
            auto_config=auto_config if opts.protocol in {"vless_reality", "shadowtls_ss"} else None,
            qr_png_base64=qr_b64,
            download_id=download_id,
            auto_download_id=auto_download_id,
            checks=checks,
            error=None,
        )
    except Exception as exc:
        JOB_STORE.update(job_id, status="error", error=str(exc))


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/api/ssh/discover-port", response_model=SSHDiscoverResponse)
async def ssh_discover_port(payload: SSHDiscoverRequest) -> SSHDiscoverResponse:
    try:
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
    except Exception as exc:
        return SSHDiscoverResponse(ok=False, error=str(exc))


@app.post("/api/sessions/login", response_model=SessionLoginResponse)
async def session_login(payload: SessionLoginRequest) -> SessionLoginResponse:
    try:
        with _ssh_connection(payload.ssh):
            pass
        session_id = SESSION_STORE.create(payload.ssh)
        return SessionLoginResponse(
            ok=True,
            session_id=session_id,
            host=payload.ssh.host,
            user=payload.ssh.user,
            port=payload.ssh.port,
        )
    except Exception as exc:
        return SessionLoginResponse(ok=False, error=str(exc))


@app.post("/api/sessions/revoke", response_model=RollbackResponse)
async def session_revoke(payload: SessionRevokeRequest) -> RollbackResponse:
    removed = SESSION_STORE.revoke(payload.session_id)
    if not removed:
        return RollbackResponse(ok=False, error="Session not found.")
    return RollbackResponse(ok=True)


@app.post("/api/provision", response_model=JobCreateResponse)
async def provision(payload: ProvisionRequest, background_tasks: BackgroundTasks) -> JobCreateResponse:
    job = JOB_STORE.create()
    background_tasks.add_task(_run_provision, job.job_id, payload)
    return JobCreateResponse(job_id=job.job_id)


@app.get("/api/jobs/{job_id}", response_model=JobStatus)
def job_status(job_id: str) -> JobStatus:
    job = JOB_STORE.get(job_id)
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
def job_result(job_id: str) -> ProvisionResponse:
    job = JOB_STORE.get(job_id)
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
async def rollback(payload: RollbackRequest) -> RollbackResponse:
    try:
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            prov = WireGuardProvisioner(ssh)
            backup = prov.rollback_last_backup()
        if not backup:
            return RollbackResponse(ok=False, error="No backup found.")
        return RollbackResponse(ok=True, backup=backup)
    except Exception as exc:
        return RollbackResponse(ok=False, error=str(exc))


@app.post("/api/clients/list", response_model=ClientListResponse)
async def client_list(payload: RollbackRequest) -> ClientListResponse:
    try:
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            if payload.protocol == "vless_reality":
                proxy = ProxyProvisioner(ssh)
                clients = proxy.list_clients()
            elif payload.protocol == "shadowtls_ss":
                proxy = ShadowTLSSSProvisioner(ssh)
                clients = proxy.list_clients()
            else:
                prov = WireGuardProvisioner(ssh)
                clients = prov.list_clients()
        return ClientListResponse(ok=True, clients=clients)
    except Exception as exc:
        return ClientListResponse(ok=False, error=str(exc))


@app.post("/api/clients/add", response_model=ClientAddResponse)
async def client_add(payload: ClientRequest) -> ClientAddResponse:
    try:
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            if payload.protocol == "vless_reality":
                proxy = ProxyProvisioner(ssh)
                result = proxy.add_client(payload.client_name or "client1")
                client_name = result["name"]
                config_value = result["link"]
                alternatives = result.get("alternatives")
                auto_config = proxy.build_singbox_auto_config(primary_link=config_value, alternatives=alternatives)
                client_ip = None
                iface = result.get("interface")
                suffix = "txt"
            elif payload.protocol == "shadowtls_ss":
                proxy = ShadowTLSSSProvisioner(ssh)
                result = proxy.add_client(payload.client_name or "client1")
                client_name = result["name"]
                config_value = None
                alternatives = None
                auto_config = result.get("auto_config")
                client_ip = None
                iface = result.get("interface")
                suffix = "txt"
            else:
                prov_kwargs = {}
                if payload.listen_port:
                    prov_kwargs["listen_port"] = payload.listen_port
                prov = WireGuardProvisioner(ssh, **prov_kwargs)
                result = prov.add_client(client_name=payload.client_name, client_ip=payload.client_ip)
                client_name = result["name"]
                config_value = result["config"]
                alternatives = None
                auto_config = None
                client_ip = result["ip"]
                iface = result.get("interface")
                suffix = "conf"
        qr_seed = config_value if config_value else "VPN Wizard"
        qr_png = _build_qr_png(qr_seed) if (config_value or auto_config) else None
        qr_b64 = base64.b64encode(qr_png).decode("ascii") if (qr_png and config_value) else None
        download_id = (
            DOWNLOAD_STORE.create(config_value, qr_png, client_name, suffix=suffix)
            if (config_value and qr_png)
            else None
        )
        auto_download_id = None
        if payload.protocol in {"vless_reality", "shadowtls_ss"} and auto_config and qr_png:
            auto_download_id = DOWNLOAD_STORE.create(auto_config, qr_png, f"{client_name}-auto", suffix="json")
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
    except Exception as exc:
        return ClientAddResponse(ok=False, error=str(exc))


@app.post("/api/clients/remove", response_model=RollbackResponse)
async def client_remove(payload: ClientRemoveRequest) -> RollbackResponse:
    try:
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            if payload.protocol == "vless_reality":
                proxy = ProxyProvisioner(ssh)
                ok = proxy.remove_client(payload.client_name)
            elif payload.protocol == "shadowtls_ss":
                proxy = ShadowTLSSSProvisioner(ssh)
                ok = proxy.remove_client(payload.client_name)
            else:
                prov = WireGuardProvisioner(ssh)
                ok = prov.remove_client(payload.client_name)
        if not ok:
            return RollbackResponse(ok=False, error="Client not found.")
        return RollbackResponse(ok=True, backup=None)
    except Exception as exc:
        return RollbackResponse(ok=False, error=str(exc))


@app.post("/api/clients/rotate", response_model=ClientAddResponse)
async def client_rotate(payload: ClientRemoveRequest) -> ClientAddResponse:
    try:
        if payload.protocol in {"vless_reality", "shadowtls_ss"}:
            return ClientAddResponse(ok=False, error="Rotate is not supported for proxy profiles.")
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            prov_kwargs = {}
            if payload.listen_port:
                prov_kwargs["listen_port"] = payload.listen_port
            prov = WireGuardProvisioner(ssh, **prov_kwargs)
            result = prov.rotate_client(payload.client_name)
        qr_png = _build_qr_png(result["config"])
        qr_b64 = base64.b64encode(qr_png).decode("ascii")
        download_id = DOWNLOAD_STORE.create(result["config"], qr_png, result.get("name"))
        return ClientAddResponse(
            ok=True,
            client_name=result["name"],
            client_ip=result["ip"],
            config=result["config"],
            qr_png_base64=qr_b64,
            download_id=download_id,
            interface=result.get("interface"),
        )
    except Exception as exc:
        return ClientAddResponse(ok=False, error=str(exc))


@app.post("/api/clients/export", response_model=ClientExportResponse)
async def client_export(payload: ClientRemoveRequest) -> ClientExportResponse:
    try:
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            if payload.protocol == "vless_reality":
                proxy = ProxyProvisioner(ssh)
                result = proxy.export_client(payload.client_name)
                client_name = result["name"]
                config_value = result["link"]
                alternatives = result.get("alternatives")
                auto_config = proxy.build_singbox_auto_config(primary_link=config_value, alternatives=alternatives)
                client_ip = None
                iface = result.get("interface")
                suffix = "txt"
            elif payload.protocol == "shadowtls_ss":
                proxy = ShadowTLSSSProvisioner(ssh)
                result = proxy.export_client(payload.client_name)
                client_name = result["name"]
                config_value = None
                alternatives = None
                auto_config = result.get("auto_config")
                client_ip = None
                iface = result.get("interface")
                suffix = "txt"
            else:
                prov = WireGuardProvisioner(ssh)
                result = prov.export_client(payload.client_name)
                client_name = result["name"]
                config_value = result["config"]
                alternatives = None
                auto_config = None
                client_ip = result["ip"]
                iface = result.get("interface")
                suffix = "conf"
        qr_seed = config_value if config_value else "VPN Wizard"
        qr_png = _build_qr_png(qr_seed) if (config_value or auto_config) else None
        qr_b64 = base64.b64encode(qr_png).decode("ascii") if (qr_png and config_value) else None
        download_id = (
            DOWNLOAD_STORE.create(config_value, qr_png, client_name, suffix=suffix)
            if (config_value and qr_png)
            else None
        )
        auto_download_id = None
        if payload.protocol in {"vless_reality", "shadowtls_ss"} and auto_config and qr_png:
            auto_download_id = DOWNLOAD_STORE.create(auto_config, qr_png, f"{client_name}-auto", suffix="json")
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
    except Exception as exc:
        return ClientExportResponse(ok=False, error=str(exc))


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
async def get_logs(payload: RollbackRequest) -> LogsResponse:
    try:
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            prov = WireGuardProvisioner(ssh)
            report = prov.get_system_report()
        return LogsResponse(ok=True, logs=report)
    except Exception as exc:
        return LogsResponse(ok=False, error=str(exc))


@app.post("/api/server/status", response_model=ServerStatusResponse)
async def server_status(payload: RollbackRequest) -> ServerStatusResponse:
    try:
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            if payload.protocol == "vless_reality":
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

        if not status.get("configured"):
            return ServerStatusResponse(ok=True, configured=False)

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
    except Exception as exc:
        return ServerStatusResponse(ok=False, configured=False, error=str(exc))


@app.post("/api/server/precheck", response_model=PrecheckResponse)
async def server_precheck(payload: ProvisionRequest) -> PrecheckResponse:
    try:
        with _ssh_connection(payload.ssh, payload.session_id) as (ssh, _resolved):
            opts = payload.options
            if opts.protocol == "vless_reality":
                proxy = ProxyProvisioner(ssh)
                proxy_port = opts.listen_port
                auto_selected = False
                if not proxy_port:
                    proxy_port = proxy.choose_free_port() or 443
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
                    proxy_port = proxy.choose_free_port() or 443
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
    except Exception as exc:
        return PrecheckResponse(ok=False, error=str(exc))


@app.post("/api/repair", response_model=JobCreateResponse)
async def run_repair(payload: RollbackRequest, background_tasks: BackgroundTasks) -> JobCreateResponse:
    job = JOB_STORE.create()

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
            JOB_STORE.update(job_id, status="error", error=str(exc))

    background_tasks.add_task(_do_repair, job.job_id, payload)
    return JobCreateResponse(job_id=job.job_id)


def _mount_miniapp() -> None:
    root = Path(__file__).resolve().parents[2]
    miniapp_dir = root / "web" / "miniapp"
    if miniapp_dir.exists():
        app.mount("/miniapp", StaticFiles(directory=str(miniapp_dir), html=True), name="miniapp")


_mount_miniapp()


def main() -> None:
    host = os.getenv("VPNW_HOST", "0.0.0.0")
    port = int(os.getenv("VPNW_PORT") or os.getenv("PORT", "8000"))
    uvicorn.run("vpn_wizard.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
