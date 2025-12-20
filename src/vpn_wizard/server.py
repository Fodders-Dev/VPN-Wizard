from __future__ import annotations

from dataclasses import dataclass, field
import base64
from io import BytesIO
import os
from pathlib import Path
import tempfile
from typing import Optional
import threading
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import qrcode
import uvicorn

from vpn_wizard.core import SSHConfig, SSHRunner, WireGuardProvisioner


app = FastAPI(title="VPN Wizard API")
cors_origins = [item.strip() for item in os.getenv("VPNW_CORS_ORIGINS", "").split(",") if item.strip()]
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


class ProvisionOptions(BaseModel):
    client_name: str = "client1"
    client_ip: str = "10.10.0.2/32"
    server_cidr: str = "10.10.0.1/24"
    listen_port: int = 51820
    dns: str = "1.1.1.1"
    mtu: Optional[int] = None
    auto_mtu: bool = True
    tune: bool = True
    check: bool = True


class ProvisionRequest(BaseModel):
    ssh: SSHPayload
    options: ProvisionOptions = ProvisionOptions()


class CheckItem(BaseModel):
    name: str
    ok: bool
    details: Optional[str] = None


class ProvisionResponse(BaseModel):
    ok: bool
    config: Optional[str] = None
    qr_png_base64: Optional[str] = None
    checks: list[CheckItem] = []
    error: Optional[str] = None


class JobCreateResponse(BaseModel):
    job_id: str


class JobStatus(BaseModel):
    job_id: str
    status: str
    progress: list[str] = []
    checks: list[CheckItem] = []
    error: Optional[str] = None
    config_ready: bool = False


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
    img = qrcode.make(config)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


@dataclass
class Job:
    job_id: str
    status: str = "queued"
    progress: list[str] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    config: Optional[str] = None
    qr_png_base64: Optional[str] = None
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
                qr_png_base64=job.qr_png_base64,
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


def _run_provision(job_id: str, payload: ProvisionRequest) -> None:
    temp_key = TempKey()
    try:
        JOB_STORE.update(job_id, status="running")

        key_path = payload.ssh.key_path
        if payload.ssh.key_content:
            temp_key = _write_temp_key(payload.ssh.key_content)
            key_path = temp_key.path

        def progress(msg: str) -> None:
            JOB_STORE.append_progress(job_id, msg)

        progress("Connecting over SSH")
        cfg = SSHConfig(
            host=payload.ssh.host,
            user=payload.ssh.user,
            port=payload.ssh.port,
            password=payload.ssh.password,
            key_path=key_path,
        )
        with SSHRunner(cfg, logger=progress) as ssh:
            opts = payload.options
            prov = WireGuardProvisioner(
                ssh,
                client_name=opts.client_name,
                client_ip=opts.client_ip,
                server_cidr=opts.server_cidr,
                listen_port=opts.listen_port,
                dns=opts.dns,
                mtu=opts.mtu,
                auto_mtu=opts.auto_mtu,
                tune=opts.tune,
                progress=progress,
            )
            prov.provision()
            config = prov.export_client_config()
            checks = prov.post_check() if opts.check else []

        qr_b64 = _build_qr_base64(config)
        JOB_STORE.update(
            job_id,
            status="done",
            config=config,
            qr_png_base64=qr_b64,
            checks=checks,
            error=None,
        )
    except Exception as exc:
        JOB_STORE.update(job_id, status="error", error=str(exc))
    finally:
        temp_key.cleanup()


@app.get("/health")
def health() -> dict:
    return {"ok": True}


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
        qr_png_base64=job.qr_png_base64,
        checks=job.checks,
        error=None,
    )


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
