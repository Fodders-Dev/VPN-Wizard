from __future__ import annotations

from vpn_wizard.server import DOWNLOAD_STORE, JobStore, download_config, download_qr


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
