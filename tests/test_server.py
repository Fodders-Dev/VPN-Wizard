from __future__ import annotations

from vpn_wizard.server import JobStore


def test_job_store_create_update_and_progress() -> None:
    store = JobStore()
    job = store.create()
    store.append_progress(job.job_id, "step 1")
    store.update(job.job_id, status="running")
    stored = store.get(job.job_id)
    assert stored is not None
    assert stored.status == "running"
    assert stored.progress == ["step 1"]
