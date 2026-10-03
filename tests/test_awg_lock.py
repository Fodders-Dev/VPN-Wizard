from types import SimpleNamespace
import threading
import pytest
from vpn_wizard.awg_lock import mutation_lock, serialized_mutation, AwgMutationBusy


def test_managed_mutation_lock_has_bounded_wait(monkeypatch, tmp_path):
    monkeypatch.setenv("VPNW_STATE_DB", str(tmp_path / "state.db"))
    config = SimpleNamespace(host="test-host", port=22)
    held = threading.Event()
    release = threading.Event()
    def worker():
        with mutation_lock(config):
            held.set()
            release.wait(3)
    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert held.wait(1)
        with pytest.raises(AwgMutationBusy):
            with mutation_lock(config, timeout=0.02):
                pytest.fail("Must not concurrently mutate the same host")
    finally:
        release.set()
        thread.join(2)
    with mutation_lock(config, timeout=0.02):
        pass


def test_decorator_releases_after_mutation_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("VPNW_STATE_DB", str(tmp_path / "state.db"))
    class Service:
        config = SimpleNamespace(host="other-host", port=22)
        @serialized_mutation
        def mutate(self):
            raise RuntimeError("test")
    with pytest.raises(RuntimeError):
        Service().mutate()
    with mutation_lock(Service.config, timeout=0.02):
        pass
