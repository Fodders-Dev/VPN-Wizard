"""Bounded cross-process serialization of managed AWG mutations."""
from contextlib import contextmanager
from functools import wraps
import hashlib
import os
from pathlib import Path
import threading
import time

from vpn_wizard.account import default_db_path

_THREAD_LOCKS = [threading.Lock() for _ in range(64)]


class AwgMutationBusy(RuntimeError):
    pass


@contextmanager
def mutation_lock(config, *, timeout=1.0):
    # Public/paid databases share this directory and therefore the same locks.
    key = hashlib.sha256(f"{config.host}:{config.port}".encode()).hexdigest()
    thread_lock = _THREAD_LOCKS[int(key[:8], 16) % len(_THREAD_LOCKS)]
    if not thread_lock.acquire(timeout=timeout):
        raise AwgMutationBusy("AWG mutation busy")
    handle = None
    try:
        if os.name != "nt":
            import fcntl
            folder = default_db_path().parent / "awg-locks"
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            handle = (folder / (key + ".lock")).open("a")
            os.chmod(handle.name, 0o600)
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise AwgMutationBusy("AWG mutation busy")
                    time.sleep(0.025)
        yield
    finally:
        if handle:
            handle.close()  # Releases flock even after an SSH exception.
        thread_lock.release()


def serialized_mutation(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with mutation_lock(self.config):
            return method(self, *args, **kwargs)
    return wrapped
