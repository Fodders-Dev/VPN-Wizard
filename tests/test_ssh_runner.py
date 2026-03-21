from __future__ import annotations

import pytest

from vpn_wizard.core import SSHConfig, SSHRunner


def test_connect_passes_banner_and_auth_timeouts(monkeypatch) -> None:
    captured: list[dict] = []

    class FakeClient:
        def set_missing_host_key_policy(self, _policy) -> None:
            return None

        def connect(self, **kwargs) -> None:
            captured.append(kwargs)

        def close(self) -> None:
            return None

    monkeypatch.setattr("vpn_wizard.core.paramiko.SSHClient", lambda: FakeClient())
    cfg = SSHConfig(host="example.com", user="root")
    runner = SSHRunner(cfg)
    runner.connect()
    assert captured
    assert captured[0]["banner_timeout"] == cfg.banner_timeout
    assert captured[0]["auth_timeout"] == cfg.auth_timeout


def test_connect_retries_when_banner_read_fails(monkeypatch) -> None:
    attempts = {"count": 0}

    class FakeClient:
        def set_missing_host_key_policy(self, _policy) -> None:
            return None

        def connect(self, **kwargs) -> None:
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise RuntimeError("Error reading SSH protocol banner")

        def close(self) -> None:
            return None

    monkeypatch.setattr("vpn_wizard.core.paramiko.SSHClient", lambda: FakeClient())
    monkeypatch.setattr("vpn_wizard.core.time.sleep", lambda _delay: None)

    cfg = SSHConfig(host="example.com", user="root", connect_retries=2, connect_retry_delay=0)
    runner = SSHRunner(cfg)
    runner.connect()
    assert attempts["count"] == 2


def test_connect_does_not_retry_for_non_banner_error(monkeypatch) -> None:
    attempts = {"count": 0}

    class FakeClient:
        def set_missing_host_key_policy(self, _policy) -> None:
            return None

        def connect(self, **kwargs) -> None:
            attempts["count"] += 1
            raise RuntimeError("Authentication failed.")

        def close(self) -> None:
            return None

    monkeypatch.setattr("vpn_wizard.core.paramiko.SSHClient", lambda: FakeClient())
    monkeypatch.setattr("vpn_wizard.core.time.sleep", lambda _delay: None)

    cfg = SSHConfig(host="example.com", user="root", connect_retries=3, connect_retry_delay=0)
    runner = SSHRunner(cfg)
    with pytest.raises(RuntimeError, match="Authentication failed"):
        runner.connect()
    assert attempts["count"] == 1


def test_connect_retries_when_server_closes_preauth(monkeypatch) -> None:
    attempts = {"count": 0}

    class FakeClient:
        def set_missing_host_key_policy(self, _policy) -> None:
            return None

        def connect(self, **kwargs) -> None:
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise EOFError()

        def close(self) -> None:
            return None

    monkeypatch.setattr("vpn_wizard.core.paramiko.SSHClient", lambda: FakeClient())
    monkeypatch.setattr("vpn_wizard.core.time.sleep", lambda _delay: None)

    cfg = SSHConfig(host="example.com", user="root", connect_retries=2, connect_retry_delay=0)
    runner = SSHRunner(cfg)
    runner.connect()
    assert attempts["count"] == 2
