from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.responses import Response

from vpn_wizard.account import AccountStore
from vpn_wizard.awg_servers import AwgPreset, AwgRegistry, AwgServer
from vpn_wizard.public_access import (
    InvalidDeviceToken,
    PublicAccessNotConfigured,
    PublicAccessService,
    RateLimitExceeded,
    RateLimitPolicy,
    SlidingWindowRateLimiter,
    UnknownServer,
    isolated_public_account_store,
    set_public_device_cookie,
    server_provision_lock,
    validate_same_origin,
)
import vpn_wizard.public_access as public_access_module


def _server(server_id: str, *, enabled: bool = True) -> AwgServer:
    return AwgServer(
        id=server_id,
        label=server_id.upper(),
        flag="🌐",
        host=f"{server_id}.example.invalid",
        user="root",
        port=22,
        password="test-only-credential",
        key_path=None,
        key_content=None,
        listen_port=443,
        enabled=enabled,
    )


def _registry() -> AwgRegistry:
    return AwgRegistry(
        servers=(_server("nl"), _server("fi"), _server("off", enabled=False)),
        presets=(AwgPreset(id="default", label="Обычный"),),
        default_server_id="nl",
    )


@dataclass
class _PeerService:
    records: dict[tuple[str | None, int], str]
    server_id: str | None

    def issue(self, peer_id: int) -> dict[str, object]:
        key = (self.server_id, peer_id)
        reused = key in self.records
        if not reused:
            self.records[key] = f"[Interface]\nPrivateKey = test-key-{peer_id}\n"
        return {"config": self.records[key], "reused": reused}


def _service(tmp_path: Path, **kwargs: object) -> tuple[PublicAccessService, dict]:
    account = AccountStore(tmp_path / "state.db", "test-encryption-key")
    records: dict[tuple[str | None, int], str] = {}

    def service_factory(_account: object, _config: object, *, server_id: str | None):
        return _PeerService(records, server_id)

    service = PublicAccessService(
        _registry(),
        account,
        "test-link-secret",
        enabled=True,
        service_factory=service_factory,
        **kwargs,
    )
    return service, records


def _bootstrap(service: PublicAccessService, client_ip: str, *, new_device: bool = False, token: str | None = None) -> str:
    return service.bootstrap_device(
        device_token=token,
        new_device=new_device,
        client_ip=client_ip,
    )


def test_issue_reuses_cookie_identity_and_allocates_independent_profiles(tmp_path: Path) -> None:
    service, records = _service(tmp_path)

    first_cookie = _bootstrap(service, "192.0.2.10")
    first = service.issue(device_token=first_cookie, client_ip="192.0.2.10", server_id="nl")
    repeat = service.issue(device_token=first.device_cookie, client_ip="192.0.2.10", server_id="nl")
    other_server = service.issue(device_token=first.device_cookie, client_ip="192.0.2.10", server_id="fi")
    other_cookie = _bootstrap(service, "192.0.2.10", new_device=True, token=first.device_cookie)
    other_device = service.issue(device_token=other_cookie, client_ip="192.0.2.10", server_id="nl")

    assert first.device_cookie == repeat.device_cookie
    assert first.reused is False
    assert repeat.reused is True
    assert other_server.reused is False
    assert other_device.device_cookie != first.device_cookie
    assert other_device.reused is False
    assert len(records) == 3
    assert all(peer_id >= 5_000_000_000_000_000_000 for _, peer_id in records)
    assert "device_cookie" not in first.config
    assert "# server: nl" in first.config


def test_bootstrap_cookie_precedes_provision_and_failed_issue_can_retry(tmp_path: Path) -> None:
    service, _records = _service(tmp_path)
    cookie = service.bootstrap_device(
        device_token=None,
        new_device=False,
        client_ip="192.0.2.25",
    )
    first = service.issue(device_token=cookie, client_ip="192.0.2.25", server_id="nl")
    retry = service.issue(device_token=cookie, client_ip="192.0.2.25", server_id="nl")

    assert first.device_cookie == cookie == retry.device_cookie
    assert first.reused is False
    assert retry.reused is True


def test_bootstrap_rotates_identity_only_on_explicit_request(tmp_path: Path) -> None:
    service, _records = _service(tmp_path)
    cookie = service.bootstrap_device(
        device_token=None,
        new_device=False,
        client_ip="192.0.2.26",
    )
    same = service.bootstrap_device(
        device_token=cookie,
        new_device=False,
        client_ip="192.0.2.26",
    )
    rotated = service.bootstrap_device(
        device_token=cookie,
        new_device=True,
        client_ip="192.0.2.26",
    )

    assert same == cookie
    assert rotated != cookie


def test_new_device_rotation_is_explicit_and_no_server_or_device_slot_cap(tmp_path: Path) -> None:
    service, records = _service(tmp_path)
    initial_cookie = _bootstrap(service, "198.51.100.4")
    initial = service.issue(device_token=initial_cookie, client_ip="198.51.100.4", server_id="nl")
    rotated_cookie = _bootstrap(
        service,
        "198.51.100.4",
        token=initial.device_cookie,
        new_device=True,
    )
    rotated = service.issue(device_token=rotated_cookie, client_ip="198.51.100.4", server_id="nl")

    assert rotated.device_cookie != initial.device_cookie
    assert len(records) == 2
    # Public peers do not use the account's 1..99 paid-device-slot validator.
    assert all(peer_id > 99 for _, peer_id in records)


def test_only_enabled_offered_servers_can_receive_new_profiles(tmp_path: Path) -> None:
    service, _records = _service(tmp_path)
    cookie = _bootstrap(service, "192.0.2.3")
    with pytest.raises(UnknownServer):
        service.issue(device_token=cookie, client_ip="192.0.2.3", server_id="off")
    with pytest.raises(UnknownServer):
        service.issue(device_token=cookie, client_ip="192.0.2.3", server_id="missing")


def test_invalid_or_tampered_device_cookie_is_rejected(tmp_path: Path) -> None:
    service, _records = _service(tmp_path)
    token = service.create_device_token()
    with pytest.raises(InvalidDeviceToken):
        service.issue(device_token=token[:-1] + ("A" if token[-1] != "A" else "B"), client_ip="192.0.2.1")
    with pytest.raises(InvalidDeviceToken):
        service.issue(device_token="not-a-token", client_ip="192.0.2.1")


def test_public_access_is_opt_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VPNW_PUBLIC_AWG_ENABLED", raising=False)
    monkeypatch.delenv("VPNW_PUBLIC_ACCESS_ENABLED", raising=False)
    account = AccountStore(tmp_path / "state.db", "test-key")
    service = PublicAccessService(_registry(), account, "test-secret")
    assert service.configured is False
    with pytest.raises(PublicAccessNotConfigured):
        service.offered_servers()


def test_device_cookie_rejects_noncanonical_signature_padding_bits(tmp_path: Path) -> None:
    service, _records = _service(tmp_path)
    token = service.create_device_token()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    index = alphabet.index(token[-1])
    assert index % 4 == 0  # SHA-256 signature leaves two unused bits.
    edited = token[:-1] + alphabet[index + 1]
    with pytest.raises(InvalidDeviceToken):
        service.issue(device_token=edited, client_ip="192.0.2.1")


def test_isolated_public_database_is_separate_and_uses_loaded_store_key(tmp_path: Path) -> None:
    paid = AccountStore(tmp_path / "state.db", "same-encryption-key")
    public = isolated_public_account_store(paid)

    assert public.db_path == tmp_path / "public-access.db"
    assert public.db_path != paid.db_path
    assert public._fernet.decrypt  # Existing AccountStore encryption is initialized.


def test_rate_limiter_enforces_device_and_ip_windows() -> None:
    now = [100.0]
    limiter = SlidingWindowRateLimiter(
        RateLimitPolicy(
            window_seconds=60,
            per_device=2,
            per_ip=3,
            hour_seconds=3600,
            per_device_per_hour=10,
            per_ip_per_hour=10,
        ),
        clock=lambda: now[0],
    )
    limiter.check(device_key="device-a", client_ip="192.0.2.1")
    limiter.check(device_key="device-a", client_ip="192.0.2.1")
    with pytest.raises(RateLimitExceeded) as error:
        limiter.check(device_key="device-a", client_ip="192.0.2.1")
    assert error.value.retry_after == 61

    now[0] += 61
    limiter.check(device_key="device-a", client_ip="192.0.2.1")
    limiter.check(device_key="device-b", client_ip="192.0.2.1")
    limiter.check(device_key="device-c", client_ip="192.0.2.1")
    with pytest.raises(RateLimitExceeded):
        limiter.check(device_key="device-d", client_ip="192.0.2.1")


def test_bootstrap_has_an_ip_rate_limit() -> None:
    now = [100.0]
    limiter = SlidingWindowRateLimiter(
        RateLimitPolicy(
            window_seconds=60,
            per_device=10,
            per_ip=10,
            hour_seconds=3600,
            per_device_per_hour=20,
            per_ip_per_hour=20,
            bootstrap_per_ip=2,
            bootstrap_per_ip_per_hour=4,
        ),
        clock=lambda: now[0],
    )
    limiter.check_bootstrap(client_ip="203.0.113.8")
    limiter.check_bootstrap(client_ip="203.0.113.8")
    with pytest.raises(RateLimitExceeded):
        limiter.check_bootstrap(client_ip="203.0.113.8")


def test_server_provision_lock_serializes_all_devices_and_releases_entries() -> None:
    active = 0
    maximum = 0
    counter_lock = threading.Lock()

    def provision() -> None:
        nonlocal active, maximum
        with server_provision_lock("NL"):
            with counter_lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.01)
            with counter_lock:
                active -= 1

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _index: provision(), range(16)))

    assert maximum == 1
    assert public_access_module._SERVER_PROVISION_LOCKS.entry_count == 0


def test_cookie_is_http_only_secure_scoped_and_same_site_lax() -> None:
    response = Response()
    set_public_device_cookie(response, "opaque-signed-value")
    cookie = response.headers["set-cookie"].lower()

    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=lax" in cookie
    assert "path=/api/public/awg" in cookie
    assert "opaque-signed-value" in cookie


def test_same_origin_validation_fails_closed() -> None:
    allowed = {"https://vpn.example.com"}
    assert validate_same_origin("https://vpn.example.com", allowed)
    assert not validate_same_origin("https://attacker.example", allowed)
    assert not validate_same_origin(None, allowed)
    assert not validate_same_origin("null", allowed)
    assert not validate_same_origin("https://vpn.example.com/path", allowed)
