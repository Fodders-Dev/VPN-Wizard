"""Прокси для приставок: доступ по домашнему IP вместо пароля.

PlayStation и Switch не дают ввести логин/пароль у прокси, поэтому кнопка в
кабинете добавляет домашний адрес в allowlist squid'а. Здесь закреплены три
инварианта: файл для squid никогда не пуст (пустой src-файл валит его),
привязки конечны по числу и времени, и фича закрыта платной подпиской.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import vpn_wizard.server as server_module
from vpn_wizard.account import AccountStore
from vpn_wizard.awg_fallback import issue_token
from vpn_wizard.console_proxy import (
    PLACEHOLDER_IP,
    ConsoleProxyConfig,
    normalize_ip,
    render_ips_file,
)
from vpn_wizard.server import app

OWNER = 449066726
NOW = 1_800_000_000


def _store(tmp_path: Path) -> AccountStore:
    return AccountStore(tmp_path / "state.db", secret_key="unit-test-secret")


# --- файл для squid --------------------------------------------------------------

def test_allowlist_is_never_empty_and_sorted() -> None:
    # Пустой src-файл — это упавший squid, поэтому localhost живёт там всегда.
    assert PLACEHOLDER_IP in render_ips_file([])
    text = render_ips_file([{"ip": "9.9.9.9"}, {"ip": "1.1.1.1"}, {"ip": "9.9.9.9"}])
    lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    assert lines == sorted(set(lines))
    assert "1.1.1.1" in lines and "9.9.9.9" in lines and PLACEHOLDER_IP in lines


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("94.19.225.110", "94.19.225.110"),
        ("  94.19.225.110 ", "94.19.225.110"),
        ("2a00:1450::1", "2a00:1450::1"),
        ("nope", None),
        ("94.19.225.110/32", None),
        ("", None),
    ],
)
def test_normalize_ip_accepts_only_a_single_address(raw, expected) -> None:
    assert normalize_ip(raw) == expected


# --- хранилище -------------------------------------------------------------------

def test_bindings_expire_and_rebinding_refreshes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.console_ip_bind(OWNER, "1.2.3.4", ttl_seconds=100, now=NOW)
    assert [row["ip"] for row in store.console_ips(OWNER, now=NOW)] == ["1.2.3.4"]
    assert store.console_ips(OWNER, now=NOW + 101) == []

    store.console_ip_bind(OWNER, "1.2.3.4", ttl_seconds=100, now=NOW + 90)
    assert [row["ip"] for row in store.console_ips(OWNER, now=NOW + 150)] == ["1.2.3.4"]

    assert store.console_ips_purge(now=NOW + 500) == 1
    assert store.console_ips_active(now=NOW + 500) == []


def test_trim_keeps_only_the_newest_bindings(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for index, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        store.console_ip_bind(OWNER, ip, ttl_seconds=1000, now=NOW + index)
    store.console_ips_trim(OWNER, keep=2)
    assert [row["ip"] for row in store.console_ips(OWNER, now=NOW + 10)] == [
        "2.2.2.2",
        "3.3.3.3",
    ]


# --- HTTP ------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("VPNW_STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("VPNW_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_HOST", "203.0.113.10")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_SSH_PASSWORD", "p")
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", "link-secret")
    monkeypatch.setenv("VPNW_CONSOLE_PROXY_ENABLED", "true")
    monkeypatch.setenv("VPNW_CONSOLE_PROXY_HOST", "203.0.113.10")
    monkeypatch.setenv("VPNW_CONSOLE_PROXY_PORT", "3129")
    monkeypatch.setenv("VPNW_CONSOLE_PROXY_IPS_FILE", str(tmp_path / "ips.txt"))
    monkeypatch.setenv("VPNW_CONSOLE_PROXY_MAX_IPS", "2")
    synced: list[bool] = []
    monkeypatch.setattr(
        server_module, "sync_ips_file", lambda cfg, store: synced.append(True) or True
    )
    yield synced


def _paid(monkeypatch: pytest.MonkeyPatch, active: bool) -> None:
    class Client:
        def __init__(self, config) -> None:
            self.config = config

        @staticmethod
        def active_user(telegram_id: int):
            return {"uuid": "u", "hwidDeviceLimit": 3} if active else None

    monkeypatch.setattr(server_module, "RemnawaveClient", Client)


def test_paid_user_binds_the_address_the_request_came_from(
    monkeypatch: pytest.MonkeyPatch, _env
) -> None:
    _paid(monkeypatch, True)
    client = TestClient(app)
    token = issue_token("link-secret", OWNER)

    response = client.post(
        f"/api/console-proxy/{OWNER}/bind",
        params={"token": token},
        headers={"X-Forwarded-For": "94.19.225.110"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["bound_ip"] == "94.19.225.110"
    assert [item["ip"] for item in body["ips"]] == ["94.19.225.110"]
    assert body["host"] == "203.0.113.10" and body["port"] == 3129
    assert _env, "binding must trigger an allowlist sync"

    # Отвязка возвращает пустой список.
    gone = client.request(
        "DELETE",
        f"/api/console-proxy/{OWNER}/bind",
        params={"token": token, "ip": "94.19.225.110"},
    )
    assert gone.status_code == 200 and gone.json()["ips"] == []


def test_free_user_sees_the_lock_and_cannot_bind(
    monkeypatch: pytest.MonkeyPatch, _env
) -> None:
    _paid(monkeypatch, False)
    client = TestClient(app)
    token = issue_token("link-secret", OWNER)

    view = client.get(f"/api/console-proxy/{OWNER}", params={"token": token})
    assert view.status_code == 200
    assert view.json()["entitled"] is False and view.json()["enabled"] is True

    denied = client.post(
        f"/api/console-proxy/{OWNER}/bind",
        params={"token": token},
        headers={"X-Forwarded-For": "94.19.225.110"},
    )
    assert denied.status_code == 403


def test_binding_needs_a_valid_token(_env) -> None:
    client = TestClient(app)
    assert (
        client.post(
            f"/api/console-proxy/{OWNER}/bind", params={"token": "wrong"}
        ).status_code
        == 403
    )


def test_third_address_pushes_out_the_oldest(
    monkeypatch: pytest.MonkeyPatch, _env
) -> None:
    _paid(monkeypatch, True)
    client = TestClient(app)
    token = issue_token("link-secret", OWNER)
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        response = client.post(
            f"/api/console-proxy/{OWNER}/bind",
            params={"token": token},
            headers={"X-Forwarded-For": ip},
        )
        assert response.status_code == 200
    ips = [item["ip"] for item in response.json()["ips"]]
    assert ips == ["2.2.2.2", "3.3.3.3"]
