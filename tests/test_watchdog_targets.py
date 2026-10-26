"""Registry-derived watchdog endpoints, exercised without network effects."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "watchdog" / "fodder-ru-watchdog"


@pytest.fixture
def watchdog(monkeypatch):
    loader = importlib.machinery.SourceFileLoader("fodder_ru_watchdog_targets", str(SCRIPT))
    spec = importlib.util.spec_from_loader("fodder_ru_watchdog_targets", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)

    def forbid_external_action(*args, **kwargs):
        pytest.fail("watchdog target tests must never send notifications or make network requests")

    monkeypatch.setattr(module, "notify", forbid_external_action)
    monkeypatch.setattr(module, "http_json", forbid_external_action)
    monkeypatch.setattr(module.urllib.request, "urlopen", forbid_external_action)
    return module


def targets(watchdog):
    return [(name, host) for name, host in watchdog.reachability_targets()]


def test_missing_or_malformed_registry_uses_safe_defaults(watchdog, monkeypatch):
    expected = [
        ("NL · сайт и панель", "82.25.60.19:443"),
        ("FI · экзит", "185.202.207.126:22"),
    ]
    monkeypatch.delenv("VPNW_AWG_SERVERS", raising=False)
    assert targets(watchdog) == expected

    for raw in ("{bad json", '{"id":"nl"}', '[{"id":"nl"},null]'):
        monkeypatch.setenv("VPNW_AWG_SERVERS", raw)
        assert targets(watchdog) == expected


def test_registry_changes_probe_targets_without_reloading(watchdog, monkeypatch):
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "host": "127.0.0.1", "public_host": "nl-new.example"},
            {"id": "fi", "host": "fi-old.example", "port": 2222},
        ]),
    )
    assert targets(watchdog) == [
        ("NL · сайт и панель", "nl-new.example:443"),
        ("FI · экзит", "fi-old.example:2222"),
    ]

    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "host": "127.0.0.1", "public_host": "nl-next.example"},
            {"id": "fi", "host": "fi-next.example", "port": "2223"},
        ]),
    )
    assert targets(watchdog) == [
        ("NL · сайт и панель", "nl-next.example:443"),
        ("FI · экзит", "fi-next.example:2223"),
    ]


def test_test_message_uses_current_targets_without_network_or_secret_data(watchdog, monkeypatch):
    secret_values = ("do-not-print-password", "/private/ssh/key", "private-key-bytes", "telegram-token")
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {
                "id": "nl",
                "host": "127.0.0.1",
                "public_host": "nl-live.example",
                "password": secret_values[0],
                "key_path": secret_values[1],
                "key_content": secret_values[2],
                "token": secret_values[3],
            },
            {
                "id": "fi",
                "host": "fi-live.example",
                "port": 2224,
                "password": secret_values[0],
                "key_path": secret_values[1],
                "key_content": secret_values[2],
                "token": secret_values[3],
            },
        ]),
    )

    message = watchdog.test_message()

    assert "NL nl-live.example:443" in message
    assert "FI fi-live.example:2224" in message
    assert all(secret not in message for secret in secret_values)
    assert all(secret not in repr(targets(watchdog)) for secret in secret_values)
    assert all(field not in message for field in ("password", "key_path", "key_content", "token"))


def test_invalid_hosts_ports_and_duplicate_ids_fall_back(watchdog, monkeypatch):
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "host": "127.0.0.1", "public_host": "nl.example/path"},
            {"id": "fi", "host": "fi.example", "port": 70000},
            {"id": "fi", "host": "other-fi.example", "port": 22},
        ]),
    )
    assert targets(watchdog) == [
        ("NL · сайт и панель", "82.25.60.19:443"),
        ("FI · экзит", "185.202.207.126:22"),
    ]


def test_loopback_and_bracketed_ipv6_are_handled_safely(watchdog, monkeypatch):
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "host": "127.0.0.1", "public_host": "[2001:db8::5]"},
            {"id": "fi", "host": "::1", "port": 22},
        ]),
    )
    assert targets(watchdog) == [
        ("NL · сайт и панель", "[2001:db8::5]:443"),
        ("FI · экзит", "185.202.207.126:22"),
    ]


@pytest.mark.parametrize(
    "host",
    ("localhost", "LOCALHOST.", "panel.localhost", "0.0.0.0", "::", "[::]"),
)
def test_localhost_names_and_unspecified_addresses_fall_back(watchdog, monkeypatch, host):
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "host": host, "public_host": host},
            {"id": "fi", "host": host, "port": 22},
        ]),
    )
    assert targets(watchdog) == [
        ("NL · сайт и панель", "82.25.60.19:443"),
        ("FI · экзит", "185.202.207.126:22"),
    ]
