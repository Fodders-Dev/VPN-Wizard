from __future__ import annotations

from vpn_wizard.urls import (
    CANONICAL_API_BASE,
    CANONICAL_MINIAPP_URL,
    resolve_public_base_url,
    resolve_public_miniapp_url,
)


def test_public_base_reads_a_changed_environment_value_each_call(monkeypatch) -> None:
    monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", "https://nl-one.example/")
    assert resolve_public_base_url() == "https://nl-one.example"
    assert resolve_public_miniapp_url(None) == "https://nl-one.example/miniapp/"

    monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", "https://nl-two.example/api/")
    assert resolve_public_base_url() == "https://nl-two.example/api"
    assert resolve_public_miniapp_url(None) == "https://nl-two.example/api/miniapp/"


def test_invalid_environment_value_uses_the_legacy_fallback(monkeypatch) -> None:
    for value in (
        "",
        "vpn-wizard",
        "ftp://nl.example",
        "https://user:secret@nl.example",
        "https://nl.example:invalid",
        "https://bad host.example",
        "https://nl.example/path?token=secret",
    ):
        monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", value)
        assert resolve_public_base_url() == CANONICAL_API_BASE
        assert resolve_public_miniapp_url(None) == CANONICAL_MINIAPP_URL


def test_explicit_base_wins_and_invalid_argument_uses_valid_environment(monkeypatch) -> None:
    monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", "https://nl-current.example")

    assert resolve_public_base_url("https://explicit.example/root/") == (
        "https://explicit.example/root"
    )
    assert resolve_public_base_url("not a URL") == "https://nl-current.example"
    assert resolve_public_miniapp_url("not a URL") == "https://nl-current.example/miniapp/"
