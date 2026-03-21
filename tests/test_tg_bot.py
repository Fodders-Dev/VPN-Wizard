from __future__ import annotations

from types import SimpleNamespace

import vpn_wizard.tg_bot as tg_bot
from vpn_wizard.urls import CANONICAL_MINIAPP_URL, resolve_public_miniapp_url


def _make_update(lang: str | None) -> SimpleNamespace:
    user = SimpleNamespace(language_code=lang)
    return SimpleNamespace(effective_user=user)


def test_lang_defaults_to_ru() -> None:
    assert tg_bot._lang(_make_update(None)) == "ru"
    assert tg_bot._lang(_make_update("ru")) == "ru"


def test_lang_uses_en_for_non_ru() -> None:
    assert tg_bot._lang(_make_update("en")) == "en"
    assert tg_bot._lang(_make_update("de")) == "en"


def test_parse_host_port() -> None:
    assert tg_bot._parse_host_port("1.2.3.4") == ("1.2.3.4", 22)
    assert tg_bot._parse_host_port("example.com:2222") == ("example.com", 2222)


def test_app_links_updated() -> None:
    ru_start = tg_bot.I18N["ru"]["start"]
    en_start = tg_bot.I18N["en"]["start"]
    assert "https://apps.apple.com/us/app/amneziawg/id6478942365" in ru_start
    assert "https://github.com/amnezia-vpn/amneziawg-windows-client/releases" in ru_start
    assert "https://github.com/amnezia-vpn/amneziawg-linux-kernel-module" in ru_start
    assert "https://apps.apple.com/us/app/amneziawg/id6478942365" in en_start
    assert "https://github.com/amnezia-vpn/amneziawg-windows-client/releases" in en_start
    assert "https://github.com/amnezia-vpn/amneziawg-linux-kernel-module" in en_start


def test_resolve_public_miniapp_url_falls_back_to_canonical() -> None:
    assert resolve_public_miniapp_url(None) == CANONICAL_MINIAPP_URL
    assert resolve_public_miniapp_url("") == CANONICAL_MINIAPP_URL
    assert resolve_public_miniapp_url("vpn-wizard") == CANONICAL_MINIAPP_URL


def test_resolve_public_miniapp_url_accepts_absolute_https_url() -> None:
    value = "https://vpn-wizard-production.up.railway.app/miniapp/"
    assert resolve_public_miniapp_url(value) == value


def test_bot_uses_canonical_miniapp_url_by_default(monkeypatch) -> None:
    monkeypatch.delenv("VPNW_MINIAPP_URL", raising=False)
    assert tg_bot._miniapp_url() == CANONICAL_MINIAPP_URL
