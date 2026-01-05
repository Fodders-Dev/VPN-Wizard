from __future__ import annotations

from types import SimpleNamespace

import vpn_wizard.tg_bot as tg_bot


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
