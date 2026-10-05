from __future__ import annotations

import inspect
import os
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


def test_help_is_free_first_and_does_not_list_platform_apps_or_paid_offers() -> None:
    ru_help = tg_bot.I18N["ru"]["help"]
    en_help = tg_bot.I18N["en"]["help"]
    for text in (ru_help, en_help):
        assert "device limit" in text or "ограничения по числу устройств" in text
        assert "promo code" in text or "промокода" in text
        assert "/wizard" in text
        assert "macOS" not in text and "paid" not in text and "оплат" not in text
    assert "📖" in tg_bot.I18N["ru"]["guide"]
    assert "📖" in tg_bot.I18N["en"]["guide"]


def test_resolve_public_miniapp_url_falls_back_to_canonical() -> None:
    assert resolve_public_miniapp_url(None) == CANONICAL_MINIAPP_URL
    assert resolve_public_miniapp_url("") == CANONICAL_MINIAPP_URL
    assert resolve_public_miniapp_url("vpn-wizard") == CANONICAL_MINIAPP_URL


def test_resolve_public_miniapp_url_accepts_absolute_https_url() -> None:
    value = "https://vpn-wizard-production.up.railway.app/miniapp/"
    assert resolve_public_miniapp_url(value) == value


def test_bot_uses_canonical_wizard_url_by_default(monkeypatch) -> None:
    monkeypatch.delenv("VPNW_MINIAPP_URL", raising=False)
    monkeypatch.delenv("VPNW_PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("VPNW_WIZARD_URL", raising=False)
    assert tg_bot._miniapp_url() == "https://77-67-89-164.nip.io/wizard/"


def test_entry_menu_has_free_link_and_native_wizard_webapp(monkeypatch) -> None:
    monkeypatch.delenv("VPNW_MINIAPP_URL", raising=False)
    monkeypatch.delenv("VPNW_PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("VPNW_WIZARD_URL", raising=False)

    keyboard = tg_bot._entry_keyboard(_make_update("ru"))

    assert len(keyboard.inline_keyboard) == 2
    free_action = keyboard.inline_keyboard[0][0]
    wizard_action = keyboard.inline_keyboard[1][0]
    assert free_action.text == "Получить бесплатный VPN"
    assert free_action.url == "https://77-67-89-164.nip.io/connect/join.html"
    assert wizard_action.text == "Настроить свой сервер"
    assert wizard_action.web_app.url == "https://77-67-89-164.nip.io/wizard/"
    assert wizard_action.url is None


def test_entry_urls_follow_configured_public_host(monkeypatch) -> None:
    monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", "https://vpn.example.test/portal/")
    monkeypatch.delenv("VPNW_MINIAPP_URL", raising=False)
    monkeypatch.delenv("VPNW_WIZARD_URL", raising=False)

    assert tg_bot._free_vpn_url() == "https://vpn.example.test/connect/join.html"
    assert tg_bot._miniapp_url() == "https://vpn.example.test/wizard/"
    assert tg_bot._portal_url() == "https://vpn.example.test/portal/"
    assert tg_bot._guide_url() == "https://vpn.example.test/connect/guide.html"


def test_help_command_shows_guide_button_on_configured_canonical_host(monkeypatch) -> None:
    import asyncio

    monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", "https://vpn.example.test/portal/")
    monkeypatch.delenv("VPNW_MINIAPP_URL", raising=False)
    captured = []

    class Message:
        async def reply_text(self, text, reply_markup=None):
            captured.append((text, reply_markup))

    update = SimpleNamespace(
        effective_user=SimpleNamespace(language_code="ru"),
        effective_message=Message(),
    )
    asyncio.run(tg_bot.help_cmd(update, SimpleNamespace()))

    text, keyboard = captured[0]
    assert "промокода" in text and "без" in text
    assert len(keyboard.inline_keyboard) == 3
    guide = keyboard.inline_keyboard[2][0]
    assert guide.text == "📖 Инструкция по подключению"
    assert guide.url == "https://vpn.example.test/connect/guide.html"


def test_start_exposes_free_entry_without_channel_check(monkeypatch) -> None:
    import asyncio

    calls = []

    async def fail_if_checked(*_args, **_kwargs):
        raise AssertionError("free entry menu must not require channel membership")

    monkeypatch.setattr(tg_bot, "_require_subscription", fail_if_checked)

    class Message:
        async def reply_text(self, text, reply_markup=None):
            calls.append((text, reply_markup))

    update = SimpleNamespace(
        effective_user=SimpleNamespace(language_code="ru"),
        effective_message=Message(),
    )
    context = SimpleNamespace(user_data={"stale": True})

    result = asyncio.run(tg_bot.start(update, context))

    assert result == tg_bot.ConversationHandler.END
    assert context.user_data == {}
    assert len(calls) == 1
    assert len(calls[0][1].inline_keyboard) == 2


def test_provisioning_and_credential_steps_keep_channel_guard() -> None:
    assert tg_bot.REQUIRED_CHANNEL == os.getenv("VPNW_REQUIRED_CHANNEL", "@fodders_dev")
    for step in (
        tg_bot.host_step,
        tg_bot.user_step,
        tg_bot.auth_step,
        tg_bot.password_step,
        tg_bot.key_step,
        tg_bot.port_step,
        tg_bot.cancel,
    ):
        assert "await _require_subscription" in inspect.getsource(step)
