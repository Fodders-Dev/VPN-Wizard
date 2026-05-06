from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

import vpn_wizard.tg_bot as tg_bot
from vpn_wizard.urls import CANONICAL_MINIAPP_URL, resolve_public_miniapp_url


def _make_update(lang: str | None) -> SimpleNamespace:
    user = SimpleNamespace(language_code=lang)
    return SimpleNamespace(effective_user=user)


def _make_owner_update(user_id: int):
    sent: list[dict] = []

    async def _reply(text, **kwargs):
        sent.append({"kind": "text", "text": text, **kwargs})

    async def _photo(photo, **kwargs):
        sent.append({"kind": "photo"})

    message = SimpleNamespace(reply_text=_reply, reply_photo=_photo)
    user = SimpleNamespace(id=user_id, language_code="ru")
    update = SimpleNamespace(effective_user=user, effective_message=message)
    return update, sent


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


def test_parse_owner_ids_handles_csv_and_blanks() -> None:
    assert tg_bot._parse_owner_ids("") == set()
    assert tg_bot._parse_owner_ids("123") == {123}
    assert tg_bot._parse_owner_ids("123, 456,abc, 789") == {123, 456, 789}


def test_is_owner_only_true_for_listed_telegram_ids(monkeypatch) -> None:
    monkeypatch.setenv("VPNW_OWNER_IDS", "111, 222")
    update_owner = SimpleNamespace(effective_user=SimpleNamespace(id=222))
    update_other = SimpleNamespace(effective_user=SimpleNamespace(id=999))
    assert tg_bot._is_owner(update_owner) is True
    assert tg_bot._is_owner(update_other) is False


def test_is_owner_returns_false_when_env_empty(monkeypatch) -> None:
    monkeypatch.delenv("VPNW_OWNER_IDS", raising=False)
    update = SimpleNamespace(effective_user=SimpleNamespace(id=111))
    assert tg_bot._is_owner(update) is False


def test_wl_ssh_config_from_env_requires_host_and_auth(monkeypatch) -> None:
    monkeypatch.delenv("VPNW_WL_VPS_HOST", raising=False)
    assert tg_bot._wl_ssh_config_from_env() is None

    monkeypatch.setenv("VPNW_WL_VPS_HOST", "1.2.3.4")
    monkeypatch.delenv("VPNW_WL_VPS_PASSWORD", raising=False)
    monkeypatch.delenv("VPNW_WL_VPS_KEY_PATH", raising=False)
    assert tg_bot._wl_ssh_config_from_env() is None

    monkeypatch.setenv("VPNW_WL_VPS_PASSWORD", "secret")
    monkeypatch.setenv("VPNW_WL_VPS_USER", "root")
    monkeypatch.setenv("VPNW_WL_VPS_PORT", "2222")
    cfg = tg_bot._wl_ssh_config_from_env()
    assert cfg is not None
    assert cfg.host == "1.2.3.4"
    assert cfg.user == "root"
    assert cfg.port == 2222
    assert cfg.password == "secret"


def test_wl_add_cmd_silent_for_non_owner(monkeypatch) -> None:
    monkeypatch.setenv("VPNW_OWNER_IDS", "111")
    update, sent = _make_owner_update(user_id=222)  # not in allow-list
    context = SimpleNamespace(args=["mom"])
    asyncio.run(tg_bot.wl_add_cmd(update, context))
    assert sent == [], "command must be a no-op for non-owners"


def test_wl_add_cmd_runs_provisioner_for_owner(monkeypatch) -> None:
    monkeypatch.setenv("VPNW_OWNER_IDS", "555")
    captured = {}

    def fake_provision(client_name: str) -> dict:
        captured["name"] = client_name
        return {
            "client_name": client_name,
            "gateway_domain": "abcd.apigw.yandexcloud.net",
            "backend_url": "https://1-2-3-4.sslip.io:8443/vpnw-wl-x",
            "link": f"vless://uuid@abcd.apigw.yandexcloud.net:443?type=xhttp#{client_name}",
            "log": [],
        }

    monkeypatch.setattr(tg_bot, "_run_wl_provision", fake_provision)
    monkeypatch.setattr(tg_bot.qrcode, "make", lambda *_args, **_kwargs: SimpleNamespace(save=lambda path: None))

    update, sent = _make_owner_update(user_id=555)
    context = SimpleNamespace(args=["dad"])
    asyncio.run(tg_bot.wl_add_cmd(update, context))
    assert captured["name"] == "dad"
    assert any("Provisioning WL profile" in str(item.get("text", "")) for item in sent)
    assert any(
        "WL profile provisioned" in str(item.get("text", ""))
        and "abcd.apigw.yandexcloud.net" in str(item.get("text", ""))
        for item in sent
    )
    # The success reply must include the streaming-limitation warning so the
    # operator doesn't mistake bot success for a working VPN profile.
    assert any(
        "Yandex API Gateway buffers" in str(item.get("text", ""))
        for item in sent
    ), "owner-facing reply should warn about the streaming limitation"
    assert any(item.get("kind") == "photo" for item in sent), "QR image should be sent"


def test_wl_add_cmd_reports_provisioner_error(monkeypatch) -> None:
    monkeypatch.setenv("VPNW_OWNER_IDS", "555")

    def boom(*_args, **_kwargs):
        raise RuntimeError("port 80 in use")

    monkeypatch.setattr(tg_bot, "_run_wl_provision", boom)
    update, sent = _make_owner_update(user_id=555)
    context = SimpleNamespace(args=["mom"])
    asyncio.run(tg_bot.wl_add_cmd(update, context))
    assert any("WL provisioning failed" in str(item.get("text", "")) for item in sent)
    assert any("port 80 in use" in str(item.get("text", "")) for item in sent)


def test_wl_cmd_shows_status_for_owner(monkeypatch) -> None:
    monkeypatch.setenv("VPNW_OWNER_IDS", "555")
    monkeypatch.delenv("VPNW_WL_VPS_HOST", raising=False)
    monkeypatch.delenv("YC_OAUTH_TOKEN", raising=False)
    update, sent = _make_owner_update(user_id=555)
    context = SimpleNamespace(args=[])
    asyncio.run(tg_bot.wl_cmd(update, context))
    text = sent[0]["text"]
    assert "VPS configured: no" in text
    assert "YC token set:   no" in text
    assert "/wl_add" in text
