from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_miniapp_uses_canonical_api_fallback_and_test_hooks() -> None:
    js = (ROOT / "web" / "miniapp" / "app.js").read_text(encoding="utf-8")
    assert 'const CANONICAL_API_BASE = "https://212-69-84-167.nip.io";' in js
    assert 'const CANONICAL_MINIAPP_URL = `${CANONICAL_API_BASE}/wizard/?v=20260722-3`;' in js
    assert 'new URL("/wizard/?v=20260722-3", window.location.origin)' in js
    assert 'new URL("/portal/?v=20260722-3", window.location.origin)' in js
    assert "tg.BackButton?.show()" in js
    assert "tg.BackButton?.onClick(returnToPortal)" in js
    assert "function resolveApiBaseFrom" in js
    assert "window.__VPNW_TEST__" in js
    config_js = (ROOT / "web" / "miniapp" / "config.js").read_text(encoding="utf-8")
    assert "vercel" in config_js
    assert "window.location.hostname" in config_js
    assert 'window.API_BASE = "https://212-69-84-167.nip.io";' in config_js


def test_miniapp_shell_is_single_flow_and_has_diagnostics_panel() -> None:
    html = (ROOT / "web" / "miniapp" / "index.html").read_text(encoding="utf-8")
    assert 'id="diagnostics-panel"' in html
    assert 'class="bottom-nav glass-panel"' in html
    assert 'data-page="connect"' in html
    assert 'id="user-input" autocomplete="username" placeholder="root" value="root" required' in html
    assert 'id="debug-log"' in html
    assert 'id="connect-progress-panel"' in html
    assert 'id="connect-checklist"' in html
    assert 'value="amneziawg"' in html
    assert 'value="xray"' in html
    assert 'id="relay-card"' in html
    assert 'id="relay-enabled-toggle"' in html
    assert 'value="shadowtls_ss"' not in html
    assert 'value="vless_reality"' not in html
    assert 'id="faq-sheet"' not in html
    assert 'class="product-switcher glass-panel"' in html
    assert 'href="/portal/?v=20260722-3"' in html
    assert 'aria-current="page"' in html


def test_connect_page_is_a_private_unified_portal() -> None:
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "Всё для VPN — в одном месте" in html
    assert "Готовый Fodder VPN" in html
    assert "Настроить свой сервер" in html
    assert 'href="/wizard/?v=20260722-3"' in html
    assert 'class="product-nav"' in html
    assert 'href="/portal/?v=20260722-3" aria-current="page"' in html
    assert "tg.BackButton&&tg.BackButton.hide()" in html
    assert 'request("/api/auth/telegram/miniapp"' in html
    assert 'request("/api/portal/links")' in html
    assert "stale browser" in html
    assert "localStorage" not in html
    assert "Happ" not in html
    assert "Reality" not in html
    assert "Поделиться VPN с близким" in html
    assert "Открыть» и «Скопировать» — это одна и та же семейная ссылка" in html
    assert "Личный · 1 устройство" in html
    assert "Семья · 5 устройств" in html
    assert "Делиться выгодно" in html
    assert "И ещё 25%" in html
    assert "вывод в деньги не предусмотрен" in html


def test_static_routes_keep_old_buttons_on_portal_and_preserve_wizard() -> None:
    source = (ROOT / "src" / "vpn_wizard" / "server.py").read_text(encoding="utf-8")
    assert 'PORTAL_ENTRY_URL = "/portal/?v=20260722-3"' in source
    assert '@app.get("/miniapp/", include_in_schema=False)' in source
    assert '"Cache-Control": "no-store, max-age=0"' in source
    assert '@app.get("/portal/", include_in_schema=False)' in source
    assert '@app.get("/wizard/", include_in_schema=False)' in source
    assert 'app.mount("/portal", StaticFiles(directory=str(connect_dir)' in source
    assert 'app.mount("/miniapp", StaticFiles(directory=str(connect_dir)' in source
    assert 'app.mount("/wizard", StaticFiles(directory=str(miniapp_dir)' in source


def test_awg_page_supports_private_family_links_without_telegram() -> None:
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert '<meta name="referrer" content="no-referrer">' in html
    assert '<link rel="icon" href="data:,">' in html
    assert 'id="personal-access"' in html
    assert 'id="family-access"' in html
    assert '"/api/awg/family/"' in html
    assert "Ни Telegram, ни регистрация не нужны" in html
    assert "amnezia-vpn/amneziawg-android/releases/download/2.0.1" in html
    assert "(или AmneziaVPN)" not in html
    assert 'value="win"' in html
    assert 'value="mac"' in html
    assert "amneziawg-windows-client/releases/latest" in html
    assert "amnezia-client/releases/latest" in html
    assert 'id="device-picker"' in html
    assert '"/access?token="' in html
    assert "У каждого устройства — свой ключ" in html


def test_bedolaga_exposes_family_link_with_the_api_token_namespace() -> None:
    handler = (
        ROOT
        / "deploy"
        / "bedolaga"
        / "overrides"
        / "app"
        / "handlers"
        / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "f'family:{int(telegram_id)}'" in handler
    assert "return f'{base}/connect/awg.html?{query}'" in handler
    assert "callback_data='fodders_awg_family'" in handler
    assert "Command('family', 'share')" in handler
    assert "Command('miniapp', 'portal')" in handler
    assert "Command('wizard', 'vpn1')" in handler
    assert "web_app=types.WebAppInfo(url=_portal_url())" in handler
    assert "web_app=types.WebAppInfo(url=_miniapp_url())" in handler


def test_bedolaga_configures_telegram_menu_button_for_the_portal() -> None:
    script = (
        ROOT
        / "deploy"
        / "bedolaga"
        / "overrides"
        / "scripts"
        / "configure_fodders_vpn1_menu.py"
    ).read_text(encoding="utf-8")
    assert "set_chat_menu_button" in script
    assert "WebAppInfo(url=portal_url)" in script
    assert "action': portal_url" in script
    assert "FODDERS_VPN1_MINIAPP_URL" in script
    assert "/portal/?v=20260722-3" in script
