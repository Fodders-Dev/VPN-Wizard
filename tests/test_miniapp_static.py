from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_miniapp_uses_canonical_api_fallback_and_test_hooks() -> None:
    js = (ROOT / "web" / "miniapp" / "app.js").read_text(encoding="utf-8")
    assert 'const CANONICAL_API_BASE = "https://212-69-84-167.nip.io";' in js
    assert 'const CANONICAL_MINIAPP_URL = `${CANONICAL_API_BASE}/wizard/`;' in js
    assert 'new URL("/wizard/", window.location.origin)' in js
    assert 'new URL("/portal/", window.location.origin)' in js
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
    assert 'href="/portal/"' in html
    assert 'aria-current="page"' in html


def test_connect_page_is_a_private_unified_portal() -> None:
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "Готовый Fodder VPN" in html
    assert "Настроить свой сервер" in html
    assert 'href="/wizard/"' in html
    assert 'href="/portal/" aria-current="page"' in html
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


def test_invite_button_carries_a_deep_link_payload() -> None:
    # A bare t.me/<bot> link opens the chat and sends nothing, so the bot has
    # nothing to answer and the button looks broken. The invite must carry the
    # campaign payload that actually credits the newcomer.
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "t.me/foddervpnbot?start=friends" in html
    assert 'id="copy-invite"' in html
    assert 'id="invite-url"' in html


def test_entry_urls_do_not_rely_on_a_cache_busting_version() -> None:
    # HTML freshness comes from the no-store header, so the /portal and /wizard
    # entry URLs never need a hand-bumped ?v= query. Static assets may still
    # carry their own version; only the page URLs are covered here.
    sources = [
        ROOT / "web" / "connect" / "index.html",
        ROOT / "web" / "connect" / "awg.html",
        ROOT / "web" / "miniapp" / "index.html",
        ROOT / "web" / "miniapp" / "app.js",
        ROOT / "src" / "vpn_wizard" / "server.py",
    ]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "/portal/?v=" not in text, path
        assert "/wizard/?v=" not in text, path


def test_connect_pages_share_one_glass_material() -> None:
    for page in ("web/connect/index.html", "web/connect/awg.html"):
        html = (ROOT / page).read_text(encoding="utf-8")
        assert 'class="aurora"' in html, page
        assert "backdrop-filter" in html, page
        # Glass must degrade for people who cannot read text through it.
        assert "prefers-reduced-transparency" in html, page
        assert "prefers-reduced-motion" in html, page
        assert 'name="color-scheme" content="light dark"' in html, page


def test_connect_page_shows_one_platform_at_a_time() -> None:
    # Without these rules every platform's instructions render at once and the
    # install step becomes a stack of near-identical buttons.
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert ".platform{display:none}" in html
    assert ".platform.on{display:block}" in html


def test_static_routes_keep_old_buttons_on_portal_and_preserve_wizard() -> None:
    source = (ROOT / "src" / "vpn_wizard" / "server.py").read_text(encoding="utf-8")
    assert 'PORTAL_ENTRY_URL = "/portal/"' in source
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
    assert "/portal/" in script
