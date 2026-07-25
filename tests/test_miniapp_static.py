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
    # nothing to answer and the button looks broken. The invite must be a deep
    # link carrying the subscriber's own referral code, served by the API.
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "links.referral_url" in html
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
    # The family token carries an epoch the API bumps on revoke, so the bot must
    # ask for the link instead of signing one against a stale epoch.
    assert "f'family:{int(telegram_id)}'" not in handler
    assert "/family-link" in handler
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


def test_connect_page_survives_the_telegram_webview() -> None:
    # Telegram's WebView ignores <a download> and target="_blank": the tap does
    # nothing at all, with no file and no error for the user.
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert "telegram-web-app.js" in html
    # ...but this is the page for people who CANNOT reach Telegram, so it must
    # never block on telegram.org. Load the SDK only inside Telegram, and async.
    assert '<script src="https://telegram.org' not in html
    assert "sdk.async=true" in html
    assert "window.TelegramWebviewProxy" in html
    assert "tg.downloadFile" in html
    assert "tg.openLink" in html
    assert "tg.openTelegramLink" in html
    # Only a real Mini App launch may hijack the click; a plain browser must keep
    # its native download.
    assert "if(!inTelegram)return;" in html


def test_portal_hands_external_links_to_telegram() -> None:
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "tg.openTelegramLink" in html
    assert "tg.openLink" in html


def test_portal_exposes_device_control() -> None:
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert 'id="devices-card"' in html
    assert 'id="devices-list"' in html
    assert "/devices" in html
    assert "/revoke" in html
    assert "/label" in html
    # Revoking is destructive and irreversible for whoever holds that config.
    assert "window.confirm" in html
    # A partially revoked key is still live somewhere; never report success.
    assert "могла остаться" in html


def test_bot_exposes_device_control() -> None:
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "Command('devices'" in handler
    assert "DEVICES_CALLBACK" in handler
    assert "DEVICE_REVOKE_CONFIRM_PREFIX" in handler
    # The confirm prefix extends the revoke prefix, so it must be registered first
    # or "are you sure?" would swallow the confirmation itself.
    assert handler.index("register(apply_device_revoke") < handler.index("register(confirm_device_revoke")
    assert "ForceReply" in handler


def test_config_caption_warns_about_the_android_recents_trap() -> None:
    # Android's "Recent files" view can surface the document without its .conf
    # name (shown as a BIN file), and AmneziaWG then refuses to open it. Observed
    # on a Huawei tablet; opening from Downloads works.
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "Загрузки" in handler
    assert "Недавние" in handler


def test_invite_link_is_personal_not_shared() -> None:
    # A single shared link credits nobody: the inviter gets no referral reward
    # and cannot grow their balance from people they bring in.
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "start=friends" not in html
    assert "links.referral_url" in html
    server = (ROOT / "src" / "vpn_wizard" / "server.py").read_text(encoding="utf-8")
    assert "referral_url" in server
    assert "BotApiClient" in server


def test_device_summary_does_not_count_suspended_as_occupied() -> None:
    # Suspended keys are retained, not in use; counting them produced "2 из 1".
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "(d.servers||[]).length>0" in html
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "d.get('servers')" in handler


def test_connect_page_offers_operator_presets() -> None:
    # If the operator's DPI drops the default junk profile the tunnel simply never
    # comes up, with no error anywhere. The preset picker is the user's only lever.
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert 'id="preset-box"' in html
    assert 'id="preset-buttons"' in html
    assert "d.presets" in html
    assert 'searchParams.set("preset"' in html
    # "default" is the plain profile and must not be sent as an override.
    assert 'u.preset!=="default"' in html


def test_bot_can_mint_an_invite() -> None:
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "Command('invite'" in handler
    assert "INVITE_CALLBACK" in handler
    assert "/invites" in handler
