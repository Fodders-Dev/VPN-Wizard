from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_miniapp_uses_canonical_api_fallback_and_test_hooks() -> None:
    js = (ROOT / "web" / "miniapp" / "app.js").read_text(encoding="utf-8")
    assert 'const CANONICAL_API_BASE = "https://212-69-84-167.nip.io";' in js
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


def test_connect_page_explains_personal_subscription_and_opens_happ_directly() -> None:
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "Это личная ссылка." in html
    assert "Не используйте чужую подписку." in html
    assert "Добавить Fodder VPN в Happ" in html
    assert '$("open-profile").href="happ://add/"+sub;' in html
    assert '$("link-text").dataset.url=sub;' in html
    assert 'var t=$("link-text").dataset.url||"";' in html


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
