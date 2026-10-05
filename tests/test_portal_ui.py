"""The Telegram cabinet keeps existing private workflows in the public design."""
from html.parser import HTMLParser
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "web" / "connect"


class PortalMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.controls = {}
        self.h1_count = 0
        self.options_closed = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "h1":
            self.h1_count += 1
        if values.get("aria-controls"):
            self.controls[values["id"]] = values
        if tag == "details" and values.get("class") == "portal-options":
            self.options_closed = "open" not in values


def test_legacy_account_keeps_shared_minimal_design():
    html = (WEB / "account.html").read_text(encoding="utf-8")
    parser = PortalMarkup()
    parser.feed(html)
    assert len(parser.ids) == len(set(parser.ids))
    assert parser.h1_count == 1
    assert parser.options_closed
    assert 'class="app vpn-minimal vpn-portal"' in html
    assert 'href="/connect/portal.css"' in html
    assert html.index('id="support-slot"') < html.index('id="public-vpn-link"')
    assert 'href="/connect/join.html"' in html
    assert 'без кодов и лимита устройств' in html
    assert 'class="sky"' not in html
    assert 'backdrop-filter' not in (WEB / "portal.css").read_text(encoding="utf-8")


def test_portal_disclosures_have_matching_accessible_controls():
    html = (WEB / "account.html").read_text(encoding="utf-8")
    parser = PortalMarkup()
    parser.feed(html)
    for trigger, panel in (("t-devices", "devices"), ("t-countries", "countries"),
                           ("t-family", "family"), ("t-consoles", "consoles")):
        assert parser.controls[trigger]["aria-controls"] == panel
        assert parser.controls[trigger]["aria-expanded"] == "false"
        assert panel in parser.ids
    assert 'setAttribute("aria-expanded",String(!$(pair[1]).hidden))' in html
    assert 'id="consoles-copy" type="button"' in html
    assert 'role="button"' not in html


def test_portal_keeps_auth_and_private_features_without_claiming_public_limits():
    html = (WEB / "account.html").read_text(encoding="utf-8")
    for endpoint in ("/api/auth/telegram/miniapp", "/api/auth/me", "/api/portal/links",
                     "/api/portal/channel-access/verify", "/api/console-proxy/"):
        assert endpoint in html
    for identifier in ("cta-connect", "family-open", "consoles-bind", "plan-row",
                       "invite-row", "wizard-link-main"):
        assert f'id="{identifier}"' in html
    assert "init_data:tg.initData" in html
    assert 'cu.searchParams.set("from","portal")' in html
    assert "var booted=false" in html
    assert "if(booted)return" in html
    assert 'if(telegramLaunch&&!tg)' in html
    assert 'if(telegramLaunch&&!(tg&&tg.initData))return show("locked")' in html
    assert 'tg.setHeaderColor("#101312")' in html
    assert "localStorage" not in html
    assert "createTextNode(label" in html
    assert "strong.textContent=value" in html


def test_free_home_has_two_ungated_primary_paths_before_optional_support():
    html = (WEB / "next.html").read_text(encoding="utf-8")
    parser = PortalMarkup()
    parser.feed(html)
    assert len(parser.ids) == len(set(parser.ids))
    assert parser.h1_count == 1
    assert 'id="public-vpn-link" href="/connect/join.html"' in html
    assert 'id="wizard-link-main" href="/wizard/"' in html
    assert html.index('id="wizard-link-main"') < html.index('id="support-slot"')
    assert "Получить бесплатный VPN" in html
    assert "Настроить свой сервер" in html
    for old in ('id="cabinet"', 'id="plan"', 'id="t-devices"', 'id="offer"',
                'id="locked"', 'id="cta-connect"', 'id="t-family"'):
        assert old not in html
    js = (WEB / "free-home.js").read_text(encoding="utf-8")
    for endpoint in ("/api/auth", "/api/portal", "localStorage", "sessionStorage"):
        assert endpoint not in js
    assert "sdk.async = true" in js
    assert 'wizard.hash = launch.toString()' in js
    assert 'free.target = "_blank"' in js
    assert "tg.openLink(free.href)" in js
    assert "tg.openTelegramLink(link.href)" in js


def test_public_catalog_exposes_self_hosted_setup_without_disclosure():
    html = (WEB / "join.html").read_text(encoding="utf-8")
    assert 'class="vpn-product-nav"' in html
    assert 'href="/wizard/">Настроить свой сервер' in html
    assert html.index('href="/wizard/"') < html.index('id="server-grid"')
    assert 'href="/portal/"' in html
    wizard = (WEB.parent / "miniapp" / "index.html").read_text(encoding="utf-8")
    assert 'id="product-managed-label">Бесплатный VPN' in wizard


def test_self_hosted_master_explains_required_login_before_ssh_secrets():
    html = (WEB.parent / "miniapp" / "index.html").read_text(encoding="utf-8")
    parser = PortalMarkup()
    parser.feed(html)
    assert len(parser.ids) == len(set(parser.ids))
    js = (WEB.parent / "miniapp" / "app.js").read_text(encoding="utf-8")
    assert 'id="auth-disclosure" open' in html
    assert 'id="connect-fields" disabled' in html
    assert html.index('id="auth-disclosure"') < html.index('id="password-input"')
    assert "Для бесплатных готовых профилей вход не нужен" in html
    assert "refs.connectFields.disabled = !canManageServer" in js
    assert "account.authenticated && !account.pin_required" in js
    assert "Можно настроить VPS без входа" not in html + js
    assert 'id="open-pin-settings-btn"' in html
    assert 'id="unlock-pin-btn"' in html
    assert 'refs.openPinSettingsBtn.addEventListener("click", () => setPage("settings"))' in js
