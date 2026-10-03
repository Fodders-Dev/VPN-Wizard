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


def test_portal_uses_shared_minimal_design_with_support_before_downloads():
    html = (WEB / "next.html").read_text(encoding="utf-8")
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
    html = (WEB / "next.html").read_text(encoding="utf-8")
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
    html = (WEB / "next.html").read_text(encoding="utf-8")
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
