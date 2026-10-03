"""Public redesign must keep anonymous issuance and progressive disclosure."""

from pathlib import Path
from html.parser import HTMLParser


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web" / "connect"


class _PublicMarkup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.scripts: list[str] = []
        self.open_details = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        if tag == "details" and "open" in values:
            self.open_details += 1


def test_public_markup_has_unique_ids_and_closed_disclosures() -> None:
    markup = _PublicMarkup()
    markup.feed((WEB / "join.html").read_text(encoding="utf-8"))
    assert len(markup.ids) == len(set(markup.ids))
    assert markup.open_details == 0
    assert markup.scripts.index("server-catalog.js") < markup.scripts.index("public-vpn.js")


def test_public_page_keeps_server_choice_and_collapsed_helpers() -> None:
    html = (WEB / "join.html").read_text(encoding="utf-8")
    for element_id in (
        "server-grid", "alternate-grid", "extra-server", "extra-profile",
        "refresh", "catalog-error", "monitor-note", "download-status",
    ):
        assert f'id="{element_id}"' in html
    assert html.count("<details") >= 2
    assert '<details open' not in html
    assert 'id="code"' not in html
    assert 'public-vpn.js' in html
    assert 'server-catalog.js' in html
    assert 'lang="ru"' in html
    assert 'name="referrer" content="no-referrer"' in html


def test_public_download_keeps_private_posts_and_independent_devices() -> None:
    script = (WEB / "public-vpn.js").read_text(encoding="utf-8")
    assert "/api/public/awg/device" in script
    assert "/api/public/awg/config" in script
    assert script.count("method:'POST'") >= 2
    assert "credentials:'same-origin'" in script
    assert "new_device:fresh" in script
    assert "server_id:server.id" in script
    assert "include_unavailable=true" in script
    assert "URL.revokeObjectURL" in script
    assert "localStorage" not in script
    assert "PrivateKey" not in script


def test_shared_support_stays_voluntary_and_motion_respects_preferences() -> None:
    script = (WEB / "server-catalog.js").read_text(encoding="utf-8")
    assert "https://t.me/fodders_dev" in script
    assert "prefers-reduced-motion: reduce" in script
    assert "document.hidden" in script
    assert "IntersectionObserver" in script
    assert '"aria-pressed"' in script
    assert "Реквизиты скоро появятся" in script
    assert 'paymentLink.hidden = true' in script


def test_support_has_explicit_actions_copy_and_collapsed_cost_explanation() -> None:
    script = (WEB / "server-catalog.js").read_text(encoding="utf-8")
    assert "Подписаться на канал" in script
    assert "Поддержать донатом" in script
    assert "На что идут деньги?" in script
    assert "support-payment-panel" in script
    assert 'navigator.clipboard.writeText(copyButton.dataset.card)' in script
    assert "Выделите номер карты выше" in script
    assert "все профили доступны и без доната или подписки" in script
