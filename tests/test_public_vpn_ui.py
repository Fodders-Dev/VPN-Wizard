"""Public redesign must keep anonymous issuance and progressive disclosure."""

from pathlib import Path
from html.parser import HTMLParser
import shutil
import subprocess


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


def test_support_precedes_server_downloads_without_blocking_skip_link() -> None:
    html = (WEB / "join.html").read_text(encoding="utf-8")
    assert html.count('id="support-slot"') == 1
    assert html.index('id="servers-title"') < html.index('id="support-slot"')
    assert html.index('id="support-slot"') < html.index('<section id="servers"')
    assert html.index('<section id="servers"') < html.index('id="server-grid"')
    assert 'href="#servers"' in html
    assert 'aria-labelledby="server-choice-title"' in html
    assert 'id="server-choice-title"' in html


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


def test_public_latency_shows_monitor_ping_not_local_placeholder() -> None:
    script = (WEB / "public-vpn.js").read_text(encoding="utf-8")
    catalog = (WEB / "server-catalog.js").read_text(encoding="utf-8")
    note = "Пинг между серверами, не с вашего устройства. Источники разные — значения напрямую не сравнивайте."
    assert note in script
    assert note in (WEB / "join.html").read_text(encoding="utf-8")
    assert "catalog.renderLatency(value,server,staleCatalog)" in script
    assert "value < 1 ? \"<1 мс\"" in catalog
    assert 'latencyOrigin === "us_monitor"' in catalog
    assert "latency.scope !== \"local\" && latency.local !== true" in catalog
    assert "Нет доступного внешнего замера" in catalog
    assert "Локально" not in script


def test_ready_status_is_clear_associated_and_keeps_profile_actions_enabled() -> None:
    script = (WEB / "public-vpn.js").read_text(encoding="utf-8")
    catalog = (WEB / "server-catalog.js").read_text(encoding="utf-8")
    assert "online:'Работает',ready:'Доступен'" in script
    assert "VPN запущен; недавних подключений нет." in script
    assert "status.setAttribute('aria-describedby',readyNote.id)" in script
    assert "if(readyNote)card.appendChild(readyNote)" in script
    assert 'state: health.state || "unknown"' in catalog
    assert 'state !== "maintenance" && state !== "unavailable"' in catalog
    assert "qrButton.disabled=button.disabled" in script
    assert "button.disabled=busy||!catalog.selectable(server)||data.public_access===false" in script


def test_catalog_status_and_latency_behavior_with_node() -> None:
    node = shutil.which("node")
    if not node:
        import pytest

        pytest.skip("Node.js is not installed")
    behavior = r'''const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(process.argv[1], "utf8");
class MockNode {
  constructor(text = "") { this.text = text; this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(""); }
  set textContent(value) { this.text = String(value); this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
}
const sandbox = { window: { matchMedia: () => null }, document: {
  createTextNode: text => new MockNode(text),
  createElement: () => new MockNode()
} };
vm.runInNewContext(source, sandbox);
const catalog = sandbox.window.FodderCatalog;
const server = (state, latency, extraHealth = {}) => ({ enabled: true, health: { state, ...extraHealth, ...(latency === undefined ? {} : { latency }) } });
for (const state of ["online", "ready", "unknown"]) {
  assert.equal(catalog.status(server(state)).state, state);
  assert.equal(catalog.selectable(server(state)), true);
}
assert.equal(catalog.selectable(server("maintenance")), false);
assert.equal(catalog.selectable(server("unavailable")), false);
const nl = server("online", { ms: 0.03, origin: "nl_monitor", label: "Пинг от NL-монитора" });
const fiLabel = "Пинг от монитора в Финляндии; не с вашего устройства";
const fi = server("online", { ms: 29, origin: "fi_monitor", label: fiLabel });
const usLabel = "Пинг от монитора в США; не с вашего устройства";
const us = server("online", { ms: 29, origin: "us_monitor", label: usLabel });
assert.equal(catalog.status(nl).latency, 0.03);
assert.equal(catalog.formatLatency(catalog.status(nl).latency), "<1 мс");
assert.equal(catalog.status(fi).latency, 29);
assert.equal(catalog.status(fi).latencyLabel, fiLabel);
assert.equal(catalog.formatLatency(catalog.status(fi).latency), "29 мс");
assert.equal(catalog.status(us).latency, 29);
assert.equal(catalog.status(us).latencyLabel, usLabel);
assert.equal(catalog.formatLatency(29, true), "—");
for (const [latency, health] of [
  [undefined, {}],
  [{ ms: 0, origin: "nl_monitor" }, {}],
  [{ ms: -1, origin: "nl_monitor" }, {}],
  [{ ms: NaN, origin: "nl_monitor" }, {}],
  [{ ms: 60001, origin: "nl_monitor" }, {}],
  [{ ms: 29, origin: "self" }, {}],
  [{ ms: 29, origin: "local" }, {}],
  [{ ms: 29, origin: "nl_monitor", scope: "local" }, {}],
  [{ ms: 29, origin: "nl_monitor", local: true }, {}],
  [{ ms: 29, origin: "nl_monitor" }, { stale: true }],
  [{ ms: 29, origin: "unknown_monitor" }, {}]
]) {
  const current = server("ready", latency, health);
  assert.equal(catalog.status(current).latency, null);
  assert.equal(catalog.formatLatency(catalog.status(current).latency), "—");
  const node = new MockNode();
  const displayed = catalog.renderLatency(node, current);
  assert.equal(node.textContent, "—");
  assert.equal(displayed.value, "—");
  assert.equal(displayed.label, health.stale ? "Нет свежего замера" : "Нет доступного внешнего замера");
}
assert.equal(catalog.formatLatency(0), "—");
assert.equal(catalog.formatLatency(-0.03), "—");
assert.equal(catalog.formatLatency(NaN), "—");
assert.equal(catalog.formatLatency(29), "29 мс");
assert.equal(catalog.formatLatency(60000), "60000 мс");
assert.equal(catalog.formatLatency(60001), "—");
const node = new MockNode();
const rendered = catalog.renderLatency(node, nl);
assert.equal(node.textContent, "<1 мс");
assert.equal(rendered.label, "Пинг от NL-монитора");
assert.equal(node.children[1].textContent, "мс");
const usNode = new MockNode();
assert.equal(catalog.renderLatency(usNode, us).value, "29 мс");
assert.equal(usNode.textContent, "29 мс");
const staleNode = new MockNode();
assert.equal(catalog.renderLatency(staleNode, nl, true).label, "Нет свежего замера");
assert.equal(staleNode.textContent, "—");
'''
    result = subprocess.run(
        [node, "-e", behavior, str(WEB / "server-catalog.js")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_public_qr_uses_private_post_and_revokes_image_on_close() -> None:
    html = (WEB / "join.html").read_text(encoding="utf-8")
    script = (WEB / "public-vpn.js").read_text(encoding="utf-8")
    assert 'id="profile-qr-dialog"' in html
    assert 'closedby="any"' in html
    assert 'aria-labelledby="profile-qr-title"' in html
    assert "qrDialog.showModal()" in script
    assert "'/api/public/awg/qr'" in script
    assert "URL.revokeObjectURL(qrUrl)" in script
    assert "qrImage.removeAttribute('src')" in script
    assert "HTMLDialogElement.prototype" in script  # Safari light-dismiss fallback


def test_public_outage_warning_precedes_any_profile_request() -> None:
    script = (WEB / "public-vpn.js").read_text(encoding="utf-8")
    style = (WEB / "server-catalog.css").read_text(encoding="utf-8")
    assert "degraded:'Не рекомендуем'" in script
    assert "unavailable:'Не работает'" in script
    assert "vpn-server-warning" in script
    action = script[script.index("async function download"):]
    assert action.index("window.confirm(country(server)") < action.index("fetch('/api/public/awg/device'")
    assert "!catalog.selectable(server)" in action
    assert "healthRank[stateOf(a)]" in script
    assert "[data-state='degraded']" in style
    assert "[data-state='unavailable']" in style


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
