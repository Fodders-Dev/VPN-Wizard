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
