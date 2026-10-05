from __future__ import annotations

import html.parser
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CONNECT = ROOT / "web" / "connect"
GUIDE_JS = CONNECT / "guide.js"


class _LocalAssetParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        for attribute in ("src", "href"):
            value = values.get(attribute)
            if value and not value.startswith(("#", "/", "//", "http:", "https:", "data:")):
                self.assets.append(value.split("#", 1)[0].split("?", 1)[0])


def test_guide_is_linked_from_free_catalog_and_home() -> None:
    catalog = (CONNECT / "join.html").read_text(encoding="utf-8")
    home = (CONNECT / "next.html").read_text(encoding="utf-8")
    assert re.search(r'href=["\'](?:/connect/)?guide\.html(?:#[^"\']*)?["\']', catalog)
    assert re.search(r'href=["\']/connect/guide\.html(?:#[^"\']*)?["\']', home)


def test_guide_local_assets_exist() -> None:
    parser = _LocalAssetParser()
    parser.feed((CONNECT / "guide.html").read_text(encoding="utf-8"))
    assert parser.assets
    missing = [asset for asset in parser.assets if not (CONNECT / asset).is_file()]
    assert not missing, f"guide references missing local assets: {missing}"


def test_guide_keeps_real_android_snapshots_and_device_instructions() -> None:
    guide = (CONNECT / "guide.html").read_text(encoding="utf-8")
    for snapshot in (
        "and-3a-files.png",
        "and-3b-import.png",
        "and-3c-tunnel.png",
        "and-3d-permission.png",
    ):
        assert (CONNECT / "assets" / "guide" / snapshot).is_file(), snapshot
        assert snapshot in guide

    assert "Установите именно AmneziaWG" in guide
    assert "На телефоне Android" in guide
    assert "На компьютере Windows" in guide
    assert "Windows 11:" in guide and "Windows 10:" in guide
    assert "Расширения имён файлов" in guide
    assert "FVPN-nl.conf" in guide


def test_repair_is_local_and_does_not_upload_or_store_profiles() -> None:
    source = GUIDE_JS.read_text(encoding="utf-8")
    forbidden = re.compile(
        r"\b(?:fetch|XMLHttpRequest|WebSocket|sendBeacon|localStorage|"
        r"sessionStorage|indexedDB|FormData)\b",
        re.IGNORECASE,
    )
    assert not forbidden.search(source)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is needed to execute the browser scripts")
def test_profile_repair_executes_real_scripts_and_preserves_download_bytes() -> None:
    harness = r"""
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const base = process.argv[1];
const saved = [];
const namingViolations = [];
const blobs = new Map();
let nextBlob = 0;
let randomCall = 0;
const handlers = {};
const elements = {
  'repair-file': { files: [], addEventListener: (name, fn) => { handlers[name] = fn; } },
  'repair-download': { disabled: true, addEventListener: (name, fn) => { handlers['button-' + name] = fn; } },
  'repair-status': { textContent: '' }
};
const window = {
  crypto: { getRandomValues(bytes) { randomCall += 1; bytes.forEach((_, i) => { bytes[i] = randomCall + i; }); return bytes; } },
  addEventListener() {}
};
const document = {
  getElementById(id) { return elements[id]; },
  querySelectorAll() { return []; },
  body: { appendChild() {} },
  createElement() {
    return {
      href: '', download: '',
      click() { saved.push({ name: this.download, bytes: Array.from(blobs.get(this.href).bytes) }); },
      remove() {}
    };
  }
};
const URL = {
  createObjectURL(blob) { const key = 'blob:stub-' + (++nextBlob); blobs.set(key, blob); return key; },
  revokeObjectURL() {}
};
const context = { window, document, URL, Uint8Array, Array, String, Date, setTimeout() {}, location: { hash: '' } };
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(base, 'profile-file.js'), 'utf8'), context);
context.FodderProfileFile = window.FodderProfileFile;
vm.runInContext(fs.readFileSync(path.join(base, 'guide.js'), 'utf8'), context);

const config = Buffer.from('[Interface]\nPrivateKey = private-example\n[Peer]\nPublicKey = public-example\n', 'utf8');
function file(name, bytes = config) {
  return { name, size: bytes.length, bytes: Array.from(bytes), async text() { return bytes.toString('utf8'); } };
}
async function select(item) { elements['repair-file'].files = item ? [item] : []; await handlers.change(); }
function click() { handlers['button-click'](); }
function check(ok, message) { if (!ok) throw new Error(message); }
function namingCheck(ok, message) { if (!ok) namingViolations.push(message); }

(async () => {
  const first = file('FVPN-nl (1).conf');
  await select(first);
  check(!elements['repair-download'].disabled, 'recognized duplicate .conf should be enabled');
  click();
  click();
  check(saved.length === 2, 'repeated click on one selected repair should create a second copy');
  check(saved[0].name !== saved[1].name, 'repeated repair downloads need distinct names');
  check(saved[0].bytes.join(',') === saved[1].bytes.join(','), 'repeated repair copy must preserve bytes');
  const second = file('FVPN-nl.conf.txt');
  await select(second);
  check(!elements['repair-download'].disabled, '.conf.txt should be enabled');
  click();

  const names = saved.map(item => item.name);
  check(saved.length === 3, 'both valid profiles should download, including the repeated copy');
  check(saved[0].bytes.join(',') === first.bytes.join(','), 'first download must be byte-for-byte unchanged');
  check(saved[2].bytes.join(',') === second.bytes.join(','), 'second profile download must be byte-for-byte unchanged');
  for (const name of names) {
    const tunnelName = name.replace(/\.conf$/i, '');
    namingCheck(path.basename(name) === name, 'download name must be a basename: ' + name);
    namingCheck(/^[A-Za-z0-9_-]+\.conf$/.test(name), 'download name must be short ASCII with only .conf: ' + name);
    namingCheck(tunnelName.length <= 15, 'AWG tunnel name (without .conf) must be at most 15 ASCII characters: ' + tunnelName);
    namingCheck(!/[\s()[\]]/.test(name), 'download name must not contain spaces or brackets: ' + name);
  }
  namingCheck(new Set(names).size === names.length, 'repeated downloads need unique names');

  await select(file('unrelated.jpg'));
  check(elements['repair-download'].disabled, 'unrelated files must be rejected');
  await select(file('FVPN-nl.conf', Buffer.concat([config, Buffer.alloc(65536)])));
  check(elements['repair-download'].disabled, 'oversized files must be rejected');

  let resolveText;
  const stale = { name: 'FVPN-nl.conf', size: config.length, bytes: Array.from(config), text() { return new Promise(resolve => { resolveText = resolve; }); } };
  elements['repair-file'].files = [stale];
  const pendingValidSelection = handlers.change();
  await select(file('new-selection.jpg'));
  check(elements['repair-download'].disabled, 'invalid new selection should disable download');
  resolveText(config.toString('utf8'));
  await pendingValidSelection;
  check(elements['repair-download'].disabled, 'stale valid read must not re-enable after invalid selection');
  click();
  check(saved.length === 3, 'stale file must not be downloadable after invalid selection');

  const generated = Array.from({ length: 24 }, () => window.FodderProfileFile.name('nl'));
  for (const name of generated) {
    const tunnelName = name.replace(/\.conf$/i, '');
    namingCheck(path.basename(name) === name, 'generated profile name must be a basename: ' + name);
    namingCheck(/^[A-Za-z0-9_-]+\.conf$/.test(name), 'generated profile name must be short ASCII: ' + name);
    namingCheck(tunnelName.length <= 15, 'generated AWG tunnel name (without .conf) must be at most 15 ASCII characters: ' + tunnelName);
    namingCheck(!/[\s()[\]]/.test(name), 'generated profile name must not contain spaces or brackets: ' + name);
  }
  namingCheck(new Set(generated).size === generated.length, 'generated names must be unique');
  const hyphenatedRegion = window.FodderProfileFile.name('nl-alt');
  namingCheck(/^FVPN-nl-[A-Za-z0-9]+\.conf$/.test(hyphenatedRegion), 'hyphenated server IDs should yield a recognizable region name: ' + hyphenatedRegion);
  process.stdout.write(JSON.stringify({ names, generated, saved: saved.length, namingViolations }));
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
"""
    result = subprocess.run(
        ["node", "-e", harness, str(CONNECT)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert len(set(payload["names"])) == 3
    assert not payload["namingViolations"], "\n".join(payload["namingViolations"])
