# Split-routing (keep RF sites direct)

Since April 2026, Russian platforms (Sber, Gosuslugi, Ozon, Kinopoisk, banks…) block
users who browse with a VPN on. So the profile must send **RF traffic direct** and
only tunnel the rest. "My bank doesn't work with VPN on" is the #1 complaint about
competitors — solving it is our main differentiator.

## Where split-routing lives

Not on the server. It's **client-side routing**, delivered through Remnawave's
**subscription templates** — one per client format. Remnawave fills in the user's
server; the template decides what goes direct vs. through the tunnel.

Install in the panel: **Subscription Settings → Templates**, paste the right file
into each client type.

| Client (who uses it)              | Type in panel   | Template                         |
|-----------------------------------|-----------------|----------------------------------|
| v2rayNG, Happ (Xray core)         | `XRAY_JSON`     | `xray-json-split-ru.json` *or* vendored bundle |
| Hiddify, sing-box (iOS/Android)   | `SINGBOX`       | vendored `singbox-ru-bundle.json` |
| Clash Meta / Mihomo               | `MIHOMO`        | vendored `mihomo-ru-bundle.yaml` |
| Stash (iOS)                       | `STASH`         | vendored `stash-ru-bundle.yaml`  |

## Two ways to do it — pick per client

### A. Maintained bundles (recommended for sing-box / Mihomo / Stash)

`bash fetch-ru-templates.sh` downloads the **legiz-ru RU bundles** from the official
Remnawave templates repo into `./vendored/`. They use regularly-updated rule sets
(e.g. `legiz-ru/sb-rule-sets/ru-bundle.srs`) covering the long tail of blocked/foreign
services, so RF stays direct without you maintaining domain lists. Re-run the script
to refresh. This is what serious RF services use — don't hand-maintain routing you can
inherit.

### B. Transparent minimal Xray (for control / understanding)

`xray-json-split-ru.json` is our own small, readable version for `XRAY_JSON`. It's the
Remnawave default template plus two rules:

- an explicit **`domain:` list of ~50 RF services** (gov, banks, MIR/NSPK, taxes,
  marketplaces, Yandex/VK/Mail.ru, telecoms) → `direct`
- **`geoip:ru`** → `direct` (catches anything hosted on RF IPs)

Everything else falls through to the proxy outbound that Remnawave injects. It
deliberately uses only `geoip:ru` and explicit domains — **no `geosite:category-*`**,
because an unknown geosite code makes Xray refuse to load the whole config and breaks
the client. Add `geosite:category-ru` yourself only if you've confirmed your users'
client ships a geosite that has it.

Trade-off: transparent and tunable, but less exhaustive than the maintained bundle.
Fine as a baseline; switch to A when you want full coverage.

## Sanity-check before shipping

On a real phone with the profile active, confirm these load **without** the tunnel
dropping them (they should resolve direct):

- [ ] gosuslugi.ru  ·  online bank app (Sber/VTB/Tinkoff)  ·  ozon.ru / wildberries.ru
- [ ] kinopoisk.ru  ·  mos.ru / nalog.ru
- [ ] a blocked/foreign site (e.g. instagram.com) **does** go through the tunnel

If a bank is still broken, add its API domain to the `domain:` list (Option B) or it's
already covered by the maintained bundle (Option A).

## Notes

- `./vendored/` is produced by the fetch script and is git-ignored — it's upstream
  content, refreshed on demand, not something we maintain by hand.
- Keep DNS sane: routing by domain needs the client to see real domains, so leave
  sniffing on (both templates do).
