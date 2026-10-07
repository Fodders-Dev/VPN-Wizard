# RUNBOOK

## First-visit app requirement and alternative protocol audit (2026-10-07)

Before server choice the public catalog must identify AmneziaWG and expose
installation links without opening help. Verify mobile 320/390px, desktop,
keyboard access, official app links and the illustrated-guide return route.
Downloads/QR, server telemetry and the self-hosted entry must remain unchanged.
Pre-release source rollback archive:
`/opt/vpn-wizard/shared/backups/awg-onboarding-20261007-075942/source.tar`
(production head before release: `0fb30a8`).

Read-only NL inventory: sing-box 1.12.22 already serves ShadowTLS v3 on TCP
10443 with a loopback Shadowsocks inbound on 20000; Xray 26.2.6 has VLESS/Reality
on TCP 8443 and VLESS/XHTTP/TLS on TCP 9443. The public website occupies TCP 443;
never replace it with an experimental listener. No experimental service was
installed, updated or restarted by this audit. Existing configurations contain
credentials: report only listener/protocol/version metadata, never full JSON.
An ephemeral loopback-only client validated the existing ShadowTLS + SS2022
chain: HTTPS through SOCKS returned HTTP 200 and 577 bytes from example.com.
The temporary process/config were removed; this server-local check does not
establish reachability from an RF provider or a user's device.

First suggested alternative trial: Hiddify + the existing ShadowTLS/SS2022
service. Export a private test profile only for the owner, then verify actual
HTTPS/data transfer (not merely TCP connect) from home Wi-Fi and mobile hotspot,
including DNS, reconnect and sustained transfer. Keep AWG intact. Only after
client confirmation should an alternative enter the anonymous public catalog.
Historical Reality failure notes are observations/hypotheses, not proof of a
specific ISP filter; do not promise that a new client or TCP guarantees access.
Current primary references:
- https://hiddify.com/app/How-to-install-Hiddify-app/
- https://sing-box.sagernet.org/configuration/outbound/shadowtls/
- https://xtls.github.io/en/config/transports/xhttp.html


## Free home and illustrated guide (2026-10-05)

`/portal/` offers two ungated routes: free profiles (`/connect/join.html`) and
self-hosted setup (`/wizard/`). Telegram login in the master protects SSH-session ownership; old
private account functionality remains at `/connect/account.html`. Paid bot entry
actions are hidden, not deleted. For deployment/rollback see RUNBOOK-managed.md.

Beginner instructions: `/connect/guide.html`. Current `and-3*` images are legacy
illustrations; fresh emulator captures await a manual AVD start after an automatic
launch was rejected. Do not call them freshly verified screenshots. For new
captures use disposable demos. Confirm all images load and device steps remain
reachable with JavaScript disabled. `profile-file.js` gives public downloads
short unique ASCII names. Filename repair in `guide.js` stays entirely local;
test `.conf.txt`, `(1).conf`, invalid/oversize files and quick selection changes,
asserting byte-identical output and zero uploads. Never capture actual keys.

Before publication run the full pytest suite and walk home → catalog → profile
or QR → illustrated guide → rename repair, plus home → VPS master sign-in → home
on a narrow mobile screen. Preserve real unavailable-server warnings.

Release tests include canonical anonymous-cookie encoding: alternate Base64
padding-bit spellings are rejected without rotating valid cookies or peer keys.
Rollback backup before release: `/var/backups/bedolaga/free-ux-20261005T055439Z/`
(both PostgreSQL databases plus web/Bedolaga overrides). Menu-layout snapshots
are separately saved under `/var/backups/bedolaga` by the configuration helper.

Deployed 2026-10-05: web/bot release `85f6887`. Full tests: 569 passed.
Live public NL download is 445 bytes with unique safe `.conf` filename; live QR
decoded as 890×890. Test profile contents were not logged and the local QA file
was removed. Bot is healthy, menu routes to `/portal/`, commands are
`free/wizard/help`, active rows are public catalog URL + self-hosted WebApp.
All 20 menu button definitions remain, including legacy inactive ones.
Persistent old-layout snapshot:
`/opt/bedolaga/data/backups/free-menu-20261005T060904Z/`
(also copied into the private rollback directory above).

## Managed server catalogue

FI provider address changed to `46.38.156.229` on 2026-10-04. SSH host keys
match the previous trusted host. Public `fi` remains `awg9` (70 retained peers);
`fi-alt` remains `awg8`. Before migration UDP 3478 was occupied by personal
`awg0`; changing only the registry port would give the wrong server key.
Back up runtime and persistent configs before any owner-approved port swap.
Cached downloads now render the current registry endpoint without rotating keys;
previously imported profiles must be re-downloaded or have Endpoint updated.
Do not remove the partial-outage overlay until an RF client test succeeds.
Applied the FI address-only migration in production; backup:
`/opt/vpn-wizard/shared/backups/fi-address-20261004-103610/`.
Public config/repeated same-key download/QR verified at `46.38.156.229:443`;
FI alternative remains UDP 4500. Actual RF VPN handshake remains unverified.
Regression run: 548 passed, plus three endpoint migration helper tests passed.

The owner approved swapping ports on 2026-10-04. Applied
`deploy/scripts/swap-fi-ports.py --apply --backup-dir <new-private-dir>` on FI:
public `awg9` now uses UDP 3478; personal `awg0` uses UDP 443. Other interfaces
remain unchanged. The helper backs up every touched configuration, changes only
the runtime listen ports (no interface restart), updates persistent/client
configs atomically and checks public-key/peer identities. It rolls back on error.
FI rollback copies: `/root/fi-3478-backup-20261004-105009/` (74 files).
Then applied `move-fi-endpoint.py --port 3478 --apply` on NL, under the same
cross-process AWG mutation lock. Environment rollback copy:
`/opt/vpn-wizard/shared/backups/fi-port-20261004-105009/vpn-wizard.env`.
Verified live/persistent listeners, matching public server key, repeated profile
reuse and QR at `46.38.156.229:3478`; all 554 tests passed. Monitoring refreshed.
At migration time no RF handshake existed; the warning was retained pending a client test.
An old imported personal awg0 profile needs Endpoint `46.38.156.229:443`;
an old public fi profile needs Endpoint `46.38.156.229:3478` or re-import.

On 2026-10-05 the owner confirmed internet access through the fresh `FVPN-fi`
profile from the RF client. The screenshot shows a recent handshake and traffic
in both directions at `46.38.156.229:3478`; exit-side counters independently
confirm a live handshake and several MB transferred. Removed the stale `fi`
partial-outage override: the primary card now follows ordinary runtime telemetry.
Kept an explicit caution for `fi-alt` UDP 4500, which was not client-tested.
This is evidence for the tested network, not a guarantee for every RF operator.

NL public primary is the existing `nl-alt` exit on UDP 3478; `nl` on UDP 443
remains an alternate choice. Do not swap server IDs, interfaces, stored keys or
`VPNW_AWG_DEFAULT_SERVER`: that legacy default selects existing encrypted rows.
Promotion is registry presentation metadata only, not a VPN restart:
`python deploy/scripts/prefer-nl-3478.py --apply --backup-dir <new-private-dir>`
on NL, followed by `systemctl restart vpn-wizard`. The helper preserves the
existing listen ports and credentials and backs up `/etc/vpn-wizard.env`.
Applied 2026-10-04; private environment backup:
`/opt/vpn-wizard/shared/backups/nl-primary-3478-20261004/vpn-wizard.env`.
Verified live 3478 profile endpoint, matching QR, same-key reuse and unchanged
443/3478 interface listeners; regression suite: 544 passed.

Enable `VPNW_AWG_FREE_SERVER_CHOICE=true` in `/etc/vpn-wizard.env` to let existing
valid free users select any enabled exit. This is not anonymous access and does
not add device slots. Keep the original default server unchanged: legacy encrypted
peer rows are mapped to it. Disabled exits remain registered for expiry handling.

Install `deploy/awg-fallback/vpn-wizard-awg-health.{service,timer}` into
`/etc/systemd/system/`, reload systemd and enable the timer. The read-only probe
runs every two minutes; no key rotation or interface restart occurs. Its snapshot
defaults to `awg-health.json` next to `VPNW_STATE_DB` (override with
`VPNW_AWG_HEALTH_PATH`). More than ten minutes old means unknown, never green.
`/api/awg/servers?include_unavailable=true` shows disabled locations too, while
the default API remains compatible with bot clients that expect offerable exits.

Latency origin: the health timer runs on NL (controller server ID defaults to
`nl`, override `VPNW_AWG_MONITOR_SERVER_ID`). For that same public host, run
read-only ICMP from enabled FI, or US if FI is absent/disabled. Grouped ports share
one measurement. Remote SSH/ICMP failure leaves RTT unknown, never a self-ping
fallback; normal VPN availability still follows interface/handshake evidence.
The catalog discards old NL self-ping snapshots immediately. Origin is named on
each card: RTTs from different monitors are not directly comparable and do not
test the user's ISP. After deployment trigger the existing health service once
and verify both NL ports use `fi_monitor` (or `us_monitor`) with a positive RTT.

Published 2026-10-07 at commit `6676afc`: NL public RTT now comes from FI,
roughly 29–31 ms during verification, with its origin clearly labelled. Idle
interfaces show "Доступен" with an explanation, not a fake confirmed handshake.
589 tests passed, including Node-rendered latency edge cases; live 320/390/1280px
checks had no horizontal overflow. Free downloads and QR remain enabled for
working/idle exits, disabled for TR. Source rollback archive:
`/opt/vpn-wizard/shared/backups/nl-health-20261007-073249/source.tar`, old commit
`fc72ad2`. Fast-forward source deploy plus web-service restart and one health
refresh only; no AWG ports, interfaces, keys or firewall changes.

Manual partial-outage notices live in `web/connect/status.json` under
`server_statuses.<id>={"state":"degraded","detail":"..."}`. Remove the notice
only after rechecking affected networks. Server-side handshakes do not guarantee
reachability from every operator; an SSH timeout does not prove a dead VPN.

Set `VPNW_SUPPORT_DETAILS` to owner-approved public bank/card/SBP details and/or
`VPNW_SUPPORT_URL` to an HTTPS donation link, then restart `vpn-wizard`. Empty
details produce an honest placeholder, not a fake payment number. The support
block appears below the portal and profile page and never gates downloads.
On the public `join.html` page it sits before server selection, with compact
mobile actions and collapsed payment/cost details; the server skip link bypasses it.
The Telegram `/portal/` entry uses `web/connect/next.html` and `portal.css`.
Verify signed-in free/paid states, anonymous fallback, narrow widths, disclosure
navigation and Telegram SDK link handling with mock credentials before rollout.
No paid entitlement or VPN-interface changes are needed for this redesign.

The 2026-10-03 catalogue was deployed directly to NL after 426 tests and mobile
browser verification. Original sources and environment are retained in
`/opt/vpn-wizard/shared/backups/catalog-20261003-120318/` (owner-only directory).
No VPN interfaces or keys were restarted/rotated. Commit/push the corresponding
local source changes before the next unrelated Git-based production update:
autodeploy resets tracked files to its upstream revision when that revision changes.

## Prereqs
- Python 3.10+
- SSH access with sudo on the VPS

## Install
```
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
pip install -r requirements-dev.txt
```

## CLI
Provision:
```
python -m vpn_wizard.cli provision --host <ip> --user <user> --password <pass> --client client1 --auto-mtu --tune --check --precheck
```

Export config + QR:
```
python -m vpn_wizard.cli export --host <ip> --user <user> --password <pass> --client client1 --out client1.conf --qr client1.png
```

Status:
```
python -m vpn_wizard.cli status --host <ip> --user <user> --password <pass>
```

Rollback last config:
```
python -m vpn_wizard.cli rollback --host <ip> --user <user> --password <pass>
```

Add client:
```
python -m vpn_wizard.cli client add --host <ip> --user <user> --password <pass> --name grandma-phone --qr grandma.png
```

List clients:
```
python -m vpn_wizard.cli client list --host <ip> --user <user> --password <pass>
```

Remove client:
```
python -m vpn_wizard.cli client remove --host <ip> --user <user> --password <pass> --name grandma-phone
```

Rotate client keys:
```
python -m vpn_wizard.cli client rotate --host <ip> --user <user> --password <pass> --name grandma-phone --qr grandma.png
```

## GUI
```
python -m vpn_wizard.gui
```

## API server (for Telegram bot/miniapp)
```
python -m vpn_wizard.server
```
Optional session tuning:
```
$env:VPNW_SESSION_TTL_SECONDS="86400"
$env:VPNW_SESSION_LIMIT="512"
```

Proxy mode defaults:
```
# optional, when miniapp runs in Proxy mode (ShadowTLS / legacy VLESS Reality)
$env:VPNW_SSH_DISCOVERY_PORTS="22,2222,22022,2200,2022,10022"
$env:VPNW_SSH_DISCOVERY_TIMEOUT="1.8"
```

## Single Railway service (API + bot in one)
```
$env:VPNW_BOT_TOKEN="YOUR_TOKEN"
$env:VPNW_MINIAPP_URL="https://vpn-wizard-production.up.railway.app/miniapp/"
python -m vpn_wizard.combined
```

## Telegram bot
```
$env:VPNW_BOT_TOKEN="YOUR_TOKEN"
$env:VPNW_MINIAPP_URL="https://vpn-wizard-production.up.railway.app/miniapp/"
python -m vpn_wizard.tg_bot
```
Commands: `/start`, `/help`, `/miniapp`, `/cancel`.
Default: bot requires subscription to `VPNW_REQUIRED_CHANNEL` (по умолчанию `@fodders_dev`). Set empty to disable.

## Tests
```
pytest
```

## Tyumen bypass (awg1)
Create a client with the `tyumen-` prefix to route it to the secondary interface:
```
python -m vpn_wizard.cli client add --host <ip> --user <user> --password <pass> --name tyumen-test --qr tyumen-test.png
```

VPS checks:
```
sudo systemctl status awg-quick@awg1
sudo wg show awg1
sudo ss -ulpn | rg 3478
sudo ufw status | rg 3478
```

Client config expectations:
- `Endpoint = <server_ip>:3478`
- `Address = 10.11.0.x/24`

## Notes
- Public entry: `/connect/join.html` (also `/vpn`). Enable
  `VPNW_PUBLIC_ACCESS_ENABLED=true` in the service environment. Public issuance
  uses an isolated encrypted `public-access.db` beside `state.db`; include both
  databases and the existing encryption/signing secrets in private backups.
- Anonymous downloads first POST same-origin JSON to `/api/public/awg/device`,
  then `/api/public/awg/config` with `server_id`. The Secure HttpOnly identity
  cookie is never placed in URLs/JS storage. A retry reuses the same keys;
  explicit `new_device` at bootstrap generates independent profiles without
  disabling earlier ones. HTTPS is required.
- The public QR button instead POSTs to `/api/public/awg/qr` with the same
  identity and `server_id`; it reuses the personal peer and returns private PNG
  with `no-store` headers. No config/key is sent to a third-party QR service.
  Closing the modal clears the image and revokes its in-memory object URL.
  Degraded/unknown exits require a warning confirmation for both download and
  QR; unavailable/disabled exits cannot issue either. Healthy exits sort first.
  Deployed 2026-10-03 after 541 tests and desktop/320/390px browser checks.
  Live HTTPS verification proved QR/config equality, repeated-config reuse,
  private image headers and bad-origin rejection. Source rollback backup:
  `/opt/vpn-wizard/shared/backups/public-qr-20261003-210900/`.
- There is no account/device-count cap for public profiles. Burst/hour request
  throttles and bounded SSH concurrency protect the service; current limiter and
  allocation locks require the existing single API worker. Keep paid entitlement
  reconciliation pointed only at the original database.
- Monitor-side latency is ICMP from the NL host, not a user's ping. Local NL
  latency is intentionally not a fake 0ms; alternate ports share host telemetry.
  Recent handshakes count peers, not unique people. Interface byte counters
  reset on peer removal/restart and are not lifetime traffic or availability.
- Exact support text/link: `VPNW_SUPPORT_DETAILS` / `VPNW_SUPPORT_URL` (HTTPS).
  Public card-only support can be supplied as `Карта: 0000 0000 0000 0000` in
  `VPNW_SUPPORT_DETAILS`; the UI extracts only the 16 digits for copying. Keep
  real payment details in deployment settings, not in Git; never store CVV,
  expiration dates, bank credentials or confirmation codes here.
  If absent, the page honestly shows pending details and the voluntary channel
  link. Never invent donation totals, payment information or fundraising progress.
- Public UI regression checks: `python -m pytest tests/test_public_vpn_ui.py
  tests/test_miniapp_static.py tests/test_public_access_routes.py -q`.
  Before deploying visual changes, verify desktop and 320/390px mobile widths,
  collapsed help/alternate ports, disabled unavailable exits, repeated downloads,
  explicit independent-device creation and reduced-motion support. Use mock
  configuration downloads for screenshots; never capture real private keys.
- A successful WG/AWG setup now requires all runtime readiness checks to pass.
  `--no-check` only hides the CLI check report; it cannot bypass service,
  interface, IP forwarding or UDP listener validation. Failed API jobs retain
  their checks and do not publish a config download or QR.
- If `awg` exists but the module is missing, Wizard attempts `dkms autoinstall`
  and package configuration for the running kernel, then verifies the backend.
  For the confirmed Ubuntu `5.15.0-43-generic` timer API incompatibility, it
  backs up and repairs the module's compatibility header before rebuilding.
  The repair is restricted to that exact ABI. Remaining failures
  report the kernel and bounded DKMS build diagnostics instead of claiming success.
- Incident recovery for the original Ubuntu 22.04 kernel `5.15.0-43-generic`:
  copy both files from `deploy/scripts/repair-amneziawg-jammy-43.sh` and
  `src/vpn_wizard/patches/amneziawg-jammy-43-timers.patch` into one directory on the VPS,
  then run the shell script as root. It backs up configs and the module's
  compatibility header under `/root/fodder-awg-repair.*`, adds timer aliases
  restricted to that exact kernel ABI, rebuilds/configures DKMS and starts AWG.
  Existing client keys/configs are retained. This is an incident-specific repair,
  not a general kernel upgrade or a patch for newer kernels.
- Use `--key` instead of `--password` for key auth.
- Server configs stored under `/etc/wireguard/`.
- Disable tuning with `--no-tune`, disable MTU with `--mtu 0`, disable auto-MTU with `--no-auto-mtu`.
- Default UDP listen port: 3478 (override with `--listen-port` or miniapp advanced field).
- Miniapp is served at `http://<host>:8000/miniapp` when running the API server.
- Miniapp UI calls client configs "profiles" to reduce confusion for end users.
- Telegram miniapp requires a public HTTPS URL configured in BotFather.
- If Telegram widget shows `Bot domain invalid`, add the exact miniapp/web domain in BotFather (/setdomain) for your bot. Domains like `*.nip.io` must match what users open in browser.
- В Telegram WebApp скачивание конфигов/QR идет через data: ссылки (если загрузка не стартует, нажмите еще раз или используйте десктоп).
- В расширенных полях миниаппа есть безопасный режим (только проверка/precheck) — он не меняет сервер.
- Prefer the Railway-hosted miniapp in production so the Telegram WebApp and API share one origin.
- For cross-origin miniapp, set `VPNW_CORS_ORIGINS="https://your-miniapp-domain"` before running the API server.
- For miniapp "remember login", backend keeps temporary SSH sessions in memory (`VPNW_SESSION_TTL_SECONDS`, `VPNW_SESSION_LIMIT`).
- Set `window.API_BASE` in `web/miniapp/config.js` to your API server URL when hosting separately.
- You can also pass `?api=https://your-api-domain` in the miniapp URL to override API base.
- Miniapp now supports explicit SSH port input and `host:port` format (for non-standard SSH ports).
- Miniapp supports two setup modes: `VPN (AmneziaWG)` and `Proxy (ShadowTLS + SS2022)`.
- Proxy mode (ShadowTLS) exports an auto-config profile URL (Hiddify / sing-box). Legacy proxy mode exports a `vless://` link + QR.
- ShadowTLS proxy configs are pinned to the primary port by default (to avoid RU ISP port filtering breaking urltest-based failover). Optional urltest can be enabled via `VPNW_SHADOWTLS_ENABLE_URLTEST=1`.
- `/api/download/<id>/config` is a snapshot: if server/proxy was reconfigured, generate a fresh URL/profile (old URL may point to outdated settings).
