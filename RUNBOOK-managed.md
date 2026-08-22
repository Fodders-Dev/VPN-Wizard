# RUNBOOK — Fodder VPN 2 (managed subscription)

Managed VPN on **your** servers: one NL profile is free while a user subscribes to
`@fodders_dev`; other exits, extra devices and console proxy setup are paid and
auto-disabled when unpaid. Stack: **Remnawave** panel + nodes, **Bedolaga** shop-bot,
and **AmneziaWG** as the production RF protocol. Reality/Happ is retired from the
active onboarding because it did not work reliably from the target RF networks.

> This is a different product from the old `vpn_wizard` self-host hub (which
> provisions a whole server per user over SSH). That tool stays useful as the
> **AmneziaWG fallback layer** in step 7. See the strategy doc for the why.

All config lives in [`deploy/`](deploy/). Files with `<<< SET` markers need your values.

---

## 0. Prerequisites

- **Servers:** 1 small VPS for the panel (~2 GB RAM, Docker) + at least 1 VPS as a
  traffic node. Your existing VPS boxes become nodes. Panel and one node can share a
  host to start. Use non-RF hosting without RF ownership (NL / FI / DE).
- **Domains:** two A-records → panel VPS, e.g. `panel.example.com` (admin UI) and
  `sub.example.com` (client subscription page).
- **Telegram:** a bot token from @BotFather (a new bot, or reuse the fodders bot),
  and your numeric Telegram id (get it from @userinfobot).
- **Local:** Docker + Docker Compose on every VPS.

Everything below runs on the VPS over SSH. Nothing here needs your Windows machine.

---

## 1. Panel

```bash
sudo mkdir -p /opt/remnawave && cd /opt/remnawave
# copy the three files from this repo's deploy/remnawave/ onto the VPS:
#   docker-compose.yml, panel.env.example, subpage.env.example
cp panel.env.example .env
cp subpage.env.example subpage.env

# generate secrets and paste them into .env
bash /path/to/deploy/scripts/gen-secrets.sh

# edit .env:  PANEL_DOMAIN, SUB_PUBLIC_DOMAIN, the JWT_* / POSTGRES_PASSWORD /
#             DATABASE_URL from gen-secrets.sh
nano .env

docker compose up -d && docker compose logs -f -t
```

### Reverse proxy (required — panel binds 127.0.0.1 only)

```bash
sudo apt-get install -y caddy   # or your distro's Caddy install
sudo cp /path/to/deploy/remnawave/Caddyfile.example /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile  # replace panel.example.com / sub.example.com
sudo systemctl reload caddy
```

Open `https://panel.example.com`. The **first account you register becomes the
superadmin** — register it now and use a strong password.

---

## 2. Remnawave entitlement profile + squad

The squad is still Bedolaga's source of subscription state. Its Reality output is
legacy and must not be shown as the working VPN path; `/awg` and `/family` issue the
actual client profiles.

In the panel UI:

1. **Config Profiles** → create a profile and paste the ready-made
   [`deploy/remnawave/config-profile-vless-reality.json`](deploy/remnawave/config-profile-vless-reality.json).
   Generate a Reality key, set your SNI/`target`, swap the example shortId — full
   steps in [`deploy/remnawave/reality-setup.md`](deploy/remnawave/reality-setup.md).
   This is the protocol clients actually use (VLESS+Reality/TCP+Vision).
   - Add a **Shadowsocks-2022** inbound too if you want a second option.
2. **Internal Squads** → create a squad (e.g. `paid`). Attach the profile's
   inbound(s) to it. A squad = "which servers this group of users can reach".
3. Copy the **squad UUID** — Bedolaga needs it (`SIMPLE_SUBSCRIPTION_SQUAD_UUID`).
4. **Settings → API Tokens** → create a token. You'll paste it into both the
   subscription page (`subpage.env`) and Bedolaga (`REMNAWAVE_API_KEY`).

> Leave the **HWID device limit OFF** for the MVP. It breaks Hiddify clients (404 on
> the sub-URL). Revisit it later only for Happ/v2RayTun users.

---

## 3. Legacy Remnawave nodes (not required for AWG delivery)

For each traffic VPS (including your existing ones): follow
[`deploy/node/README.md`](deploy/node/README.md). Short version:

1. Panel → **Nodes → Create node**, enter the VPS IP + port `2222`, copy the
   generated `SECRET_KEY`.
2. On the VPS: drop `deploy/node/docker-compose.yml`, paste the `SECRET_KEY`,
   `docker compose up -d`.
3. Open the Reality inbound (`3478/tcp`) in the firewall. Assign the node's inbounds to the
   `paid` squad. Node should show **online**.

---

## 4. Legacy Happ subscription page (not part of onboarding)

Already defined as the `remnawave-subscription-page` service in the panel
`docker-compose.yml`. Just finish its env:

```bash
cd /opt/remnawave
nano subpage.env     # set REMNAWAVE_API_TOKEN (the token from step 2)
docker compose up -d remnawave-subscription-page
```

Visit `https://sub.example.com/<some-test-subscription>` later to see the
"Install app" + "Add subscription" buttons. This is the page non-technical users
open — it deep-links into Happ / v2RayTun / Hiddify.

---

## 5. Bedolaga shop-bot (paid billing)

Follow [`deploy/bedolaga/README.md`](deploy/bedolaga/README.md). Short version:

```bash
cd /opt
git clone https://github.com/BEDOLAGA-DEV/remnawave-bedolaga-telegram-bot bedolaga
cd bedolaga && cp .env.example .env
# set the keys from deploy/bedolaga/bedolaga.env.example into .env:
#   BOT_TOKEN, ADMIN_IDS, REMNAWAVE_API_URL, REMNAWAVE_API_KEY,
#   SIMPLE_SUBSCRIPTION_SQUAD_UUID, CHANNEL_IS_REQUIRED_SUB=false,
#   TELEGRAM_STARS_ENABLED=true, PRICE_*
nano .env
docker compose up -d && docker compose logs -f
```

Then, in Telegram:

1. Open the bot, `/start` (you're admin via `ADMIN_IDS`).
2. Make the bot an admin of `@fodders_dev`, then configure the numeric channel id
   in VPN Wizard. Do not make the channel mandatory for paid Bedolaga users.
3. Run `disable_trial_tariffs.py`; a fresh account must not be offered a Bedolaga trial.

---

## 6. Smoke test (do this before inviting anyone)

- [ ] Before the NL cutover: free access is disabled and no Bedolaga trial is offered.
- [ ] After the NL cutover: fresh Telegram account → subscribe to `@fodders_dev`
      → one NL device is issued without a Remnawave trial.
- [ ] Telegram menu button / `/miniapp` → versioned `/portal/` entry; “Подключить мой VPN”
      opens the personal AWG installer and “Свой сервер” opens `/wizard/`.
- [ ] On **Android**, send `/awg`, install the official AmneziaWG app, import the
      personal `.conf` and verify that traffic flows through UDP 443.
- [ ] On **iPhone**, send `/awg`, install the official AmneziaWG app, import the
      personal `.conf` and verify that traffic flows.
- [ ] Send `/family`, open the link in an ordinary browser without Telegram,
      choose each country, and import the separate family profile.
- [ ] Confirm the owner's and family member's configs have different keys and both
      remain usable at the same time.
- [ ] Buy the 30-day plan with **Telegram Stars** → subscription extends.
- [ ] Let a test profile expire (or expire it manually) → access is **cut off**.
- [ ] Renew that profile → owner and family peers resume with their existing configs.
- [ ] `/vpn1` and `/wizard` still expose saved VPS servers, provisioning and profiles.
- [ ] Portal top switch opens Wizard; Wizard top switch and Telegram BackButton return to portal.
- [ ] Unsubscribe from the channel during a trial → trial is disabled.

BotFather's **Main Mini App** (`Open` in the bot profile and the large launch
button) is separate from the Bot API menu button. Set its Web App URL to:

```text
https://77-67-89-164.nip.io/portal/
```

When all boxes pass, you have the "paid → works, unpaid → off" loop. That's the MVP.

---

## 7. Primary RF resilience

- **AmneziaWG primary (WIRED — see [`deploy/awg-fallback/`](deploy/awg-fallback/)):**
  `vpn_wizard` now exposes an entitlement-checked AWG issue endpoint + a Remnawave
  webhook for teardown, so AWG peers are tied to the same subscription. Set the
  `VPNW_REMNAWAVE_*` / `VPNW_AWG_FALLBACK_*` env, enable the panel webhook
  (`WEBHOOK_URL=…/api/integrations/remnawave/webhook`), and put the AmneziaWG button
  first in Bedolaga. Personal profiles use
  `/api/awg/<tid>/config?token=<hmac>`. `/family` creates one separate, private
  browser link per owner at `/api/awg/family/<tid>/config?token=<family-hmac>`;
  the family peer inherits the owner's entitlement but has independent keys.
  This still needs a provisioned AWG VPS (existing `vpn_wizard` tooling) behind it.
- **Split-routing (DONE — see [`deploy/remnawave/routing/`](deploy/remnawave/routing/)):**
  RF sites (bank, Gosuslugi, Ozon, Kinopoisk) go direct, only the rest is tunneled —
  since Apr 2026 RF platforms block VPN users, and "my bank doesn't work with VPN on"
  is the #1 complaint. Install per client via panel → Subscription Settings → Templates:
  run `bash deploy/remnawave/routing/fetch-ru-templates.sh` for the maintained sing-box/
  Mihomo/Stash bundles, and/or paste `xray-json-split-ru.json` for a transparent Xray
  version. Sanity-check list is in that folder's README.
- **Second protocol:** Reality is not part of the current product. Evaluate a new
  fallback only after a real RF-network test proves it works better than AWG.
- **IP rotation:** keep spare VPS at different providers; when an ASN/subnet gets
  blocked (Hetzner AS24940 is a known case), add a fresh node and move the squad's
  inbounds. Users re-read the sub-URL automatically.

---

## Operating notes

- **Keep it invite-only.** Do not advertise the bot or list it in catalogs. ФАС
  fined a channel owner (27.01.2026) for linking to VPN-sale bots — that's this exact
  model. Growth via word-of-mouth and referrals only.
- **DB timezone is UTC** (do not change it in the panel compose). Bot TZ is
  Europe/Moscow for user-facing times.
- **Backups:** snapshot the panel `remnawave-db-data` volume and the Bedolaga
  Postgres volume. Nodes are stateless — losing one loses no accounts.
- **Payments:** Stars is the low-friction default; expect ~30–50% lost between what
  a user pays and what you withdraw. Tribute is the ruble path. Don't submit a
  YooKassa application describing "VPN" — see the strategy doc.
- Full market/legal/payment analysis: the "Fodder VPN 2 — strategy and MVP" artifact
  and `scratchpad/*.md`.
