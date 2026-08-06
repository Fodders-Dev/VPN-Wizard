# Bedolaga shop-bot (billing / storefront)

Bedolaga is the Telegram shop-bot that sits in front of Remnawave: it sells paid
subscriptions, reminds users before expiry, and disables paid exits when unpaid.
Free Netherlands access is enforced separately by VPN Wizard from channel
membership, never by a temporary Bedolaga tariff. It talks to the panel over the API.
License: MIT.

We run a pinned upstream commit and supply a tuned `.env`. The only source-tree
change on the VPS is the Compose host-port binding: the bot API is bound to
`127.0.0.1:18080`, because the existing mini-app already owns port 8080.

## Install

```bash
cd /opt
git clone https://github.com/BEDOLAGA-DEV/remnawave-bedolaga-telegram-bot bedolaga
cd bedolaga
cp .env.example .env
# open .env and set the keys listed in ../VPN-Wizard/deploy/bedolaga/bedolaga.env.example
docker compose up -d postgres redis

# Clean-database bootstrap for the current upstream migration layout.
# Migration 0001 creates the current model schema, so mark that schema as head
# instead of replaying historical ALTERs against it.
docker compose run --rm --no-deps bot alembic upgrade 0001
docker compose run --rm --no-deps bot alembic stamp head
docker compose run --rm --no-deps bot alembic check

docker compose up -d bot
docker compose logs -f bot
```

Do not use the `upgrade 0001` + `stamp head` shortcut on an existing Bedolaga
database. Existing installations must run the normal incremental migrations
after taking a database backup.

## Wire-up order (see the master runbook for detail)

1. Panel must be up and you must have created an **API token** and an **internal
   squad**. Remnawave remains the entitlement source; the working client path is AWG.
2. Put the API token in `REMNAWAVE_API_KEY` and the squad UUID in
   `SIMPLE_SUBSCRIPTION_SQUAD_UUID`.
3. For a fresh deployment, create a bot in BotFather. For the existing
   `@foddervpnbot`, use `cutover-existing-bot.sh`: it atomically transfers the
   existing token to Bedolaga, leaves the legacy API/mini-app running without a
   poller, and rolls back on failure. The legacy API receives the same secret as
   `VPNW_TELEGRAM_AUTH_TOKEN` solely to validate Mini App signatures. Never run
   two pollers on the same token.
4. Install `overrides/app/handlers/fodders_vpn1.py` and apply
   `fodders-vpn1-compat.patch` before building the image. This preserves
   the unified `/portal` entry (with `/miniapp` compatibility), the original `/vpn1` + `/wizard` self-hosted
   flow, and `/help` in the combined bot.
5. Make `@foddervpnbot` an administrator of `@fodders_dev`, then put the numeric
   channel id in VPN Wizard's `VPNW_CHANNEL_ACCESS_CHANNEL_ID`.
6. Run `scripts/disable_trial_tariffs.py` once in the bot container. It disables
   new Bedolaga trials but preserves already active trials until their original expiry.
7. Run `scripts/configure_paid_tariffs.py` in the bot container. It creates the
   fixed 1 / 3 / 5-device plans with 30 / 90 / 180 / 360-day prices. The second
   device is the no-Telegram family link; it is not an extra unbilled slot.
8. With channel access still disabled, buy a plan with Stars and confirm the paid
   loop. Enable free access only after the replacement NL IP passes the smoke test.

## Operations

- The Bedolaga PostgreSQL and Redis containers are separate from Remnawave.
- `assets/fodder-vpn-welcome.png` is the Fodder-branded Telegram message image.
  Deploy it as `/opt/bedolaga/vpn_logo.png` and recreate the bot container so the
  cached Telegram `file_id` is refreshed.
- Apply `suppress-upstream-startup-report.patch` before building. It keeps
  technical startup reports and upstream promotional buttons out of the
  owner's product chat without disabling payment/ticket admin notifications.
- `/usr/local/sbin/remnawave-backup` backs up both databases and the deployment
  configuration nightly; archives are root-only in `/var/backups/remnawave`.
- Keep the Bedolaga web API private. The public VPN Wizard API serves the unified
  portal, validates Telegram initData and issues signed AWG links.

## Gotchas

- **HWID device limit + Hiddify:** if you turn on Remnawave's HWID device limit,
  Hiddify clients get a 404 on the sub-URL (they don't send `x-hwid`). Happ and
  v2RayTun work. For the MVP, leave HWID off or only enforce it for Happ users.
- **Prices are kopeks.** Double-check every `PRICE_*` before going live.
- **Referral rewards are balance (kopeks), not bonus days** in Bedolaga. If you
  want "+7 days for a friend", configure it in the admin UI or adjust expectations.
