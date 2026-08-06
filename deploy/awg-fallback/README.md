# AmneziaWG fallback (tied to the Remnawave subscription)

The paid product runs on Remnawave (VLESS+Reality). AmneziaWG is the **"premium
stability"** layer for users whose Reality gets throttled — no panel manages AWG, so
`vpn_wizard` provisions it on a dedicated AWG VPS and keeps it tied to the *same*
subscription Bedolaga sells:

```
   user taps an exit country in Bedolaga
        │  signed link:  /api/awg/<tid>/config?token=<hmac>&server=<id>
        ▼
   vpn_wizard  ──(1) pull: is <tid>'s subscription ACTIVE?──►  Remnawave API
        │                                                      (/api/users/by-telegram-id)
        │  yes → add/reuse AWG peer "sub-<tid>-<server>" over SSH, return .conf + QR
        ▼
   selected AWG VPS  (NL / FI / FR / TR / US)

   Remnawave ──(2) push: user.disabled / user.expired / user.revoked──►  vpn_wizard
                     POST /api/integrations/remnawave/webhook (HMAC-signed)
                     → suspends that user's peers on every installed exit, retaining keys

   systemd timer ──(3) every 2 minutes re-checks all retained peers
                     → repairs missed disable/enable webhooks
```

Pull on issue, webhook push plus periodic reconciliation — belt and suspenders. No
billing logic is duplicated; entitlement always comes from Remnawave.

## Prerequisites

1. An **AWG server** already set up with the existing tooling (`vpn_wizard` provision +
   `client add`). This service only adds/removes *peers* on it; it does not build the
   server. Point the env below at that VPS.
2. The `vpn_wizard` API server reachable over HTTPS (it already runs behind Caddy — see
   `deploy/vpn-wizard.Caddyfile`).

## Configure `vpn_wizard` (env)

```bash
# Remnawave (entitlement pull + webhook verify)
VPNW_REMNAWAVE_API_URL="https://panel.example.com"
VPNW_REMNAWAVE_API_KEY="<panel API token>"          # Settings → API Tokens
VPNW_REMNAWAVE_WEBHOOK_SECRET="<64-char a-zA-Z0-9>"  # MUST equal the panel's WEBHOOK_SECRET_HEADER

# Legacy/default AWG server. Keep this block: old links and already-imported
# default profiles continue to use its original encrypted row and private key.
VPNW_AWG_FALLBACK_HOST="203.0.113.10"
VPNW_AWG_FALLBACK_SSH_USER="root"
VPNW_AWG_FALLBACK_SSH_PORT="22"
VPNW_AWG_FALLBACK_SSH_PASSWORD="..."        # or use a key instead:
# VPNW_AWG_FALLBACK_SSH_KEY="/path/to/id_ed25519"
# VPNW_AWG_FALLBACK_SSH_KEY_CONTENT="-----BEGIN OPENSSH PRIVATE KEY-----\n..."
# VPNW_AWG_FALLBACK_LISTEN_PORT="3478"       # optional, if the AWG iface uses a non-default port

# Secret used to sign per-user AWG links (share with whatever builds the link)
VPNW_AWG_LINK_SECRET="<random string>"

# Multi-exit registry. Use one dedicated SSH key which every AWG node authorizes.
# The first/default server reuses the legacy peer table; other ids get independent
# encrypted profiles, so one Telegram user can install all countries at once.
VPNW_AWG_DEFAULT_SERVER="nl"
VPNW_AWG_SERVERS='[
  {"id":"nl","label":"Нидерланды","flag":"🇳🇱","host":"127.0.0.1","user":"root","key_path":"/etc/vpn-wizard-awg/id_ed25519","listen_port":443},
  {"id":"fi","label":"Финляндия","flag":"🇫🇮","host":"203.0.113.20","user":"root","key_path":"/etc/vpn-wizard-awg/id_ed25519","listen_port":3478},
  {"id":"fr","label":"Франция","flag":"🇫🇷","host":"203.0.113.25","user":"root","key_path":"/etc/vpn-wizard-awg/id_ed25519","listen_port":3478},
  {"id":"tr","label":"Турция","flag":"🇹🇷","host":"203.0.113.30","user":"root","key_path":"/etc/vpn-wizard-awg/id_ed25519","listen_port":3478},
  {"id":"us","label":"США","flag":"🇺🇸","host":"203.0.113.40","user":"root","key_path":"/etc/vpn-wizard-awg/id_ed25519","listen_port":3478}
]'

# Optional one-time gift for members of a Telegram channel. Membership is
# verified with getChatMember; the local state DB prevents a second claim.
# Trials can issue only the configured exit and only device slot 1.
VPNW_CHANNEL_OFFER_ENABLED=true
VPNW_CHANNEL_OFFER_KEY="fodders-dev-2026-08"
VPNW_CHANNEL_OFFER_CHANNEL_ID="-1000000000000"
VPNW_CHANNEL_OFFER_CHANNEL_URL="https://t.me/example_channel"
VPNW_CHANNEL_OFFER_DAYS=7
VPNW_CHANNEL_OFFER_TRAFFIC_GB=100
VPNW_AWG_TRIAL_SERVER_ID="fr"
```

## Turn on the Remnawave webhook (panel `.env`)

```bash
WEBHOOK_ENABLED=true
WEBHOOK_URL=https://<vpn-wizard-domain>/api/integrations/remnawave/webhook
WEBHOOK_SECRET_HEADER=<64-char a-zA-Z0-9>    # same value as VPNW_REMNAWAVE_WEBHOOK_SECRET
```

Remnawave signs each webhook body with `HMAC-SHA256` and sends it in the
`X-Remnawave-Signature` header; the endpoint rejects anything that doesn't verify.

## Add the button in Bedolaga

The compatibility handler in
`deploy/bedolaga/overrides/app/handlers/fodders_vpn1.py` registers `/awg` and the
`fodders_awg` callback. The menu configuration script adds a visible **AmneziaWG**
button for users with an active subscription. Give the Bedolaga container the same:

```
VPNW_AWG_LINK_SECRET=<same secret as vpn-wizard>
VPNW_AWG_PUBLIC_URL=https://<vpn-wizard-domain>
VPNW_AWG_PUBLIC_SERVERS='[{"id":"nl","display":"🇳🇱 Нидерланды"},{"id":"fi","display":"🇫🇮 Финляндия"},{"id":"fr","display":"🇫🇷 Франция"},{"id":"tr","display":"🇹🇷 Турция"},{"id":"us","display":"🇺🇸 США"}]'
```

The handler links to:

```
https://<vpn-wizard-domain>/api/awg/<telegram_id>/config?token=<token>&server=<id>
```

where `token = HMAC_SHA256(str(telegram_id), VPNW_AWG_LINK_SECRET)` in hex. It also
offers `/qr` and the official AmneziaWG downloads page.

## Endpoints (added to the vpn_wizard API)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/api/integrations/remnawave/webhook` | `X-Remnawave-Signature` | suspend/resume on subscription changes |
| `GET`  | `/api/awg/{telegram_id}/config` | link token + active sub | issue/reuse `.conf` |
| `GET`  | `/api/awg/{telegram_id}/qr` | link token + active sub | same config as PNG QR |
| `GET`  | `/api/awg/servers` | public labels only | list exit choices without IPs/SSH secrets |
| `POST` | `/api/portal/channel-offer/claim` | Telegram cabinet session + channel membership | claim the one-time channel gift |

## Behaviour notes

- **Lazy provisioning:** a peer is created on the first `/config` request (which
  re-checks the subscription), not eagerly for every payer. `user.enabled` webhooks
  resume an existing retained peer but don't provision a new one — issuance does.
- **Idempotent:** the default peer `sub-<tid>` and extra peers
  `sub-<tid>-<server>` are stored (Fernet-encrypted, like other secrets), so repeat
  requests return the same config without touching SSH.
- **Teardown:** on `user.disabled` / `user.expired` / `user.revoked` / `user.limited` /
  `user.deleted`, its public key is removed from the live interface but its keys and
  encrypted config are retained. A renewal restores the same peer, so the user's
  already-imported `.conf` works again.
- **Trial isolation:** when `VPNW_AWG_TRIAL_SERVER_ID` is set, both live webhooks
  and the reconciliation timer keep trial peers suspended on every other exit.
- If the AWG fallback env is not set, the endpoints return `503` and the rest of the
  product is unaffected.

Install the reconciliation fallback:

```bash
install -m 0644 deploy/awg-fallback/vpn-wizard-awg-reconcile.service /etc/systemd/system/
install -m 0644 deploy/awg-fallback/vpn-wizard-awg-reconcile.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn-wizard-awg-reconcile.timer
```

## Smoke test

```bash
# entitlement + issue (compute token first)
TID=12345
TOKEN=$(python -c "import hmac,hashlib,os;print(hmac.new(os.environ['VPNW_AWG_LINK_SECRET'].encode(),b'$TID',hashlib.sha256).hexdigest())")
curl -i "https://<vpn-wizard-domain>/api/awg/$TID/config?token=$TOKEN"   # 200 .conf if active, 403 if not

# webhook teardown (signature over the exact body)
BODY='{"event":"user.expired","data":{"telegramId":"12345"}}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$VPNW_REMNAWAVE_WEBHOOK_SECRET" -hex | awk '{print $2}')
curl -i -X POST "https://<vpn-wizard-domain>/api/integrations/remnawave/webhook" \
  -H "Content-Type: application/json" -H "X-Remnawave-Signature: $SIG" -d "$BODY"
```
