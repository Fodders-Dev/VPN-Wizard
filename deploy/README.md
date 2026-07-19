# deploy/

Two things live here now:

- **`vpn-wizard.*`** — deployment for the existing self-host hub bot (systemd, Caddy,
  git-autodeploy). Unchanged.
- **`remnawave/`, `node/`, `bedolaga/`, `scripts/`** — the **Fodder VPN 2** managed
  subscription stack. Start with [`../RUNBOOK-managed.md`](../RUNBOOK-managed.md).

## Managed stack at a glance

```
                       ┌─────────────────────────────┐
   Telegram user ────► │  Bedolaga bot (billing,      │  sells plans, 14-day trial
                       │  trial-for-channel, reminders)│  for @fodders_dev, Stars
                       └──────────────┬──────────────┘
                                      │ Remnawave API
                       ┌──────────────▼──────────────┐
   sub.example.com ◄── │  Remnawave PANEL  (users,    │  expire dates, auto-disable,
   (install buttons,   │  squads, sub-page)  panel VPS │  live sub-URL, API tokens
    deep-links)        └──────────────┬──────────────┘
                                      │ node protocol (:2222)
                    ┌─────────────────┼─────────────────┐
              ┌─────▼─────┐     ┌─────▼─────┐      ┌─────▼─────┐
              │  node 1   │     │  node 2   │  …   │  node N   │  Xray: VLESS+Reality
              │ (your VPS)│     │ (your VPS)│      │           │  / SS2022, port 443
              └───────────┘     └───────────┘      └───────────┘
```

| Folder        | Runs on        | Copy to        | Purpose                              |
|---------------|----------------|----------------|--------------------------------------|
| `remnawave/`  | panel VPS      | `/opt/remnawave` | panel + db + redis + sub-page; Reality config profile |
| `node/`       | each traffic VPS | `/opt/remnanode` | Xray traffic node                  |
| `bedolaga/`   | panel VPS (or its own) | cloned repo | shop-bot: billing, trial, reminders |
| `awg-fallback/` | vpn_wizard API | — (env + docs) | AmneziaWG tied to the Remnawave subscription |
| `scripts/`    | panel VPS      | —              | `gen-secrets.sh`                     |

Files with `<<< SET` markers need real values before you `docker compose up`.
When protecting dotfiles in Caddy, use
[`remnawave/fodder-vpn-subpage.caddy`](remnawave/fodder-vpn-subpage.caddy):
Remnawave's authenticated UI config intentionally lives at
`/assets/.app-config-v2.json` and must not be caught by a blanket dotfile deny rule.

## What stays from the old stack

The old `vpn_wizard` (per-user SSH provisioning of AmneziaWG / ShadowTLS+SS2022 /
VLESS) is not thrown away — in the managed model it becomes the **AmneziaWG fallback
layer** (RUNBOOK-managed.md step 7), since no panel manages AmneziaWG.
