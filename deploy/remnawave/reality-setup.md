# VLESS + Reality config profile

The ready-to-paste Xray config is [`config-profile-vless-reality.json`](config-profile-vless-reality.json).
It follows Remnawave's official VLESS-TCP-Reality template (Xray `network: "raw"`,
`clients: []` — the panel injects users and the `xtls-rprx-vision` flow itself).

This is the paid product's protocol: VLESS + Reality over TCP with Vision. It has the
best client coverage in RF (Happ, v2rayNG, Streisand, Hiddify all speak it) and, as of
mid-2026, survives DPI better than plain TLS when the SNI/dest are chosen well.

---

## 1. Generate a Reality key pair

Reality needs an x25519 private key. Easiest is the panel: in the Config Profile /
inbound editor Remnawave has a **"Generate x25519"** button — use it and the private
key is filled in for you (the panel derives the public key for client links).

CLI fallback (any host with Docker):

```bash
docker run --rm ghcr.io/xtls/xray-core:latest x25519
```

Output (labels vary by Xray version):

```
PrivateKey: WABC...      <- goes into realitySettings.privateKey
Password:   xYZ...       <- this is the public key; the panel/clients use it (pbk)
```

> Older Xray prints `Private key:` / `Public key:` instead of `PrivateKey:` /
> `Password:`. Same meaning. You only paste the **private** key into the config;
> Remnawave computes the public key for the subscription links.

Generate a shortId too (even-length hex, ≤16 chars):

```bash
openssl rand -hex 8
```

Replace the example `"a1b2c3d4e5f60718"` in the JSON with your own. Keep the empty
`""` entry — it lets clients that send no shortId still connect.

---

## 2. Choose the SNI / dest (the domain you "borrow")

`target` and `serverNames` must point at a real HTTPS site. RF DPI sees this SNI, so
it has to look like normal browsing. Requirements:

- Supports **TLS 1.3 + HTTP/2** (Reality needs both).
- **Reachable from your VPS** and **not blocked inside RF** (the SNI must look
  innocuous to RF DPI).
- Prefer a plain origin site over Cloudflare/Fastly-fronted domains.
- Vary it across servers — don't put the same SNI on all your nodes.

Default in the file: `www.nvidia.com`. Other solid 2026 picks: `www.samsung.com`,
`www.tesla.com`, `gateway.icloud.com`, `www.icloud.com`. Verify one before using:

```bash
# from the VPS: should report TLS1.3 and ALPN h2
curl -sv -o /dev/null --tls-max 1.3 https://www.nvidia.com 2>&1 | grep -Ei "TLS1.3|ALPN|HTTP/2"
```

`serverNames` and `target` should use the SAME host. Keep port `443`.

---

## 3. Paste into the panel

1. Panel → **Config Profiles → Create**. Paste the JSON.
2. Replace `PASTE_XRAY_PRIVATE_KEY_HERE` (or click Generate), set your `serverNames`/
   `target`, swap the example shortId.
3. Save. Attach the `VLESS_TCP_REALITY` inbound to your **`paid` internal squad**
   (runbook step 2) and to your **node(s)** (step 3).
4. Ensure the client **flow is `xtls-rprx-vision`** (Remnawave applies this by default
   for Reality-raw; check the inbound's client settings if links don't connect).

---

## 4. Firewall

Open the inbound port on every node:

```bash
sudo ufw allow 443/tcp
```

Node port `2222` only needs to be reachable from the panel — restrict it to the panel
IP if you can.

---

## Notes

- **Split-routing (RF sites direct, not through the tunnel)** is a *client-side*
  routing concern, not this server inbound — it's configured in the subscription
  template / client profile. That's runbook step 7, and the #1 differentiator since
  RF platforms started blocking VPN users (Apr 2026).
- **Post-quantum Reality (ML-DSA-65)** exists in 2026 Xray as optional hardening, but
  not every simple client supports it yet — leave it off for the MVP to keep Happ/
  v2rayNG/Streisand working, revisit once client support is universal.
- For a second protocol, add a **Shadowsocks-2022** inbound to the same profile later;
  Hysteria2 once Xray-core support settles (watch ISPs that drop UDP).
- Switch `log.loglevel` to `"none"` for production if you want to honor "no logs".
