# Maintenance — 2026-11-02 (Europe/Moscow)

## USA disk cleanup

USA 147.45.125.36 root filesystem grew from 143 MiB free (99% used) to
1.1 GiB free (88% used). Cleaned apt package cache and regenerable apt lists,
rotated btmp.1, 80 MiB of archived journals, and the abandoned
/var/tmp/mkinitramfs_EeHkb3 workspace from October 15 after verifying no apt,
dpkg or mkinitramfs process was running. Retained installed kernels, current
VPN configuration and running containers. awg-quick@awg0 remained active;
remnanode remained up with two weeks of uptime.

## NL address replacement

Ran Set-VpnServerIp.ps1 nl 151.243.212.136. Existing SSH/AWG identities and
runtime interfaces verified. Updated 266 persisted profiles, six configuration
files, one SQLite row and two Remnawave rows. HTTPS/catalog returned 200;
Telegram menu URLs updated. Controller backup: change-nl-ip-7a5a6l_m.

The migration initially moved the website shortcut to NL by mistake. It was
restored to the RU public host: https://fodders.ru/vpn/ resolves to
https://77-91-113-109.nip.io/connect/join.html (verified HTTP 200).
The Windows launcher now pins the public website to the RU host independently
of the changing NL VPN address.
Public history JSON and repository seed date NL to 2026-11-02.

BotFather continues to use setdomain 77-91-113-109.nip.io and Main App URL
https://77-91-113-109.nip.io/portal/. Existing imported client profiles
require an Endpoint edit preserving the port, or downloading/importing the
refreshed profile.
