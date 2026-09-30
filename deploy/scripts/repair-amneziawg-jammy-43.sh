#!/usr/bin/env bash
# One-off recovery for a half-installed AmneziaWG PPA on Ubuntu 5.15.0-43.
# Keeps /etc/amnezia and all client keys unchanged; no reboot is required.
set -euo pipefail

[[ $EUID == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $(uname -r) == 5.15.0-43-generic ]] || {
    echo 'This repair is only for Ubuntu kernel 5.15.0-43-generic.' >&2
    exit 1
}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=/usr/src/amneziawg-1.0.0
[[ -f $source_dir/compat/compat.h ]] || { echo 'DKMS source missing.' >&2; exit 1; }
backup_dir=$(mktemp -d /root/fodder-awg-repair.XXXXXX)
chmod 700 "$backup_dir"
cp -a "$source_dir/compat/compat.h" "$backup_dir/compat.h"
tar -czf "$backup_dir/amnezia-configs.tar.gz" -C /etc/amnezia amneziawg
chmod 600 "$backup_dir/amnezia-configs.tar.gz"
echo "Recovery backup: $backup_dir"

if ! grep -q 'Fodder repair: Ubuntu' "$source_dir/compat/compat.h"; then
    patch --dry-run -d "$source_dir" -p1 < "$script_dir/amneziawg-jammy-43-timers.patch"
    patch -d "$source_dir" -p1 < "$script_dir/amneziawg-jammy-43-timers.patch"
fi
dkms build -m amneziawg -v 1.0.0 -k "$(uname -r)"
dkms install -m amneziawg -v 1.0.0 -k "$(uname -r)"
DEBIAN_FRONTEND=noninteractive dpkg --configure amneziawg-dkms amneziawg
modprobe amneziawg
systemctl restart awg-quick@awg0
systemctl is-active awg-quick@awg0
awg show awg0
ss -lun | awk 'NR == 1 || /:3478 /'
