"""Device slots: what a subscriber has handed out, and to whom it still answers.

A subscription buys N *device slots*. Each slot is one physical device and may
hold a key on several exits at once, so the unit a person recognises ("мамин
телефон") is the slot, not the key. This module turns the raw peer rows plus
whatever the exits report into that view, and back again:

    collect_usage(...)  -> read `awg show` on one exit, cache last-seen/traffic
    list_devices(...)   -> the slots a subscriber owns, with live status
    revoke_device(...)  -> destroy a slot's keys everywhere, freeing the slot

Usage is cached rather than read per request: answering "when was this last
used" means SSH-ing every exit, which must never sit in a user-facing path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import time
from typing import Any, Callable, Iterable, Optional

from vpn_wizard.awg_fallback import (
    MAX_DEVICE_SLOT,
    device_owner_slot,
    device_peer_id,
    family_guest_id,
    family_owner_id,
)

FAMILY_SLOT = 2

# `awg show` prints one block per peer; we key on the tunnel address because it
# is the one field we also hold locally, inside the stored client config.
_PEER_BLOCK_RE = re.compile(r"^peer:\s*(\S+)", re.M)
_ADDRESS_RE = re.compile(r"^Address\s*=\s*([0-9.]+)", re.M)
_ALLOWED_IPS_RE = re.compile(r"allowed ips:\s*([0-9./]+)")
_HANDSHAKE_RE = re.compile(r"latest handshake:\s*([^\n]+)")
_TRANSFER_RE = re.compile(
    r"transfer:\s*([\d.]+)\s*(\w+)\s*received,\s*([\d.]+)\s*(\w+)\s*sent"
)

_UNITS = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
_INTERVALS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "week": 604800,
    "month": 2592000,
    "year": 31536000,
}


def _to_bytes(amount: str, unit: str) -> int:
    try:
        return int(float(amount) * _UNITS.get(unit, 1))
    except (TypeError, ValueError):
        return 0


def parse_handshake_age(text: str) -> Optional[int]:
    """Seconds since the handshake, or ``None`` when the peer never connected.

    ``awg show`` reports an English phrase ("1 day, 7 hours, 23 seconds ago"),
    not a timestamp.
    """
    value = (text or "").strip().lower()
    if not value or value.startswith("never"):
        return None
    if value in {"now", "just now"}:
        return 0
    total = 0
    for amount, unit in re.findall(r"(\d+)\s+(second|minute|hour|day|week|month|year)s?", value):
        total += int(amount) * _INTERVALS[unit]
    return total or None


def parse_awg_show(output: str) -> dict[str, dict[str, Any]]:
    """Map tunnel address -> {last_handshake_age, rx_bytes, tx_bytes}."""
    result: dict[str, dict[str, Any]] = {}
    blocks = output.split("peer: ")[1:] if "peer: " in output else []
    for block in blocks:
        allowed = _ALLOWED_IPS_RE.search(block)
        if not allowed:
            continue
        address = allowed.group(1).split("/")[0]
        handshake = _HANDSHAKE_RE.search(block)
        transfer = _TRANSFER_RE.search(block)
        result[address] = {
            "last_handshake_age": parse_handshake_age(handshake.group(1)) if handshake else None,
            "rx_bytes": _to_bytes(transfer.group(1), transfer.group(2)) if transfer else 0,
            "tx_bytes": _to_bytes(transfer.group(3), transfer.group(4)) if transfer else 0,
        }
    return result


def config_address(config_text: Optional[str]) -> Optional[str]:
    """The tunnel address a stored client config was issued with."""
    if not config_text:
        return None
    found = _ADDRESS_RE.search(config_text)
    return found.group(1) if found else None


def collect_usage(
    account: Any,
    server_id: Optional[str],
    peers: Iterable[dict[str, Any]],
    show_output: str,
    *,
    now: Optional[int] = None,
) -> int:
    """Fold one exit's ``awg show`` into the usage cache. Returns rows written."""
    stamp = int(now if now is not None else time.time())
    live = parse_awg_show(show_output)
    written = 0
    for peer in peers:
        address = config_address(peer.get("config"))
        if not address:
            continue
        stats = live.get(address)
        if stats is None:
            continue
        age = stats["last_handshake_age"]
        account.awg_record_usage(
            server_id or "",
            int(peer["telegram_id"]),
            last_handshake_at=(stamp - age) if age is not None else None,
            rx_bytes=stats["rx_bytes"],
            tx_bytes=stats["tx_bytes"],
        )
        written += 1
    return written


@dataclass
class DeviceSlot:
    slot: int
    label: str
    is_family: bool
    servers: list[str] = field(default_factory=list)
    suspended_servers: list[str] = field(default_factory=list)
    last_seen_at: Optional[int] = None
    total_bytes: int = 0

    @property
    def used(self) -> bool:
        return bool(self.servers or self.suspended_servers)

    def public(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "label": self.label,
            "family": self.is_family,
            "servers": self.servers,
            "suspended_servers": self.suspended_servers,
            "in_use": self.used,
            "last_seen_at": self.last_seen_at,
            "total_bytes": self.total_bytes,
        }


def default_label(slot: int, is_family: bool) -> str:
    if is_family:
        return "Для близкого"
    return f"Устройство {slot}"


def peer_id_for_slot(owner_telegram_id: int, slot: int) -> int:
    return device_peer_id(owner_telegram_id, slot)


def slot_of_peer(peer_id: int, owner_telegram_id: int) -> Optional[int]:
    """Which of the owner's slots this peer id is, if any."""
    peer_id = int(peer_id)
    if peer_id == int(owner_telegram_id):
        return 1
    if family_owner_id(peer_id) == int(owner_telegram_id):
        return FAMILY_SLOT
    pair = device_owner_slot(peer_id)
    if pair and pair[0] == int(owner_telegram_id):
        return pair[1]
    return None


def list_devices(
    account: Any,
    owner_telegram_id: int,
    device_limit: int,
    *,
    legacy_server_id: Optional[str] = None,
) -> list[DeviceSlot]:
    """Every slot the subscription pays for, whether or not it has been used."""
    owner_telegram_id = int(owner_telegram_id)
    limit = max(1, min(int(device_limit or 1), MAX_DEVICE_SLOT))
    labels = account.awg_get_device_labels(owner_telegram_id)

    slots: dict[int, DeviceSlot] = {}
    for slot in range(1, limit + 1):
        is_family = slot == FAMILY_SLOT
        slots[slot] = DeviceSlot(
            slot=slot,
            label=labels.get(slot) or default_label(slot, is_family),
            is_family=is_family,
        )

    rows: list[tuple[Optional[str], dict[str, Any]]] = []
    for peer in account.awg_list_peers():
        rows.append((legacy_server_id, peer))
    for peer in account.awg_list_server_peers():
        rows.append((str(peer.get("server_id")), peer))

    peer_ids: list[int] = []
    owned: list[tuple[Optional[str], dict[str, Any], int]] = []
    for server_id, peer in rows:
        slot = slot_of_peer(peer["telegram_id"], owner_telegram_id)
        if slot is None:
            continue
        owned.append((server_id, peer, slot))
        peer_ids.append(int(peer["telegram_id"]))

    usage = account.awg_get_usage(sorted(set(peer_ids))) if peer_ids else {}

    for server_id, peer, slot in owned:
        # A slot beyond the current limit still exists on disk after a downgrade;
        # show it so its owner can see (and revoke) what is still out there.
        device = slots.get(slot)
        if device is None:
            is_family = slot == FAMILY_SLOT
            device = DeviceSlot(
                slot=slot,
                label=labels.get(slot) or default_label(slot, is_family),
                is_family=is_family,
            )
            slots[slot] = device
        name = server_id or (legacy_server_id or "")
        if peer.get("status") == "active":
            device.servers.append(name)
        else:
            device.suspended_servers.append(name)
        stats = usage.get((server_id or "", int(peer["telegram_id"])))
        if stats:
            device.total_bytes += int(stats["rx_bytes"]) + int(stats["tx_bytes"])
            seen = stats["last_handshake_at"]
            if seen and (device.last_seen_at is None or seen > device.last_seen_at):
                device.last_seen_at = int(seen)

    return [slots[key] for key in sorted(slots)]


def revoke_device(
    owner_telegram_id: int,
    slot: int,
    services: Iterable[Any],
    *,
    on_error: Optional[Callable[[Any, Exception], None]] = None,
) -> int:
    """Destroy a slot's keys on every exit. Returns how many were removed.

    Revoking is deliberately permanent: the point is that a config handed to
    someone else stops working. The slot itself stays available, so the owner can
    issue a fresh key for a new device.
    """
    peer_id = peer_id_for_slot(owner_telegram_id, slot)
    removed = 0
    for service in services:
        try:
            if service.revoke(peer_id):
                removed += 1
        except Exception as exc:  # one dead exit must not block the others
            if on_error is not None:
                on_error(service, exc)
    return removed
