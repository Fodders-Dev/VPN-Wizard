"""Business metrics for the owner.

Three systems each hold a piece of the truth and none of them holds the piece
that matters most:

    the billing bot   knows who registered, subscribed and paid
    Remnawave        knows entitlements
    this service     knows whether anyone ever actually connected

For a VPN that last one decides everything. A dashboard that reports "3 users,
2 active subscriptions" while every key has `last_handshake = NULL` is reporting
a business that does not exist yet, so the funnel here is built around real
handshakes rather than sign-ups.

Deliberately aggregate-only: no click streams, no per-user journeys. We sell
privacy, and a per-user behaviour log would be both a broken promise and a
liability. Everything below is derived from records we already keep to run the
service.
"""
from __future__ import annotations

import datetime as dt
import os
import time
from typing import Any, Iterable, Optional

from vpn_wizard.awg_fallback import device_owner_slot, family_owner_id
from vpn_wizard.web_signup import is_web_account

DAY = 86400
ACTIVE_WINDOW = 7 * DAY


def owner_ids() -> set[int]:
    """Telegram ids allowed to read business metrics."""
    raw = (os.getenv("VPNW_OWNER_IDS") or "").replace(";", ",")
    ids: set[int] = set()
    for chunk in raw.split(","):
        cleaned = chunk.strip()
        if cleaned.isdigit():
            ids.add(int(cleaned))
    return ids


def _rate(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


def _owner_of(peer_id: int) -> int:
    """The subscriber a peer belongs to, whatever slot it is."""
    peer_id = int(peer_id)
    family = family_owner_id(peer_id)
    if family:
        return family
    pair = device_owner_slot(peer_id)
    return pair[0] if pair else peer_id


def _collect_peers(account: Any, legacy_server_id: Optional[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for peer in account.awg_list_peers():
        rows.append({**peer, "server_id": legacy_server_id or ""})
    for peer in account.awg_list_server_peers():
        rows.append({**peer, "server_id": str(peer.get("server_id") or "")})
    return rows


def connection_funnel(
    account: Any,
    legacy_server_id: Optional[str],
    *,
    paying_owners: Optional[set[int]] = None,
    now: Optional[int] = None,
) -> dict[str, Any]:
    """How far people actually get: key issued -> connected -> still using -> paid."""
    stamp = int(now if now is not None else time.time())
    peers = _collect_peers(account, legacy_server_id)
    usage = account.awg_get_usage(sorted({int(p["telegram_id"]) for p in peers})) if peers else {}

    owners_with_key: set[int] = set()
    owners_connected: set[int] = set()
    owners_active: set[int] = set()
    keys_never_used = 0

    for peer in peers:
        peer_id = int(peer["telegram_id"])
        owner = _owner_of(peer_id)
        owners_with_key.add(owner)
        stats = usage.get((peer.get("server_id") or "", peer_id)) or {}
        seen = stats.get("last_handshake_at")
        if seen:
            owners_connected.add(owner)
            if stamp - int(seen) <= ACTIVE_WINDOW:
                owners_active.add(owner)
        else:
            keys_never_used += 1

    paying = paying_owners or set()
    with_key = len(owners_with_key)
    return {
        "issued_key": with_key,
        "ever_connected": len(owners_connected),
        "active_7d": len(owners_active),
        "paying": len(paying & owners_with_key) if paying else 0,
        "connect_rate": _rate(len(owners_connected), with_key),
        "retention_rate": _rate(len(owners_active), len(owners_connected)),
        # The number to watch: keys handed out that never carried a packet.
        "keys_never_used": keys_never_used,
        "keys_total": len(peers),
    }


def usage_by_country(
    account: Any,
    registry: Any,
    legacy_server_id: Optional[str],
    *,
    now: Optional[int] = None,
) -> list[dict[str, Any]]:
    stamp = int(now if now is not None else time.time())
    peers = _collect_peers(account, legacy_server_id)
    usage = account.awg_get_usage(sorted({int(p["telegram_id"]) for p in peers})) if peers else {}

    labels = {server.id: server.display for server in getattr(registry, "servers", [])}
    enabled = {server.id: bool(getattr(server, "enabled", True)) for server in getattr(registry, "servers", [])}

    buckets: dict[str, dict[str, Any]] = {}
    for peer in peers:
        server_id = str(peer.get("server_id") or "")
        bucket = buckets.setdefault(
            server_id,
            {
                "id": server_id,
                "label": labels.get(server_id, server_id or "—"),
                "enabled": enabled.get(server_id, True),
                "keys": 0,
                "connected_keys": 0,
                "active_keys": 0,
                "bytes": 0,
            },
        )
        bucket["keys"] += 1
        stats = usage.get((server_id, int(peer["telegram_id"]))) or {}
        # Lifetime totals, not the device's current reading: that one is reset
        # every time the interface is rebuilt.
        bucket["bytes"] += int(stats.get("rx_total") or 0) + int(stats.get("tx_total") or 0)
        seen = stats.get("last_handshake_at")
        if seen:
            bucket["connected_keys"] += 1
            if stamp - int(seen) <= ACTIVE_WINDOW:
                bucket["active_keys"] += 1

    return sorted(buckets.values(), key=lambda item: (-item["active_keys"], -item["bytes"], item["id"]))


def invite_stats(account: Any, issuers: Iterable[int], *, now: Optional[int] = None) -> dict[str, Any]:
    stamp = int(now if now is not None else time.time())
    issued = redeemed = live = expired = 0
    for issuer in set(int(value) for value in issuers):
        for invite in account.invite_list(issuer):
            issued += 1
            if invite.get("used_at"):
                redeemed += 1
            elif invite.get("expires_at") and invite["expires_at"] <= stamp:
                expired += 1
            else:
                live += 1
    return {
        "issued": issued,
        "redeemed": redeemed,
        "outstanding": live,
        "expired": expired,
        "redeem_rate": _rate(redeemed, issued),
    }


def audience_split(account: Any, legacy_server_id: Optional[str]) -> dict[str, int]:
    """Where subscribers came from: Telegram, or an invite on the website."""
    owners = {_owner_of(int(peer["telegram_id"])) for peer in _collect_peers(account, legacy_server_id)}
    from_invite = sum(1 for owner in owners if is_web_account(owner))
    return {
        "total": len(owners),
        "from_invite": from_invite,
        "from_telegram": len(owners) - from_invite,
    }


def _section(payload: dict[str, Any], *path: str) -> dict[str, Any]:
    node: Any = payload
    for key in path:
        node = (node or {}).get(key) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


def business_from_bot(bot_stats: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Reshape the billing bot's own aggregates into what an owner asks about."""
    payload = bot_stats or {}
    users = _section(payload, "users")
    subs = _section(payload, "subscriptions")
    overview_users = _section(payload, "overview", "users")
    overview_pay = _section(payload, "overview", "payments")

    return {
        "users_total": int(users.get("total_users") or overview_users.get("total") or 0),
        "new_today": int(users.get("new_today") or 0),
        "new_week": int(users.get("new_week") or 0),
        "new_month": int(users.get("new_month") or 0),
        "subs_active": int(subs.get("active_subscriptions") or 0),
        "subs_trial": int(subs.get("trial_subscriptions") or 0),
        "subs_paid": int(subs.get("paid_subscriptions") or 0),
        "purchased_week": int(subs.get("purchased_week") or 0),
        "purchased_month": int(subs.get("purchased_month") or 0),
        "trial_to_paid": float(subs.get("trial_to_paid_conversion") or 0.0),
        "renewals": int(subs.get("renewals_count") or 0),
        "balance_rubles": float(overview_users.get("balance_rubles") or 0.0),
        "paid_today_rubles": float(overview_pay.get("today_rubles") or 0.0),
    }


def alerts(funnel: dict[str, Any], countries: list[dict[str, Any]], business: dict[str, Any]) -> list[dict[str, str]]:
    """The few things worth waking up for, stated plainly."""
    out: list[dict[str, str]] = []

    if funnel["issued_key"] and not funnel["ever_connected"]:
        out.append({
            "level": "critical",
            "text": "Ключи выданы, но ни один ещё не подключался — проверьте, доходит ли UDP до экзитов.",
        })
    elif funnel["keys_never_used"]:
        out.append({
            "level": "warn",
            "text": f"{funnel['keys_never_used']} выданных ключей ни разу не использовались — люди застревают на импорте.",
        })

    for country in countries:
        if country["keys"] and not country["connected_keys"]:
            state = "отключена в выборе" if not country["enabled"] else "предлагается людям"
            out.append({
                "level": "warn",
                "text": f"{country['label']}: {country['keys']} ключ(ей), ни одного подключения ({state}).",
            })

    if business["subs_active"] and not business["subs_paid"]:
        out.append({
            "level": "info",
            "text": "Платящих подписок пока нет — все на пробном периоде.",
        })
    return out


def daily_snapshot(report: dict[str, Any]) -> dict[str, Any]:
    """The handful of counts worth keeping day over day.

    Deliberately narrow: enough to answer "are we growing", nothing that could
    describe a person.
    """
    business, funnel = report["business"], report["funnel"]
    return {
        "users": business["users_total"],
        "subs_active": business["subs_active"],
        "subs_paid": business["subs_paid"],
        "issued_key": funnel["issued_key"],
        "ever_connected": funnel["ever_connected"],
        "active_7d": funnel["active_7d"],
        "traffic_bytes": report["traffic_bytes"],
        "invites_redeemed": report["invites"]["redeemed"],
    }


def day_key(now: Optional[int] = None) -> str:
    stamp = int(now if now is not None else time.time())
    return dt.datetime.fromtimestamp(stamp, dt.timezone.utc).strftime("%Y-%m-%d")


def trend(history: list[dict[str, Any]], field: str) -> dict[str, Any]:
    """Change over the recorded window, for one counter."""
    series = [int(row.get(field) or 0) for row in history]
    if not series:
        return {"series": [], "change": 0, "first": 0, "last": 0}
    return {
        "series": series,
        "first": series[0],
        "last": series[-1],
        "change": series[-1] - series[0],
    }


def collect(
    account: Any,
    registry: Any,
    bot_stats: Optional[dict[str, Any]],
    *,
    legacy_server_id: Optional[str] = None,
    paying_owners: Optional[set[int]] = None,
    history: Optional[list[dict[str, Any]]] = None,
    now: Optional[int] = None,
) -> dict[str, Any]:
    stamp = int(now if now is not None else time.time())
    business = business_from_bot(bot_stats)
    funnel = connection_funnel(
        account, legacy_server_id, paying_owners=paying_owners, now=stamp
    )
    countries = usage_by_country(account, registry, legacy_server_id, now=stamp)
    audience = audience_split(account, legacy_server_id)
    invites = invite_stats(
        account,
        [owner for owner in _owner_candidates(account, legacy_server_id)],
        now=stamp,
    )
    return {
        "ok": True,
        "generated_at": stamp,
        "bot_reachable": bot_stats is not None,
        "business": business,
        "funnel": funnel,
        "audience": audience,
        "countries": countries,
        "invites": invites,
        "traffic_bytes": sum(item["bytes"] for item in countries),
        "alerts": alerts(funnel, countries, business),
        "history": list(history or []),
    }


def _owner_candidates(account: Any, legacy_server_id: Optional[str]) -> set[int]:
    """Everyone who could have issued an invite: real Telegram subscribers."""
    owners = {_owner_of(int(peer["telegram_id"])) for peer in _collect_peers(account, legacy_server_id)}
    return {owner for owner in owners if not is_web_account(owner)} | owner_ids()
