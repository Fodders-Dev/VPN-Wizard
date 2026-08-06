"""Reconcile retained AmneziaWG peers against Remnawave entitlements."""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable

from vpn_wizard.account import build_account_store
from vpn_wizard.awg_fallback import (
    AwgFallbackConfig,
    AwgFallbackService,
    device_owner_slot,
    family_owner_id,
)
from vpn_wizard.awg_devices import collect_usage
from vpn_wizard.bot_api import BotApiClient, subscription_facts_of
from vpn_wizard.metrics import collect as collect_metrics, daily_snapshot, day_key
from vpn_wizard.awg_servers import AwgRegistry
from vpn_wizard.remnawave import RemnawaveClient, RemnawaveConfig, device_limit_of


def reconcile_awg_peers(
    account: Any,
    remnawave: Any,
    awg: Any,
    *,
    server_services: dict[str, Any] | None = None,
    max_suspend_ratio: float = 0.5,
    legacy_server_id: str | None = None,
    trial_server_id: str | None = None,
    trial_lookup: Callable[[int], bool | None] | None = None,
) -> dict[str, Any]:
    """Bring retained AWG peers in line with Remnawave entitlements.

    A two-phase pass with a circuit breaker: entitlements are read first, then
    suspends are applied only if the panel affirmatively confirmed that some users
    ARE active. This prevents a systemic panel failure — a wrong API URL, a
    by-telegram-id route that 404s after an upgrade, a proxy returning 404, or a
    response-schema drift, all of which make ``active_user()`` return ``None`` for
    everyone — from cascading into suspending every paying customer. Ambiguity
    fails OPEN (users keep access); the real-time webhook remains the primary path.
    """
    result: dict[str, Any] = {
        "checked": 0,
        "suspended": 0,
        "resumed": 0,
        "unchanged": 0,
        "errors": [],
    }
    to_suspend: list[tuple[int, Any, str | None]] = []
    to_resume: list[tuple[int, Any, str | None]] = []
    active_seen = 0
    server_services = server_services or {}
    peers = [(peer, awg, legacy_server_id) for peer in account.awg_list_peers()]
    peers.extend(
        (peer, server_services.get(str(peer["server_id"])), str(peer["server_id"]))
        for peer in account.awg_list_server_peers()
    )
    entitlement_cache: dict[int, dict[str, Any] | None | Exception] = {}
    trial_cache: dict[int, bool | None] = {}

    for peer, service, server_id in peers:
        telegram_id = int(peer["telegram_id"])
        family_owner = family_owner_id(telegram_id)
        device_owner = device_owner_slot(telegram_id)
        entitlement_id = family_owner or (device_owner[0] if device_owner else telegram_id)
        required_slot = device_owner[1] if device_owner else (1 if family_owner is None else None)
        result["checked"] += 1
        status = str(peer.get("status") or "")
        if service is None:
            result["errors"].append(
                {
                    "telegram_id": telegram_id,
                    "server_id": server_id,
                    "error": "server_not_configured",
                }
            )
            continue
        if entitlement_id not in entitlement_cache:
            try:
                entitlement_cache[entitlement_id] = remnawave.active_user(entitlement_id)
            except Exception as exc:
                entitlement_cache[entitlement_id] = exc
        entitlement = entitlement_cache[entitlement_id]
        if isinstance(entitlement, Exception):
            # A per-peer lookup failure (network/5xx/decrypt) must never be read as
            # "not entitled" — leave the peer as-is and record it.
            error = {"telegram_id": telegram_id, "error": f"{type(entitlement).__name__}: {entitlement}"}
            if server_id is not None:
                error["server_id"] = server_id
            result["errors"].append(error)
            continue
        owner_active = entitlement is not None
        if owner_active and trial_lookup is not None and entitlement_id not in trial_cache:
            try:
                trial_cache[entitlement_id] = trial_lookup(entitlement_id)
            except Exception:
                # Billing ambiguity follows the same fail-open rule as other
                # policy lookups: never disconnect a payer during an API outage.
                trial_cache[entitlement_id] = None
        owner_trial = trial_cache.get(entitlement_id)
        location_allowed = not (
            owner_trial is True
            and trial_server_id
            and server_id != trial_server_id
        )
        peer_entitled = owner_active and (
            required_slot is None or required_slot <= device_limit_of(entitlement)
        ) and location_allowed
        if owner_active:
            active_seen += 1
        if peer_entitled:
            if status == "suspended":
                to_resume.append((telegram_id, service, server_id))
            else:
                result["unchanged"] += 1
        else:
            if status == "active":
                to_suspend.append((telegram_id, service, server_id))
            else:
                result["unchanged"] += 1

    if to_suspend:
        considered = active_seen + len(to_suspend)
        # "Nobody is active" used to count as a systemic failure, because a broken
        # panel route returned the same thing as an unentitled user. It no longer
        # does: the client raises on any HTTP error, so a peer whose lookup failed
        # is skipped and recorded above and can never reach this list. Everything
        # here got a successful answer meaning "not entitled".
        #
        # On a young service every subscriber lapsing at once is an ordinary
        # Tuesday, and treating it as an outage left expired keys working — the
        # service was given away for free and nothing said so. What remains worth
        # guarding is drift that makes almost everyone look inactive while the
        # panel still answers 200, so the ratio guard stays, but only at a scale
        # and a proportion that no honest churn reaches.
        systemic_failure = (
            considered >= 10 and len(to_suspend) / considered > max_suspend_ratio
        )
        if systemic_failure:
            result["errors"].append(
                {
                    "telegram_id": None,
                    "error": (
                        f"circuit_breaker: skipped {len(to_suspend)} suspend(s) — panel "
                        f"confirmed only {active_seen} active user(s); treating as a systemic "
                        "failure, not mass expiry"
                    ),
                }
            )
            result["skipped_suspends"] = len(to_suspend)
            to_suspend = []

    for telegram_id, service, server_id in to_resume:
        try:
            service.resume(telegram_id)
            result["resumed"] += 1
        except Exception as exc:
            error = {"telegram_id": telegram_id, "error": f"{type(exc).__name__}: {exc}"}
            if server_id is not None:
                error["server_id"] = server_id
            result["errors"].append(error)
    for telegram_id, service, server_id in to_suspend:
        try:
            service.suspend(telegram_id)
            result["suspended"] += 1
        except Exception as exc:
            error = {"telegram_id": telegram_id, "error": f"{type(exc).__name__}: {exc}"}
            if server_id is not None:
                error["server_id"] = server_id
            result["errors"].append(error)
    return result


def _read_awg_show(service: Any) -> str:
    """Ask one exit what its peers have been doing."""
    with service._ssh() as ssh:  # same credentials the service already provisions with
        return ssh.run("awg show 2>/dev/null || wg show", sudo=True, check=False, pty=False)


def refresh_usage(
    account: Any,
    legacy_service: Any,
    server_services: dict[str, Any],
    registry: Any,
    *,
    read: Any = None,
) -> int:
    """Cache last-seen/traffic for every peer, one SSH per exit."""
    read = read or _read_awg_show
    default = registry.default_server
    legacy_id = getattr(default, "id", None)
    targets: list[tuple[str | None, Any, list[dict[str, Any]]]] = [
        (legacy_id, legacy_service, account.awg_list_peers())
    ]
    for server_id, service in server_services.items():
        peers = [
            peer
            for peer in account.awg_list_server_peers()
            if str(peer.get("server_id")) == str(server_id)
        ]
        targets.append((server_id, service, peers))

    rows = 0
    for server_id, service, peers in targets:
        if not peers or service is None:
            continue
        try:
            output = read(service)
        except Exception:
            continue  # a dead exit must not stop the others being refreshed
        rows += collect_usage(account, server_id, peers, output)
    return rows


def main() -> int:
    account = build_account_store()
    legacy_config = AwgFallbackConfig.from_env()
    legacy_service = AwgFallbackService(account, legacy_config)
    server_services: dict[str, AwgFallbackService] = {}
    registry = AwgRegistry.from_env()
    default = registry.default_server
    bot = BotApiClient()
    for server in registry.servers:
        if default is not None and server.id == default.id:
            continue
        server_services[server.id] = AwgFallbackService(
            account,
            AwgFallbackConfig.from_server(server, link_secret=legacy_config.link_secret),
            server_id=server.id,
        )
    result = reconcile_awg_peers(
        account,
        RemnawaveClient(RemnawaveConfig.from_env()),
        legacy_service,
        server_services=server_services,
        legacy_server_id=getattr(default, "id", None),
        trial_server_id=(os.getenv("VPNW_AWG_TRIAL_SERVER_ID") or "").strip() or None,
        trial_lookup=(
            lambda telegram_id: (
                bool(facts["is_trial"]) if facts["known"] else None
            )
            if (facts := subscription_facts_of(bot.user_by_telegram_id(telegram_id)))
            else None
        ),
    )
    # Refresh "last seen" while we already hold SSH access to every exit. Doing it
    # here keeps it off user-facing requests, and a failure must never turn a
    # successful reconcile into a failed run.
    try:
        result["usage_rows"] = refresh_usage(account, legacy_service, server_services, registry)
    except Exception as exc:  # telemetry is a nicety; entitlements are not
        result["errors"].append({"error": "usage_refresh_failed", "detail": str(exc)})
    # One aggregate row per day, written while we are already awake. Overwriting
    # today's row means the figure is always the latest of the day.
    try:
        report = collect_metrics(
            account,
            registry,
            bot._get("/stats/full") if bot.config.configured else None,
            legacy_server_id=getattr(default, "id", None),
        )
        account.metrics_save_day(day_key(), daily_snapshot(report))
    except Exception as exc:  # history is a nicety; entitlements are not
        result["errors"].append({"error": "metrics_snapshot_failed", "detail": str(exc)})
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
