"""Reconcile retained AmneziaWG peers against Remnawave entitlements."""
from __future__ import annotations

import json
import sys
from typing import Any

from vpn_wizard.account import build_account_store
from vpn_wizard.awg_fallback import (
    AwgFallbackConfig,
    AwgFallbackService,
    family_owner_id,
)
from vpn_wizard.awg_servers import AwgRegistry
from vpn_wizard.remnawave import RemnawaveClient, RemnawaveConfig


def reconcile_awg_peers(
    account: Any,
    remnawave: Any,
    awg: Any,
    *,
    server_services: dict[str, Any] | None = None,
    max_suspend_ratio: float = 0.5,
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
    peers = [(peer, awg, None) for peer in account.awg_list_peers()]
    peers.extend(
        (peer, server_services.get(str(peer["server_id"])), str(peer["server_id"]))
        for peer in account.awg_list_server_peers()
    )
    entitlement_cache: dict[int, bool | Exception] = {}

    for peer, service, server_id in peers:
        telegram_id = int(peer["telegram_id"])
        entitlement_id = family_owner_id(telegram_id) or telegram_id
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
                entitlement_cache[entitlement_id] = (
                    remnawave.active_user(entitlement_id) is not None
                )
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
        if entitlement:
            active_seen += 1
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
        systemic_failure = active_seen == 0 or (
            considered >= 5 and len(to_suspend) / considered > max_suspend_ratio
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


def main() -> int:
    account = build_account_store()
    legacy_config = AwgFallbackConfig.from_env()
    legacy_service = AwgFallbackService(account, legacy_config)
    server_services: dict[str, AwgFallbackService] = {}
    registry = AwgRegistry.from_env()
    default = registry.default_server
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
    )
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
