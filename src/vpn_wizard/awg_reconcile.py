"""Reconcile retained AmneziaWG peers against Remnawave entitlements."""
from __future__ import annotations

import json
import sys
from typing import Any

from vpn_wizard.account import build_account_store
from vpn_wizard.awg_fallback import AwgFallbackService
from vpn_wizard.remnawave import RemnawaveClient, RemnawaveConfig


def reconcile_awg_peers(
    account: Any, remnawave: Any, awg: Any, *, max_suspend_ratio: float = 0.5
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
    to_suspend: list[int] = []
    to_resume: list[int] = []
    active_seen = 0

    for peer in account.awg_list_peers():
        telegram_id = int(peer["telegram_id"])
        result["checked"] += 1
        status = str(peer.get("status") or "")
        try:
            entitled = remnawave.active_user(telegram_id) is not None
        except Exception as exc:
            # A per-peer lookup failure (network/5xx/decrypt) must never be read as
            # "not entitled" — leave the peer as-is and record it.
            result["errors"].append(
                {"telegram_id": telegram_id, "error": f"{type(exc).__name__}: {exc}"}
            )
            continue
        if entitled:
            active_seen += 1
            if status == "suspended":
                to_resume.append(telegram_id)
            else:
                result["unchanged"] += 1
        else:
            if status == "active":
                to_suspend.append(telegram_id)
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

    for telegram_id in to_resume:
        try:
            awg.resume(telegram_id)
            result["resumed"] += 1
        except Exception as exc:
            result["errors"].append(
                {"telegram_id": telegram_id, "error": f"{type(exc).__name__}: {exc}"}
            )
    for telegram_id in to_suspend:
        try:
            awg.suspend(telegram_id)
            result["suspended"] += 1
        except Exception as exc:
            result["errors"].append(
                {"telegram_id": telegram_id, "error": f"{type(exc).__name__}: {exc}"}
            )
    return result


def main() -> int:
    account = build_account_store()
    result = reconcile_awg_peers(
        account,
        RemnawaveClient(RemnawaveConfig.from_env()),
        AwgFallbackService(account),
    )
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
