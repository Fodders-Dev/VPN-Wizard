"""Getting a VPN without Telegram.

Telegram is unreachable in Russia without a VPN, so requiring it to obtain one is
circular — the people who need the product most cannot reach the place that hands
it out. This module lets an existing subscriber mint an invite code, pass it along
by any channel (SMS, WhatsApp, in person), and lets the recipient start a trial
straight from the website.

The redeemer is registered in the billing bot with a **synthetic Telegram id** from
a reserved range. That one decision keeps everything downstream unchanged:
entitlement lookups, AWG peer ids, device slots, suspend/resume and the reconcile
pass all key on a Telegram id and neither know nor care that this one was minted
by us. When the user later reaches Telegram for real, the accounts are merged.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import secrets
import time
from typing import Any, Optional

# Synthetic account ids live in a narrow window bounded on three sides:
#   * above real Telegram ids (~10^10 today) so they can never collide;
#   * at or below MAX_DEVICE_OWNER_ID, the ceiling the device/family peer-id
#     arithmetic in awg_fallback validates against;
#   * far below 2^53, because Remnawave is a Node service and JSON numbers there
#     are float64 — an id past that limit comes back rounded (…847 was stored as
#     …848) and every later lookup by id silently finds nothing.
JS_MAX_SAFE_INTEGER = 9_007_199_254_740_991
WEB_ACCOUNT_ID_BASE = 900_000_000_000
WEB_ACCOUNT_ID_MAX = 999_999_999_999

# No look-alike characters: these codes get read aloud and retyped from SMS.
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_RE = re.compile(r"^[A-Z2-9]{4}-[A-Z2-9]{4}$")

DEFAULT_MAX_OUTSTANDING = 3
DEFAULT_INVITE_TTL_DAYS = 14
DEFAULT_TRIAL_DAYS = 7


class InviteError(RuntimeError):
    """Raised with a message meant to be shown to a person."""


def generate_code() -> str:
    body = "".join(secrets.choice(_ALPHABET) for _ in range(8))
    return f"{body[:4]}-{body[4:]}"


def normalize_code(raw: str) -> Optional[str]:
    """Accept what a human actually types: lowercase, spaces, missing dash."""
    cleaned = re.sub(r"[^A-Za-z0-9]", "", str(raw or "")).upper()
    if len(cleaned) != 8:
        return None
    candidate = f"{cleaned[:4]}-{cleaned[4:]}"
    return candidate if _CODE_RE.match(candidate) else None


def is_web_account(telegram_id: int) -> bool:
    return WEB_ACCOUNT_ID_BASE <= int(telegram_id) <= WEB_ACCOUNT_ID_MAX


def web_account_id(seed: Optional[int] = None) -> int:
    """A unique synthetic Telegram id for someone who signed up on the website."""
    if seed is not None:
        return WEB_ACCOUNT_ID_BASE + int(seed)
    return WEB_ACCOUNT_ID_BASE + secrets.randbelow(WEB_ACCOUNT_ID_MAX - WEB_ACCOUNT_ID_BASE)


@dataclass
class InviteConfig:
    max_outstanding: int = DEFAULT_MAX_OUTSTANDING
    ttl_days: int = DEFAULT_INVITE_TTL_DAYS
    trial_days: int = DEFAULT_TRIAL_DAYS

    @classmethod
    def from_env(cls) -> "InviteConfig":
        def _int(name: str, fallback: int) -> int:
            raw = (os.getenv(name) or "").strip()
            return int(raw) if raw.isdigit() else fallback

        return cls(
            max_outstanding=_int("VPNW_INVITE_MAX_OUTSTANDING", DEFAULT_MAX_OUTSTANDING),
            ttl_days=_int("VPNW_INVITE_TTL_DAYS", DEFAULT_INVITE_TTL_DAYS),
            trial_days=_int("VPNW_WEB_TRIAL_DAYS", DEFAULT_TRIAL_DAYS),
        )


def outstanding_invites(account: Any, issuer_telegram_id: int, *, now: Optional[int] = None) -> list[dict[str, Any]]:
    """Invites that could still be redeemed — unused and not expired."""
    stamp = int(now if now is not None else time.time())
    return [
        invite
        for invite in account.invite_list(issuer_telegram_id)
        if not invite.get("used_at") and (not invite.get("expires_at") or invite["expires_at"] > stamp)
    ]


def create_invite(
    account: Any,
    issuer_telegram_id: int,
    config: Optional[InviteConfig] = None,
    *,
    note: Optional[str] = None,
    now: Optional[int] = None,
) -> dict[str, Any]:
    """Mint one invite, capped so a subscription cannot become a trial factory."""
    config = config or InviteConfig()
    stamp = int(now if now is not None else time.time())
    live = outstanding_invites(account, issuer_telegram_id, now=stamp)
    if len(live) >= config.max_outstanding:
        raise InviteError(
            f"Уже есть {len(live)} неиспользованных приглашений — "
            "дождитесь, пока их активируют, или удалите лишние."
        )
    expires_at = stamp + config.ttl_days * 86400 if config.ttl_days else None
    for _ in range(5):  # collisions are vanishingly rare; retry rather than crash
        code = generate_code()
        if account.invite_get(code) is None:
            account.invite_create(code, issuer_telegram_id, expires_at=expires_at, note=note)
            return {"code": code, "expires_at": expires_at}
    raise InviteError("Не удалось создать код, попробуйте ещё раз.")


def check_invite(account: Any, raw_code: str, *, now: Optional[int] = None) -> dict[str, Any]:
    """Validate a typed code, saying precisely why it is unusable."""
    stamp = int(now if now is not None else time.time())
    code = normalize_code(raw_code)
    if code is None:
        raise InviteError("Код должен быть из 8 символов, например ABCD-2345.")
    invite = account.invite_get(code)
    if invite is None:
        raise InviteError("Такого приглашения не существует. Проверьте код.")
    if invite.get("used_at"):
        raise InviteError("Это приглашение уже активировано — попросите новое.")
    if invite.get("expires_at") and invite["expires_at"] <= stamp:
        raise InviteError("Срок приглашения истёк — попросите новое.")
    return invite
