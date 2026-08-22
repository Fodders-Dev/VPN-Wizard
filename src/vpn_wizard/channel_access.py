"""Free Netherlands access tied to Fodder's Dev channel membership."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import time
from typing import Any, Optional
from urllib import error as urllib_error, request as urllib_request
from urllib.parse import urlencode

from vpn_wizard.web_signup import is_web_account


class ChannelAccessError(RuntimeError):
    """Membership could not be checked reliably."""


@dataclass(frozen=True)
class ChannelAccessConfig:
    enabled: bool
    channel_id: str
    channel_url: str
    free_server_id: str
    web_grace_hours: int
    membership_cache_seconds: int
    bot_token: str

    @classmethod
    def from_env(cls) -> "ChannelAccessConfig":
        enabled = (os.getenv("VPNW_CHANNEL_ACCESS_ENABLED") or "").strip().lower() in {
            "1", "true", "yes", "on"
        }

        def number(name: str, fallback: int, minimum: int = 1) -> int:
            raw = (os.getenv(name) or "").strip()
            try:
                value = int(raw)
            except ValueError:
                value = fallback
            return max(minimum, value)

        return cls(
            enabled=enabled,
            channel_id=(os.getenv("VPNW_CHANNEL_ACCESS_CHANNEL_ID") or "").strip(),
            channel_url=(
                os.getenv("VPNW_CHANNEL_ACCESS_CHANNEL_URL") or "https://t.me/fodders_dev"
            ).strip(),
            free_server_id=(os.getenv("VPNW_CHANNEL_ACCESS_SERVER_ID") or "nl").strip(),
            # 0 hours means the website profile never expires: the first profile
            # is a gift, not a trial with a countdown.
            web_grace_hours=number("VPNW_CHANNEL_ACCESS_WEB_GRACE_HOURS", 12, minimum=0),
            membership_cache_seconds=number(
                "VPNW_CHANNEL_ACCESS_CACHE_SECONDS", 300, minimum=0
            ),
            bot_token=(
                os.getenv("VPNW_TELEGRAM_AUTH_TOKEN") or os.getenv("VPNW_BOT_TOKEN") or ""
            ).strip(),
        )

    @property
    def configured(self) -> bool:
        return bool(
            self.enabled
            and self.channel_id
            and self.channel_url
            and self.free_server_id
            and self.bot_token
        )


@dataclass(frozen=True)
class ChannelAccessStatus:
    configured: bool
    active: bool
    kind: Optional[str] = None
    access_id: Optional[int] = None
    telegram_id: Optional[int] = None
    grace_expires_at: Optional[int] = None
    membership_checked_at: Optional[int] = None


def telegram_channel_member(config: ChannelAccessConfig, telegram_id: int) -> bool:
    if not config.configured:
        raise ChannelAccessError("Channel access is not configured.")
    query = urlencode({"chat_id": config.channel_id, "user_id": int(telegram_id)})
    url = f"https://api.telegram.org/bot{config.bot_token}/getChatMember?{query}"
    try:
        with urllib_request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib_error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise ChannelAccessError("Telegram membership check failed.") from exc
    if not isinstance(payload, dict):
        raise ChannelAccessError("Telegram returned an invalid response.")
    result = payload.get("result")
    if not payload.get("ok") or not isinstance(result, dict):
        raise ChannelAccessError("Telegram membership check failed.")
    status = str(result.get("status") or "")
    return status in {"creator", "administrator", "member"} or (
        status == "restricted" and bool(result.get("is_member"))
    )


def access_status(
    store: Any,
    access_id: int,
    config: Optional[ChannelAccessConfig] = None,
    *,
    refresh_membership: bool = False,
    create_member: bool = False,
    now: Optional[int] = None,
) -> ChannelAccessStatus:
    """Resolve a linked member or an unlinked website grace account."""
    config = config or ChannelAccessConfig.from_env()
    stamp = int(now if now is not None else time.time())
    if not config.configured:
        return ChannelAccessStatus(configured=False, active=False)

    access_id = int(access_id)
    row = store.channel_access_get(access_id)
    if is_web_account(access_id):
        # grace_expires_at == 0 is a profile issued without a deadline.
        expires = int((row or {}).get("grace_expires_at") or 0)
        active = bool(
            row
            and row.get("status") == "active"
            and not row.get("telegram_id")
            and (expires == 0 or expires > stamp)
        )
        return ChannelAccessStatus(
            configured=True,
            active=active,
            kind="grace" if row else None,
            access_id=access_id,
            grace_expires_at=expires or None,
        )

    row = store.channel_access_by_telegram(access_id) or row
    checked = int((row or {}).get("membership_checked_at") or 0)
    cached = bool(row and checked and checked + config.membership_cache_seconds > stamp)
    if not refresh_membership and cached:
        active = bool(row.get("membership_active") and row.get("status") == "active")
        return ChannelAccessStatus(
            configured=True,
            active=active,
            kind="member",
            access_id=int(row["access_id"]),
            telegram_id=access_id,
            membership_checked_at=checked,
        )
    if not refresh_membership and row is None and not create_member:
        return ChannelAccessStatus(configured=True, active=False, telegram_id=access_id)

    member = telegram_channel_member(config, access_id)
    if member:
        row = store.channel_access_grant_member(access_id, checked_at=stamp)
    elif row is not None:
        store.channel_access_set_membership(access_id, False, checked_at=stamp)
        row = store.channel_access_by_telegram(access_id)
    return ChannelAccessStatus(
        configured=True,
        active=member,
        kind="member",
        access_id=int((row or {}).get("access_id") or access_id),
        telegram_id=access_id,
        membership_checked_at=stamp,
    )
