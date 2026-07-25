"""Read-only client for the Bedolaga bot's admin API.

Referral codes live in the bot's own database, not ours, so the portal cannot
build a subscriber's personal invite link on its own. Rather than reach into
another service's Postgres, ask its API for the one field we need.

Deliberately read-only and best-effort: an invite link is a nicety, and the bot
being down must never break the portal.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any, Optional
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 4


@dataclass
class BotApiConfig:
    base_url: str
    token: str
    timeout: int = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls) -> "BotApiConfig":
        raw = (os.getenv("VPNW_BOT_API_URL") or "").strip().rstrip("/")
        return cls(
            base_url=raw,
            token=(os.getenv("VPNW_BOT_API_TOKEN") or "").strip(),
            timeout=int((os.getenv("VPNW_BOT_API_TIMEOUT") or "").strip() or DEFAULT_TIMEOUT),
        )

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.token)


class BotApiClient:
    def __init__(self, config: Optional[BotApiConfig] = None) -> None:
        self.config = config or BotApiConfig.from_env()

    def _get(self, path: str) -> Optional[dict[str, Any]]:
        if not self.config.configured:
            return None
        request = urllib.request.Request(
            f"{self.config.base_url}{path}",
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                if response.status != 200:
                    return None
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return None

    def _post(self, path: str, payload: dict[str, Any]) -> Optional[dict[str, Any]]:
        if not self.config.configured:
            return None
        request = urllib.request.Request(
            f"{self.config.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                if response.status not in (200, 201):
                    return None
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return None

    def user_by_telegram_id(self, telegram_id: int) -> Optional[dict[str, Any]]:
        return self._get(f"/users/by-telegram-id/{int(telegram_id)}")

    def create_user(
        self,
        telegram_id: int,
        *,
        first_name: str = "Гость сайта",
        referred_by_id: Optional[int] = None,
    ) -> Optional[dict[str, Any]]:
        """Register a website signup in the billing bot.

        The id is synthetic (see ``web_signup``) so the rest of the system — trials,
        AWG peers, device slots, reconcile — keeps working unchanged.
        """
        payload: dict[str, Any] = {
            "telegram_id": int(telegram_id),
            "first_name": first_name,
            "language": "ru",
        }
        if referred_by_id is not None:
            payload["referred_by_id"] = int(referred_by_id)
        return self._post("/users", payload)

    def grant_trial(
        self,
        user_id: int,
        *,
        days: int,
        device_limit: int = 1,
        traffic_limit_gb: Optional[int] = None,
    ) -> Optional[dict[str, Any]]:
        payload: dict[str, Any] = {
            "is_trial": True,
            "duration_days": int(days),
            "device_limit": int(device_limit),
        }
        if traffic_limit_gb is not None:
            payload["traffic_limit_gb"] = int(traffic_limit_gb)
        return self._post(f"/users/{int(user_id)}/subscription", payload)

    def referral_code(self, telegram_id: int) -> Optional[str]:
        user = self.user_by_telegram_id(telegram_id)
        if not user:
            return None
        code = str(user.get("referral_code") or "").strip()
        return code or None


def referral_link(bot_username: str, code: Optional[str]) -> Optional[str]:
    """The bot deep link that credits this subscriber for the newcomer."""
    username = (bot_username or "").strip().lstrip("@")
    if not username or not code:
        return None
    return f"https://t.me/{username}?start={code}"
