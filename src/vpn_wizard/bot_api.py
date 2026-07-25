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

    def user_by_telegram_id(self, telegram_id: int) -> Optional[dict[str, Any]]:
        return self._get(f"/users/by-telegram-id/{int(telegram_id)}")

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
