"""Thin Remnawave panel client + webhook verification.

Used by the AmneziaWG fallback: entitlement is pulled from the panel (is this
Telegram user's subscription active?), and teardown is pushed by the panel via
webhooks. This keeps AWG access tied to the same subscription Bedolaga sells,
without duplicating any billing logic here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request as _UrlRequest, urlopen

# Remnawave user lifecycle events (libs/contract/constants/events/events.ts).
ENABLE_EVENTS = frozenset({"user.created", "user.enabled", "user.traffic_reset"})
DISABLE_EVENTS = frozenset(
    {"user.disabled", "user.expired", "user.revoked", "user.limited", "user.deleted"}
)

_ACTIVE_STATUS = "ACTIVE"


def verify_webhook_signature(
    secret: str, raw_body: bytes, signature_header: Optional[str]
) -> bool:
    """Validate the ``X-Remnawave-Signature`` header.

    Remnawave signs the raw request body with HMAC-SHA256 (hex) using
    ``WEBHOOK_SECRET_HEADER`` (see backend webhook-logger.processor.ts).
    """
    if not secret or not signature_header:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header.strip())


def parse_event(raw_body: bytes) -> tuple[str, dict[str, Any]]:
    """Return ``(event_name, user_dict)`` from a webhook body."""
    payload = json.loads(raw_body.decode("utf-8"))
    event = str(payload.get("event") or "")
    data = payload.get("data")
    return event, data if isinstance(data, dict) else {}


def event_action(event: str) -> Optional[str]:
    """Map an event name to ``"enable"`` | ``"disable"`` | ``None`` (ignore)."""
    if event in ENABLE_EVENTS:
        return "enable"
    if event in DISABLE_EVENTS:
        return "disable"
    return None


def _parse_expire(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def user_is_active(user: dict[str, Any], *, now: Optional[datetime] = None) -> bool:
    """A user is entitled when status is ACTIVE and not past ``expireAt``."""
    if str(user.get("status") or "").upper() != _ACTIVE_STATUS:
        return False
    expire = _parse_expire(user.get("expireAt"))
    if expire is not None:
        now = now or datetime.now(timezone.utc)
        if expire <= now:
            return False
    return True


def telegram_id_of(user: dict[str, Any]) -> Optional[int]:
    raw = user.get("telegramId")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def device_limit_of(user: dict[str, Any], *, default: int = 1, maximum: int = 99) -> int:
    """Read the paid HWID/device limit from a Remnawave user safely.

    Missing, malformed and zero values fail closed to one device. Bedolaga syncs
    its subscription ``device_limit`` into Remnawave's ``hwidDeviceLimit``.
    """
    raw = user.get("hwidDeviceLimit")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = int(default)
    return max(1, min(value, int(maximum)))


@dataclass
class RemnawaveConfig:
    api_url: str
    api_key: str
    webhook_secret: str

    @classmethod
    def from_env(cls) -> "RemnawaveConfig":
        return cls(
            api_url=(os.getenv("VPNW_REMNAWAVE_API_URL") or "").strip().rstrip("/"),
            api_key=(os.getenv("VPNW_REMNAWAVE_API_KEY") or "").strip(),
            webhook_secret=(os.getenv("VPNW_REMNAWAVE_WEBHOOK_SECRET") or "").strip(),
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_url and self.api_key)


class RemnawaveError(RuntimeError):
    pass


class RemnawaveClient:
    def __init__(self, config: RemnawaveConfig, *, timeout: float = 10.0) -> None:
        self.config = config
        self.timeout = timeout

    def _get(self, path: str) -> Any:
        if not self.config.configured:
            raise RemnawaveError(
                "Remnawave API not configured (VPNW_REMNAWAVE_API_URL / _API_KEY)."
            )
        request = _UrlRequest(
            f"{self.config.api_url}{path}",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as resp:
                body = resp.read()
        except HTTPError as exc:
            # A 404 used to be swallowed as "this user does not exist". The panel
            # answers 200 with an empty list for an unknown user and only 404s
            # when the route itself is wrong — so conflating them made a broken
            # endpoint indistinguishable from every subscriber having expired.
            # That ambiguity is what forced reconcile to refuse to suspend anyone
            # whenever nobody was active, which in turn let lapsed keys stay live.
            raise RemnawaveError(f"Remnawave API error {exc.code} for {path}") from exc
        except URLError as exc:
            raise RemnawaveError(f"Remnawave API unreachable: {exc.reason}") from exc
        return json.loads(body.decode("utf-8"))

    def users_by_telegram_id(self, telegram_id: int) -> list[dict[str, Any]]:
        data = self._get(f"/api/users/by-telegram-id/{int(telegram_id)}")
        resp = data.get("response") if isinstance(data, dict) else data
        if isinstance(resp, list):
            return [u for u in resp if isinstance(u, dict)]
        if isinstance(resp, dict):
            return [resp]
        return []

    def active_user(
        self, telegram_id: int, *, now: Optional[datetime] = None
    ) -> Optional[dict[str, Any]]:
        """Return the first ACTIVE, non-expired user for this Telegram id, if any."""
        for user in self.users_by_telegram_id(telegram_id):
            if user_is_active(user, now=now):
                return user
        return None
