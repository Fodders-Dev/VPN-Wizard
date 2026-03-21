from __future__ import annotations

from urllib.parse import urlparse


CANONICAL_API_BASE = "https://vpn-wizard-production.up.railway.app"
CANONICAL_MINIAPP_URL = f"{CANONICAL_API_BASE}/miniapp/"


def resolve_public_miniapp_url(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return CANONICAL_MINIAPP_URL
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return CANONICAL_MINIAPP_URL
    return raw
