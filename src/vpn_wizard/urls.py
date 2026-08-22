from __future__ import annotations

from urllib.parse import urlparse


CANONICAL_API_BASE = "https://77-67-89-164.nip.io"
CANONICAL_MINIAPP_URL = f"{CANONICAL_API_BASE}/miniapp/"


def resolve_public_base_url(value: str | None) -> str:
    raw = (value or "").strip().rstrip("/")
    if not raw:
        return CANONICAL_API_BASE
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return CANONICAL_API_BASE
    return raw


def resolve_public_miniapp_url(value: str | None) -> str:
    raw = (value or "").strip().rstrip("/")
    if raw:
        parsed = urlparse(raw)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return f"{raw}/"
    return f"{resolve_public_base_url(value)}/miniapp/"
