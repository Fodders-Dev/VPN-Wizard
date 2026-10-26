from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse


CANONICAL_API_BASE = "https://82-25-60-19.nip.io"
CANONICAL_MINIAPP_URL = f"{CANONICAL_API_BASE}/miniapp/"
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _valid_http_base_url(value: str | None) -> str | None:
    raw = (value or "").strip().rstrip("/")
    if not raw or any(ord(char) < 33 for char in raw):
        return None
    try:
        parsed = urlparse(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
        or parsed.query
        or parsed.fragment
    ):
        return None
    if "%" in hostname:
        return None
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        dns_name = hostname[:-1] if hostname.endswith(".") else hostname
        labels = dns_name.split(".")
        if (
            not dns_name
            or dns_name.endswith(".")
            or len(dns_name) > 253
            or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels)
        ):
            return None
    return raw


def resolve_public_base_url(value: str | None = None) -> str:
    """Resolve an explicit base, then the current deployment env, then legacy default."""
    for candidate in (value, os.getenv("VPNW_PUBLIC_BASE_URL")):
        normalized = _valid_http_base_url(candidate)
        if normalized:
            return normalized
    return CANONICAL_API_BASE


def resolve_public_miniapp_url(value: str | None) -> str:
    raw = _valid_http_base_url(value)
    if raw:
        return f"{raw}/"
    return f"{resolve_public_base_url(value)}/miniapp/"
