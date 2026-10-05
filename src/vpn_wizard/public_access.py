"""Anonymous public issuance of per-device AmneziaWG profiles.

The browser receives a signed random identity in an HttpOnly cookie and sends it
again for downloads. The token contains no account data. Peer records and
encrypted configs live in an isolated AccountStore and use the existing
``AwgFallbackService`` storage and provisioning behavior.

HTTP routes deliberately stay in ``server.py``. This module exposes the route
building blocks so applications can choose their own paths and response models.
"""
from __future__ import annotations

import base64
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from vpn_wizard.account import AccountStore
from vpn_wizard.awg_fallback import AwgFallbackConfig, AwgFallbackService
from vpn_wizard.awg_servers import AwgRegistry, apply_preset


PUBLIC_DEVICE_COOKIE = "vpnw_public_device"
PUBLIC_DEVICE_COOKIE_PATH = "/api/public/awg"
PUBLIC_DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365


def public_access_enabled() -> bool:
    """Public issuance is opt-in at deployment time."""
    raw = os.getenv("VPNW_PUBLIC_ACCESS_ENABLED")
    if raw is None:
        raw = os.getenv("VPNW_PUBLIC_AWG_ENABLED", "")
    return raw.strip().lower() in {
        "1", "true", "yes", "on"
    }


def isolated_public_account_store(account: Any) -> AccountStore:
    """Open public peer storage beside the paid database, using its key securely.

    This keeps public rows out of the paid account database scanned by reconcile.
    Only the already-loaded AccountStore object supplies the encryption secret;
    callers never need to copy it through an environment variable or log it.
    """
    path = getattr(account, "db_path", None)
    secret_key = getattr(account, "secret_key", None)
    if path is None or not secret_key:
        raise PublicAccessNotConfigured(
            "Public access needs a file-backed AccountStore with its encryption key loaded."
        )
    path = str(path)
    if path == ":memory:":
        raise PublicAccessNotConfigured("Public access needs a file-backed AccountStore.")
    store = AccountStore(
        db_path=Path(path).with_name("public-access.db"),
        secret_key=secret_key,
        auth_ttl_seconds=getattr(account, "auth_ttl_seconds", 60 * 60 * 24 * 30),
    )
    os.chmod(store.db_path, 0o600)
    return store


class PublicAccessError(Exception):
    """Base exception for expected public-access request failures."""


class InvalidDeviceToken(PublicAccessError):
    """The supplied anonymous device token is malformed or was not signed here."""


class UnknownServer(PublicAccessError):
    """The requested server does not exist in the offered server list."""


class PublicAccessNotConfigured(PublicAccessError):
    """The registry or signing secret is not ready for public issuance."""


class RateLimitExceeded(PublicAccessError):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = max(1, int(retry_after))
        super().__init__("Too many profile requests. Try again later.")


@dataclass(frozen=True)
class RateLimitPolicy:
    """Sliding-window request ceilings; profile issue calls include re-downloads."""

    window_seconds: int = 600
    per_device: int = 8
    per_ip: int = 40
    hour_seconds: int = 3600
    per_device_per_hour: int = 30
    per_ip_per_hour: int = 180
    bootstrap_per_ip: int = 60
    bootstrap_per_ip_per_hour: int = 240
    max_concurrent_provisions: int = 2


class SlidingWindowRateLimiter:
    """Small process-local limiter suitable for the current single-worker API.

    Deployments with multiple workers should share a limiter (for example Redis)
    or route public issue traffic to one worker. Keys are HMAC-like hashes, so
    raw client IPs and browser tokens are not retained even in process memory.
    """

    def __init__(
        self,
        policy: RateLimitPolicy = RateLimitPolicy(),
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self._clock = clock
        self._events: dict[tuple[str, str, int], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self.provision_slots = threading.BoundedSemaphore(
            max(1, int(policy.max_concurrent_provisions))
        )

    @staticmethod
    def _ip_key(client_ip: Optional[str]) -> str:
        raw = (client_ip or "unknown").strip()
        try:
            canonical = str(ipaddress.ip_address(raw))
        except ValueError:
            # Do not accept arbitrary proxy headers as trusted IP addresses.
            canonical = "unknown"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def check(self, *, device_key: str, client_ip: Optional[str]) -> None:
        now = self._clock()
        ip_key = self._ip_key(client_ip)
        dimensions = (
            ("device", device_key, self.policy.window_seconds, self.policy.per_device),
            ("ip", ip_key, self.policy.window_seconds, self.policy.per_ip),
            ("device", device_key, self.policy.hour_seconds, self.policy.per_device_per_hour),
            ("ip", ip_key, self.policy.hour_seconds, self.policy.per_ip_per_hour),
        )
        with self._lock:
            for kind, value, window, limit in dimensions:
                events = self._events[(kind, value, window)]
                cutoff = now - window
                while events and events[0] <= cutoff:
                    events.popleft()
                if len(events) >= limit:
                    raise RateLimitExceeded(int(events[0] + window - now) + 1)
            for kind, value, window, _limit in dimensions:
                self._events[(kind, value, window)].append(now)
            # Expired empty queues otherwise grow with each new browser identity.
            if len(self._events) > 4096:
                for key, events in tuple(self._events.items()):
                    if not events or events[-1] <= now - key[2]:
                        self._events.pop(key, None)

    def check_bootstrap(self, *, client_ip: Optional[str]) -> None:
        """Bound cheap cookie bootstrap separately from SSH profile issuance."""
        now = self._clock()
        ip_key = self._ip_key(client_ip)
        dimensions = (
            ("bootstrap-ip", ip_key, self.policy.window_seconds, self.policy.bootstrap_per_ip),
            ("bootstrap-ip", ip_key, self.policy.hour_seconds, self.policy.bootstrap_per_ip_per_hour),
        )
        with self._lock:
            for kind, value, window, limit in dimensions:
                events = self._events[(kind, value, window)]
                cutoff = now - window
                while events and events[0] <= cutoff:
                    events.popleft()
                if len(events) >= limit:
                    raise RateLimitExceeded(int(events[0] + window - now) + 1)
            for kind, value, window, _limit in dimensions:
                self._events[(kind, value, window)].append(now)
            if len(self._events) > 4096:
                for key, events in tuple(self._events.items()):
                    if not events or events[-1] <= now - key[2]:
                        self._events.pop(key, None)


class _ServerProvisionLockPool:
    """Process-wide per-server locks; idle entries are removed immediately."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._entries: dict[str, tuple[threading.RLock, int]] = {}

    @contextmanager
    def hold(self, server_id: str):
        key = str(server_id).strip().lower()
        if not key:
            raise ValueError("A server id is required for AWG provisioning.")
        with self._guard:
            lock, users = self._entries.get(key, (threading.RLock(), 0))
            self._entries[key] = (lock, users + 1)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
            with self._guard:
                current_lock, users = self._entries[key]
                if users <= 1:
                    self._entries.pop(key, None)
                else:
                    self._entries[key] = (current_lock, users - 1)

    @property
    def entry_count(self) -> int:
        with self._guard:
            return len(self._entries)


_SERVER_PROVISION_LOCKS = _ServerProvisionLockPool()


def server_provision_lock(server_id: str):
    """Lock the full AWG add-client operation for this server in this process.

    Main should use this around paid and public ``AwgFallbackService.issue``
    calls inside the same worker thread. AWG peer IP allocation reads and rewrites
    the server config, so serializing only requests from the same browser is not
    sufficient.
    """
    return _SERVER_PROVISION_LOCKS.hold(server_id)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_b64url(value: str) -> bytes:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if not value or len(value) > 128 or any(char not in alphabet for char in value):
        raise ValueError("Malformed token payload")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    # Reject alternate encodings with nonzero unused padding bits. Generated
    # cookies are canonical; an edited final character must not be accepted.
    if _b64url(decoded) != value:
        raise ValueError("Noncanonical token payload")
    return decoded


class PublicAccessService:
    """Issue anonymous profiles using an existing registry and encrypted store."""

    _TOKEN_VERSION = "v1"
    # Keep anonymous peer IDs in a separate range from Telegram and existing
    # device/family synthetic IDs, while remaining within SQLite's signed int64.
    _PEER_ID_MIN = 5_000_000_000_000_000_000
    _PEER_ID_SPAN = 3_000_000_000_000_000_000

    def __init__(
        self,
        registry: AwgRegistry,
        account: Any,
        link_secret: str,
        *,
        limiter: Optional[SlidingWindowRateLimiter] = None,
        service_factory: Optional[Callable[..., AwgFallbackService]] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        self.registry = registry
        self.link_secret = (link_secret or "").strip()
        self.enabled = public_access_enabled() if enabled is None else bool(enabled)
        self._public_ready = bool(self.enabled and self.link_secret and self.registry.offerable)
        if self._public_ready:
            # Enforce isolation here so route wiring cannot accidentally put
            # public peers into the database consumed by paid AWG reconcile.
            self.account = isolated_public_account_store(account)
            with self.account._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS public_awg_identity_peers (
                        identity_key TEXT NOT NULL,
                        server_id TEXT NOT NULL,
                        peer_id INTEGER NOT NULL UNIQUE,
                        PRIMARY KEY (identity_key, server_id)
                    )
                    """
                )
        else:
            # An opt-out deployment does not create or mutate public state.
            self.account = account
        self.limiter = limiter or SlidingWindowRateLimiter()
        self._service_factory = service_factory or AwgFallbackService

    @property
    def configured(self) -> bool:
        return self._public_ready

    def offered_servers(self) -> dict[str, Any]:
        """Return the existing sanitized registry catalog for the public picker."""
        if not self.enabled or not self.link_secret:
            raise PublicAccessNotConfigured("Public AWG access is not configured.")
        return {
            "servers": [server.public() for server in self.registry.offerable],
            "default_server": self.registry.default_server.id if self.registry.default_server else None,
        }

    def create_device_token(self) -> str:
        """Mint a random, signed browser identity without creating a profile."""
        if not self.enabled or not self.link_secret:
            raise PublicAccessNotConfigured("Public AWG access is not configured.")
        payload = _b64url(secrets.token_bytes(32))
        signed = f"{self._TOKEN_VERSION}.{payload}"
        signature = hmac.new(
            self.link_secret.encode("utf-8"),
            f"public-device:{signed}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        return f"{signed}.{_b64url(signature)}"

    def bootstrap_device(
        self,
        *,
        device_token: Optional[str],
        new_device: bool,
        client_ip: Optional[str],
    ) -> str:
        """Return the cookie value before SSH issuance so failed downloads retry.

        POST /api/public/awg/device should validate Origin, call this helper and
        send the result only through ``Set-Cookie``. ``new_device`` rotates the
        identity explicitly; otherwise a valid existing identity is preserved.
        """
        if not self.configured:
            raise PublicAccessNotConfigured("Public AWG access is not configured.")
        self.limiter.check_bootstrap(client_ip=client_ip)
        if device_token and not new_device:
            try:
                return self._device_key(device_token)[0]
            except InvalidDeviceToken:
                # Signing-key rotation/stale browser cookies must not strand
                # visitors. Old profiles remain installed; mint a new identity.
                pass
        return self.create_device_token()

    def _device_key(self, token: Optional[str]) -> tuple[str, str]:
        if not self.enabled or not self.link_secret:
            raise PublicAccessNotConfigured("Public AWG access is not configured.")
        if token is None or not token.strip():
            fresh = self.create_device_token()
            return fresh, self._device_key(fresh)[1]
        parts = token.strip().split(".")
        if len(parts) != 3 or parts[0] != self._TOKEN_VERSION:
            raise InvalidDeviceToken("Invalid anonymous device token.")
        try:
            payload = _decode_b64url(parts[1])
            signature = _decode_b64url(parts[2])
        except (ValueError, TypeError):
            raise InvalidDeviceToken("Invalid anonymous device token.") from None
        if len(payload) != 32 or len(signature) != hashlib.sha256().digest_size:
            raise InvalidDeviceToken("Invalid anonymous device token.")
        signed = f"{parts[0]}.{parts[1]}"
        expected = hmac.new(
            self.link_secret.encode("utf-8"),
            f"public-device:{signed}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, signature):
            raise InvalidDeviceToken("Invalid anonymous device token.")
        return token.strip(), hashlib.sha256(payload).hexdigest()

    def _peer_id(self, device_key: str, server_id: str) -> int:
        """Resolve a stable, collision-free peer ID in the public-only database."""
        conn = self.account._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT peer_id FROM public_awg_identity_peers WHERE identity_key=? AND server_id=?",
                (device_key, server_id),
            ).fetchone()
            if existing is not None:
                conn.commit()
                return int(existing[0])

            counter = 0
            while True:
                digest = hmac.new(
                    self.link_secret.encode("utf-8"),
                    f"public-peer:{device_key}:{server_id}:{counter}".encode("ascii"),
                    hashlib.sha256,
                ).digest()
                peer_id = self._PEER_ID_MIN + (
                    int.from_bytes(digest[:8], "big") % self._PEER_ID_SPAN
                )
                collision = conn.execute(
                    "SELECT 1 FROM public_awg_identity_peers WHERE peer_id=?",
                    (peer_id,),
                ).fetchone()
                if collision is None:
                    conn.execute(
                        "INSERT INTO public_awg_identity_peers(identity_key, server_id, peer_id) VALUES (?, ?, ?)",
                        (device_key, server_id, peer_id),
                    )
                    conn.commit()
                    return peer_id
                counter += 1
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def issue(
        self,
        *,
        device_token: str,
        client_ip: Optional[str],
        server_id: Optional[str] = None,
        preset_id: Optional[str] = None,
    ) -> "PublicProfileIssue":
        """Return a profile; a repeated valid device token reuses the same peer.

        ``bootstrap_device`` must establish the cookie before this SSH operation;
        a missing token is rejected so a failed download can be retried with the
        same identity. Supplying an unoffered server, including a registered-but-
        disabled server, is rejected.
        """
        if not self.enabled:
            raise PublicAccessNotConfigured("Public AWG access is disabled.")
        if not device_token:
            raise InvalidDeviceToken("Bootstrap the anonymous device cookie first.")
        token, device_key = self._device_key(device_token)
        self.limiter.check(device_key=device_key, client_ip=client_ip)
        if not self.registry.offerable:
            raise PublicAccessNotConfigured("No public AWG servers are available.")
        server = self.registry.get_server(server_id) if server_id else self.registry.default_server
        if server is None or server not in self.registry.offerable:
            raise UnknownServer("Unknown or unavailable AWG server.")
        preset = self.registry.get_preset(preset_id) if preset_id else None
        if preset_id and preset is None:
            raise UnknownServer("Unknown AWG profile preset.")

        # Same storage routing as server._awg_service_for: the default server
        # continues to use its legacy peer table, preserving existing storage.
        default = self.registry.default_server
        storage_server_id = None if default is not None and server.id == default.id else server.id
        config = AwgFallbackConfig.from_server(server, link_secret=self.link_secret)
        peer_id = self._peer_id(device_key, server.id)
        if not self.limiter.provision_slots.acquire(blocking=False):
            raise RateLimitExceeded(10)
        try:
            service = self._service_factory(self.account, config, server_id=storage_server_id)
            # AwgFallbackService serializes mutations across API/reconcile
            # processes with a bounded filesystem lock, after validation.
            issued = service.issue(peer_id)
        finally:
            self.limiter.provision_slots.release()
        config_text = apply_preset(issued["config"], preset)
        display = getattr(server, "display", "") or server.id
        header = f"# Fodder VPN — {display}\n# server: {server.id}\n"
        config_text = header + config_text.lstrip("\n")
        return PublicProfileIssue(
            device_cookie=token,
            server=server.public(),
            config=config_text,
            filename=f"FVPN-{server.id[:6]}.conf",
            reused=bool(issued.get("reused")),
            preset=preset.id if preset else (self.registry.presets[0].id if self.registry.presets else None),
        )


@dataclass(frozen=True)
class PublicProfileIssue:
    """Result for route code; keep ``device_cookie`` out of JSON and URLs."""

    device_cookie: str
    server: dict[str, Any]
    config: str
    filename: str
    reused: bool
    preset: Optional[str]


def set_public_device_cookie(response: Any, token: str) -> None:
    """Set the opaque identity only as a secure, HttpOnly cookie."""
    response.set_cookie(
        key=PUBLIC_DEVICE_COOKIE,
        value=token,
        max_age=PUBLIC_DEVICE_COOKIE_MAX_AGE,
        path=PUBLIC_DEVICE_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="lax",
    )


def validate_same_origin(origin: Optional[str], allowed_origins: set[str] | tuple[str, ...] | list[str]) -> bool:
    """Exact Origin allowlist check for cookie-authenticated POST routes.

    Values must be bare origins (scheme + host + optional port), configured by
    the trusted application/deployment layer. Missing, opaque, or path-bearing
    Origin values fail closed.
    """
    if not origin:
        return False
    try:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            return False
        normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    except (TypeError, ValueError):
        return False
    return normalized in {value.rstrip("/").lower() for value in allowed_origins}
