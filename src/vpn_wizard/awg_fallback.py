"""AmneziaWG fallback tied to a Remnawave subscription.

Remnawave/Bedolaga manage the paid VLESS product. AmneziaWG is not manageable by
any panel, so it lives here as a "premium stability" layer on a dedicated AWG VPS
that this service provisions over SSH:

    issue(tid)   -> caller confirms an active subscription, then we add (or reuse)
                    an AWG peer named ``sub-<telegram_id>`` and return its config.
    suspend(tid) -> called when the subscription becomes inactive; removes the
                    public key from awg0 but retains the same client config.
    resume(tid)  -> puts that public key back when the subscription is renewed.

The peer config is stored encrypted. A renewal therefore restores the old peer and
the user's already-imported config starts working again. Provisioning operations are
injectable so the logic is unit-testable without SSH.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Optional

from vpn_wizard.core import SSHConfig, SSHRunner, WireGuardProvisioner


_SERVER_ID_RE = re.compile(r"[^a-z0-9-]")
DEVICE_PEER_ID_OFFSET = 3_000_000_000_000_000
FAMILY_GUEST_ID_OFFSET = 4_000_000_000_000_000
_MAX_FAMILY_OWNER_ID = 999_999_999_999
MAX_DEVICE_SLOT = 99


def peer_name(telegram_id: int, server_id: Optional[str] = None) -> str:
    """Deterministic peer name. Matches core's ``^[a-zA-Z0-9_-]{1,32}$``."""
    base = f"sub-{int(telegram_id)}"
    if not server_id:
        return base
    clean = _SERVER_ID_RE.sub("", str(server_id).strip().lower())[:16]
    candidate = f"{base}-{clean}" if clean else base
    if len(candidate) <= 32:
        return candidate
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:6]
    return f"{candidate[:25]}-{digest}"


def issue_token(secret: str, telegram_id: int) -> str:
    """Signed token for the per-user AWG link, so ids can't be enumerated.

    Bedolaga (or any bot) builds the link as:
        https://<vpnwizard>/api/awg/<tid>/config?token=<issue_token>
    where token = HMAC-SHA256(str(tid), VPNW_AWG_LINK_SECRET) in hex.
    """
    return hmac.new(secret.encode("utf-8"), str(int(telegram_id)).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_issue_token(secret: str, telegram_id: int, token: Optional[str]) -> bool:
    if not secret or not token:
        return False
    return hmac.compare_digest(issue_token(secret, telegram_id), token.strip())


def device_peer_id(owner_telegram_id: int, slot: int) -> int:
    """Stable peer id for one paid device slot.

    Slot 1 deliberately remains the Telegram id used by all profiles already in
    production. Extra slots use a reversible synthetic range, so every device has
    independent WireGuard keys without adding another account or database table.
    """
    owner = int(owner_telegram_id)
    slot = int(slot)
    if owner <= 0 or owner > _MAX_FAMILY_OWNER_ID:
        raise ValueError("Invalid device owner Telegram id.")
    if slot < 1 or slot > MAX_DEVICE_SLOT:
        raise ValueError(f"Device slot must be between 1 and {MAX_DEVICE_SLOT}.")
    if slot == 1:
        return owner
    # The shareable no-Telegram family link is the paid second device, not a
    # hidden free peer. Both owner and relative therefore receive the same slot-2
    # config and can never exceed the subscription's device allowance.
    if slot == 2:
        return FAMILY_GUEST_ID_OFFSET + owner
    return DEVICE_PEER_ID_OFFSET + owner * 100 + slot


def device_owner_slot(peer_id: int) -> Optional[tuple[int, int]]:
    """Map an extra-device synthetic peer back to ``(owner, slot)``."""
    family_owner = int(peer_id) - FAMILY_GUEST_ID_OFFSET
    if 0 < family_owner <= _MAX_FAMILY_OWNER_ID:
        return family_owner, 2
    encoded = int(peer_id) - DEVICE_PEER_ID_OFFSET
    if encoded <= 0:
        return None
    owner, slot = divmod(encoded, 100)
    if 0 < owner <= _MAX_FAMILY_OWNER_ID and 2 <= slot <= MAX_DEVICE_SLOT:
        return owner, slot
    return None


def family_guest_id(owner_telegram_id: int) -> int:
    """Stable peer id for the owner's single family slot.

    It intentionally lives far outside Telegram's id range, so the guest gets
    independent AWG keys without pretending to be another Telegram account.
    """
    owner = int(owner_telegram_id)
    if owner <= 0 or owner > _MAX_FAMILY_OWNER_ID:
        raise ValueError("Invalid family owner Telegram id.")
    return FAMILY_GUEST_ID_OFFSET + owner


def family_owner_id(peer_id: int) -> Optional[int]:
    """Map a synthetic family peer back to the paying Telegram account."""
    value = int(peer_id) - FAMILY_GUEST_ID_OFFSET
    if 0 < value <= _MAX_FAMILY_OWNER_ID:
        return value
    return None


def family_issue_token(secret: str, owner_telegram_id: int) -> str:
    """Sign the one-family-slot link separately from the owner's own link."""
    message = f"family:{int(owner_telegram_id)}"
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_family_issue_token(
    secret: str,
    owner_telegram_id: int,
    token: Optional[str],
) -> bool:
    if not secret or not token:
        return False
    try:
        expected = family_issue_token(secret, owner_telegram_id)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, token.strip())


@dataclass
class AwgFallbackConfig:
    host: str
    user: str
    port: int
    password: Optional[str]
    key_path: Optional[str]
    key_content: Optional[str]
    listen_port: Optional[int]
    link_secret: str

    @classmethod
    def from_env(cls) -> "AwgFallbackConfig":
        def _int(name: str) -> Optional[int]:
            raw = (os.getenv(name) or "").strip()
            return int(raw) if raw.isdigit() else None

        return cls(
            host=(os.getenv("VPNW_AWG_FALLBACK_HOST") or "").strip(),
            user=(os.getenv("VPNW_AWG_FALLBACK_SSH_USER") or "root").strip(),
            port=_int("VPNW_AWG_FALLBACK_SSH_PORT") or 22,
            password=(os.getenv("VPNW_AWG_FALLBACK_SSH_PASSWORD") or "").strip() or None,
            key_path=(os.getenv("VPNW_AWG_FALLBACK_SSH_KEY") or "").strip() or None,
            key_content=(os.getenv("VPNW_AWG_FALLBACK_SSH_KEY_CONTENT") or "").strip() or None,
            listen_port=_int("VPNW_AWG_FALLBACK_LISTEN_PORT"),
            link_secret=(os.getenv("VPNW_AWG_LINK_SECRET") or "").strip(),
        )

    @classmethod
    def from_server(cls, server: Any, *, link_secret: str) -> "AwgFallbackConfig":
        """Build a provisioning config from one registry entry."""
        return cls(
            host=str(server.host),
            user=str(server.user),
            port=int(server.port),
            password=server.password,
            key_path=server.key_path,
            key_content=server.key_content,
            listen_port=server.listen_port,
            link_secret=link_secret,
        )

    @property
    def configured(self) -> bool:
        return bool(self.host and (self.password or self.key_path or self.key_content))


class AwgFallbackService:
    """Provision/tear down AWG peers, mapped to Telegram ids in the account store."""

    def __init__(
        self,
        account: Any,
        config: Optional[AwgFallbackConfig] = None,
        *,
        server_id: Optional[str] = None,
        provision: Optional[Callable[[str], str]] = None,
        deprovision: Optional[Callable[[str], bool]] = None,
        suspend: Optional[Callable[[str], bool]] = None,
        resume: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.account = account
        self.config = config or AwgFallbackConfig.from_env()
        self.server_id = str(server_id) if server_id else None
        self._provision = provision or self._ssh_provision
        self._deprovision = deprovision or self._ssh_deprovision
        self._suspend = suspend or self._ssh_suspend
        self._resume = resume or self._ssh_resume

    # --- public API -------------------------------------------------------
    def _get_peer(self, telegram_id: int) -> Optional[dict[str, Any]]:
        if self.server_id is None:
            return self.account.awg_get_peer(telegram_id)
        return self.account.awg_get_server_peer(telegram_id, self.server_id)

    def _save_peer(
        self,
        telegram_id: int,
        *,
        client_name: str,
        remnawave_uuid: Optional[str],
        config: Optional[str],
        status: str,
    ) -> dict[str, Any]:
        kwargs = {
            "client_name": client_name,
            "remnawave_uuid": remnawave_uuid,
            "config": config,
            "status": status,
        }
        if self.server_id is None:
            return self.account.awg_save_peer(telegram_id, **kwargs)
        return self.account.awg_save_server_peer(telegram_id, self.server_id, **kwargs)

    def _set_status(self, telegram_id: int, status: str) -> None:
        if self.server_id is None:
            self.account.awg_set_status(telegram_id, status)
        else:
            self.account.awg_set_server_status(telegram_id, self.server_id, status)

    def _delete_peer(self, telegram_id: int) -> bool:
        if self.server_id is None:
            return self.account.awg_delete_peer(telegram_id)
        return self.account.awg_delete_server_peer(telegram_id, self.server_id)

    def issue(self, telegram_id: int, *, remnawave_uuid: Optional[str] = None) -> dict[str, Any]:
        """Return an AWG config for this user, provisioning the peer on first use.

        The caller MUST have already confirmed an active subscription.
        """
        telegram_id = int(telegram_id)
        existing = self._get_peer(telegram_id)
        if existing and existing.get("status") == "active" and existing.get("config"):
            return {"config": existing["config"], "client_name": existing["client_name"], "reused": True}
        if existing and existing.get("status") == "suspended" and existing.get("config"):
            if not self._resume(existing["client_name"]):
                raise RuntimeError("Suspended AWG peer could not be restored.")
            self._save_peer(
                telegram_id,
                client_name=existing["client_name"],
                remnawave_uuid=remnawave_uuid or existing.get("remnawave_uuid"),
                config=existing["config"],
                status="active",
            )
            return {
                "config": existing["config"],
                "client_name": existing["client_name"],
                "reused": True,
                "resumed": True,
            }

        name = peer_name(telegram_id, self.server_id)
        config_text = self._provision(name)
        self._save_peer(
            telegram_id,
            client_name=name,
            remnawave_uuid=remnawave_uuid,
            config=config_text,
            status="active",
        )
        return {"config": config_text, "client_name": name, "reused": False}

    def suspend(self, telegram_id: int) -> bool:
        """Disable access while retaining the peer keys and encrypted config."""
        telegram_id = int(telegram_id)
        existing = self._get_peer(telegram_id)
        if not existing:
            return False
        if existing.get("status") == "suspended":
            return True
        self._suspend(existing["client_name"])
        self._set_status(telegram_id, "suspended")
        return True

    def resume(self, telegram_id: int) -> bool:
        """Re-enable a retained peer so the existing client config works again."""
        telegram_id = int(telegram_id)
        existing = self._get_peer(telegram_id)
        if not existing:
            return False
        if existing.get("status") == "active":
            return True
        if not self._resume(existing["client_name"]):
            raise RuntimeError("Suspended AWG peer could not be restored.")
        self._set_status(telegram_id, "active")
        return True

    def revoke(self, telegram_id: int) -> bool:
        """Permanently remove the AWG peer and its stored config."""
        telegram_id = int(telegram_id)
        existing = self._get_peer(telegram_id)
        if not existing:
            return False
        try:
            self._deprovision(existing["client_name"])
        finally:
            self._delete_peer(telegram_id)
        return True

    # --- default SSH-backed provisioning ---------------------------------
    @contextmanager
    def _ssh(self):
        temp_key: Optional[Path] = None
        key_path = self.config.key_path
        if self.config.key_content:
            handle = tempfile.NamedTemporaryFile("w", suffix=".key", delete=False)
            handle.write(self.config.key_content)
            handle.close()
            os.chmod(handle.name, 0o600)
            temp_key = Path(handle.name)
            key_path = str(temp_key)
        cfg = SSHConfig(
            host=self.config.host,
            user=self.config.user,
            port=self.config.port,
            password=self.config.password,
            key_path=key_path,
        )
        try:
            with SSHRunner(cfg) as ssh:
                yield ssh
        finally:
            if temp_key is not None:
                temp_key.unlink(missing_ok=True)

    def _provisioner(self, ssh: Any) -> WireGuardProvisioner:
        if self.config.listen_port:
            return WireGuardProvisioner(ssh, listen_port=self.config.listen_port)
        return WireGuardProvisioner(ssh)

    def _ssh_provision(self, name: str) -> str:
        with self._ssh() as ssh:
            result = self._provisioner(ssh).add_client(client_name=name)
        return result["config"]

    def _ssh_deprovision(self, name: str) -> bool:
        with self._ssh() as ssh:
            return self._provisioner(ssh).remove_client(name)

    def _ssh_suspend(self, name: str) -> bool:
        with self._ssh() as ssh:
            return self._provisioner(ssh).suspend_client(name)

    def _ssh_resume(self, name: str) -> bool:
        with self._ssh() as ssh:
            return self._provisioner(ssh).resume_client(name)
