from __future__ import annotations

from dataclasses import dataclass
import base64
from hashlib import pbkdf2_hmac, sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Any, Optional
from urllib.parse import parse_qsl

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_AUTH_TTL_SECONDS = 60 * 60 * 24 * 30
DEFAULT_TELEGRAM_MAX_AGE_SECONDS = 60 * 60 * 24


def _now() -> int:
    return int(time.time())


def _root_dir() -> Path:
    return Path(__file__).resolve().parents[2]


def default_db_path() -> Path:
    explicit = (os.getenv("VPNW_STATE_DB") or "").strip()
    if explicit:
        return Path(explicit)
    return _root_dir() / ".vpnw" / "state.db"


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _derive_fernet(secret: str) -> Fernet:
    digest = sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def resolve_secret_key() -> str:
    value = (os.getenv("VPNW_SECRET_KEY") or "").strip()
    if value:
        return value
    raise RuntimeError("VPNW_SECRET_KEY must be configured.")


def build_account_store() -> "AccountStore":
    return AccountStore(default_db_path(), resolve_secret_key())


@dataclass
class AccountStore:
    db_path: Path
    secret_key: str
    auth_ttl_seconds: int = DEFAULT_AUTH_TTL_SECONDS

    def __post_init__(self) -> None:
        self.db_path = Path(self.db_path)
        _ensure_parent(self.db_path)
        self._fernet = _derive_fernet(self.secret_key)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    telegram_id INTEGER NOT NULL UNIQUE,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    language_code TEXT,
                    photo_url TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    pin_enabled INTEGER NOT NULL DEFAULT 0,
                    pin_hash TEXT,
                    pin_salt TEXT
                );

                CREATE TABLE IF NOT EXISTS auth_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    pin_unlocked INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS saved_servers (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    label TEXT NOT NULL,
                    host TEXT NOT NULL,
                    ssh_user TEXT NOT NULL,
                    ssh_port INTEGER NOT NULL,
                    mode TEXT,
                    listen_port INTEGER,
                    proxy_sni TEXT,
                    password_enc TEXT,
                    key_content_enc TEXT,
                    relay_host TEXT,
                    relay_ssh_user TEXT,
                    relay_ssh_port INTEGER,
                    relay_password_enc TEXT,
                    relay_key_content_enc TEXT,
                    relay_public_host TEXT,
                    relay_listen_port INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_servers_identity
                    ON saved_servers(user_id, host, ssh_user, ssh_port, COALESCE(mode, ''));

                CREATE TABLE IF NOT EXISTS awg_fallback_peers (
                    telegram_id INTEGER PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    remnawave_uuid TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    config_enc TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS awg_fallback_server_peers (
                    server_id TEXT NOT NULL,
                    telegram_id INTEGER NOT NULL,
                    client_name TEXT NOT NULL,
                    remnawave_uuid TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    config_enc TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (server_id, telegram_id)
                );

                CREATE INDEX IF NOT EXISTS idx_awg_server_peers_telegram
                    ON awg_fallback_server_peers(telegram_id);

                -- A device slot is one physical device, so its name belongs to the
                -- slot rather than to a country: renaming "Мамин телефон" once must
                -- apply to every exit that slot holds a key on.
                CREATE TABLE IF NOT EXISTS awg_device_labels (
                    owner_telegram_id INTEGER NOT NULL,
                    slot INTEGER NOT NULL,
                    label TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (owner_telegram_id, slot)
                );

                -- Invite codes: the only way to start a trial from the website.
                -- Telegram is unreachable in Russia without a VPN, so requiring it
                -- to GET a VPN is circular; an invite lets an existing subscriber
                -- hand access to someone over SMS or in person instead. Keeping it
                -- invite-only also avoids advertising a VPN publicly.
                CREATE TABLE IF NOT EXISTS web_invites (
                    code TEXT PRIMARY KEY,
                    issuer_telegram_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    used_at INTEGER,
                    used_by INTEGER,
                    note TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_web_invites_issuer
                    ON web_invites(issuer_telegram_id);

                -- Bumped when the owner revokes the family slot. It goes into the
                -- family link's signature, so a revoked link stops re-provisioning
                -- the guest instead of quietly handing the key back.
                CREATE TABLE IF NOT EXISTS awg_family_epoch (
                    owner_telegram_id INTEGER PRIMARY KEY,
                    epoch INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                );

                -- Last-seen/traffic per peer, refreshed by the reconcile pass.
                -- Cached because reading it means SSH-ing every exit, which must
                -- never happen on a user-facing request.
                CREATE TABLE IF NOT EXISTS awg_peer_usage (
                    server_id TEXT NOT NULL,
                    telegram_id INTEGER NOT NULL,
                    last_handshake_at INTEGER,
                    rx_bytes INTEGER NOT NULL DEFAULT 0,
                    tx_bytes INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (server_id, telegram_id)
                );
                """
            )
            self._ensure_saved_server_columns(conn)

    def _ensure_saved_server_columns(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute("PRAGMA table_info(saved_servers)").fetchall()
        existing = {str(row["name"]) for row in rows}
        additions = {
            "relay_host": "TEXT",
            "relay_ssh_user": "TEXT",
            "relay_ssh_port": "INTEGER",
            "relay_password_enc": "TEXT",
            "relay_key_content_enc": "TEXT",
            "relay_public_host": "TEXT",
            "relay_listen_port": "INTEGER",
        }
        for column, kind in additions.items():
            if column in existing:
                continue
            conn.execute(f"ALTER TABLE saved_servers ADD COLUMN {column} {kind}")

    def _encrypt(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        return self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def _decrypt(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        try:
            return self._fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("Could not decrypt saved server secret.") from exc

    def _clean_sessions(self, conn: sqlite3.Connection) -> None:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (_now(),))

    def upsert_user_from_telegram(self, payload: dict[str, Any]) -> dict[str, Any]:
        telegram_id = int(payload["id"])
        now = _now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM users WHERE telegram_id = ?",
                (telegram_id,),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE users
                    SET username = ?, first_name = ?, last_name = ?, language_code = ?, photo_url = ?, updated_at = ?
                    WHERE telegram_id = ?
                    """,
                    (
                        payload.get("username"),
                        payload.get("first_name"),
                        payload.get("last_name"),
                        payload.get("language_code"),
                        payload.get("photo_url"),
                        now,
                        telegram_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO users (
                        telegram_id, username, first_name, last_name, language_code, photo_url, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        telegram_id,
                        payload.get("username"),
                        payload.get("first_name"),
                        payload.get("last_name"),
                        payload.get("language_code"),
                        payload.get("photo_url"),
                        now,
                        now,
                    ),
                )
            row = conn.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)).fetchone()
            return self._serialize_user(row)

    def _serialize_user(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            raise RuntimeError("User not found.")
        return {
            "id": int(row["id"]),
            "telegram_id": int(row["telegram_id"]),
            "username": row["username"],
            "first_name": row["first_name"],
            "last_name": row["last_name"],
            "language_code": row["language_code"],
            "photo_url": row["photo_url"],
            "pin_enabled": bool(row["pin_enabled"]),
        }

    def create_auth_session(self, user_id: int) -> str:
        now = _now()
        session_id = secrets.token_urlsafe(32)
        with self._connect() as conn:
            self._clean_sessions(conn)
            row = conn.execute(
                "SELECT pin_enabled FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("User not found.")
            conn.execute(
                """
                INSERT INTO auth_sessions (session_id, user_id, created_at, expires_at, pin_unlocked)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    user_id,
                    now,
                    now + self.auth_ttl_seconds,
                    0 if bool(row["pin_enabled"]) else 1,
                ),
            )
        return session_id

    def get_auth_session(self, session_id: str) -> Optional[dict[str, Any]]:
        if not session_id:
            return None
        with self._connect() as conn:
            self._clean_sessions(conn)
            row = conn.execute(
                """
                SELECT auth_sessions.session_id, auth_sessions.user_id, auth_sessions.pin_unlocked,
                       users.telegram_id, users.username, users.first_name, users.last_name, users.language_code,
                       users.photo_url, users.pin_enabled
                FROM auth_sessions
                JOIN users ON users.id = auth_sessions.user_id
                WHERE auth_sessions.session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE auth_sessions SET expires_at = ? WHERE session_id = ?",
                (_now() + self.auth_ttl_seconds, session_id),
            )
            return {
                "session_id": row["session_id"],
                "user": {
                    "id": int(row["user_id"]),
                    "telegram_id": int(row["telegram_id"]),
                    "username": row["username"],
                    "first_name": row["first_name"],
                    "last_name": row["last_name"],
                    "language_code": row["language_code"],
                    "photo_url": row["photo_url"],
                    "pin_enabled": bool(row["pin_enabled"]),
                },
                "pin_unlocked": bool(row["pin_unlocked"]),
            }

    def revoke_auth_session(self, session_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM auth_sessions WHERE session_id = ?", (session_id,))
            return cursor.rowcount > 0

    def save_server(
        self,
        *,
        user_id: int,
        host: str,
        ssh_user: str,
        ssh_port: int,
        password: Optional[str],
        key_content: Optional[str],
        mode: Optional[str],
        listen_port: Optional[int],
        proxy_sni: Optional[str],
        label: Optional[str],
        relay: Optional[dict[str, Any]] = None,
        server_id: Optional[str] = None,
    ) -> dict[str, Any]:
        now = _now()
        clean_label = (label or "").strip() or f"{ssh_user}@{host}"
        clean_mode = (mode or "").strip() or None
        relay_data = self._normalize_relay(relay)
        with self._connect() as conn:
            existing = None
            if server_id:
                existing = conn.execute(
                    "SELECT id FROM saved_servers WHERE id = ? AND user_id = ?",
                    (server_id, user_id),
                ).fetchone()
            if existing is None:
                existing = conn.execute(
                    """
                    SELECT id FROM saved_servers
                    WHERE user_id = ? AND host = ? AND ssh_user = ? AND ssh_port = ? AND COALESCE(mode, '') = COALESCE(?, '')
                    """,
                    (user_id, host, ssh_user, ssh_port, clean_mode),
                ).fetchone()
            resolved_id = existing["id"] if existing else secrets.token_hex(12)
            if existing:
                conn.execute(
                    """
                    UPDATE saved_servers
                    SET label = ?, mode = ?, listen_port = ?, proxy_sni = ?, password_enc = ?, key_content_enc = ?,
                        relay_host = ?, relay_ssh_user = ?, relay_ssh_port = ?, relay_password_enc = ?,
                        relay_key_content_enc = ?, relay_public_host = ?, relay_listen_port = ?,
                        updated_at = ?, last_used_at = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (
                        clean_label,
                        clean_mode,
                        listen_port,
                        proxy_sni,
                        self._encrypt(password),
                        self._encrypt(key_content),
                        relay_data["host"],
                        relay_data["ssh_user"],
                        relay_data["ssh_port"],
                        self._encrypt(relay_data["password"]),
                        self._encrypt(relay_data["key_content"]),
                        relay_data["public_host"],
                        relay_data["listen_port"],
                        now,
                        now,
                        resolved_id,
                        user_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO saved_servers (
                        id, user_id, label, host, ssh_user, ssh_port, mode, listen_port, proxy_sni,
                        password_enc, key_content_enc, relay_host, relay_ssh_user, relay_ssh_port,
                        relay_password_enc, relay_key_content_enc, relay_public_host, relay_listen_port,
                        created_at, updated_at, last_used_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        resolved_id,
                        user_id,
                        clean_label,
                        host,
                        ssh_user,
                        ssh_port,
                        clean_mode,
                        listen_port,
                        proxy_sni,
                        self._encrypt(password),
                        self._encrypt(key_content),
                        relay_data["host"],
                        relay_data["ssh_user"],
                        relay_data["ssh_port"],
                        self._encrypt(relay_data["password"]),
                        self._encrypt(relay_data["key_content"]),
                        relay_data["public_host"],
                        relay_data["listen_port"],
                        now,
                        now,
                        now,
                    ),
                )
            row = conn.execute(
                "SELECT * FROM saved_servers WHERE id = ? AND user_id = ?",
                (resolved_id, user_id),
            ).fetchone()
            return self._serialize_saved_server(row)

    def list_servers(self, user_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM saved_servers
                WHERE user_id = ?
                ORDER BY last_used_at DESC, updated_at DESC, label COLLATE NOCASE ASC
                """,
                (user_id,),
            ).fetchall()
            return [self._serialize_saved_server(row) for row in rows]

    def delete_server(self, user_id: int, server_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM saved_servers WHERE id = ? AND user_id = ?",
                (server_id, user_id),
            )
            return cursor.rowcount > 0

    def rename_server(self, user_id: int, server_id: str, label: Optional[str]) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM saved_servers WHERE id = ? AND user_id = ?",
                (server_id, user_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("Saved server not found.")
            clean_label = (label or "").strip() or f"{row['ssh_user']}@{row['host']}"
            conn.execute(
                "UPDATE saved_servers SET label = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                (clean_label, _now(), server_id, user_id),
            )
            updated = conn.execute(
                "SELECT * FROM saved_servers WHERE id = ? AND user_id = ?",
                (server_id, user_id),
            ).fetchone()
            return self._serialize_saved_server(updated)

    def touch_server(self, user_id: int, server_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE saved_servers SET last_used_at = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                (_now(), _now(), server_id, user_id),
            )

    def resolve_server_credentials(
        self,
        *,
        user_id: int,
        server_id: str,
        require_pin_unlocked: bool,
        auth_session_id: Optional[str] = None,
    ) -> dict[str, Any]:
        if require_pin_unlocked and auth_session_id:
            session = self.get_auth_session(auth_session_id)
            if session is None:
                raise RuntimeError("Account session expired.")
            if session["user"]["id"] != user_id:
                raise RuntimeError("Saved server does not belong to the current account.")
            if session["user"]["pin_enabled"] and not session["pin_unlocked"]:
                raise RuntimeError("PIN unlock required before accessing saved servers.")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM saved_servers WHERE id = ? AND user_id = ?",
                (server_id, user_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("Saved server not found.")
            relay_public_host = (row["relay_public_host"] or row["relay_host"] or "").strip() or None
            relay_host = (row["relay_host"] or "").strip() or None
            relay_user = (row["relay_ssh_user"] or "").strip() or None
            relay_port = int(row["relay_ssh_port"]) if row["relay_ssh_port"] else None
            relay_listen_port = int(row["relay_listen_port"]) if row["relay_listen_port"] else None
            relay = None
            if relay_host and relay_user and relay_port:
                relay = {
                    "host": relay_host,
                    "user": relay_user,
                    "port": relay_port,
                    "password": self._decrypt(row["relay_password_enc"]),
                    "key_content": self._decrypt(row["relay_key_content_enc"]),
                    "public_host": relay_public_host,
                    "listen_port": relay_listen_port,
                }
            return {
                "id": row["id"],
                "host": row["host"],
                "user": row["ssh_user"],
                "port": int(row["ssh_port"]),
                "password": self._decrypt(row["password_enc"]),
                "key_content": self._decrypt(row["key_content_enc"]),
                "mode": row["mode"],
                "listen_port": row["listen_port"],
                "proxy_sni": row["proxy_sni"],
                "label": row["label"],
                "relay": relay,
            }

    def configure_pin(self, user_id: int, pin: Optional[str], enabled: bool) -> dict[str, Any]:
        with self._connect() as conn:
            if enabled:
                clean_pin = (pin or "").strip()
                if len(clean_pin) < 4:
                    raise RuntimeError("PIN must be at least 4 digits.")
                salt = secrets.token_hex(16)
                digest = pbkdf2_hmac("sha256", clean_pin.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
                conn.execute(
                    "UPDATE users SET pin_enabled = 1, pin_hash = ?, pin_salt = ?, updated_at = ? WHERE id = ?",
                    (digest, salt, _now(), user_id),
                )
                conn.execute(
                    "UPDATE auth_sessions SET pin_unlocked = 0 WHERE user_id = ?",
                    (user_id,),
                )
            else:
                conn.execute(
                    "UPDATE users SET pin_enabled = 0, pin_hash = NULL, pin_salt = NULL, updated_at = ? WHERE id = ?",
                    (_now(), user_id),
                )
                conn.execute(
                    "UPDATE auth_sessions SET pin_unlocked = 1 WHERE user_id = ?",
                    (user_id,),
                )
        return self.get_user(user_id)

    def unlock_pin(self, session_id: str, pin: str) -> bool:
        clean_pin = (pin or "").strip()
        with self._connect() as conn:
            self._clean_sessions(conn)
            row = conn.execute(
                """
                SELECT auth_sessions.user_id, users.pin_enabled, users.pin_hash, users.pin_salt
                FROM auth_sessions
                JOIN users ON users.id = auth_sessions.user_id
                WHERE auth_sessions.session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                return False
            if not bool(row["pin_enabled"]):
                conn.execute(
                    "UPDATE auth_sessions SET pin_unlocked = 1 WHERE session_id = ?",
                    (session_id,),
                )
                return True
            expected = row["pin_hash"] or ""
            salt = row["pin_salt"] or ""
            actual = pbkdf2_hmac("sha256", clean_pin.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
            if not hmac.compare_digest(expected, actual):
                return False
            conn.execute(
                "UPDATE auth_sessions SET pin_unlocked = 1 WHERE session_id = ?",
                (session_id,),
            )
            return True

    def get_user(self, user_id: int) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return self._serialize_user(row)

    # --- AmneziaWG fallback peers -----------------------------------------
    def _serialize_awg_peer(self, row: sqlite3.Row | None) -> Optional[dict[str, Any]]:
        if row is None:
            return None
        return {
            "telegram_id": int(row["telegram_id"]),
            "client_name": row["client_name"],
            "remnawave_uuid": row["remnawave_uuid"],
            "status": row["status"],
            "config": self._decrypt(row["config_enc"]),
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
        }

    def awg_get_peer(self, telegram_id: int) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM awg_fallback_peers WHERE telegram_id = ?",
                (int(telegram_id),),
            ).fetchone()
            return self._serialize_awg_peer(row)

    def awg_list_peers(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM awg_fallback_peers ORDER BY telegram_id"
            ).fetchall()
            return [
                peer
                for row in rows
                if (peer := self._serialize_awg_peer(row)) is not None
            ]

    def awg_save_peer(
        self,
        telegram_id: int,
        *,
        client_name: str,
        remnawave_uuid: Optional[str],
        config: Optional[str],
        status: str = "active",
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO awg_fallback_peers
                    (telegram_id, client_name, remnawave_uuid, status, config_enc, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(telegram_id) DO UPDATE SET
                    client_name = excluded.client_name,
                    remnawave_uuid = excluded.remnawave_uuid,
                    status = excluded.status,
                    config_enc = excluded.config_enc,
                    updated_at = excluded.updated_at
                """,
                (
                    int(telegram_id),
                    client_name,
                    remnawave_uuid,
                    status,
                    self._encrypt(config),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM awg_fallback_peers WHERE telegram_id = ?",
                (int(telegram_id),),
            ).fetchone()
        peer = self._serialize_awg_peer(row)
        assert peer is not None
        return peer

    def awg_set_status(self, telegram_id: int, status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE awg_fallback_peers SET status = ?, updated_at = ? WHERE telegram_id = ?",
                (status, _now(), int(telegram_id)),
            )

    def awg_delete_peer(self, telegram_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM awg_fallback_peers WHERE telegram_id = ?",
                (int(telegram_id),),
            )
            return cur.rowcount > 0

    # Multi-exit peers intentionally live beside the original single-exit table.
    # Keeping the legacy row untouched means an already-imported NL profile retains
    # its private key while the same Telegram user can also own FI/TR/US profiles.
    def _serialize_awg_server_peer(self, row: sqlite3.Row | None) -> Optional[dict[str, Any]]:
        peer = self._serialize_awg_peer(row)
        if peer is not None:
            peer["server_id"] = str(row["server_id"])
        return peer

    def awg_get_server_peer(self, telegram_id: int, server_id: str) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM awg_fallback_server_peers
                WHERE server_id = ? AND telegram_id = ?
                """,
                (str(server_id), int(telegram_id)),
            ).fetchone()
            return self._serialize_awg_server_peer(row)

    def awg_list_server_peers(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM awg_fallback_server_peers
                ORDER BY telegram_id, server_id
                """
            ).fetchall()
            return [
                peer
                for row in rows
                if (peer := self._serialize_awg_server_peer(row)) is not None
            ]

    def awg_save_server_peer(
        self,
        telegram_id: int,
        server_id: str,
        *,
        client_name: str,
        remnawave_uuid: Optional[str],
        config: Optional[str],
        status: str = "active",
    ) -> dict[str, Any]:
        now = _now()
        server_id = str(server_id)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO awg_fallback_server_peers
                    (server_id, telegram_id, client_name, remnawave_uuid, status, config_enc, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_id, telegram_id) DO UPDATE SET
                    client_name = excluded.client_name,
                    remnawave_uuid = excluded.remnawave_uuid,
                    status = excluded.status,
                    config_enc = excluded.config_enc,
                    updated_at = excluded.updated_at
                """,
                (
                    server_id,
                    int(telegram_id),
                    client_name,
                    remnawave_uuid,
                    status,
                    self._encrypt(config),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                """
                SELECT * FROM awg_fallback_server_peers
                WHERE server_id = ? AND telegram_id = ?
                """,
                (server_id, int(telegram_id)),
            ).fetchone()
        peer = self._serialize_awg_server_peer(row)
        assert peer is not None
        return peer

    def awg_set_server_status(self, telegram_id: int, server_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE awg_fallback_server_peers
                SET status = ?, updated_at = ?
                WHERE server_id = ? AND telegram_id = ?
                """,
                (status, _now(), str(server_id), int(telegram_id)),
            )

    def awg_delete_server_peer(self, telegram_id: int, server_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """
                DELETE FROM awg_fallback_server_peers
                WHERE server_id = ? AND telegram_id = ?
                """,
                (str(server_id), int(telegram_id)),
            )
            return cur.rowcount > 0

    # --- website invites ---------------------------------------------------
    def invite_create(
        self,
        code: str,
        issuer_telegram_id: int,
        *,
        expires_at: Optional[int] = None,
        note: Optional[str] = None,
    ) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO web_invites (code, issuer_telegram_id, created_at, expires_at, note)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(code), int(issuer_telegram_id), _now(), expires_at, (note or "").strip() or None),
            )
        return {"code": str(code), "issuer_telegram_id": int(issuer_telegram_id)}

    def invite_get(self, code: str) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM web_invites WHERE code = ?", (str(code),)
            ).fetchone()
        if row is None:
            return None
        return {
            "code": str(row["code"]),
            "issuer_telegram_id": int(row["issuer_telegram_id"]),
            "created_at": int(row["created_at"]),
            "expires_at": row["expires_at"],
            "used_at": row["used_at"],
            "used_by": row["used_by"],
            "note": row["note"],
        }

    def invite_list(self, issuer_telegram_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM web_invites WHERE issuer_telegram_id = ?
                ORDER BY created_at DESC
                """,
                (int(issuer_telegram_id),),
            ).fetchall()
        return [
            {
                "code": str(row["code"]),
                "created_at": int(row["created_at"]),
                "expires_at": row["expires_at"],
                "used_at": row["used_at"],
                "used_by": row["used_by"],
                "note": row["note"],
            }
            for row in rows
        ]

    def invite_redeem(self, code: str, used_by: int, *, now: Optional[int] = None) -> bool:
        """Claim an invite. Atomic, so two people cannot use the same code."""
        stamp = int(now if now is not None else _now())
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE web_invites SET used_at = ?, used_by = ?
                WHERE code = ? AND used_at IS NULL
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (stamp, int(used_by), str(code), stamp),
            )
            return cursor.rowcount > 0

    def invite_release(self, code: str, used_by: int) -> bool:
        """Hand a claimed invite back after signup failed.

        Scoped to the claimer so a late failure can never release someone else's
        successful redemption.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE web_invites SET used_at = NULL, used_by = NULL
                WHERE code = ? AND used_by = ?
                """,
                (str(code), int(used_by)),
            )
            return cursor.rowcount > 0

    def invite_delete(self, code: str, issuer_telegram_id: int) -> bool:
        """Withdraw an unused invite."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM web_invites
                WHERE code = ? AND issuer_telegram_id = ? AND used_at IS NULL
                """,
                (str(code), int(issuer_telegram_id)),
            )
            return cursor.rowcount > 0

    # --- family link epoch --------------------------------------------------
    def awg_family_epoch(self, owner_telegram_id: int) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT epoch FROM awg_family_epoch WHERE owner_telegram_id = ?",
                (int(owner_telegram_id),),
            ).fetchone()
        return int(row["epoch"]) if row else 0

    def awg_bump_family_epoch(self, owner_telegram_id: int) -> int:
        """Invalidate every family link this owner has handed out."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO awg_family_epoch (owner_telegram_id, epoch, updated_at)
                VALUES (?, 1, ?)
                ON CONFLICT(owner_telegram_id) DO UPDATE SET
                    epoch = awg_family_epoch.epoch + 1,
                    updated_at = excluded.updated_at
                """,
                (int(owner_telegram_id), _now()),
            )
        return self.awg_family_epoch(owner_telegram_id)

    # --- device slots: names and last-seen ---------------------------------
    def awg_get_device_labels(self, owner_telegram_id: int) -> dict[int, str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT slot, label FROM awg_device_labels WHERE owner_telegram_id = ?",
                (int(owner_telegram_id),),
            ).fetchall()
            return {int(row["slot"]): str(row["label"]) for row in rows}

    def awg_set_device_label(
        self, owner_telegram_id: int, slot: int, label: Optional[str]
    ) -> None:
        """Name a device slot. An empty label clears it back to the default."""
        clean = (label or "").strip()
        with self._connect() as conn:
            if not clean:
                conn.execute(
                    "DELETE FROM awg_device_labels WHERE owner_telegram_id = ? AND slot = ?",
                    (int(owner_telegram_id), int(slot)),
                )
                return
            conn.execute(
                """
                INSERT INTO awg_device_labels (owner_telegram_id, slot, label, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(owner_telegram_id, slot) DO UPDATE SET
                    label = excluded.label,
                    updated_at = excluded.updated_at
                """,
                (int(owner_telegram_id), int(slot), clean[:40], _now()),
            )

    def awg_record_usage(
        self,
        server_id: str,
        telegram_id: int,
        *,
        last_handshake_at: Optional[int],
        rx_bytes: int,
        tx_bytes: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO awg_peer_usage
                    (server_id, telegram_id, last_handshake_at, rx_bytes, tx_bytes, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_id, telegram_id) DO UPDATE SET
                    last_handshake_at = excluded.last_handshake_at,
                    rx_bytes = excluded.rx_bytes,
                    tx_bytes = excluded.tx_bytes,
                    updated_at = excluded.updated_at
                """,
                (
                    str(server_id),
                    int(telegram_id),
                    int(last_handshake_at) if last_handshake_at else None,
                    max(0, int(rx_bytes)),
                    max(0, int(tx_bytes)),
                    _now(),
                ),
            )

    def awg_get_usage(self, telegram_ids: list[int]) -> dict[tuple[str, int], dict[str, Any]]:
        """Cached last-seen/traffic keyed by ``(server_id, peer_id)``."""
        if not telegram_ids:
            return {}
        placeholders = ",".join("?" for _ in telegram_ids)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM awg_peer_usage WHERE telegram_id IN ({placeholders})",
                [int(value) for value in telegram_ids],
            ).fetchall()
        return {
            (str(row["server_id"]), int(row["telegram_id"])): {
                "last_handshake_at": row["last_handshake_at"],
                "rx_bytes": int(row["rx_bytes"] or 0),
                "tx_bytes": int(row["tx_bytes"] or 0),
                "updated_at": int(row["updated_at"] or 0),
            }
            for row in rows
        }

    def _serialize_saved_server(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            raise RuntimeError("Saved server not found.")
        relay_public_host = (row["relay_public_host"] or row["relay_host"] or "").strip() or None
        relay_host = (row["relay_host"] or "").strip() or None
        relay_user = (row["relay_ssh_user"] or "").strip() or None
        relay_port = int(row["relay_ssh_port"]) if row["relay_ssh_port"] else None
        return {
            "id": row["id"],
            "label": row["label"],
            "host": row["host"],
            "ssh_user": row["ssh_user"],
            "ssh_port": int(row["ssh_port"]),
            "mode": row["mode"],
            "listen_port": row["listen_port"],
            "proxy_sni": row["proxy_sni"],
            "has_password": bool(row["password_enc"]),
            "has_key": bool(row["key_content_enc"]),
            "relay_enabled": bool(relay_host and relay_user and relay_port),
            "relay_public_host": relay_public_host,
            "relay_ssh_host": relay_host,
            "relay_ssh_user": relay_user,
            "relay_ssh_port": relay_port,
            "relay_listen_port": int(row["relay_listen_port"]) if row["relay_listen_port"] else None,
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
            "last_used_at": int(row["last_used_at"]),
        }

    def _normalize_relay(self, relay: Optional[dict[str, Any]]) -> dict[str, Any]:
        relay = relay or {}
        host = str(relay.get("host") or "").strip()
        ssh_user = str(relay.get("user") or relay.get("ssh_user") or "").strip()
        ssh_port_raw = relay.get("port", relay.get("ssh_port"))
        ssh_port = int(ssh_port_raw) if ssh_port_raw else None
        public_host = str(relay.get("public_host") or host).strip() or None
        listen_port_raw = relay.get("listen_port")
        listen_port = int(listen_port_raw) if listen_port_raw else None
        if not host or not ssh_user or not ssh_port:
            return {
                "host": None,
                "ssh_user": None,
                "ssh_port": None,
                "password": None,
                "key_content": None,
                "public_host": None,
                "listen_port": None,
            }
        return {
            "host": host,
            "ssh_user": ssh_user,
            "ssh_port": ssh_port,
            "password": relay.get("password"),
            "key_content": relay.get("key_content"),
            "public_host": public_host,
            "listen_port": listen_port,
        }


def _validate_age(auth_date: int, max_age_seconds: int = DEFAULT_TELEGRAM_MAX_AGE_SECONDS) -> None:
    if auth_date <= 0:
        raise RuntimeError("Invalid Telegram auth timestamp.")
    if abs(_now() - auth_date) > max_age_seconds:
        raise RuntimeError("Telegram auth payload is too old.")


def verify_telegram_login(payload: dict[str, Any], bot_token: str) -> dict[str, Any]:
    provided_hash = str(payload.get("hash") or "").strip()
    if not provided_hash:
        raise RuntimeError("Telegram login hash is missing.")
    auth_date = int(payload.get("auth_date") or 0)
    _validate_age(auth_date)
    data_check_string = "\n".join(
        f"{key}={payload[key]}"
        for key in sorted(payload)
        if key != "hash" and payload.get(key) not in {None, ""}
    )
    secret_key = sha256(bot_token.encode("utf-8")).digest()
    expected_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), "sha256").hexdigest()
    if not hmac.compare_digest(expected_hash, provided_hash):
        raise RuntimeError("Telegram login hash mismatch.")
    return {
        "id": int(payload["id"]),
        "username": payload.get("username"),
        "first_name": payload.get("first_name"),
        "last_name": payload.get("last_name"),
        "photo_url": payload.get("photo_url"),
        "language_code": payload.get("language_code"),
    }


def verify_telegram_webapp_init_data(init_data: str, bot_token: str) -> dict[str, Any]:
    pairs = [(key, value) for key, value in parse_qsl(init_data, keep_blank_values=True)]
    payload = dict(pairs)
    provided_hash = (payload.get("hash") or "").strip()
    if not provided_hash:
        raise RuntimeError("Telegram miniapp hash is missing.")
    data_check_string = "\n".join(
        f"{key}={value}"
        for key, value in sorted(pairs, key=lambda item: item[0])
        if key != "hash"
    )
    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), "sha256").digest()
    expected_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), "sha256").hexdigest()
    if not hmac.compare_digest(expected_hash, provided_hash):
        raise RuntimeError("Telegram miniapp hash mismatch.")
    auth_date = int(payload.get("auth_date") or 0)
    _validate_age(auth_date)
    user_raw = payload.get("user")
    if not user_raw:
        raise RuntimeError("Telegram miniapp payload does not contain user data.")
    user = json.loads(user_raw)
    return {
        "id": int(user["id"]),
        "username": user.get("username"),
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
        "photo_url": user.get("photo_url"),
        "language_code": user.get("language_code"),
    }
