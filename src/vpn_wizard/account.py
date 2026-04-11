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
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_servers_identity
                    ON saved_servers(user_id, host, ssh_user, ssh_port, COALESCE(mode, ''));
                """
            )

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
        server_id: Optional[str] = None,
    ) -> dict[str, Any]:
        now = _now()
        clean_label = (label or "").strip() or f"{ssh_user}@{host}"
        clean_mode = (mode or "").strip() or None
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
                        password_enc, key_content_enc, created_at, updated_at, last_used_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    def _serialize_saved_server(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            raise RuntimeError("Saved server not found.")
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
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
            "last_used_at": int(row["last_used_at"]),
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
