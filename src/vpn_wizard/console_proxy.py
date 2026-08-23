"""Прокси для приставок.

PlayStation и Switch не умеют вводить логин и пароль у прокси, поэтому доступ
выдаётся по домашнему IP: человек нажимает кнопку в кабинете со своего Wi-Fi,
его адрес попадает в allowlist squid'а на отдельном no-auth порту, и приставке
остаётся вписать только адрес и порт. Привязка живёт TTL дней и продлевается
повторным нажатием — так динамические IP не копятся навсегда, а чужие соседи
по CGNAT не получают вечный прокси.

Wizard работает на той же машине, что и squid, поэтому файл пишется локально,
а squid перечитывает конфиг мягким `squid -k reconfigure` — активные
соединения не рвутся.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Iterable, Optional

logger = logging.getLogger("vpn_wizard")

# Пустой файл в src-ACL валит squid при старте, поэтому localhost живёт в списке
# всегда: безвреден и гарантирует непустоту.
PLACEHOLDER_IP = "127.0.0.1"


@dataclass(frozen=True)
class ConsoleProxyConfig:
    enabled: bool
    host: str
    port: int
    ips_file: str
    ttl_days: int
    max_ips: int

    @classmethod
    def from_env(cls) -> "ConsoleProxyConfig":
        def _int(name: str, fallback: int, minimum: int = 1) -> int:
            raw = (os.getenv(name) or "").strip()
            try:
                return max(minimum, int(raw))
            except ValueError:
                return fallback

        return cls(
            enabled=(os.getenv("VPNW_CONSOLE_PROXY_ENABLED") or "").strip().lower()
            in {"1", "true", "yes", "on"},
            host=(os.getenv("VPNW_CONSOLE_PROXY_HOST") or "").strip(),
            port=_int("VPNW_CONSOLE_PROXY_PORT", 3129),
            ips_file=(
                os.getenv("VPNW_CONSOLE_PROXY_IPS_FILE")
                or "/etc/squid/fodder_console_ips.txt"
            ).strip(),
            ttl_days=_int("VPNW_CONSOLE_PROXY_TTL_DAYS", 30),
            max_ips=_int("VPNW_CONSOLE_PROXY_MAX_IPS", 2),
        )

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.host and self.ips_file)


def normalize_ip(raw: str) -> Optional[str]:
    """Одиночный публичный адрес — ровно то, что видно в заголовке запроса."""
    try:
        value = ipaddress.ip_address((raw or "").strip())
    except ValueError:
        return None
    return str(value)


def render_ips_file(rows: Iterable[dict[str, Any]]) -> str:
    """Файл для acl src: по адресу на строку, отсортировано и без дублей."""
    ips = sorted({str(row["ip"]) for row in rows} | {PLACEHOLDER_IP})
    lines = ["# Managed by vpn-wizard (console proxy). Do not edit by hand."]
    lines += ips
    return "\n".join(lines) + "\n"


def sync_ips_file(config: ConsoleProxyConfig, store: Any) -> bool:
    """Привести allowlist к базе; True — если файл реально поменялся."""
    if not config.configured:
        return False
    content = render_ips_file(store.console_ips_active())
    try:
        with open(config.ips_file, encoding="utf-8") as handle:
            if handle.read() == content:
                return False
    except OSError:
        pass
    tmp = config.ips_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.replace(tmp, config.ips_file)
    try:
        subprocess.run(
            ["squid", "-k", "reconfigure"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except Exception:
        # Файл уже верный; не перечитавший конфиг squid догонит на следующем
        # изменении, а ронять запрос из-за этого нельзя.
        logger.warning("console proxy: squid reconfigure failed", exc_info=True)
    return True
