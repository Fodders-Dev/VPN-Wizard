"""Public, stale-aware VPN telemetry; never confuse SSH reachability with VPN health."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any

from vpn_wizard.account import default_db_path
from vpn_wizard.awg_fallback import AwgFallbackConfig, AwgFallbackService
from vpn_wizard.awg_servers import AwgRegistry, free_server_choice_enabled

MAX_AGE = 600
RECENT_WINDOW = 300
MAX_COUNTER = 2**64 - 1
STATES = {
    "online": "Есть VPN-подключения",
    "ready": "VPN запущен, ждёт подключения",
    "unavailable": "VPN не запущен",
    "unknown": "Статус не подтверждён",
    "degraded": "Работает не во всех сетях",
    "maintenance": "Временно отключён",
}


def snapshot_path() -> Path:
    return Path(os.getenv("VPNW_AWG_HEALTH_PATH") or default_db_path().with_name("awg-health.json"))


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _counter(value: Any, maximum: int = MAX_COUNTER) -> int | None:
    # In particular, do not coerce booleans, floats, or arbitrary snapshot strings.
    return value if type(value) is int and 0 <= value <= maximum else None


def _runtime_number(value: str) -> int | None:
    return _counter(int(value)) if re.fullmatch(r"[0-9]{1,20}", value) else None


def _host_key(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host.lower().rstrip(".")


def measure_latency(host: str, *, local: bool = False, now: int | None = None) -> dict[str, Any]:
    """ICMP reference from the NL monitor process, never client/tunnel latency.

    The existing timer runs on NL. Run this only from that monitor; the catalog
    reader never probes. Linux ping has both a deadline and a subprocess timeout
    (including DNS). Raw stdout/stderr and destination addresses stay private.
    """
    stamp = int(time.time() if now is None else now)
    try:
        address = ipaddress.ip_address(host)
        local = local or address.is_loopback
        valid_host = not address.is_unspecified and not address.is_multicast
    except ValueError:
        valid_host = bool(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", host))
        local = local or host.lower().rstrip(".") == "localhost"
    result: dict[str, Any] = {
        "ms": None, "origin": "nl_monitor", "method": "icmp",
        "scope": "local" if local else "remote", "checked_at": stamp,
    }
    if local or not valid_host or os.name == "nt":
        return result
    try:
        response = subprocess.run(
            ["ping", "-n", "-c", "3", "-W", "1", "-w", "4", "--", host],
            capture_output=True, text=True, timeout=5, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        # A partial response is still a real measurement; deadline expiry can
        # return 1 despite receiving replies. A summary alone is not enough.
        replies = re.search(r"(\d+) (?:packets )?received", response.stdout)
        summary = re.search(
            r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = "
            r"[0-9.]+/([0-9]+(?:\.[0-9]+)?)/[0-9.]+/[0-9.]+ ms", response.stdout,
        )
        if response.returncode in (0, 1) and replies and int(replies[1]) > 0 and summary:
            value = float(summary[1])
            if math.isfinite(value) and 0 <= value <= 60000:
                result["ms"] = round(value, 3)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return result


def probe(server: Any, *, now: int | None = None, service: Any = None) -> dict[str, Any]:
    """Read runtime counters, never keys/config files; retain only aggregates."""
    stamp = int(time.time() if now is None else now)
    result: dict[str, Any] = {"state": "unknown", "checked_at": stamp}
    if not server.enabled:
        return {**result, "state": "maintenance"}
    try:
        if service is None:
            service = AwgFallbackService(None, AwgFallbackConfig.from_server(server, link_secret=""))
        with service._ssh() as ssh:
            ports = ssh.run("awg show all listen-port", sudo=True, pty=False)
            interfaces = [row.split() for row in ports.splitlines() if row.strip()]
            if any(len(row) != 2 or not re.fullmatch(r"[a-z][a-z0-9]{1,14}", row[0])
                   or _runtime_number(row[1]) is None or not 0 <= int(row[1]) <= 65535
                   for row in interfaces):
                return result
            matches = [
                row for row in interfaces
                if (not server.interface or row[0] == server.interface)
                and (not server.listen_port or row[1] == str(server.listen_port))
                and int(row[1]) > 0
            ]
            if not matches:
                return {**result, "state": "unavailable", "available_ports": []}
            iface = matches[0][0]
            result["available_ports"] = [int(matches[0][1])]
            handshakes = ssh.run(f"awg show {iface} latest-handshakes", sudo=True, pty=False)
            peers = [row.split() for row in handshakes.splitlines() if row.strip()]
            if any(len(row) != 2 or _runtime_number(row[1]) is None for row in peers):
                return result
            fresh = len({key for key, value in peers if 0 < int(value) <= stamp
                         and stamp - int(value) <= RECENT_WINDOW})
            result.update(state="online" if fresh else "ready", recent_connections=fresh)
            try:
                transfer = ssh.run(f"awg show {iface} transfer", sudo=True, pty=False)
                rows = [row.split() for row in transfer.splitlines() if row.strip()]
                if all(len(row) == 3 and _runtime_number(row[1]) is not None
                       and _runtime_number(row[2]) is not None for row in rows):
                    totals = {key: (int(rx), int(tx)) for key, rx, tx in rows}
                    rx, tx = sum(v[0] for v in totals.values()), sum(v[1] for v in totals.values())
                    if _counter(rx) is not None and _counter(tx) is not None:
                        result["traffic"] = {"received_bytes": rx, "sent_bytes": tx}
            except Exception:
                # Optional counters cannot invalidate the successful health probe.
                pass
            return result
    except Exception:
        # Failed SSH is ambiguous: it must not be advertised as a dead VPN or leak credentials.
        return result


def refresh(registry: AwgRegistry, *, path: Path | None = None) -> dict[str, Any]:
    servers = [s for s in registry.servers if s.usable]
    hosts = list(dict.fromkeys(_host_key(s.endpoint_host) for s in servers if s.enabled))
    with ThreadPoolExecutor(max_workers=4) as pool:
        # Ping the public endpoint even for the monitor's own exit. This is a
        # real reachability measurement of the address users receive, not the
        # SSH/loopback address used to administer the box.
        latency_jobs = {host: pool.submit(measure_latency, host, local=False) for host in hosts}
        results = list(pool.map(probe, servers))
        latencies = {host: job.result() for host, job in latency_jobs.items()}
    for server, result in zip(servers, results):
        if server.enabled:
            result["latency"] = latencies[_host_key(server.endpoint_host)]
    data = {"servers": dict(zip((s.id for s in servers), results))}
    target = path or snapshot_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, delete=False) as handle:
            name = handle.name
            json.dump(data, handle, ensure_ascii=False)
        os.chmod(name, 0o644)
        os.replace(name, target)
    finally:
        if name and Path(name).exists():
            Path(name).unlink()
    return data


def _public_latency(value: Any, stamp: int, *, local: bool = False) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    checked = _counter(value.get("checked_at"))
    fresh = checked is not None and checked > 0 and 0 <= stamp - checked <= MAX_AGE
    valid = (value.get("origin") == "nl_monitor" and value.get("method") == "icmp"
             and value.get("scope") in ("local", "remote"))
    ms = value.get("ms")
    valid_ms = type(ms) in (int, float) and 0 <= ms <= 60000 and math.isfinite(ms)
    scope = "local" if local else value["scope"] if valid else "unknown"
    return {
        "ms": ms if fresh and valid and valid_ms and scope == "remote" else None,
        "origin": "nl_monitor", "method": "icmp",
        "scope": scope,
        "local": False,
        "checked_at": checked if fresh and valid else None,
        "label": "Пинг от монитора в Нидерландах; не с вашего устройства",
    }


def public_catalog(registry: AwgRegistry, *, include_unavailable: bool = False, now: int | None = None) -> dict[str, Any]:
    stamp = int(time.time() if now is None else now)
    snapshot = read_json(snapshot_path()).get("servers", {})
    if not isinstance(snapshot, dict):
        snapshot = {}
    notices = read_json(Path(__file__).resolve().parents[2] / "web/connect/status.json").get("server_statuses", {})
    if not isinstance(notices, dict):
        notices = {}
    body = registry.public()
    choices = [s for s in registry.servers if s.usable] if include_unavailable else registry.offerable
    # Group alternate ports by the actual configured host, never publish its IP
    # or a hash of it. Prefer the primary's public ID regardless of list order.
    groups: dict[str, str] = {}
    for server in sorted((s for s in registry.servers if s.usable), key=lambda s: (s.alt_port, s.id)):
        groups.setdefault(_host_key(server.endpoint_host), server.id)
    body["servers"] = []
    for server in choices:
        row = snapshot.get(server.id, {})
        row = row if isinstance(row, dict) else {}
        checked = _counter(row.get("checked_at"))
        fresh = checked is not None and checked > 0 and 0 <= stamp - checked <= MAX_AGE
        state = row.get("state", "unknown") if fresh else "unknown"
        if not isinstance(state, str) or state not in STATES:
            state = "unknown"
        runtime_state = state
        note = notices.get(server.id, {})
        note = note if isinstance(note, dict) else {}
        # An operator restriction only qualifies a confirmed running VPN.
        # Unknown/stale/down evidence must remain visible even with a notice.
        operator_state = note.get("state")
        if operator_state not in ("degraded", "maintenance"):
            operator_state = None
        if state in ("online", "ready") and operator_state:
            state = operator_state
        if not server.enabled:
            state = "maintenance"
        running = fresh and runtime_state in ("online", "ready")
        ports = row.get("available_ports")
        ports = sorted({p for p in ports if _counter(p, 65535) is not None and p > 0
                        and (not server.listen_port or p == server.listen_port)}) if fresh and isinstance(ports, list) else None
        traffic = row.get("traffic")
        traffic = traffic if running and isinstance(traffic, dict) else {}
        rx, tx = _counter(traffic.get("received_bytes")), _counter(traffic.get("sent_bytes"))
        detail = note.get("detail")
        body["servers"].append({
            **server.public(), "enabled": server.enabled,
            "host_group": groups[_host_key(server.host)],
            "vpn_port": server.listen_port,
            "health": {
                "state": state, "label": STATES[state],
                "runtime_state": runtime_state, "operator_state": operator_state,
                "checked_at": checked if fresh else None,
                "stale": not fresh,
                "detail": detail[:500] if isinstance(detail, str) else "",
                "recent_connections": _counter(row.get("recent_connections")) if running else None,
                "recent_connections_window_seconds": RECENT_WINDOW,
                "recent_connections_label": "Число пиров с handshake за 5 минут до проверки",
                "available_ports": ports,
                "available_ports_label": "UDP-порты интерфейса VPN; доступность из вашей сети не проверена",
                # The value is always a ping from the NL monitor to the public
                # endpoint. It must not turn into the confusing word
                # "Локально" merely because SSH happens on the same controller.
                "latency": _public_latency(row.get("latency"), stamp, local=False),
                "traffic": {"received_bytes": rx, "sent_bytes": tx,
                            "scope": "interface_current_peers", "direction": "server",
                            "label": "Сумма счётчиков текущих пиров; сбрасывается при перезапуске или удалении пиров"}
                if rx is not None and tx is not None else None,
            },
        })
    body["free_server_choice"] = free_server_choice_enabled()
    url = os.getenv("VPNW_SUPPORT_URL", "").strip()
    body["support"] = {
        "details": os.getenv("VPNW_SUPPORT_DETAILS", "").strip()[:2000],
        "url": url if url.startswith("https://") else "",
    }
    body["status_note"] = "Статус отражает работу VPN на сервере, но не гарантирует доступность у вашего оператора."
    return body


def main() -> None:
    data = refresh(AwgRegistry.from_env())
    print(json.dumps(data, ensure_ascii=False))


if __name__ == "__main__":
    main()
