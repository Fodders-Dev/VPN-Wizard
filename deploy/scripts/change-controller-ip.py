"""Safely migrate the Netherlands control server's public IPv4 and URLs."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from functools import wraps
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
import urllib.error
import urllib.request


DEFAULT_ENV = Path("/etc/vpn-wizard.env")
BACKUP_ROOT = Path("/var/backups/vpn-wizard")
OLD_DOMAIN = "77-67-89-164.nip.io"
URL_ENV_KEYS = {
    "VPNW_PUBLIC_BASE_URL", "VPNW_MINIAPP_URL", "VPNW_CORS_ORIGINS",
    "VPNW_WIZARD_URL", "VPNW_AWG_PUBLIC_URL", "FODDERS_PORTAL_URL",
    "FODDERS_VPN1_MINIAPP_URL", "WEBHOOK_URL", "REMNAWAVE_WEBHOOK_URL",
    "API_URL", "PUBLIC_URL", "SUB_PUBLIC_URL",
}
DOMAIN_ENV_KEYS = {"PANEL_DOMAIN", "SUB_PUBLIC_DOMAIN", "PUBLIC_DOMAIN"}
ENV_URL_KEYS = {
    "vpn": URL_ENV_KEYS,
    "bedolaga_env": {"FODDERS_PORTAL_URL", "FODDERS_VPN1_MINIAPP_URL", "VPNW_AWG_PUBLIC_URL", "REMNAWAVE_API_URL"},
    "remnawave_env": {"WEBHOOK_URL", "WEBHOOK_BASE_URL", "REMNAWAVE_WEBHOOK_URL", "REMNAWAVE_API_URL"},
    "subpage_env": {"API_URL", "BACKEND_URL", "PUBLIC_URL", "WEBHOOK_URL", "REMNAWAVE_API_URL", "REMNAWAVE_PANEL_URL"},
}
ENV_DOMAIN_KEYS = {
    "remnawave_env": {"PANEL_DOMAIN", "SUB_PUBLIC_DOMAIN", "FRONT_END_DOMAIN"},
    "subpage_env": {"SUB_PUBLIC_DOMAIN", "PUBLIC_DOMAIN"},
}
DEFAULT_PATHS = {
    "caddy": Path("/etc/caddy/Caddyfile"),
    "subpage_caddy": Path("/etc/caddy/fodder-vpn-subpage.caddy"),
    "bedolaga_env": Path("/opt/bedolaga/.env"),
    "remnawave_env": Path("/opt/remnawave/.env"),
    "subpage_env": Path("/opt/remnawave/subpage.env"),
    "xray": Path("/usr/local/etc/xray/config.json"),
    "cert": Path("/usr/local/etc/xray/fvpn-test-certs/fullchain.pem"),
    "key": Path("/usr/local/etc/xray/fvpn-test-certs/key.pem"),
}
ENV_LINE = re.compile(r"^(?P<prefix>\ufeff?\s*[A-Za-z_][A-Za-z0-9_]*\s*=)(?P<value>.*)$")


class ChangeError(RuntimeError):
    """Safe, metadata-only migration failure."""


class RuntimeOperationFailure(ChangeError):
    def __init__(self, message: str, report: dict[str, Any]):
        super().__init__(message)
        self.report = report


def _exit_helper():
    path = Path(__file__).with_name("change-exit-ip.py")
    spec = importlib.util.spec_from_file_location("_change_exit_ip_shared", path)
    if spec is None or spec.loader is None:
        raise ChangeError("Existing AWG identity helpers are unavailable.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_public_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ChangeError("New IP must be a globally routable IPv4 address.") from None
    if address.version != 4 or not address.is_global or address.is_multicast or address.is_unspecified or address.is_reserved:
        raise ChangeError("New IP must be a globally routable IPv4 address.")
    return str(address)


def _domain_for(ip: str) -> str:
    return ip.replace(".", "-") + ".nip.io"


def _replace_refs(value: str, old_ip: str, new_ip: str, old_domain: str, new_domain: str) -> str:
    # Domain suffixes in subdomains are valid (panel-vpn.OLD_DOMAIN), while a
    # longer label or a .evil suffix is intentionally outside these boundaries.
    domain = re.compile(r"(?<![A-Za-z0-9-])" + re.escape(old_domain) + r"(?=$|[/:?#,\s'\";])", re.I)
    ip = re.compile(r"(?<![0-9.])" + re.escape(old_ip) + r"(?![0-9.])")
    return ip.sub(new_ip, domain.sub(new_domain, value))


def _decode_value(raw: str) -> tuple[str, str, str]:
    leading = raw[:len(raw) - len(raw.lstrip())]
    trailing = raw[len(raw.rstrip()):]
    value = raw.strip()
    if value.startswith("'") and value.endswith("'") and len(value) >= 2:
        return value[1:-1], leading, trailing
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            raise ChangeError("Malformed double-quoted environment value.") from None
        if not isinstance(decoded, str):
            raise ChangeError("Malformed double-quoted environment value.")
        return decoded, leading, trailing
    return re.sub(r"\s+#.*$", "", value).strip(), leading, trailing


def _encode_value(previous: str, value: str, leading: str, trailing: str) -> str:
    trimmed = previous.strip()
    if trimmed.startswith("'") and trimmed.endswith("'"):
        if "'" in value:
            raise ChangeError("Cannot preserve single-quoted environment value safely.")
        encoded = "'" + value + "'"
    elif trimmed.startswith('"') and trimmed.endswith('"'):
        encoded = json.dumps(value, ensure_ascii=True)
    else:
        encoded = value
    return leading + encoded + trailing


def _transform_env(raw: bytes, key: str, old_ip: str, new_ip: str, *, registry: bool = False) -> tuple[bytes, int]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ChangeError(f"{key} must be UTF-8.") from None
    old_domain, new_domain = _domain_for(old_ip), _domain_for(new_ip)
    lines = text.splitlines(keepends=True)
    seen: set[str] = set()
    changed = 0
    new_origin = "https://" + new_domain
    for i, line in enumerate(lines):
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        match = ENV_LINE.match(body)
        if not match:
            continue
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", match.group("prefix"))
        if not name_match:
            continue
        name = name_match.group(1)
        seen.add(name)
        if registry and name == "VPNW_AWG_SERVERS":
            value, leading, trailing = _decode_value(match.group("value"))
            try:
                nodes = json.loads(value)
            except json.JSONDecodeError:
                raise ChangeError("VPNW_AWG_SERVERS is not valid JSON.") from None
            if not isinstance(nodes, list):
                raise ChangeError("VPNW_AWG_SERVERS must be a list.")
            selected = [n for n in nodes if isinstance(n, dict) and
                        (n.get("id") == "nl" or n.get("id") == "nl-alt" or n.get("alt_of") == "nl")]
            if len([n for n in selected if n.get("id") == "nl"]) != 1:
                raise ChangeError("Expected exactly one Netherlands registry entry.")
            if len({str(n.get("id")) for n in selected}) != len(selected):
                raise ChangeError("Netherlands registry identities are not unique.")
            for node in selected:
                host = str(node.get("host") or "").strip()
                if host not in {"127.0.0.1", "localhost"}:
                    raise ChangeError("Netherlands SSH registry host must remain loopback.")
                public = str(node.get("public_host") or "").strip()
                if public != old_ip and public != new_ip:
                    raise ChangeError("Netherlands public endpoint does not match the expected migration source.")
                if public != new_ip:
                    node["public_host"] = new_ip
            new_value = json.dumps(nodes, separators=(",", ":"), ensure_ascii=True)
        elif name in ENV_URL_KEYS.get(key, set()):
            value, leading, trailing = _decode_value(match.group("value"))
            new_value = new_origin if key == "vpn" and name == "VPNW_PUBLIC_BASE_URL" else _replace_refs(value, old_ip, new_ip, old_domain, new_domain)
        elif name in ENV_DOMAIN_KEYS.get(key, set()):
            value, leading, trailing = _decode_value(match.group("value"))
            new_value = _replace_refs(value, old_ip, new_ip, old_domain, new_domain)
        else:
            continue
        if new_value != value if not (registry and name == "VPNW_AWG_SERVERS") else new_value != json.dumps(json.loads(value), separators=(",", ":"), ensure_ascii=True):
            lines[i] = match.group("prefix") + _encode_value(match.group("value"), new_value, leading, trailing) + ending
            changed += 1
    if key == "vpn" and "VPNW_PUBLIC_BASE_URL" not in seen:
        lines.append(f"VPNW_PUBLIC_BASE_URL='{new_origin}'\n")
        changed += 1
    return "".join(lines).encode("utf-8"), changed


def transform_caddy(raw: bytes, old_ip: str, new_ip: str) -> tuple[bytes, int]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ChangeError("Caddy configuration must be UTF-8.") from None
    updated = _replace_refs(text, old_ip, new_ip, _domain_for(old_ip), _domain_for(new_ip))
    return updated.encode("utf-8"), int(updated != text)


def transform_xray(raw: bytes, old_ip: str, new_ip: str) -> tuple[bytes, int]:
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ChangeError("Xray configuration is not valid UTF-8 JSON.") from None
    changed = 0
    for inbound in config.get("inbounds", []):
        if not isinstance(inbound, dict) or inbound.get("port") != 9443:
            continue
        stream = inbound.get("streamSettings")
        if not isinstance(stream, dict):
            continue
        for section, field in (("tlsSettings", "serverName"), ("xhttpSettings", "host")):
            values = stream.get(section)
            if isinstance(values, dict) and isinstance(values.get(field), str):
                before = values[field]
                values[field] = _replace_refs(before, old_ip, new_ip, _domain_for(old_ip), _domain_for(new_ip))
                changed += int(values[field] != before)
    if not changed:
        return raw, 0
    # Keep readable formatting while preserving all unrelated Xray values.
    return (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), changed


def cached_nl_identities(db_paths: list[Path], secret: str) -> dict[str, str]:
    helper = _exit_helper()
    cipher = helper._derive_fernet(secret)
    result: dict[str, str] = {}
    by_server: dict[str, list[str]] = {"nl": [], "nl-alt": []}
    for path in db_paths:
        if not path.exists():
            continue
        if path.is_symlink():
            raise ChangeError("Refusing to read a symlinked account database.")
        try:
            conn = sqlite3.connect("file:" + str(path.resolve()) + "?mode=ro", uri=True)
            try:
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if "awg_fallback_peers" in tables:
                    by_server["nl"].extend(row[0] for row in conn.execute(
                        "SELECT config_enc FROM awg_fallback_peers WHERE config_enc IS NOT NULL"))
                if "awg_fallback_server_peers" in tables:
                    by_server["nl-alt"].extend(row[0] for row in conn.execute(
                        "SELECT config_enc FROM awg_fallback_server_peers WHERE server_id='nl-alt' AND config_enc IS NOT NULL"))
            finally:
                conn.close()
        except sqlite3.Error:
            raise ChangeError("Could not read cached NL AWG identities from the account database.") from None
    for server_id, tokens in by_server.items():
        found: set[str] = set()
        for token in tokens:
            if not token:
                continue
            try:
                config = cipher.decrypt(str(token).encode("utf-8")).decode("utf-8")
            except Exception:
                raise ChangeError("Could not decrypt a cached NL AWG identity.") from None
            key = helper._profile_identity(config)
            if key is None:
                raise ChangeError("A cached NL AWG profile has no valid peer identity.")
            found.add(key)
        if len(found) != 1:
            raise ChangeError(f"Expected one consistent cached AWG identity for {server_id}.")
        result[server_id] = next(iter(found))
    if set(result) != {"nl", "nl-alt"}:
        raise ChangeError("Both legacy NL and nl-alt encrypted identities are required.")
    return result


def _assigned_address(new_ip: str, runner: Callable[..., Any]) -> bool:
    try:
        result = runner(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=10, check=False)
    except Exception:
        return False
    if result.returncode != 0:
        return False
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", result.stdout):
        try:
            if str(ipaddress.ip_interface(token).ip) == new_ip:
                return True
        except ValueError:
            pass
    return False


def _run_payload(payload: dict[str, Any], runner: Callable[..., Any]) -> dict[str, Any]:
    helper = _exit_helper()
    try:
        result = runner([sys.executable, "-c", helper.REMOTE_CODE], input=json.dumps(payload),
                        capture_output=True, text=True, timeout=240, check=False)
    except Exception:
        raise ChangeError("Local AWG runtime/profile inspection failed.") from None
    try:
        report = json.loads(result.stdout)
    except Exception:
        raise ChangeError("Local AWG helper returned no safe status report.") from None
    if not isinstance(report, dict):
        raise ChangeError("Local AWG helper returned an invalid status report.")
    if result.returncode != 0 or report.get("error"):
        reason = str(report.get("error", "")) if isinstance(report, dict) else ""
        raise RuntimeOperationFailure("Local AWG runtime/profile validation failed" + (f" ({reason})." if reason.isidentifier() else "."), report)
    return report


def _verify_runtime_identities(interfaces: Any, expected: list[dict[str, Any]], baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(interfaces, dict) or not interfaces:
        raise ChangeError("NL AWG runtime inspection returned no interface fingerprints.")
    for item in expected:
        configured = item.get("interface")
        if configured:
            candidate = interfaces.get(configured)
            matches = [candidate] if isinstance(candidate, dict) else []
        else:
            matches = [value for value in interfaces.values() if isinstance(value, dict)
                       and value.get("listen_port") == item["listen_port"]]
        if len(matches) != 1 or matches[0].get("listen_port") != item["listen_port"]:
            raise ChangeError("NL AWG listener does not uniquely match the configured port.")
        if matches[0].get("public_key_verified") is not True:
            raise ChangeError("NL AWG runtime key does not match its cached identity.")
    if baseline is not None and interfaces != baseline:
        raise ChangeError("NL AWG interface, listener, public key, or peer fingerprints changed during migration.")
    return interfaces


def _catalog_status_ok(status: str) -> bool:
    match = re.fullmatch(r"HTTP/1\.[01]\s+(\d{3})(?:\s+.*)?", status.strip())
    return bool(match and match.group(1) == "200")


def _local_tls_check(domain: str, *, timeout: float = 8) -> dict[str, Any]:
    context = ssl.create_default_context()
    with __import__("socket").create_connection(("127.0.0.1", 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            cert = tls.getpeercert()
            tls.sendall(f"GET /connect/join.html HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode("ascii"))
            status = tls.recv(256).split(b"\r\n", 1)[0].decode("ascii", "replace")
            if not _catalog_status_ok(status):
                raise ChangeError("Public catalog check failed after TLS verification.")
            return {"tls_verified": True, "catalog_status": status.split(" ", 2)[1],
                    "not_after": cert.get("notAfter", "")}


def _local_xray_tls_check(domain: str, *, timeout: float = 8) -> dict[str, Any]:
    context = ssl.create_default_context()
    with __import__("socket").create_connection(("127.0.0.1", 9443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            return {"tls_verified": True, "alpn": tls.selected_alpn_protocol(),
                    "not_after": tls.getpeercert().get("notAfter", "")}


def _xray_has_trial(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ChangeError("Xray configuration could not be read safely.") from None
    return any(isinstance(item, dict) and item.get("port") == 9443 for item in config.get("inbounds", []))


def _lstat_regular(path: Path) -> os.stat_result:
    if path.is_symlink() or not path.is_file():
        raise ChangeError(f"Refusing a missing or symlinked file: {path.name}.")
    return path.stat(follow_symlinks=False)


def _atomic_write(path: Path, data: bytes, metadata: os.stat_result | None = None) -> None:
    metadata = metadata or _lstat_regular(path)
    if path.is_symlink():
        raise ChangeError("Refusing to replace a symlinked file.")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.nl-ip-", dir=str(path.parent))
    temp = Path(temp_name)
    try:
        if hasattr(os, "fchown"):
            os.fchown(fd, metadata.st_uid, metadata.st_gid)
        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        if os.name != "nt":
            dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    finally:
        temp.unlink(missing_ok=True)


def _backup_files(root: Path, snapshots: dict[Path, tuple[bytes, os.stat_result]]) -> Path:
    if root.is_symlink():
        raise ChangeError("Private backup root cannot be a symlink.")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if hasattr(os, "geteuid") and os.geteuid() == 0 and root.stat().st_uid != 0:
        raise ChangeError("Private backup root must be owned by root.")
    os.chmod(root, 0o700)
    backup = Path(tempfile.mkdtemp(prefix="change-nl-ip-", dir=str(root)))
    os.chmod(backup, 0o700)
    manifest: list[dict[str, str]] = []
    try:
        for index, (path, (data, metadata)) in enumerate(snapshots.items()):
            name = f"{index:03d}-{path.name}"
            target = backup / name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(target, 0o600)
            manifest.append({"path": str(path), "backup": name})
        (backup / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
        os.chmod(backup / "manifest.json", 0o600)
        return backup
    except Exception:
        shutil.rmtree(backup, ignore_errors=True)
        raise


def _restore_snapshots(snapshots: dict[Path, tuple[bytes, os.stat_result]], changed: list[Path]) -> bool:
    ok = True
    for path in reversed(changed):
        try:
            data, metadata = snapshots[path]
            _atomic_write(path, data, metadata)
        except Exception:
            ok = False
    return ok


def _read_candidates(env_path: Path, paths: dict[str, Path], old_ip: str, new_ip: str) -> tuple[dict[Path, bytes], dict[str, int], dict[str, str]]:
    changes: dict[Path, bytes] = {}
    counts: dict[str, int] = {}
    env_raw = env_path.read_bytes()
    env_updated, n = _transform_env(env_raw, "vpn", old_ip, new_ip, registry=True)
    if env_updated != env_raw:
        changes[env_path] = env_updated
    counts["vpn_env"] = n
    for name in ("bedolaga_env", "remnawave_env", "subpage_env"):
        path = paths[name]
        if path.is_symlink():
            raise ChangeError(f"Refusing symlinked {name}.")
        if not path.exists():
            counts[name] = 0
            continue
        raw = path.read_bytes()
        updated, n = _transform_env(raw, name, old_ip, new_ip)
        counts[name] = n
        if updated != raw:
            changes[path] = updated
    for name in ("caddy", "subpage_caddy"):
        path = paths[name]
        if path.is_symlink():
            raise ChangeError(f"Refusing symlinked {name}.")
        if not path.exists():
            counts[name] = 0
            continue
        raw = path.read_bytes()
        updated, n = transform_caddy(raw, old_ip, new_ip)
        counts[name] = n
        if updated != raw:
            changes[path] = updated
    xray_path = paths["xray"]
    if xray_path.is_symlink():
        raise ChangeError("Refusing a symlinked Xray config.")
    if xray_path.exists():
        raw = xray_path.read_bytes()
        updated, n = transform_xray(raw, old_ip, new_ip)
        counts["xray"] = n
        if updated != raw:
            changes[xray_path] = updated
    else:
        counts["xray"] = 0
    return changes, counts, {"old_domain": _domain_for(old_ip), "new_domain": _domain_for(new_ip)}


def _validate_staged_xray(path: Path, data: bytes, runner: Callable[..., Any]) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.stem}.stage-", suffix=".json", dir=str(path.parent))
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        result = runner(["/usr/local/bin/xray", "run", "-test", "-config", str(staged)],
                        capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            raise ChangeError("Staged Xray config validation failed.")
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("Staged Xray config validation failed.") from None
    finally:
        staged.unlink(missing_ok=True)


def _validate_staged_caddy(main_path: Path, subpage_path: Path, candidates: dict[Path, bytes],
                           runner: Callable[..., Any]) -> None:
    if main_path.is_symlink() or not main_path.is_file():
        raise ChangeError("Main Caddy configuration is missing or symlinked.")
    stage_files: list[Path] = []
    try:
        main_data = candidates.get(main_path, main_path.read_bytes())
        subpage_data = candidates.get(subpage_path, subpage_path.read_bytes() if subpage_path.exists() else None)
        stage_subpage: Path | None = None
        if subpage_data is not None:
            fd, name = tempfile.mkstemp(prefix=".fodder-vpn-subpage-stage-", suffix=".caddy", dir=str(subpage_path.parent))
            stage_subpage = Path(name)
            with os.fdopen(fd, "wb") as handle:
                handle.write(subpage_data)
                handle.flush()
                os.fsync(handle.fileno())
            stage_files.append(stage_subpage)
        text = main_data.decode("utf-8")
        replaced_subpage_import = False
        if stage_subpage is not None:
            lines: list[str] = []
            for line in text.splitlines(keepends=True):
                match = re.match(r"^(?P<indent>\s*import\s+)(?P<path>[^\s{}]+)(?P<tail>\s*(?:#.*)?(?:\r?\n)?)$", line, re.I)
                if not match:
                    lines.append(line)
                    continue
                source = match.group("path").strip('"\'')
                candidate = (main_path.parent / source).resolve() if not Path(source).is_absolute() else Path(source).resolve()
                if candidate == subpage_path.resolve() or Path(source).name == subpage_path.name:
                    lines.append(match.group("indent") + str(stage_subpage) + match.group("tail"))
                    replaced_subpage_import = True
                elif any(char in source for char in "*?["):
                    try:
                        matches = sorted(Path(p).resolve() for p in __import__("glob").glob(str(main_path.parent / source)))
                    except Exception:
                        matches = []
                    if subpage_path.resolve() in matches:
                        for item in matches:
                            replacement = stage_subpage if item == subpage_path.resolve() else item
                            lines.append(match.group("indent") + str(replacement) + match.group("tail"))
                        replaced_subpage_import = True
                    else:
                        lines.append(line)
                else:
                    lines.append(line)
            if subpage_path in candidates and not replaced_subpage_import:
                raise ChangeError("Staged subpage Caddy file is not imported by the main configuration.")
            main_data = "".join(lines).encode("utf-8")
        fd, name = tempfile.mkstemp(prefix=f".{main_path.name}.nl-stage-", suffix=".caddyfile", dir=str(main_path.parent))
        stage_main = Path(name)
        with os.fdopen(fd, "wb") as handle:
            handle.write(main_data)
            handle.flush()
            os.fsync(handle.fileno())
        stage_files.append(stage_main)
        _checked(["caddy", "validate", "--config", str(stage_main), "--adapter", "caddyfile"], runner)
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("Staged full Caddy configuration validation failed.") from None
    finally:
        for path in stage_files:
            path.unlink(missing_ok=True)


def _checked(args: list[str], runner: Callable[..., Any], *, input_text: str | None = None, timeout: int = 120) -> Any:
    try:
        result = runner(args, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception:
        raise ChangeError(f"Required operation failed: {args[0]}.") from None
    if result.returncode:
        raise ChangeError(f"Required operation failed: {args[0]}.")
    return result


def _pg_run(sql: str, runner: Callable[..., Any], timeout: int = 120) -> str:
    args = ["docker", "exec", "-i", "remnawave-db", "sh", "-c",
            'exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -F "|"']
    result = _checked(args, runner, input_text=sql, timeout=timeout)
    return result.stdout.strip()


def _pg_rows(old_ip: str, runner: Callable[..., Any]) -> list[tuple[str, str, str]]:
    sql = " UNION ALL ".join(
        f"SELECT '{table}', uuid::text, address FROM public.{table} WHERE address = '{old_ip}'"
        for table in ("hosts", "nodes")
    ) + ";\n"
    output = _pg_run(sql, runner, timeout=45)
    rows: list[tuple[str, str, str]] = []
    for line in output.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3 or parts[0] not in {"hosts", "nodes"} or not re.fullmatch(r"[0-9a-fA-F-]{36}", parts[1]) or parts[2] != old_ip:
            raise ChangeError("Remnawave node lookup returned invalid metadata.")
        rows.append((parts[0], parts[1], parts[2]))
    return rows


def _pg_dump(container: str, dest: Path, runner: Callable[..., Any]) -> None:
    command = ["docker", "exec", container, "sh", "-c",
               'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc']
    try:
        result = runner(command, capture_output=True, timeout=180, check=False)
    except Exception:
        raise ChangeError("PostgreSQL backup failed before any database update.") from None
    if result.returncode:
        raise ChangeError("PostgreSQL backup failed before any database update.")
    data = result.stdout if isinstance(result.stdout, bytes) else str(result.stdout).encode("latin1")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _pg_apply(rows: list[tuple[str, str, str]], old_ip: str, new_ip: str, runner: Callable[..., Any]) -> None:
    statements = ["BEGIN;"]
    for table, uuid, _address in rows:
        statements.append(
            "DO $$ BEGIN UPDATE public." + table + " SET address='" + new_ip + "' WHERE uuid='" + uuid
            + "' AND address='" + old_ip + "'; IF NOT FOUND THEN RAISE EXCEPTION 'row_changed'; END IF; END $$;"
        )
    statements.append("COMMIT;")
    _pg_run("\n".join(statements), runner, timeout=90)


def _pg_restore(rows: list[tuple[str, str, str]], old_ip: str, new_ip: str, runner: Callable[..., Any]) -> bool:
    if not rows:
        return True
    statements = ["BEGIN;"]
    for table, uuid, _address in rows:
        statements.append(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM public." + table + " WHERE uuid='" + uuid + "' AND address='" + new_ip
            + "') THEN UPDATE public." + table + " SET address='" + old_ip + "' WHERE uuid='" + uuid
            + "' AND address='" + new_ip + "'; ELSIF NOT EXISTS (SELECT 1 FROM public." + table + " WHERE uuid='" + uuid
            + "' AND address='" + old_ip + "') THEN RAISE EXCEPTION 'row_changed'; END IF; END $$;"
        )
    statements.append("COMMIT;")
    try:
        _pg_run("\n".join(statements), runner, timeout=90)
        return True
    except ChangeError:
        return False


def _sqlite_rows(path: Path, old_ip: str) -> list[tuple[str, str, str]]:
    if path.is_symlink():
        raise ChangeError("Refusing a symlinked account database.")
    if not path.exists():
        return []
    try:
        conn = sqlite3.connect("file:" + str(path.resolve()) + "?mode=ro", uri=True)
        try:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "saved_servers" not in tables:
                return []
            columns = {row[1] for row in conn.execute("PRAGMA table_info(saved_servers)")}
            target_columns = [name for name in ("host", "relay_host", "relay_public_host") if name in columns]
            rows: list[tuple[str, str, str]] = []
            for column in target_columns:
                rows.extend((str(row[0]), column, str(row[1])) for row in conn.execute(
                    f'SELECT id, "{column}" FROM saved_servers WHERE "{column}" = ?', (old_ip,)))
            return rows
        finally:
            conn.close()
    except sqlite3.Error:
        raise ChangeError("Could not inspect saved server database rows.") from None


def _sqlite_apply(path: Path, rows: list[tuple[str, str, str]], old_ip: str, new_ip: str) -> None:
    if not rows:
        return
    try:
        conn = sqlite3.connect(path, timeout=15)
        try:
            with conn:
                for row_id, column, original in rows:
                    cur = conn.execute(f'UPDATE saved_servers SET "{column}" = ? WHERE id = ? AND "{column}" = ?',
                                       (new_ip, row_id, original))
                    if cur.rowcount != 1:
                        raise sqlite3.IntegrityError("saved_server_changed")
        finally:
            conn.close()
    except sqlite3.Error:
        raise ChangeError("Saved server addresses could not be updated transactionally.") from None


def _sqlite_restore(path: Path, rows: list[tuple[str, str, str]], old_ip: str, new_ip: str) -> bool:
    try:
        conn = sqlite3.connect(path, timeout=15)
        try:
            with conn:
                for row_id, column, original in rows:
                    cur = conn.execute(f'UPDATE saved_servers SET "{column}" = ? WHERE id = ? AND "{column}" = ?',
                                       (original, row_id, new_ip))
                    if cur.rowcount == 0:
                        current = conn.execute(f'SELECT "{column}" FROM saved_servers WHERE id = ?', (row_id,)).fetchone()
                        if current is None or current[0] != original:
                            raise sqlite3.IntegrityError("saved_server_changed")
        finally:
            conn.close()
        return True
    except sqlite3.Error:
        return False


def _online_sqlite_backup(path: Path, dest: Path) -> None:
    if path.is_symlink():
        raise ChangeError("Refusing to back up a symlinked account database.")
    if not path.exists():
        return
    source = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    target = sqlite3.connect(dest)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(dest, 0o600)


def _menu_layout_call(mode: str, old_ip: str, new_ip: str, payload: dict[str, Any], runner: Callable[..., Any]) -> dict[str, Any]:
    # The helper leaves buttons/rows intact and changes only their URL actions.
    code = r'''import asyncio,copy,hashlib,json,sys
from app.database.database import AsyncSessionLocal
from app.services.menu_layout.service import MenuLayoutService
mode,old_ip,new_ip=sys.argv[1:]
old_domain=old_ip.replace('.','-')+'.nip.io'; new_domain=new_ip.replace('.','-')+'.nip.io'
def repl(s):
 import re
 s=re.sub(r'(?<![A-Za-z0-9-])'+re.escape(old_domain)+r'(?=$|[/:?#,\s\'";])',new_domain,s,flags=re.I)
 s=re.sub(r'(?<![0-9.])'+re.escape(old_ip)+r'(?![0-9.])',new_ip,s)
 return s
def digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
async def run():
 payload=json.load(sys.stdin)
 async with AsyncSessionLocal() as db:
  current=copy.deepcopy(await MenuLayoutService.get_config(db)); current_hash=digest(current)
  if mode=='read': print(json.dumps({'config':current,'digest':current_hash},separators=(',',':'),ensure_ascii=False)); return
  if mode=='restore':
   target=payload['config']; target_hash=digest(target)
   if current_hash == target_hash: print(json.dumps({'restored':True})); return
   if current_hash != payload['expected_digest']: raise RuntimeError('layout_changed')
   val=MenuLayoutService.validate_config(target)
   if not val['is_valid']: raise RuntimeError('restore_invalid')
   await MenuLayoutService.save_config(db,target); print(json.dumps({'restored':True})); return
  if current_hash != payload['expected_digest']: raise RuntimeError('layout_changed')
  updated=copy.deepcopy(current)
  def visit(value,key=''):
   if isinstance(value,dict):
    for k,v in list(value.items()):
     if isinstance(v,str) and k in ('action','url','web_app_url'):
      value[k]=repl(v)
     else: visit(v,k)
   elif isinstance(value,list):
    for item in value: visit(item,key)
  visit(updated)
  val=MenuLayoutService.validate_config(updated)
  if not val['is_valid']: raise RuntimeError('layout_invalid')
  if updated != current: await MenuLayoutService.save_config(db,updated)
  print(json.dumps({'changed':updated!=current,'digest':digest(updated)},separators=(',',':')))
asyncio.run(run())
'''
    args = ["docker", "exec", "-i", "remnawave_bot", "python", "-c", code, mode, old_ip, new_ip]
    try:
        result = runner(args, input=json.dumps(payload, separators=(",", ":")), capture_output=True,
                        text=True, timeout=60, check=False)
        data = json.loads(result.stdout) if result.stdout else {}
    except Exception:
        raise ChangeError("Bedolaga menu layout could not be inspected or updated safely.") from None
    if result.returncode or not isinstance(data, dict):
        raise ChangeError("Bedolaga menu layout operation failed safely.")
    return data


def _telegram_menu(token: str, method: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"https://api.telegram.org/bot{token}/{method}"
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                    headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read(65536))
    except Exception:
        raise ChangeError("Telegram menu URL update failed; no user messages were sent.") from None
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise ChangeError("Telegram menu URL update failed; no user messages were sent.")
    return result.get("result") if isinstance(result.get("result"), dict) else {}


def _rewrite_menu_config(value: Any, old_ip: str, new_ip: str) -> Any:
    old_domain, new_domain = _domain_for(old_ip), _domain_for(new_ip)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(item, str) and key in {"action", "url", "web_app_url"}:
                result[key] = _replace_refs(item, old_ip, new_ip, old_domain, new_domain)
            else:
                result[key] = _rewrite_menu_config(item, old_ip, new_ip)
        return result
    if isinstance(value, list):
        return [_rewrite_menu_config(item, old_ip, new_ip) for item in value]
    return value


def _menu_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


@contextmanager
def _migration_lock():
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        lock_path = Path("/run/lock/vpn-wizard-nl-endpoint-migration.lock")
    else:
        lock_path = Path(tempfile.gettempdir()) / "vpn-wizard-nl-endpoint-migration.lock"
    if lock_path.is_symlink():
        raise ChangeError("NL migration lock file cannot be a symlink.")
    try:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock_path, flags, 0o600)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ChangeError("NL migration lock must be a regular file.")
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0 and metadata.st_uid != 0:
            raise ChangeError("NL migration lock file must be owned by root.")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ChangeError("NL migration lock file must have mode 0600.")
        if os.name == "nt":
            os.chmod(lock_path, 0o600)
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("Could not acquire the NL migration lock.") from None
    finally:
        if "fd" in locals():
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:
                pass
            os.close(fd)


def _locked_migration(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        with _migration_lock():
            return function(*args, **kwargs)
    return wrapper


def _pending_journal_path(backup_root: Path) -> Path:
    return backup_root / "nl-endpoint.pending.json"


def _read_pending_journal(backup_root: Path) -> dict[str, Any] | None:
    path = _pending_journal_path(backup_root)
    if path.is_symlink():
        raise ChangeError("Pending NL migration journal cannot be a symlink.")
    if not path.exists():
        return None
    try:
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ChangeError("Pending NL migration journal must be a regular mode-0600 file.")
        if os.name != "nt" and metadata.st_uid != 0:
            raise ChangeError("Pending NL migration journal must be root-owned.")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("Pending NL migration journal is unreadable or invalid.") from None
    if not isinstance(payload, dict) or payload.get("schema") != 1 or payload.get("status") != "pending":
        raise ChangeError("Pending NL migration journal has an unsupported format.")
    try:
        old_ip = validate_public_ipv4(payload.get("old_ip", ""))
        new_ip = validate_public_ipv4(payload.get("new_ip", ""))
    except ChangeError:
        raise ChangeError("Pending NL migration journal contains invalid endpoint addresses.") from None
    backup_id = payload.get("initial_backup")
    if not isinstance(backup_id, str) or not re.fullmatch(r"change-nl-ip-[A-Za-z0-9_-]+", backup_id):
        raise ChangeError("Pending NL migration journal identity is invalid.")
    backup = backup_root / backup_id
    if backup.parent != backup_root or backup.is_symlink() or not backup.is_dir():
        raise ChangeError("Pending NL migration backup directory is missing or unsafe.")
    services = payload.get("service_needs")
    service_keys = {"caddy", "api", "bedolaga", "remnawave", "xray"}
    if not isinstance(services, dict) or set(services) != service_keys or not all(type(v) is bool for v in services.values()):
        raise ChangeError("Pending NL migration service recovery metadata is invalid.")
    return {"old_ip": old_ip, "new_ip": new_ip, "initial_backup": backup_id, "service_needs": services}


def _write_pending_journal(backup_root: Path, old_ip: str, new_ip: str, backup_id: str,
                           service_needs: dict[str, bool]) -> None:
    path = _pending_journal_path(backup_root)
    if path.is_symlink() or path.exists():
        raise ChangeError("A pending NL migration journal already exists; refusing a second migration.")
    data = json.dumps({"schema": 1, "status": "pending", "old_ip": old_ip, "new_ip": new_ip,
                       "initial_backup": backup_id, "service_needs": service_needs}, separators=(",", ":")).encode()
    fd, name = tempfile.mkstemp(prefix=".nl-endpoint-journal-", dir=str(backup_root))
    temp = Path(name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(temp, 0o600)
        if hasattr(os, "fchown") and hasattr(os, "geteuid") and os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
        if os.name != "nt":
            dfd = os.open(backup_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    finally:
        temp.unlink(missing_ok=True)


def _clear_pending_journal(backup_root: Path) -> None:
    path = _pending_journal_path(backup_root)
    if path.exists():
        _read_pending_journal(backup_root)
        path.unlink()
        if os.name != "nt":
            dfd = os.open(backup_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)


def _tls_wait(domain: str, checker: Callable[[str], dict[str, Any]], attempts: int = 30) -> dict[str, Any]:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            return checker(domain)
        except Exception as exc:
            last = exc
            time.sleep(3)
    if last:
        raise ChangeError("New public hostname TLS/catalog verification failed after bounded retries.") from None
    raise ChangeError("New public hostname TLS/catalog verification failed.")


@_locked_migration
def migrate_controller(new_ip: str, env_path: Path = DEFAULT_ENV, apply: bool = False, *,
                       runtime_runner: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
                       command_runner: Callable[..., Any] = subprocess.run,
                       service_runner: Callable[..., Any] = subprocess.run,
                       backup_root: Path = BACKUP_ROOT,
                       paths: dict[str, Path] | None = None,
                       address_checker: Callable[[str], bool] | None = None,
                       tls_checker: Callable[[str], dict[str, Any]] = _local_tls_check,
                       xray_tls_checker: Callable[[str], dict[str, Any]] = _local_xray_tls_check,
                       certificate_sync: Callable[[str], Any] | None = None,
                       menu_layout_updater: Callable[..., Any] | None = None,
                       telegram_client: Callable[..., Any] = _telegram_menu,
                       root_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    new_ip = validate_public_ipv4(new_ip)
    backup_root = Path(backup_root)
    if backup_root.is_symlink():
        raise ChangeError("Private backup root cannot be a symlink.")
    pending_journal = _read_pending_journal(backup_root)
    paths = {**DEFAULT_PATHS, **(paths or {})}
    if env_path.is_symlink() or not env_path.is_file():
        raise ChangeError("Environment file is missing or symlinked.")
    helper = _exit_helper()
    values, _lines, _index = helper.parse_env(env_path.read_bytes())
    nodes = json.loads(values["VPNW_AWG_SERVERS"])
    nl = [node for node in nodes if node.get("id") == "nl"]
    if len(nl) != 1:
        raise ChangeError("Expected exactly one NL public registry entry.")
    selected = [nl[0]] + [node for node in nodes if node is not nl[0] and
                          (node.get("id") == "nl-alt" or node.get("alt_of") == "nl")]
    old_ips = {str(node.get("public_host") or "") for node in selected}
    if len(old_ips) != 1 or not next(iter(old_ips)):
        raise ChangeError("NL and nl-alt must share one current public endpoint.")
    registry_ip = validate_public_ipv4(next(iter(old_ips)))
    recovery = pending_journal is not None
    if pending_journal:
        if new_ip != pending_journal["new_ip"]:
            raise ChangeError("A pending NL migration targets a different IP; finish that target before starting another.")
        if registry_ip not in {pending_journal["old_ip"], pending_journal["new_ip"]}:
            raise ChangeError("Pending NL migration journal does not match the current registry endpoint.")
        old_ip = pending_journal["old_ip"]
    else:
        old_ip = registry_ip
    for node in selected:
        if str(node.get("host") or "").strip() != "127.0.0.1":
            raise ChangeError("NL SSH control hosts must remain loopback.")
        if not isinstance(node.get("listen_port"), int) or not 1 <= node["listen_port"] <= 65535:
            raise ChangeError("NL registry listen ports are invalid.")
    if len([n for n in selected if n.get("id") == "nl-alt"]) != 1:
        raise ChangeError("Expected exactly one nl-alt registry entry.")
    if not values.get("VPNW_AWG_DEFAULT_SERVER", "nl").strip() in {"", "nl"}:
        raise ChangeError("The default AWG server must remain NL during this migration.")
    if not values.get("VPNW_SECRET_KEY", "").strip():
        raise ChangeError("VPNW_SECRET_KEY is required to verify cached encrypted identities.")
    state_raw = values.get("VPNW_STATE_DB", "").strip()
    if state_raw == ":memory:":
        raise ChangeError("A file-backed account database is required to verify NL identities.")
    state_db = Path(state_raw) if state_raw else Path(__file__).resolve().parents[2] / ".vpnw" / "state.db"
    identities = cached_nl_identities([state_db, state_db.with_name("public-access.db")], values["VPNW_SECRET_KEY"])
    iface_payload = [
        {"id": str(node["id"]), "interface": node.get("interface") or None,
         "listen_port": int(node["listen_port"]), "public_key": identities[str(node["id"])]}
        for node in selected
    ]
    assigned = address_checker(new_ip) if address_checker else _assigned_address(new_ip, command_runner)
    if not assigned:
        raise ChangeError("New IP is not assigned to a local network interface.")
    run_runtime = runtime_runner or (lambda payload: _run_payload(payload, command_runner))
    inspection = run_runtime({"mode": "inspect", "old_ip": old_ip, "new_ip": new_ip, "interfaces": iface_payload})
    interfaces = _verify_runtime_identities(inspection.get("interfaces"), iface_payload)
    profile_count = inspection.get("profiles_to_update")
    if not isinstance(interfaces, dict) or not isinstance(profile_count, int) or profile_count < 0:
        raise ChangeError("NL runtime inspection returned invalid metadata.")
    changes, file_counts, domains = _read_candidates(env_path, paths, old_ip, new_ip)
    old_domain, new_domain = domains["old_domain"], domains["new_domain"]
    db_rows = _sqlite_rows(state_db, old_ip)
    if old_ip == new_ip:
        db_rows = []
    pg_rows = _pg_rows(old_ip, command_runner) if old_ip != new_ip and paths["remnawave_env"].exists() else []
    bedolaga_values = _read_simple_env(paths["bedolaga_env"]) if paths["bedolaga_env"].exists() else {}
    token = bedolaga_values.get("BOT_TOKEN", "").strip()
    updater = menu_layout_updater or (lambda mode, payload: _menu_layout_call(mode, old_ip, new_ip, payload, command_runner))
    menu_preflight: dict[str, Any] | None = None
    telegram_needs_update = False
    menu_layout_needs_update = False
    current_button: dict[str, Any] | None = None
    if token:
        menu_preflight = updater("read", {})
        if not isinstance(menu_preflight.get("config"), dict) or not isinstance(menu_preflight.get("digest"), str):
            raise ChangeError("Bedolaga menu layout inspection returned invalid metadata.")
        menu_layout_needs_update = _rewrite_menu_config(menu_preflight["config"], old_ip, new_ip) != menu_preflight["config"]
        current_button = telegram_client(token, "getChatMenuButton", {})
        desired_portal = _replace_refs(bedolaga_values.get("FODDERS_PORTAL_URL", "https://" + old_domain),
                                       old_ip, new_ip, old_domain, new_domain)
        current_url = (current_button.get("web_app") or {}).get("url") if isinstance(current_button, dict) else None
        telegram_needs_update = not isinstance(current_button, dict) or current_button.get("type") != "web_app" or current_url != desired_portal
    elif old_ip != new_ip and paths["bedolaga_env"].exists():
        raise ChangeError("Bedolaga BOT_TOKEN is missing; cannot update and verify its Telegram menu URL.")
    service_needs = {
        "caddy": paths["caddy"] in changes or paths["subpage_caddy"] in changes,
        "api": env_path in changes,
        "bedolaga": paths["bedolaga_env"] in changes,
        "remnawave": paths["remnawave_env"] in changes or paths["subpage_env"] in changes or bool(pg_rows),
        "xray": paths["xray"] in changes,
    }
    if pending_journal:
        service_needs = {key: value or pending_journal["service_needs"][key]
                         for key, value in service_needs.items()}
    total_changed = bool(changes or profile_count or db_rows or pg_rows or menu_layout_needs_update or telegram_needs_update)
    if not apply:
        tls = _tls_wait(new_domain, tls_checker, attempts=1)
        xray_tls = None
        if _xray_has_trial(paths["xray"]):
            xray_tls = _tls_wait(new_domain, xray_tls_checker, attempts=1)
        return {"server": "nl", "old_ip": old_ip, "new_ip": new_ip, "selected_profiles": len(selected),
                "profiles_to_update": profile_count, "runtime_verified": True,
                "files_to_update": len(changes), "database_rows_to_update": len(db_rows),
                "remnawave_rows_to_update": len(pg_rows), "menu_layout_would_update": menu_layout_needs_update,
                "telegram_menu_would_update": telegram_needs_update,
                "verified": True, "applied": False, "recovery_pending": recovery,
                "would_change": bool(total_changed or recovery), "tls": tls, "xray_tls": xray_tls}
    if root_check is not None and not root_check():
        raise ChangeError("Applying an NL endpoint migration requires root on the control server.")
    if root_check is None and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ChangeError("Applying an NL endpoint migration requires root on the control server.")
    if not total_changed and not recovery:
        tls = _tls_wait(new_domain, tls_checker)
        xray_tls = _tls_wait(new_domain, xray_tls_checker) if _xray_has_trial(paths["xray"]) else None
        return {"server": "nl", "old_ip": old_ip, "new_ip": new_ip, "selected_profiles": len(selected),
                "profiles_changed": 0, "runtime_verified": True, "changed": False,
                "services_restarted": False, "tls": tls, "xray_tls": xray_tls, "verified": True, "applied": True}

    # Every file is validated before backup or mutation. Optional absent paths are
    # explicitly skipped; present symlinks are rejected by _read_candidates.
    snapshots: dict[Path, tuple[bytes, os.stat_result]] = {}
    for path in (paths["cert"], paths["key"]):
        if path.is_symlink():
            raise ChangeError("Refusing a symlinked Xray certificate or private key.")
    for path in set(changes) | {p for p in (paths["cert"], paths["key"]) if p.exists()}:
        metadata = _lstat_regular(path)
        snapshots[path] = (path.read_bytes(), metadata)
    # Online backups preserve a consistent view of both SQLite databases before
    # saved-server rows or menu configuration are touched.
    for db_path in (state_db, state_db.with_name("public-access.db")):
        if db_path.exists() and db_path.is_symlink():
            raise ChangeError("Refusing to back up a symlinked SQLite database.")
    backup = _backup_files(backup_root, snapshots)
    for db_path in (state_db, state_db.with_name("public-access.db")):
        if db_path.exists():
            _online_sqlite_backup(db_path, backup / ("sqlite-" + db_path.name))
    _pg_dump("remnawave-db", backup / "remnawave.dump", command_runner)
    _pg_dump("remnawave_bot_db", backup / "bedolaga.dump", command_runner)
    (backup / "remnawave-target-rows.json").write_text(
        json.dumps([{"table": table, "uuid": row_uuid, "address": address}
                   for table, row_uuid, address in pg_rows], separators=(",", ":")), encoding="utf-8")
    os.chmod(backup / "remnawave-target-rows.json", 0o600)
    (backup / "database-backups.json").write_text(
        json.dumps(["remnawave-db", "remnawave_bot_db"], separators=(",", ":")), encoding="utf-8")
    os.chmod(backup / "database-backups.json", 0o600)
    journal_backup_id = pending_journal["initial_backup"] if pending_journal else backup.name
    changed_paths: list[Path] = []
    caddy_touched = False
    api_touched = False
    bedolaga_touched = False
    remnawave_touched = False
    xray_touched = False
    menu_metadata: dict[str, Any] = {"telegram_menu_updated": False, "menu_layout_updated": False}
    try:
        caddy_changed = service_needs["caddy"]
        xray_changed = service_needs["xray"]
        if caddy_changed:
            _validate_staged_caddy(paths["caddy"], paths["subpage_caddy"], changes, command_runner)
        if xray_changed:
            _validate_staged_xray(paths["xray"], changes.get(paths["xray"], paths["xray"].read_bytes()), command_runner)
        if not pending_journal:
            _write_pending_journal(backup_root, old_ip, new_ip, backup.name, service_needs)
        for path, data in changes.items():
            # Add to rollback set before replace; replace can succeed before a
            # directory fsync reports failure.
            changed_paths.append(path)
            _atomic_write(path, data, snapshots[path][1])
        if caddy_changed:
            _checked(["caddy", "validate", "--config", str(paths["caddy"])], command_runner)
            caddy_touched = True
            _checked(["systemctl", "reload", "caddy"], service_runner)
            _tls_wait(new_domain, tls_checker)
        # Runtime endpoint rewrites use the existing standalone AWG helper. It
        # verifies all interfaces before and after and never restarts AWG.
        remote_report = run_runtime({"mode": "apply", "old_ip": old_ip, "new_ip": new_ip, "interfaces": iface_payload}) if profile_count else {
            "applied": True, "profiles_changed": 0, "keys_and_peers_unchanged": True}
        if remote_report.get("applied") is not True or remote_report.get("keys_and_peers_unchanged") is not True:
            raise ChangeError("AWG profile update or identity verification failed.")
        if profile_count:
            _verify_runtime_identities(remote_report.get("interfaces"), iface_payload, interfaces)
        api_changed = service_needs["api"]
        remna_changed = service_needs["remnawave"]
        # Read and privately snapshot Bedolaga's persisted button layout before
        # either database is changed. The update itself is conditional on the
        # saved digest still matching this snapshot.
        if token and menu_preflight:
            layout_config = menu_preflight["config"]
            layout_digest = menu_preflight["digest"]
            menu_metadata["previous_menu"] = current_button or {}
            layout_backup = backup / "bedolaga-menu-layout.json"
            layout_backup.write_text(json.dumps(layout_config, ensure_ascii=False), encoding="utf-8")
            os.chmod(layout_backup, 0o600)
            menu_metadata["menu_layout_original"] = layout_config
            menu_metadata["menu_layout_digest"] = layout_digest
        sqlite_changed = bool(db_rows)
        if sqlite_changed:
            _sqlite_apply(state_db, db_rows, old_ip, new_ip)
        if pg_rows:
            _pg_apply(pg_rows, old_ip, new_ip, command_runner)
        if api_changed:
            api_touched = True
            _checked(["systemctl", "restart", "vpn-wizard"], service_runner)
            _checked(["systemctl", "start", "vpn-wizard-awg-health.service"], service_runner, timeout=120)
        if service_needs["bedolaga"]:
            bedolaga_touched = True
            _checked(["docker", "compose", "-f", "/opt/bedolaga/docker-compose.yml", "up", "-d", "--no-deps",
                      "--force-recreate", "--pull", "never", "bot"], service_runner, timeout=180)
        if remna_changed or pg_rows:
            remnawave_touched = True
            _checked(["docker", "compose", "-f", "/opt/remnawave/docker-compose.yml", "up", "-d", "--no-deps",
                      "--force-recreate", "--pull", "never", "remnawave", "remnawave-subscription-page"],
                     service_runner, timeout=180)
        if token and telegram_needs_update:
            portal = _replace_refs(bedolaga_values.get("FODDERS_PORTAL_URL", "https://" + old_domain), old_ip, new_ip, old_domain, new_domain)
            telegram_client(token, "setChatMenuButton", {"menu_button": {"type": "web_app", "text": "Fodder VPN", "web_app": {"url": portal}}})
            menu_metadata["telegram_menu_updated"] = True
        if token and menu_layout_needs_update:
            menu_metadata["menu_layout_applied_digest"] = _menu_digest(_rewrite_menu_config(layout_config, old_ip, new_ip))
            layout_result = updater("apply", {"expected_digest": menu_metadata["menu_layout_digest"]})
            menu_metadata["menu_layout_updated"] = bool(layout_result.get("changed"))
            menu_metadata["menu_layout_applied_digest"] = layout_result.get("digest") or menu_metadata["menu_layout_applied_digest"]
        if xray_changed:
            # The certificate helper may replace both private files. They were
            # snapshotted before this point and must join the rollback set first.
            for cert_path in (paths["cert"], paths["key"]):
                if cert_path.exists() and cert_path not in changed_paths:
                    changed_paths.append(cert_path)
            xray_touched = True
            if certificate_sync is None:
                cert_args = ["/usr/bin/python3", "/opt/vpn-wizard/app/deploy/scripts/refresh-xhttp-test-certificate.py",
                             "--domain", new_domain, "--apply"]
                _checked(cert_args, command_runner, timeout=180)
            else:
                certificate_sync(new_domain)
            xray_tls = _tls_wait(new_domain, xray_tls_checker)
        else:
            xray_tls = _tls_wait(new_domain, xray_tls_checker) if _xray_has_trial(paths["xray"]) else None
        if caddy_changed:
            _checked(["systemctl", "is-active", "--quiet", "caddy"], service_runner)
        tls = _tls_wait(new_domain, tls_checker)
        _clear_pending_journal(backup_root)
        return {"server": "nl", "old_ip": old_ip, "new_ip": new_ip, "selected_profiles": len(selected),
                "profiles_changed": int(remote_report.get("profiles_changed", profile_count)),
                "runtime_verified": True, "files_changed": len(changes), "sqlite_rows_changed": len(db_rows),
                "remnawave_rows_changed": len(pg_rows), "changed": True, "services_restarted": True,
                "backup": journal_backup_id, "recovered": recovery, "tls": tls, "xray_tls": xray_tls, "menu": {k: v for k, v in menu_metadata.items()
                                                                  if k.endswith("updated")},
                "verified": True, "applied": True}
    except Exception as failure:
        failure_report = failure.report if isinstance(failure, RuntimeOperationFailure) else {}
        profile_rollback = failure_report.get("rollback_ok") is True if "rollback_ok" in failure_report else True
        remote_report = locals().get("remote_report")
        remote_backup = (remote_report.get("backup_id") if isinstance(remote_report, dict) else None) or failure_report.get("backup_id")
        if remote_backup and (not failure_report or failure_report.get("rollback_ok") is not True):
            try:
                restore = run_runtime({"mode": "restore", "backup_id": remote_backup})
                profile_rollback = restore.get("rollback_ok") is True
            except Exception:
                profile_rollback = False
        sqlite_rollback = _sqlite_restore(state_db, db_rows, old_ip, new_ip) if locals().get("sqlite_changed") else True
        pg_rollback = _pg_restore(pg_rows, old_ip, new_ip, command_runner) if locals().get("pg_rows") else True
        menu_rollback = True
        menu_state = locals().get("menu_metadata", {})
        if menu_state.get("menu_layout_original") is not None and menu_state.get("menu_layout_applied_digest"):
            try:
                updater = menu_layout_updater or (lambda mode, payload: _menu_layout_call(mode, old_ip, new_ip, payload, command_runner))
                menu_rollback = updater("restore", {"expected_digest": menu_state.get("menu_layout_applied_digest"),
                                                       "config": menu_state["menu_layout_original"]}).get("restored") is True
            except Exception:
                menu_rollback = False
        if menu_state.get("previous_menu") is not None and paths["bedolaga_env"].exists():
            try:
                token = _read_simple_env(paths["bedolaga_env"]).get("BOT_TOKEN", "").strip()
                if token:
                    telegram_client(token, "setChatMenuButton", {"menu_button": menu_state["previous_menu"]})
            except Exception:
                menu_rollback = False
        files_rollback = _restore_snapshots(snapshots, locals().get("changed_paths", []))
        service_rollback: bool | None = None
        if any((caddy_touched, api_touched, bedolaga_touched, remnawave_touched, xray_touched)):
            service_rollback = True
            try:
                if caddy_touched:
                    _checked(["caddy", "validate", "--config", str(paths["caddy"])], command_runner)
                    _checked(["systemctl", "reload", "caddy"], service_runner)
                if api_touched:
                    _checked(["systemctl", "restart", "vpn-wizard"], service_runner)
                    _checked(["systemctl", "start", "vpn-wizard-awg-health.service"], service_runner, timeout=120)
                if bedolaga_touched:
                    _checked(["docker", "compose", "-f", "/opt/bedolaga/docker-compose.yml", "up", "-d", "--no-deps",
                              "--force-recreate", "--pull", "never", "bot"], service_runner, timeout=180)
                if remnawave_touched:
                    _checked(["docker", "compose", "-f", "/opt/remnawave/docker-compose.yml", "up", "-d", "--no-deps",
                              "--force-recreate", "--pull", "never", "remnawave", "remnawave-subscription-page"],
                             service_runner, timeout=180)
                if xray_touched:
                    _checked(["systemctl", "restart", "xray"], service_runner)
            except ChangeError:
                service_rollback = False
        message = str(failure) if isinstance(failure, ChangeError) else "NL migration failed after changes began."
        journal_path = _pending_journal_path(backup_root)
        journal_status = ("Pending journal retained; rerun the same target to resume."
                          if journal_path.is_file() and not journal_path.is_symlink()
                          else "No pending journal was created.")
        raise ChangeError(f"{message} Rollback status: files={files_rollback}, profiles={profile_rollback}, sqlite={sqlite_rollback}, remnawave_db={pg_rollback}, menus={menu_rollback}, services={service_rollback}. {journal_status} Backup: {journal_backup_id}.") from None


def _read_simple_env(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ChangeError(f"Could not read {path.name} as UTF-8.") from None
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = ENV_LINE.match(line)
        if match:
            name = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", match.group("prefix"))
            if name:
                values[name.group(1)] = _decode_value(match.group("value"))[0]
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--new-ip", required=True)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--apply", action="store_true", help="apply after verification; default is dry-run")
    args = parser.parse_args(argv)
    try:
        result = migrate_controller(args.new_ip, env_path=args.env, apply=args.apply)
    except ChangeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
