"""Update the stable fodders.ru VPN shortcut after a VPN endpoint change.

The public shortcut is backed by a small Caddy import on the site server. This
module validates a candidate IP, checks the new endpoint before applying, and
keeps the live Caddy files recoverable if validation or reload fails.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

import paramiko


SITE_URL = "https://fodders.ru/vpn/"
SITE_ORIGIN = "https://fodders.ru"
JOIN_PATH = "/connect/join.html"
CATALOG_PATH = "/api/awg/servers?include_unavailable=true"
ADDRESS_HISTORY_PATH = "/connect/server-address-history.json"
ADDRESS_HISTORY_URL = "https://77-91-113-109.nip.io" + ADDRESS_HISTORY_PATH
SSH_ALIAS = "fodders"
SSH_PORT_DEFAULT = 22


class SiteLinkSyncError(ValueError):
    """A safe, user-facing failure while updating the public VPN shortcut."""

    def __init__(self, message: str, *, result: dict[str, Any] | None = None):
        super().__init__(message)
        self.result = result or {}


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes = b""


def target_for_ip(new_ip: str) -> tuple[str, str]:
    """Return the nip.io hostname and join URL for a valid public IPv4."""
    try:
        address = ipaddress.ip_address(str(new_ip).strip())
    except ValueError:
        raise SiteLinkSyncError("The VPN endpoint must be a public IPv4 address.") from None
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_private
    ):
        raise SiteLinkSyncError("The VPN endpoint must be a public IPv4 address.")
    domain = "-".join(str(address).split(".")) + ".nip.io"
    return domain, f"https://{domain}{JOIN_PATH}"


def build_caddy_snippet(new_ip: str) -> bytes:
    """Build the exact-path, cache-disabled shortcut route for the IP."""
    _domain, target_url = target_for_ip(new_ip)
    return (
        "@fodderVpnEntry path /vpn /vpn/\n"
        "handle @fodderVpnEntry {\n"
        '    header Cache-Control "no-store"\n'
        f"    redir {target_url} 302\n"
        "}\n"
    ).encode("ascii")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _http_get(url: str, *, timeout: float = 15.0) -> HttpResult:
    """GET with normal TLS certificate validation and redirects disabled."""
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    request = Request(url, headers={
        "User-Agent": "Fodder-VPN-link-check/1.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return HttpResult(
                status=int(response.status),
                headers={str(key).lower(): str(value) for key, value in response.headers.items()},
                body=response.read(1024 * 1024),
            )
    except HTTPError as response:
        return HttpResult(
            status=int(response.code),
            headers={str(key).lower(): str(value) for key, value in response.headers.items()},
            body=response.read(1024 * 1024),
        )
    except (URLError, TimeoutError, OSError):
        raise SiteLinkSyncError("An HTTPS check for the VPN endpoint or site failed.") from None


def _response_status(response: Any) -> int:
    try:
        return int(response.status)
    except (AttributeError, TypeError, ValueError):
        raise SiteLinkSyncError("An HTTPS check returned an invalid response.") from None


def _response_header(response: Any, name: str) -> str | None:
    headers = getattr(response, "headers", {})
    if hasattr(headers, "items"):
        for key, value in headers.items():
            if str(key).casefold() == name.casefold():
                return str(value)
    return None


def _check_endpoint_readiness(domain: str, http_get: Callable[..., Any]) -> None:
    join = http_get(f"https://{domain}{JOIN_PATH}", timeout=15.0)
    if _response_status(join) != 200:
        raise SiteLinkSyncError("The new VPN endpoint did not serve the profile page over HTTPS.")

    catalog = http_get(f"https://{domain}{CATALOG_PATH}", timeout=15.0)
    if _response_status(catalog) != 200:
        raise SiteLinkSyncError("The new VPN endpoint did not serve its public server catalog.")
    body = getattr(catalog, "body", b"")
    try:
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        parsed = json.loads(body)
    except (UnicodeError, TypeError, json.JSONDecodeError):
        raise SiteLinkSyncError("The new VPN endpoint returned an invalid public server catalog.") from None
    if not isinstance(parsed, dict) or not isinstance(parsed.get("servers"), list) or not parsed["servers"]:
        raise SiteLinkSyncError("The new VPN endpoint returned no public VPN servers.")


def _verify_public_shortcut(target_url: str, http_get: Callable[..., Any]) -> None:
    # Query probes confirm that neither the request query nor another path is
    # reflected into Location. Requests do not follow the 302 response.
    paths = (
        "/vpn",
        "/vpn/",
        "/vpn?codex_probe=must-drop",
        "/vpn/?codex_probe=must-drop",
    )
    for path in paths:
        response = http_get(f"{SITE_ORIGIN}{path}", timeout=15.0)
        if _response_status(response) != 302:
            raise SiteLinkSyncError(
                "The public VPN shortcut did not return the expected redirect.",
                result={"runtime_mismatch": True},
            )
        if _response_header(response, "location") != target_url:
            raise SiteLinkSyncError(
                "The public VPN shortcut returned an unexpected destination.",
                result={"runtime_mismatch": True},
            )
        cache_control = _response_header(response, "cache-control")
        if cache_control is None or cache_control.strip().lower() != "no-store":
            raise SiteLinkSyncError(
                "The public VPN shortcut response is missing Cache-Control: no-store.",
                result={"runtime_mismatch": True},
            )

    destination = http_get(target_url, timeout=15.0)
    if _response_status(destination) != 200:
        raise SiteLinkSyncError("The redirected VPN profile page did not return HTTP 200.")


def _local_ssh_path(value: str, home: Path) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(value))
    path = Path(expanded)
    if not path.is_absolute():
        path = home / path
    return path


def _connect_fodders(*, home: Path | None = None,
                     config_path: Path | None = None,
                     known_hosts_path: Path | None = None,
                     socket_connect: Callable[..., Any] | None = None,
                     ssh_factory: Callable[[], Any] | None = None) -> Any:
    """Open a direct, pinned Paramiko connection using ~/.ssh/config alias."""
    home = home or Path.home()
    config_path = config_path or (home / ".ssh" / "config")
    known_hosts_path = known_hosts_path or (home / ".ssh" / "known_hosts")
    if config_path.is_symlink() or not config_path.is_file():
        raise SiteLinkSyncError("The strict local SSH config for alias fodders is unavailable.")
    if known_hosts_path.is_symlink() or not known_hosts_path.is_file():
        raise SiteLinkSyncError("Strict local SSH known_hosts validation is unavailable.")

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            config = paramiko.SSHConfig.from_file(handle).lookup(SSH_ALIAS)
    except Exception:
        raise SiteLinkSyncError("The local SSH config for alias fodders could not be read.") from None

    hostname = str(config.get("hostname") or "").strip()
    host_key_alias = str(config.get("hostkeyalias") or hostname).strip()
    username = str(config.get("user") or "").strip()
    try:
        port = int(config.get("port", SSH_PORT_DEFAULT))
    except (TypeError, ValueError):
        raise SiteLinkSyncError("The local SSH config for alias fodders has an invalid port.") from None
    if not hostname or not host_key_alias or not username or not 1 <= port <= 65535:
        raise SiteLinkSyncError("The local SSH config for alias fodders is incomplete.")

    identities = config.get("identityfile") or []
    if isinstance(identities, str):
        identities = [identities]
    identity_files = [_local_ssh_path(str(value), home) for value in identities]
    if not identity_files or any(path.is_symlink() or not path.is_file() for path in identity_files):
        raise SiteLinkSyncError("A configured SSH identity file for alias fodders is unavailable.")

    ssh_factory = ssh_factory or paramiko.SSHClient
    socket_connect = socket_connect or socket.create_connection
    try:
        sock = socket_connect((hostname, port), timeout=10.0)
    except OSError:
        raise SiteLinkSyncError("A direct SSH connection to the fodders site server failed.") from None

    client = ssh_factory()
    try:
        client.load_host_keys(str(known_hosts_path))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=host_key_alias,
            port=port,
            username=username,
            key_filename=[str(path) for path in identity_files],
            sock=sock,
            timeout=10.0,
            banner_timeout=10.0,
            auth_timeout=10.0,
            look_for_keys=False,
            allow_agent=False,
        )
        return client
    except Exception:
        try:
            client.close()
        finally:
            try:
                sock.close()
            except Exception:
                pass
        raise SiteLinkSyncError("Strict SSH authentication or host-key verification for fodders failed.") from None


REMOTE_SCRIPT = r'''import hashlib, json, os, re, secrets, stat, subprocess, tempfile, time
from pathlib import Path
try:
    import fcntl
except ImportError:
    fcntl = None

MAIN_PATH = Path('/etc/caddy/Caddyfile')
SNIPPET_PATH = Path('/etc/caddy/fodder-vpn-link.caddy')
ADDRESS_HISTORY_PATH = Path('/var/www/fodders-site/connect/server-address-history.json')
BACKUP_ROOT = Path('/var/backups/fodders-site')
LOCK_PATH = Path('/run/lock/fodders-site-vpn-link.lock')
ANCHOR_RE = re.compile(rb'(?P<indent>[ \t]*)import[ \t]+/etc/caddy/fodders-desk\.caddy[ \t]*')
IMPORT_RE = re.compile(rb'(?P<indent>[ \t]*)import[ \t]+/etc/caddy/fodder-vpn-link\.caddy[ \t]*')
ROUTE_RE = re.compile(
    rb'\A@fodderVpnEntry path /vpn /vpn/\n'
    rb'handle @fodderVpnEntry \{\n'
    rb'    header Cache-Control "no-store"\n'
    rb'    redir https://[0-9]+-[0-9]+-[0-9]+-[0-9]+\.nip\.io/connect/join\.html 302\n'
    rb'\}\n?\Z')
run_command = subprocess.run


class OperationFailure(Exception):
    def __init__(self, code):
        self.code = code


def fail(code):
    raise OperationFailure(code)


def acquire_site_lock():
    if fcntl is None:
        fail('flock_unavailable')
    if LOCK_PATH.parent.is_symlink() or not LOCK_PATH.parent.is_dir() or LOCK_PATH.is_symlink():
        fail('lock_path_invalid')
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(LOCK_PATH), flags, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or (os.name == 'posix' and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077))):
            os.close(fd)
            fail('lock_file_not_private')
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except OperationFailure:
        raise
    except Exception:
        fail('site_lock_failed')


def release_site_lock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(args, code):
    try:
        result = run_command(args, capture_output=True, text=True, timeout=30, check=False)
    except Exception:
        fail(code)
    if getattr(result, 'returncode', 1) != 0:
        fail(code)


def read_regular(path, required):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if required:
            fail('caddy_main_missing')
        return None
    except OSError:
        fail('caddy_file_unreadable')
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail('caddy_symlink_or_type_refused')
    try:
        return (path.read_bytes(), info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
    except OSError:
        fail('caddy_file_unreadable')


def assert_source_hashes(main_hash, snippet_hash):
    current_main = read_regular(MAIN_PATH, True)
    current_snippet = read_regular(SNIPPET_PATH, False)
    actual_main_hash = digest(current_main[0])
    actual_snippet_hash = digest(current_snippet[0]) if current_snippet is not None else None
    if actual_main_hash != main_hash or actual_snippet_hash != snippet_hash:
        fail('caddy_source_changed')


def _line_records(data):
    records = []
    for line in data.splitlines(keepends=True):
        if line.endswith(b'\r\n'):
            body, ending = line[:-2], b'\r\n'
        elif line.endswith(b'\n'):
            body, ending = line[:-1], b'\n'
        else:
            body, ending = line, b''
        records.append([body, ending])
    return records


def build_main_candidates(main_data, snippet_stage):
    records = _line_records(main_data)
    anchors = [(i, match.group('indent')) for i, (body, _ending) in enumerate(records)
               for match in [ANCHOR_RE.fullmatch(body)] if match]
    imports = [(i, match.group('indent')) for i, (body, _ending) in enumerate(records)
               for match in [IMPORT_RE.fullmatch(body)] if match]
    if len(anchors) != 1 or len(imports) > 1:
        fail('caddy_import_anchor_invalid')
    anchor_index, indent = anchors[0]
    newline = b'\r\n' if b'\r\n' in main_data else b'\n'
    final_import = indent + b'import /etc/caddy/fodder-vpn-link.caddy'
    staged_import = indent + b'import ' + str(snippet_stage).encode('ascii')
    if imports:
        import_index, import_indent = imports[0]
        if import_index != anchor_index - 1 or import_indent != indent:
            fail('caddy_import_position_invalid')
        actual_records = [list(record) for record in records]
    else:
        actual_records = [list(record) for record in records]
        actual_records.insert(anchor_index, [final_import, newline])
    actual_main = b''.join(body + ending for body, ending in actual_records)

    staged_records = [list(record) for record in actual_records]
    staged_anchor = next(i for i, (body, _ending) in enumerate(staged_records)
                         if ANCHOR_RE.fullmatch(body))
    staged_index = staged_anchor - 1
    if staged_index >= 0 and IMPORT_RE.fullmatch(staged_records[staged_index][0]):
        staged_records[staged_index][0] = staged_import
    else:
        staged_records.insert(staged_anchor, [staged_import, newline])
    staged_main = b''.join(body + ending for body, ending in staged_records)
    return actual_main, staged_main


def write_stage(directory, prefix, data):
    fd, raw = tempfile.mkstemp(prefix=prefix, dir=str(directory))
    path = Path(raw)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return path
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            path.unlink()
        except OSError:
            pass
        fail('stage_write_failed')


def atomic_write(path, data, uid, gid, mode):
    fd, raw = tempfile.mkstemp(prefix='.fodder-vpn-link-write-', dir=str(path.parent))
    temporary = Path(raw)
    try:
        if hasattr(os, 'fchown'):
            os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            temporary.unlink()
        except OSError:
            pass
        fail('atomic_write_failed')


def ensure_private_backup_root():
    parent = BACKUP_ROOT.parent
    if parent.is_symlink() or not parent.is_dir():
        fail('backup_parent_invalid')
    if BACKUP_ROOT.is_symlink():
        fail('backup_root_invalid')
    if not BACKUP_ROOT.exists():
        try:
            BACKUP_ROOT.mkdir(mode=0o700)
        except OSError:
            fail('backup_root_create_failed')
    try:
        info = BACKUP_ROOT.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or (os.name == 'posix' and stat.S_IMODE(info.st_mode) & 0o077)
            or (os.name == 'posix' and info.st_uid != 0)
        ):
            fail('backup_root_not_private')
    except OSError:
        fail('backup_root_invalid')


def write_backup_file(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        fail('backup_write_failed')


def create_backup(main_snapshot, snippet_snapshot, applied_main, applied_snippet):
    ensure_private_backup_root()
    name = 'vpn-link-' + time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '-' + secrets.token_hex(6)
    backup = BACKUP_ROOT / name
    try:
        backup.mkdir(mode=0o700)
    except OSError:
        fail('backup_create_failed')
    write_backup_file(backup / 'Caddyfile', main_snapshot[0])
    if snippet_snapshot is not None:
        write_backup_file(backup / 'fodder-vpn-link.caddy', snippet_snapshot[0])
    manifest = {
        'main': {'uid': main_snapshot[1], 'gid': main_snapshot[2], 'mode': main_snapshot[3]},
        'source_main_sha256': digest(main_snapshot[0]),
        'snippet_exists': snippet_snapshot is not None,
        'snippet': ({'uid': snippet_snapshot[1], 'gid': snippet_snapshot[2], 'mode': snippet_snapshot[3]}
                    if snippet_snapshot is not None else None),
        'source_snippet_sha256': digest(snippet_snapshot[0]) if snippet_snapshot is not None else None,
        'applied_main_sha256': digest(applied_main),
        'applied_snippet_sha256': digest(applied_snippet),
    }
    write_backup_file(backup / 'manifest.json', json.dumps(manifest, separators=(',', ':')).encode('ascii'))
    return backup


def validate_caddy(config_path):
    command(['caddy', 'validate', '--config', str(config_path), '--adapter', 'caddyfile'],
            'caddy_validation_failed')


def _read_backup_file(path):
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            fail('rollback_backup_file_invalid')
        return path.read_bytes()
    except OperationFailure:
        raise
    except Exception:
        fail('rollback_backup_file_unreadable')


def restore_backup(backup, expected_main_hash=None, expected_snippet_hash=None):
    if backup.parent != BACKUP_ROOT or not re.fullmatch(r'vpn-link-[0-9]{8}-[0-9]{6}-[0-9a-f]{12}', backup.name):
        fail('rollback_backup_path_invalid')
    ensure_private_backup_root()
    if backup.is_symlink() or not backup.is_dir():
        fail('rollback_backup_unavailable')
    try:
        backup_info = backup.lstat()
        if (os.name == 'posix'
                and (backup_info.st_uid != 0 or stat.S_IMODE(backup_info.st_mode) & 0o077)):
            fail('rollback_backup_not_private')
        read_regular(MAIN_PATH, True)
        read_regular(SNIPPET_PATH, False)
    except OperationFailure:
        raise
    except Exception:
        fail('rollback_target_unreadable')
    try:
        manifest = json.loads(_read_backup_file(backup / 'manifest.json').decode('ascii'))
        main_data = _read_backup_file(backup / 'Caddyfile')
        snippet_data = (_read_backup_file(backup / 'fodder-vpn-link.caddy')
                        if manifest['snippet_exists'] else None)
        if digest(main_data) != manifest.get('source_main_sha256'):
            fail('rollback_snapshot_invalid')
        if manifest['snippet_exists']:
            if snippet_data is None or digest(snippet_data) != manifest.get('source_snippet_sha256'):
                fail('rollback_snapshot_invalid')
        elif manifest.get('source_snippet_sha256') is not None:
            fail('rollback_snapshot_invalid')

        main_snapshot = read_regular(MAIN_PATH, True)
        snippet_snapshot = read_regular(SNIPPET_PATH, False)
        expected_main_hash = expected_main_hash or manifest.get('applied_main_sha256')
        expected_snippet_hash = expected_snippet_hash or manifest.get('applied_snippet_sha256')
        current_main_hash = digest(main_snapshot[0])
        current_snippet_hash = digest(snippet_snapshot[0]) if snippet_snapshot is not None else None
        if current_main_hash != expected_main_hash or current_snippet_hash != expected_snippet_hash:
            fail('rollback_conflict')

        main_meta = manifest['main']
        atomic_write(MAIN_PATH, main_data, int(main_meta['uid']), int(main_meta['gid']), int(main_meta['mode']))
        if manifest['snippet_exists']:
            snippet_meta = manifest['snippet']
            atomic_write(SNIPPET_PATH, snippet_data, int(snippet_meta['uid']), int(snippet_meta['gid']), int(snippet_meta['mode']))
        elif SNIPPET_PATH.exists():
            SNIPPET_PATH.unlink()
    except OperationFailure:
        raise
    except Exception:
        fail('rollback_snapshot_invalid')
    validate_caddy(MAIN_PATH)
    command(['systemctl', 'reload', 'caddy'], 'rollback_reload_failed')
    return True


def apply(params):
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        fail('remote_not_root')
    domain = params.get('domain', '')
    if not re.fullmatch(r'[0-9]+-[0-9]+-[0-9]+-[0-9]+\.nip\.io', domain):
        fail('target_domain_invalid')
    if MAIN_PATH.parent.is_symlink() or SNIPPET_PATH.parent.is_symlink():
        fail('caddy_directory_symlink_refused')
    main_snapshot = read_regular(MAIN_PATH, True)
    snippet_snapshot = read_regular(SNIPPET_PATH, False)
    snippet = (
        '@fodderVpnEntry path /vpn /vpn/\n'
        'handle @fodderVpnEntry {\n'
        '    header Cache-Control "no-store"\n'
        f'    redir https://{domain}/connect/join.html 302\n'
        '}\n'
    ).encode('ascii')
    stage_snippet = None
    stage_main = None
    backup = None
    mutated = False
    source_main_hash = digest(main_snapshot[0])
    source_snippet_hash = digest(snippet_snapshot[0]) if snippet_snapshot is not None else None
    applied_main_hash = None
    applied_snippet_hash = None
    expected_main_hash = source_main_hash
    expected_snippet_hash = source_snippet_hash
    try:
        actual_main, _candidate_main = build_main_candidates(
            main_snapshot[0], SNIPPET_PATH.parent / '.fodder-vpn-link-candidate-placeholder.caddy')
        applied_main_hash = digest(actual_main)
        applied_snippet_hash = digest(snippet)
        changed = actual_main != main_snapshot[0] or snippet_snapshot is None or snippet != snippet_snapshot[0]
        if not changed:
            validate_caddy(MAIN_PATH)
            runtime_active = True
            try:
                command(['systemctl', 'is-active', '--quiet', 'caddy'], 'caddy_runtime_inactive')
            except OperationFailure:
                runtime_active = False
            return {
                'ok': True, 'changed': False, 'runtime_verified': True,
                'runtime_active': runtime_active, 'runtime_reloaded': False, 'backup_path': None,
            }

        # Candidate main references this staged snippet, never the active one.
        stage_snippet = write_stage(SNIPPET_PATH.parent, '.fodder-vpn-link-candidate-', snippet)
        _actual_main, staged_main = build_main_candidates(main_snapshot[0], stage_snippet)
        stage_main = write_stage(MAIN_PATH.parent, '.fodder-vpn-main-candidate-', staged_main)
        validate_caddy(stage_main)
        assert_source_hashes(source_main_hash, source_snippet_hash)
        backup = create_backup(main_snapshot, snippet_snapshot, actual_main, snippet)
        snippet_meta = snippet_snapshot[1:] if snippet_snapshot is not None else (0, 0, 0o644)
        main_meta = main_snapshot[1:]
        assert_source_hashes(source_main_hash, source_snippet_hash)
        atomic_write(SNIPPET_PATH, snippet, int(snippet_meta[0]), int(snippet_meta[1]), int(snippet_meta[2]))
        mutated = True
        expected_snippet_hash = applied_snippet_hash
        assert_source_hashes(expected_main_hash, expected_snippet_hash)
        atomic_write(MAIN_PATH, actual_main, int(main_meta[0]), int(main_meta[1]), int(main_meta[2]))
        expected_main_hash = applied_main_hash
        assert_source_hashes(expected_main_hash, expected_snippet_hash)
        validate_caddy(MAIN_PATH)
        command(['systemctl', 'reload', 'caddy'], 'caddy_reload_failed')
        return {
            'ok': True, 'changed': True, 'runtime_verified': True,
            'runtime_reloaded': True, 'backup_path': str(backup),
        }
    except OperationFailure as exc:
        rolled_back = None
        rollback_conflict = False
        rollback_reloaded = False
        if mutated and backup is not None:
            try:
                restore_backup(backup, expected_main_hash, expected_snippet_hash)
                rolled_back = True
                rollback_reloaded = True
            except OperationFailure as rollback_error:
                rolled_back = False
                rollback_conflict = rollback_error.code == 'rollback_conflict'
        return {
            'ok': False, 'error': exc.code, 'changed': False,
            'rolled_back': rolled_back, 'rollback_conflict': rollback_conflict,
            'rollback_reloaded': rollback_reloaded,
            'backup_path': str(backup) if backup else None,
        }
    except Exception:
        rolled_back = None
        rollback_conflict = False
        rollback_reloaded = False
        if mutated and backup is not None:
            try:
                restore_backup(backup, expected_main_hash, expected_snippet_hash)
                rolled_back = True
                rollback_reloaded = True
            except Exception as rollback_error:
                rolled_back = False
                rollback_conflict = getattr(rollback_error, 'code', None) == 'rollback_conflict'
        return {
            'ok': False, 'error': 'unexpected_remote_failure', 'changed': False,
            'rolled_back': rolled_back, 'rollback_conflict': rollback_conflict,
            'rollback_reloaded': rollback_reloaded,
            'backup_path': str(backup) if backup else None,
        }
    finally:
        for path in (stage_main, stage_snippet):
            if path is not None:
                try:
                    path.unlink()
                except OSError:
                    pass


def rollback(params):
    backup_raw = params.get('backup_path', '')
    backup = Path(backup_raw)
    try:
        restore_backup(backup)
        return {'ok': True, 'rolled_back': True, 'runtime_reloaded': True}
    except OperationFailure as exc:
        return {
            'ok': False, 'error': exc.code, 'rolled_back': False,
            'rollback_conflict': exc.code == 'rollback_conflict', 'runtime_reloaded': False,
        }
    except Exception:
        return {
            'ok': False, 'error': 'unexpected_rollback_failure', 'rolled_back': False,
            'rollback_conflict': False, 'runtime_reloaded': False,
        }


def reconcile(params):
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        fail('remote_not_root')
    domain = params.get('domain', '')
    if not re.fullmatch(r'[0-9]+-[0-9]+-[0-9]+-[0-9]+\.nip\.io', domain):
        fail('target_domain_invalid')
    if MAIN_PATH.parent.is_symlink() or SNIPPET_PATH.parent.is_symlink():
        fail('caddy_directory_symlink_refused')
    main_snapshot = read_regular(MAIN_PATH, True)
    snippet_snapshot = read_regular(SNIPPET_PATH, False)
    if snippet_snapshot is None:
        fail('site_disk_target_mismatch')
    snippet = (
        '@fodderVpnEntry path /vpn /vpn/\n'
        'handle @fodderVpnEntry {\n'
        '    header Cache-Control "no-store"\n'
        f'    redir https://{domain}/connect/join.html 302\n'
        '}\n'
    ).encode('ascii')
    actual_main, _staged_main = build_main_candidates(
        main_snapshot[0], SNIPPET_PATH.parent / '.fodder-vpn-link-reconcile-check.caddy')
    if actual_main != main_snapshot[0] or snippet_snapshot[0] != snippet:
        fail('site_disk_target_mismatch')
    expected_main_hash = digest(main_snapshot[0])
    expected_snippet_hash = digest(snippet_snapshot[0])
    validate_caddy(MAIN_PATH)
    assert_source_hashes(expected_main_hash, expected_snippet_hash)
    command(['systemctl', 'reload', 'caddy'], 'caddy_reconcile_reload_failed')
    return {'ok': True, 'changed': False, 'runtime_reloaded': True}


def inspect(params):
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        fail('remote_not_root')
    domain = params.get('domain', '')
    if not re.fullmatch(r'[0-9]+-[0-9]+-[0-9]+-[0-9]+\.nip\.io', domain):
        fail('target_domain_invalid')
    if MAIN_PATH.parent.is_symlink() or SNIPPET_PATH.parent.is_symlink():
        fail('caddy_directory_symlink_refused')
    main_snapshot = read_regular(MAIN_PATH, True)
    snippet_snapshot = read_regular(SNIPPET_PATH, False)
    snippet = (
        '@fodderVpnEntry path /vpn /vpn/\n'
        'handle @fodderVpnEntry {\n'
        '    header Cache-Control "no-store"\n'
        f'    redir https://{domain}/connect/join.html 302\n'
        '}\n'
    ).encode('ascii')
    actual_main, _staged_main = build_main_candidates(
        main_snapshot[0], Path('/etc/caddy/.fodder-vpn-link-read-only-check.caddy'))
    has_import = any(IMPORT_RE.fullmatch(body) for body, _ending in _line_records(main_snapshot[0]))
    snippet_has_route = (
        snippet_snapshot is not None
        and ROUTE_RE.fullmatch(snippet_snapshot[0].replace(b'\r\n', b'\n')) is not None
    )
    missing_route = not has_import or not snippet_has_route
    would_change = actual_main != main_snapshot[0] or snippet_snapshot is None or snippet != snippet_snapshot[0]
    return {
        'ok': True,
        'would_change': would_change,
        'missing_route': missing_route,
        'target_current': not would_change,
    }


def address_history(params):
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        fail('remote_not_root')
    for directory in (Path('/var'), Path('/var/www'), Path('/var/www/fodders-site'), ADDRESS_HISTORY_PATH.parent):
        if directory.is_symlink():
            fail('address_history_directory_symlink_refused')
        if not directory.is_dir():
            fail('address_history_directory_missing')
    snapshot = read_regular(ADDRESS_HISTORY_PATH, True)
    try:
        document = json.loads(snapshot[0].decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError):
        fail('address_history_json_invalid')
    if not isinstance(document, dict) or document.get('schema') != 1 or not isinstance(document.get('servers'), dict):
        fail('address_history_schema_invalid')
    estimated = document.get('estimated', [])
    if (not isinstance(estimated, list)
            or any(not isinstance(item, str) or item not in ('nl', 'fi', 'us', 'tr') for item in estimated)
            or len(set(estimated)) != len(estimated)):
        fail('address_history_estimated_invalid')
    server_id = params.get('server_id', '')
    if server_id not in ('nl', 'fi', 'us', 'tr'):
        fail('address_history_server_invalid')
    changed_on = params.get('changed_on', '')
    if not re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}', changed_on):
        fail('address_history_date_invalid')
    try:
        import datetime
        if datetime.date.fromisoformat(changed_on).isoformat() != changed_on:
            fail('address_history_date_invalid')
    except ValueError:
        fail('address_history_date_invalid')
    current = document['servers'].get(server_id)
    was_estimated = server_id in estimated
    if current == changed_on and not was_estimated:
        return {'ok': True, 'changed': False, 'changed_on': current, 'verified': True, 'backup_path': None}
    if params.get('mode') == 'address-age-inspect':
        return {'ok': True, 'changed': False, 'would_change': True, 'changed_on': current, 'estimated': was_estimated, 'verified': True}
    if params.get('mode') != 'address-age-apply':
        fail('address_history_mode_invalid')
    if current is not None and (not isinstance(current, str) or not re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}', current)):
        fail('address_history_entry_invalid')
    document['servers'][server_id] = changed_on
    document['estimated'] = [item for item in estimated if item != server_id]
    updated = (json.dumps(document, ensure_ascii=False, indent=2) + '\n').encode('utf-8')

    if BACKUP_ROOT.parent.is_symlink() or BACKUP_ROOT.is_symlink() or not BACKUP_ROOT.is_dir():
        fail('backup_root_invalid')
    backup_info = BACKUP_ROOT.lstat()
    if backup_info.st_uid != 0 or stat.S_IMODE(backup_info.st_mode) & 0o077:
        fail('backup_root_not_private')
    backup = BACKUP_ROOT / ('server-address-history-' + time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '-' + secrets.token_hex(6))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(backup), flags, 0o600)
    try:
        os.fchown(fd, snapshot[1], snapshot[2])
        with os.fdopen(fd, 'wb') as stream:
            stream.write(snapshot[0])
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try: os.close(fd)
        except OSError: pass
        try: backup.unlink()
        except OSError: pass
        fail('address_history_backup_failed')

    assert_current_history(snapshot[0])
    atomic_write(ADDRESS_HISTORY_PATH, updated, snapshot[1], snapshot[2], snapshot[3])
    verified = read_regular(ADDRESS_HISTORY_PATH, True)
    if verified[0] != updated:
        fail('address_history_verify_failed')
    return {'ok': True, 'changed': True, 'changed_on': changed_on, 'verified': True, 'backup_path': str(backup)}


def assert_current_history(expected):
    current = read_regular(ADDRESS_HISTORY_PATH, True)
    if current[0] != expected:
        fail('address_history_source_changed')


def run(params):
    mode = params.get('mode')
    if mode not in ('apply', 'rollback', 'inspect', 'reconcile', 'address-age-inspect', 'address-age-apply'):
        return {'ok': False, 'error': 'mode_invalid'}
    try:
        lock_fd = acquire_site_lock()
    except OperationFailure as exc:
        return {'ok': False, 'error': exc.code}
    try:
        if mode == 'apply':
            return apply(params)
        if mode == 'rollback':
            return rollback(params)
        if mode == 'inspect':
            return inspect(params)
        if mode in ('address-age-inspect', 'address-age-apply'):
            return address_history(params)
        return reconcile(params)
    except OperationFailure as exc:
        return {
            'ok': False,
            'error': exc.code,
            'rollback_conflict': exc.code == 'rollback_conflict',
            'runtime_reloaded': False,
        }
    except Exception:
        return {'ok': False, 'error': 'unexpected_remote_failure', 'runtime_reloaded': False}
    finally:
        release_site_lock(lock_fd)
'''


def _remote_script(mode: str, *, domain: str | None = None,
                   backup_path: str | None = None) -> str:
    params: dict[str, str] = {"mode": mode}
    if domain is not None:
        params["domain"] = domain
    if backup_path is not None:
        params["backup_path"] = backup_path
    serialized = json.dumps(params, separators=(",", ":"))
    # JSON contains only the validated public IP-derived target or a strict
    # backup path. The remote command itself stays fixed and receives code via stdin.
    return REMOTE_SCRIPT + "\nPARAMS = json.loads(" + repr(serialized) + ")\nprint(json.dumps(run(PARAMS), separators=(',', ':')))\n"


def _address_history_script(server_id: str, changed_on: str, *, apply: bool) -> str:
    params = {
        "mode": "address-age-apply" if apply else "address-age-inspect",
        "server_id": server_id,
        "changed_on": changed_on,
    }
    serialized = json.dumps(params, separators=(",", ":"))
    return REMOTE_SCRIPT + "\nPARAMS = json.loads(" + repr(serialized) + ")\nprint(json.dumps(run(PARAMS), separators=(',', ':')))\n"


def sync_server_address_age(server_id: str, changed_on: str, apply: bool = False, *,
                            ssh_connect: Callable[[], Any] | None = None,
                            home: Path | None = None,
                            config_path: Path | None = None,
                            known_hosts_path: Path | None = None,
                            socket_connect: Callable[..., Any] | None = None,
                            ssh_factory: Callable[[], Any] | None = None) -> dict[str, Any]:
    """Update one public server's IP-age date on the separate site host.

    The default is a read-only plan. Apply uses the strict `fodders` SSH alias,
    writes a private backup before the atomic replacement, then verifies both
    the remote file and the HTTPS asset served to visitors.
    """
    if server_id not in ("nl", "fi", "us", "tr"):
        raise SiteLinkSyncError("The VPN server ID for the public age marker is invalid.")
    try:
        parsed_date = __import__("datetime").date.fromisoformat(changed_on)
    except (TypeError, ValueError):
        raise SiteLinkSyncError("The VPN IP-change date is invalid.") from None
    if parsed_date.isoformat() != changed_on:
        raise SiteLinkSyncError("The VPN IP-change date is invalid.")

    client = None
    result: dict[str, Any] = {
        "server": server_id,
        "changed_on": changed_on,
        "website_updated": False,
        "verified": False,
        "applied": False,
    }
    try:
        if ssh_connect is not None:
            client = ssh_connect()
        else:
            client = _connect_fodders(
                home=home,
                config_path=config_path,
                known_hosts_path=known_hosts_path,
                socket_connect=socket_connect,
                ssh_factory=ssh_factory,
            )
        remote = _execute_remote(
            client,
            _address_history_script(server_id, changed_on, apply=False),
        )
        if remote.get("ok") is not True or remote.get("verified") is not True:
            raise SiteLinkSyncError("The public website's server-age file could not be inspected safely.", result=result)
        if not apply:
            result.update({
                "dry_run": True,
                "would_change": remote.get("would_change") is True,
                "verified": True,
            })
            return result

        remote = _execute_remote(
            client,
            _address_history_script(server_id, changed_on, apply=True),
        )
        if remote.get("ok") is not True or remote.get("verified") is not True or remote.get("changed_on") != changed_on:
            raise SiteLinkSyncError("The public website's server-age date did not verify after the update.", result=result)
        backup_path = remote.get("backup_path")
        if remote.get("changed") is True:
            if not isinstance(backup_path, str) or not re.fullmatch(
                r"/var/backups/fodders-site/server-address-history-[0-9]{8}-[0-9]{6}-[0-9a-f]{12}",
                backup_path,
            ):
                raise SiteLinkSyncError("The public website updated its age file without valid backup metadata.", result=result)

        get = _http_get
        response = get(ADDRESS_HISTORY_URL + "?v=" + changed_on + "&check=" + str(time.time_ns()), timeout=15.0)
        if _response_status(response) != 200:
            raise SiteLinkSyncError("The public website did not serve the updated server-age file.", result=result)
        try:
            body = response.body.decode("utf-8") if isinstance(response.body, bytes) else response.body
            published = json.loads(body)
        except (UnicodeError, TypeError, json.JSONDecodeError):
            raise SiteLinkSyncError("The public website served an invalid server-age file.", result=result) from None
        if not isinstance(published, dict) or not isinstance(published.get("servers"), dict) or published["servers"].get(server_id) != changed_on:
            raise SiteLinkSyncError("The public website served a stale server-age date.", result=result)

        result.update({
            "website_updated": remote.get("changed") is True,
            "verified": True,
            "applied": True,
            "dry_run": False,
            "backup_path": backup_path,
        })
        return result
    except SiteLinkSyncError:
        raise
    except Exception:
        raise SiteLinkSyncError("The public website's server-age date could not be synchronized safely.", result=result) from None
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _execute_remote(client: Any, script: str) -> dict[str, Any]:
    try:
        stdin, stdout, _stderr = client.exec_command("python3 -", timeout=120)
        stdin.write(script)
        stdin.flush()
        if hasattr(stdin, "channel") and hasattr(stdin.channel, "shutdown_write"):
            stdin.channel.shutdown_write()
        output = stdout.read()
        status = stdout.channel.recv_exit_status()
        if status != 0:
            raise SiteLinkSyncError("The site server did not complete the VPN shortcut operation safely.")
        if isinstance(output, bytes):
            output = output.decode("utf-8", "strict")
        result = json.loads(output)
        if not isinstance(result, dict):
            raise ValueError("bad response")
        return result
    except SiteLinkSyncError:
        raise
    except Exception:
        raise SiteLinkSyncError("The site server returned an invalid VPN shortcut status.") from None


def _safe_backup_path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if not re.fullmatch(r"/var/backups/fodders-site/vpn-link-[0-9]{8}-[0-9]{6}-[0-9a-f]{12}", value):
        return None
    return value


def sync_site_link(new_ip: str, apply: bool = False, *,
                   http_get: Callable[..., Any] | None = None,
                   ssh_connect: Callable[[], Any] | None = None,
                   home: Path | None = None,
                   config_path: Path | None = None,
                   known_hosts_path: Path | None = None,
                   socket_connect: Callable[..., Any] | None = None,
                   ssh_factory: Callable[[], Any] | None = None) -> dict[str, Any]:
    """Sync the public shortcut. Default is a read-only dry run.

    `http_get` and `ssh_connect` are injectable for local tests; neither is
    needed by callers. The endpoint readiness checks and public verification
    use certificate-validating HTTPS.
    """
    domain, target_url = target_for_ip(new_ip)
    result: dict[str, Any] = {
        "site_url": SITE_URL,
        "target_url": target_url,
        "site_updated": False,
        "verified": False,
        "applied": False,
    }
    get = http_get or _http_get
    client = None
    try:
        _check_endpoint_readiness(domain, get)
        if ssh_connect is not None:
            client = ssh_connect()
        else:
            client = _connect_fodders(
                home=home,
                config_path=config_path,
                known_hosts_path=known_hosts_path,
                socket_connect=socket_connect,
                ssh_factory=ssh_factory,
            )
        if not apply:
            plan = _execute_remote(client, _remote_script("inspect", domain=domain))
            if plan.get("ok") is not True:
                raise SiteLinkSyncError("The current site Caddy files could not be inspected safely.", result=result)
            result.update({
                "dry_run": True,
                "endpoint_verified": True,
                "would_change": plan.get("would_change") is True,
                "missing_route": plan.get("missing_route") is True,
            })
            if plan.get("target_current") is True:
                _verify_public_shortcut(target_url, get)
                result["verified"] = True
            return result

        remote = _execute_remote(client, _remote_script("apply", domain=domain))
        if remote.get("ok") is not True:
            if remote.get("rolled_back") is True:
                message = "The site shortcut update failed and the site files were rolled back."
            elif remote.get("rollback_conflict") is True:
                message = "The site files changed during the shortcut update; rollback was refused to preserve those changes."
            elif remote.get("rolled_back") is False:
                message = "The site shortcut update failed and the site rollback also failed; the site needs inspection."
            else:
                message = "The site shortcut update failed before any site files were changed."
            failure = dict(result)
            failure.update({
                "applied": False,
                "site_updated": remote.get("rolled_back") is False,
                "attempted_update": remote.get("rolled_back") is not None,
                "rollback_succeeded": remote.get("rolled_back"),
                "rollback_conflict": remote.get("rollback_conflict") is True,
                "runtime_reloaded": remote.get("runtime_reloaded") is True,
                "rollback_reloaded": remote.get("rollback_reloaded") is True,
                "backup_path": _safe_backup_path(remote.get("backup_path")),
            })
            raise SiteLinkSyncError(message, result=failure)

        changed = remote.get("changed") is True
        backup_path = _safe_backup_path(remote.get("backup_path"))
        if changed and backup_path is None:
            failure = dict(result)
            failure.update({
                "applied": True,
                "site_updated": True,
                "attempted_update": True,
                "verified": False,
                "runtime_reloaded": remote.get("runtime_reloaded") is True,
                "rollback_succeeded": False,
            })
            raise SiteLinkSyncError(
                "The site changed but did not return safe backup metadata; the update needs inspection.",
                result=failure,
            )
        runtime_reloaded = remote.get("runtime_reloaded") is True
        if not changed:
            try:
                _verify_public_shortcut(target_url, get)
            except SiteLinkSyncError as verify_error:
                if verify_error.result.get("runtime_mismatch") is not True:
                    failure = dict(result)
                    failure.update({
                        "applied": True,
                        "site_updated": False,
                        "verified": False,
                        "runtime_reloaded": False,
                        "rollback_succeeded": None,
                    })
                    raise SiteLinkSyncError(
                        "The site files already match the target, but the current public shortcut could not be verified.",
                        result=failure,
                    ) from verify_error
                try:
                    reconciled = _execute_remote(client, _remote_script("reconcile", domain=domain))
                except SiteLinkSyncError:
                    reconciled = {"ok": False, "runtime_reloaded": False}
                if reconciled.get("ok") is not True or reconciled.get("runtime_reloaded") is not True:
                    failure = dict(result)
                    failure.update({
                        "applied": True,
                        "site_updated": False,
                        "verified": False,
                        "runtime_reloaded": False,
                        "rollback_succeeded": None,
                    })
                    raise SiteLinkSyncError(
                        "The site files match the target, but Caddy could not reconcile its running route.",
                        result=failure,
                    ) from verify_error
                runtime_reloaded = True
                try:
                    _verify_public_shortcut(target_url, get)
                except SiteLinkSyncError as retry_error:
                    failure = dict(result)
                    failure.update({
                        "applied": True,
                        "site_updated": False,
                        "verified": False,
                        "runtime_reloaded": True,
                        "rollback_succeeded": None,
                    })
                    raise SiteLinkSyncError(
                        "Caddy reloaded the matching site files, but the public shortcut still failed verification.",
                        result=failure,
                    ) from retry_error
            result.update({
                "site_updated": False,
                "verified": True,
                "applied": True,
                "dry_run": False,
                "runtime_reloaded": runtime_reloaded,
                "backup_path": None,
            })
            return result

        try:
            _verify_public_shortcut(target_url, get)
        except SiteLinkSyncError as verify_error:
            rollback_succeeded: bool | None = None
            rollback_conflict = False
            rollback_reloaded = False
            if backup_path is None:
                rollback_succeeded = False
            else:
                try:
                    rollback = _execute_remote(client, _remote_script("rollback", backup_path=backup_path))
                    rollback_succeeded = rollback.get("ok") is True and rollback.get("rolled_back") is True
                    rollback_conflict = rollback.get("rollback_conflict") is True
                    rollback_reloaded = rollback.get("runtime_reloaded") is True
                except SiteLinkSyncError:
                    rollback_succeeded = False
            failure = dict(result)
            failure.update({
                "applied": True,
                "site_updated": changed and rollback_succeeded is not True,
                "attempted_update": changed,
                "verified": False,
                "backup_path": backup_path,
                "rollback_succeeded": rollback_succeeded,
                "rollback_conflict": rollback_conflict,
                "runtime_reloaded": runtime_reloaded,
                "rollback_reloaded": rollback_reloaded,
            })
            if rollback_succeeded is True:
                message = "The public VPN shortcut could not be verified; the site changes were rolled back."
            elif rollback_conflict:
                message = "The public VPN shortcut could not be verified; rollback was refused to preserve later site edits."
            elif rollback_succeeded is False:
                message = "The public VPN shortcut could not be verified and the site rollback failed; the site needs inspection."
            else:
                message = "The public VPN shortcut could not be verified; no site changes were needed."
            raise SiteLinkSyncError(message, result=failure) from verify_error

        result.update({
            "site_updated": changed,
            "verified": True,
            "applied": True,
            "dry_run": False,
            "runtime_reloaded": runtime_reloaded,
            "backup_path": backup_path,
        })
        return result
    except SiteLinkSyncError:
        raise
    except Exception:
        raise SiteLinkSyncError("The site VPN shortcut could not be synchronized safely.", result=result) from None
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--new-ip", required=True, help="new public VPN IPv4 endpoint")
    parser.add_argument("--apply", action="store_true", help="apply the site update; otherwise only print the target")
    args = parser.parse_args(argv)
    try:
        result = sync_site_link(args.new_ip, apply=args.apply)
    except SiteLinkSyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
