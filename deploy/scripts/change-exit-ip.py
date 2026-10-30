"""Safely migrate an AWG exit IP from the control server (dry-run by default)."""
from __future__ import annotations

import argparse
import base64
from datetime import date
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
from urllib.parse import quote

import paramiko
from cryptography.fernet import Fernet, InvalidToken


DEFAULT_ENV = Path("/etc/vpn-wizard.env")
DEFAULT_ENV_POSIX = "/etc/vpn-wizard.env"
BACKUP_ROOT = Path("/var/backups/vpn-wizard")
SERVER_IDS = {"fi", "us", "tr"}
LAUNCHER_SERVER_IDS = SERVER_IDS | {"nl"}
IFACE_RE = re.compile(r"^[a-z][a-z0-9]{1,14}$")
ENV_ASSIGN_RE = re.compile(r"^(?P<prefix>\ufeff?\s*[A-Za-z_][A-Za-z0-9_]*\s*=)(?P<value>.*)$")
REMOTE_CODE = r'''
import hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path('/etc/amnezia/amneziawg')
BACKUPS = Path('/var/backups/vpn-wizard')

def fail(message):
    raise RuntimeError(message)

def awg(*args):
    try:
        result = subprocess.run(['awg', *args], capture_output=True, text=True, timeout=12, check=False)
    except Exception:
        fail('runtime_query_failed')
    if result.returncode != 0:
        fail('runtime_query_failed')
    return result.stdout.strip()

def inspect_runtime(expected):
    raw = awg('show', 'all', 'listen-port')
    ports = {}
    for line in raw.splitlines():
        row = line.split()
        if len(row) != 2 or not re.fullmatch(r'[a-z][a-z0-9]{1,14}', row[0]) or not row[1].isdigit():
            fail('runtime_listener_output_invalid')
        ports[row[0]] = int(row[1])
    expected_by_iface = {}
    for entry in expected:
        iface = entry.get('interface')
        if not iface:
            candidates = [name for name, port in ports.items() if port == entry['listen_port']]
            if len(candidates) != 1:
                fail('runtime_interface_ambiguous')
            iface = candidates[0]
        if iface in expected_by_iface:
            fail('runtime_interface_ambiguous')
        expected_by_iface[iface] = entry
    for iface, entry in expected_by_iface.items():
        entry['interface'] = iface
    if any(iface not in ports or ports[iface] != entry['listen_port'] for iface, entry in expected_by_iface.items()):
        fail('runtime_listener_mismatch')
    result = {}
    for iface, port in sorted(ports.items()):
        public = awg('show', iface, 'public-key').strip()
        if not re.fullmatch(r'[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=', public):
            fail('runtime_public_identity_missing')
        entry = expected_by_iface.get(iface)
        if entry is not None and public != entry['public_key']:
            fail('runtime_public_identity_mismatch')
        peers = sorted(value.strip() for value in awg('show', iface, 'peers').splitlines() if value.strip())
        if any(not re.fullmatch(r'[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=', peer) for peer in peers):
            fail('runtime_peer_output_invalid')
        result[iface] = {
            'listen_port': port,
            'public_key_fingerprint': hashlib.sha256(public.encode()).hexdigest(),
            'public_key_verified': entry is not None,
            'peer_count': len(peers),
            'peer_fingerprint': hashlib.sha256('\n'.join(peers).encode()).hexdigest(),
        }
    return result

def endpoint_files(old_ip):
    if ROOT.is_symlink() or not ROOT.is_dir():
        fail('awg_config_root_invalid')
    files = []
    for directory in sorted(ROOT.glob('clients*')):
        if directory.is_symlink():
            fail('client_directory_symlink_refused')
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if not (path.name.endswith('.conf') or path.name.endswith('.conf.suspended')):
                continue
            if path.is_symlink() or not path.is_file():
                fail('client_file_symlink_or_type_refused')
            data = path.read_bytes()
            changed = []
            for line in data.splitlines(keepends=True):
                match = re.match(
                    rb'(?i)^([ \t]*Endpoint[ \t]*=[ \t]*)' + re.escape(old_ip.encode())
                    + rb'(?=:[0-9]+(?:[ \t]*(?:[#;].*)?)?\r?\n?$)', line
                )
                changed.append(match.group(1) + NEW_IP.encode() + line[match.end():] if match else line)
            updated = b''.join(changed)
            if updated != data:
                files.append((path, data, updated))
    return files

def atomic_write(path, data, source_stat):
    fd, temp_name = tempfile.mkstemp(prefix='.' + path.name + '.exit-ip-', dir=str(path.parent))
    temp = Path(temp_name)
    try:
        if hasattr(os, 'fchown'):
            os.fchown(fd, source_stat.st_uid, source_stat.st_gid)
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, stat.S_IMODE(source_stat.st_mode))
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        if os.name != 'nt':
            dfd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass

def make_backup(files):
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BACKUPS.is_symlink():
        fail('backup_root_symlink_refused')
    if hasattr(os, 'geteuid') and BACKUPS.stat().st_uid != 0:
        fail('backup_root_not_root_owned')
    os.chmod(BACKUPS, 0o700)
    target = Path(tempfile.mkdtemp(prefix='exit-ip-', dir=str(BACKUPS)))
    os.chmod(target, 0o700)
    names = []
    for path, data, _ in files:
        relative = path.relative_to(ROOT)
        dest = target / relative
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = path.stat(follow_symlinks=False)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IMODE(st.st_mode))
        try:
            if hasattr(os, 'fchown'):
                os.fchown(fd, st.st_uid, st.st_gid)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try: os.close(fd)
            except OSError: pass
            raise
        shutil.copystat(path, dest, follow_symlinks=False)
        names.append(relative.as_posix())
    manifest = target / 'manifest.json'
    fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump({'files': names}, handle)
        handle.flush()
        os.fsync(handle.fileno())
    return target.name

def restore(backup_id):
    if not re.fullmatch(r'exit-ip-[A-Za-z0-9_-]+', backup_id):
        fail('backup_id_invalid')
    backup = BACKUPS / backup_id
    if backup.parent != BACKUPS or backup.is_symlink() or not backup.is_dir():
        fail('backup_not_found')
    manifest = json.loads((backup / 'manifest.json').read_text(encoding='utf-8'))
    for name in manifest.get('files', []):
        rel = Path(name)
        if rel.is_absolute() or len(rel.parts) != 2 or not rel.parts[0].startswith('clients') or rel.name in {'', '.', '..'}:
            fail('backup_manifest_invalid')
        source, target = backup / rel, ROOT / rel
        if source.is_symlink() or target.is_symlink() or not source.is_file():
            fail('restore_path_invalid')
        atomic_write(target, source.read_bytes(), source.stat(follow_symlinks=False))
    return {'restored': len(manifest.get('files', [])), 'rollback_ok': True}

payload = json.load(sys.stdin)
NEW_IP = payload.get('new_ip', '')
try:
    if payload['mode'] == 'restore':
        print(json.dumps(restore(payload['backup_id'])))
        raise SystemExit(0)
    interfaces = payload['interfaces']
    before = inspect_runtime(interfaces)
    if payload['mode'] == 'runtime':
        print(json.dumps({'interfaces': before}))
        raise SystemExit(0)
    files = endpoint_files(payload['old_ip'])
    if payload['mode'] == 'inspect':
        print(json.dumps({'interfaces': before, 'profiles_to_update': len(files), 'backup_id': None, 'applied': False}))
        raise SystemExit(0)
    backup_id = make_backup(files) if files else None
    written = []
    try:
        for path, original, updated in files:
            if path.is_symlink():
                fail('client_file_symlink_refused')
            st = path.stat(follow_symlinks=False)
            written.append((path, original, st))
            atomic_write(path, updated, st)
        after = inspect_runtime(interfaces)
        if before != after:
            fail('runtime_identity_changed')
    except Exception:
        rollback_ok = True
        for path, original, st in reversed(written):
            try: atomic_write(path, original, st)
            except Exception: rollback_ok = False
        print(json.dumps({'applied': False, 'profiles_changed': len(written), 'backup_id': backup_id, 'rollback_ok': rollback_ok, 'error': 'apply_or_runtime_verification_failed'}))
        raise SystemExit(2)
    print(json.dumps({'applied': True, 'profiles_changed': len(written), 'backup_id': backup_id, 'interfaces': after, 'keys_and_peers_unchanged': True}))
except SystemExit:
    raise
except Exception as exc:
    # Emit fixed metadata only; never include command output or file contents.
    print(json.dumps({'error': str(exc) if str(exc).isidentifier() else 'remote_operation_failed'}))
    raise SystemExit(2)
'''


class ChangeError(RuntimeError):
    """A safe, user-readable failure without secrets or command output."""


class RemoteOperationFailure(ChangeError):
    """Safe failure that retains the remote helper's metadata for rollback."""

    def __init__(self, message: str, report: dict[str, Any]):
        super().__init__(message)
        self.report = report


def _decode_env_value(value: str) -> str:
    value = value.strip()
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise ChangeError("Malformed single-quoted environment value.")
        return value[1:-1]
    if value.startswith('"'):
        try:
            result = json.loads(value)
        except json.JSONDecodeError:
            raise ChangeError("Malformed double-quoted environment value.") from None
        if not isinstance(result, str):
            raise ChangeError("Malformed double-quoted environment value.")
        return result
    return re.sub(r"\s+#.*$", "", value).strip()


def parse_env(raw: bytes) -> tuple[dict[str, str], list[str], int]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ChangeError("Environment file must be UTF-8.") from None
    lines = text.splitlines(keepends=True)
    values: dict[str, str] = {}
    registry_indices: list[int] = []
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        match = ENV_ASSIGN_RE.match(body)
        if not match:
            continue
        name = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", match.group("prefix")).group(1)
        value = _decode_env_value(match.group("value"))
        if name == "VPNW_AWG_SERVERS":
            registry_indices.append(index)
        values[name] = value
    if len(registry_indices) != 1:
        raise ChangeError("Expected exactly one VPNW_AWG_SERVERS assignment.")
    try:
        registry = json.loads(values["VPNW_AWG_SERVERS"])
    except (KeyError, json.JSONDecodeError):
        raise ChangeError("VPNW_AWG_SERVERS is not valid JSON.") from None
    if not isinstance(registry, list) or not all(isinstance(item, dict) for item in registry):
        raise ChangeError("VPNW_AWG_SERVERS must be a list of server objects.")
    return values, lines, registry_indices[0]


def validate_public_ipv4(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise ChangeError("New IP must be a globally routable IPv4 address.") from None
    if parsed.version != 4 or not parsed.is_global or parsed.is_multicast or parsed.is_unspecified or parsed.is_reserved:
        raise ChangeError("New IP must be a globally routable IPv4 address.")
    return str(parsed)


def select_nodes(nodes: list[dict[str, Any]], server_id: str, new_ip: str) -> tuple[list[dict[str, Any]], str, str]:
    if server_id not in SERVER_IDS:
        raise ChangeError("Only fi, us, or tr exits can be migrated.")
    primary = [node for node in nodes if node.get("id") == server_id]
    if len(primary) != 1:
        raise ChangeError("Expected exactly one registry entry for the requested exit.")
    selected = [primary[0]] + [
        node for node in nodes
        if node is not primary[0]
        and (node.get("id") == f"{server_id}-alt" or node.get("alt_of") == server_id)
    ]
    old_host = str(selected[0].get("host") or "").strip()
    endpoint_host = str(selected[0].get("public_host") or old_host).strip()
    if not old_host or any(str(node.get("host") or "").strip() != old_host for node in selected):
        raise ChangeError("Selected exit and alternate must use the same current SSH host.")
    if not endpoint_host or any(str(node.get("public_host") or node.get("host") or "").strip() != endpoint_host for node in selected):
        raise ChangeError("Selected exit and alternate must use the same current public endpoint.")
    try:
        endpoint_address = ipaddress.ip_address(endpoint_host)
    except ValueError:
        raise ChangeError("The current public endpoint must be an IPv4 address.") from None
    if endpoint_address.version != 4 or endpoint_address.is_loopback or endpoint_address.is_unspecified:
        raise ChangeError("The current public endpoint must be an IPv4 address.")
    if len({str(node.get("id")) for node in selected}) != len(selected):
        raise ChangeError("Selected exit registry identities must be unique.")
    try:
        host_address = ipaddress.ip_address(old_host)
    except ValueError:
        host_address = None
    if old_host.lower().rstrip(".") == "localhost" or old_host.lower().endswith(".localhost") or (host_address and host_address.is_loopback):
        raise ChangeError("Refusing to migrate the local control server.")
    nl_hosts = {str(node.get("host") or "").strip() for node in nodes if node.get("id") == "nl"}
    if old_host in nl_hosts:
        raise ChangeError("Refusing to migrate the Netherlands control server.")
    interfaces: set[str] = set()
    ports: set[int] = set()
    for node in selected:
        interface = str(node.get("interface") or "") or None
        port = node.get("listen_port")
        if interface is not None and (not IFACE_RE.fullmatch(interface) or interface in interfaces):
            raise ChangeError("Each selected exit needs a unique, valid AWG interface.")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ChangeError("Each selected exit needs a valid configured listen port.")
        if interface is None and port in ports:
            raise ChangeError("A selected exit without an interface has an ambiguous listen port.")
        if interface is not None:
            interfaces.add(interface)
        ports.add(port)
        if not (node.get("password") or node.get("key_path")):
            raise ChangeError("Registry credentials are missing for the selected exit.")
    return selected, old_host, endpoint_host


def update_registry_text(raw: bytes, lines: list[str], index: int, nodes: list[dict[str, Any]], selected: list[dict[str, Any]], new_ip: str, old_endpoint: str) -> bytes:
    selected_ids = {node["id"] for node in selected}
    updated_nodes: list[dict[str, Any]] = []
    for node in nodes:
        item = dict(node)
        if item.get("id") in selected_ids:
            item["host"] = new_ip
            if item.get("public_host") == old_endpoint:
                item["public_host"] = new_ip
        updated_nodes.append(item)
    if updated_nodes == nodes:
        return raw
    line = lines[index]
    ending = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
    body = line[:-len(ending)] if ending else line
    match = ENV_ASSIGN_RE.match(body)
    assert match is not None
    serialized = json.dumps(updated_nodes, separators=(",", ":"), ensure_ascii=True)
    current_value = match.group("value")
    leading = current_value[:len(current_value) - len(current_value.lstrip())]
    trailing = current_value[len(current_value.rstrip()):]
    trimmed = current_value.strip()
    if trimmed.startswith("'") and trimmed.endswith("'"):
        if "'" in serialized:
            raise ChangeError("A single-quoted registry contains an apostrophe that cannot be safely preserved.")
        encoded = "'" + serialized + "'"
    elif trimmed.startswith('"') and trimmed.endswith('"'):
        encoded = json.dumps(serialized, ensure_ascii=True)
    else:
        encoded = serialized
    encoded = leading + encoded + trailing
    lines[index] = match.group("prefix") + encoded + ending
    return "".join(lines).encode("utf-8")


def _derive_fernet(secret: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest()))


def _profile_identity(config: str) -> str | None:
    in_peer = False
    public_keys: set[str] = set()
    for line in config.splitlines():
        section = re.match(r"\s*\[([^]]+)\]", line)
        if section:
            in_peer = section.group(1).strip().lower() == "peer"
        if not in_peer:
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        name = key.strip().lower()
        value = value.split("#", 1)[0].split(";", 1)[0].strip()
        if name == "publickey":
            public_keys.add(value)
    if len(public_keys) != 1:
        return None
    public_key = next(iter(public_keys))
    if not re.fullmatch(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=", public_key):
        return None
    return public_key


def cached_identities(db_paths: list[Path], secret: str, selected: list[dict[str, Any]], old_endpoint: str = "", new_ip: str = "") -> dict[str, str]:
    cipher = _derive_fernet(secret)
    result: dict[str, str] = {}
    for node in selected:
        server_id = str(node["id"])
        found: list[str] = []
        for path in db_paths:
            if not path.exists():
                continue
            if path.is_symlink():
                raise ChangeError("Refusing to read a symlinked account database.")
            uri = "file:" + quote(str(path.resolve())) + "?mode=ro"
            try:
                connection = sqlite3.connect(uri, uri=True)
                try:
                    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if "awg_fallback_server_peers" not in tables:
                        continue
                    rows = connection.execute(
                        "SELECT config_enc FROM awg_fallback_server_peers WHERE server_id = ? AND config_enc IS NOT NULL",
                        (server_id,),
                    ).fetchall()
                finally:
                    connection.close()
            except sqlite3.Error:
                raise ChangeError("Could not read cached AWG identities from the account database.") from None
            for (token,) in rows:
                if not token:
                    continue
                try:
                    config = cipher.decrypt(str(token).encode("utf-8")).decode("utf-8")
                except (InvalidToken, UnicodeDecodeError):
                    raise ChangeError("Could not decrypt a cached AWG identity.") from None
                public_key = _profile_identity(config)
                if public_key is None:
                    raise ChangeError("A cached AWG profile has no valid peer identity.")
                # Endpoint values in stored profiles are intentionally historical:
                # they change only when a user next downloads that profile.
                found.append(public_key)
        unique = set(found)
        if not unique:
            raise ChangeError(f"No cached encrypted AWG identity exists for {server_id}; refusing to guess.")
        if len(unique) != 1:
            raise ChangeError(f"Cached encrypted profiles disagree about the {server_id} interface identity.")
        result[server_id] = next(iter(unique))
    return result


def interface_payload(selected: list[dict[str, Any]], identities: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {"id": str(node["id"]), "interface": (str(node["interface"]) if node.get("interface") else None),
         "listen_port": int(node["listen_port"]), "public_key": identities[str(node["id"])]}
        for node in selected
    ]


def replace_endpoint_bytes(data: bytes, old_ip: str, new_ip: str) -> bytes:
    """Replace only a matching Endpoint host; retain port, comments and bytes."""
    pattern = re.compile(
        rb"(?i)^(?P<prefix>[ \t]*Endpoint[ \t]*=[ \t]*)"
        + re.escape(old_ip.encode("ascii"))
        + rb"(?=:[0-9]+(?:[ \t]*(?:[#;].*)?)?\r?$)",
        re.MULTILINE,
    )
    return pattern.sub(lambda match: match.group("prefix") + new_ip.encode("ascii"), data)


class _OldHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, known_keys: list[paramiko.PKey]):
        self._known_keys = known_keys

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        if not any(key.get_name() == known.get_name() and key.asbytes() == known.asbytes() for known in self._known_keys):
            raise paramiko.SSHException("Host key does not match the previously trusted server.")
        client.get_host_keys().add(hostname, key.get_name(), key)


def _trusted_old_keys(path: Path, host: str, port: int) -> list[paramiko.PKey]:
    if path.is_symlink() or not path.is_file():
        raise ChangeError("Trusted SSH known_hosts file is unavailable or unsafe.")
    try:
        keys = paramiko.HostKeys(str(path))
    except (OSError, paramiko.SSHException):
        raise ChangeError("Trusted SSH known_hosts file could not be read.") from None
    aliases = [host, f"[{host}]:{port}"]
    found: list[paramiko.PKey] = []
    for alias in aliases:
        entries = keys.lookup(alias)
        if entries:
            found.extend(entries.values())
    unique: dict[tuple[str, bytes], paramiko.PKey] = {(key.get_name(), key.asbytes()): key for key in found}
    if not unique:
        raise ChangeError("No trusted SSH host key exists for the current exit host.")
    return list(unique.values())


class ParamikoRemote:
    """One strict SSH connection to the new IP, pinned to the old host key."""

    def __init__(self, node: dict[str, Any], old_host: str, new_ip: str,
                 *, known_hosts: Path | None = None,
                 socket_connect: Callable[..., Any] = socket.create_connection,
                 ssh_factory: Callable[[], paramiko.SSHClient] = paramiko.SSHClient):
        self.node, self.old_host, self.new_ip = node, old_host, new_ip
        self.known_hosts = known_hosts or (Path.home() / ".ssh" / "known_hosts")
        self.socket_connect, self.ssh_factory = socket_connect, ssh_factory
        self.client: paramiko.SSHClient | None = None
        self.host_key: paramiko.PKey | None = None

    def connect(self) -> "ParamikoRemote":
        port = int(self.node.get("port") or 22)
        try:
            with self.socket_connect((self.new_ip, port), timeout=6):
                pass
        except OSError:
            raise ChangeError("The new IP is not accepting a connection on the registry SSH port.") from None
        old_keys = _trusted_old_keys(self.known_hosts, self.old_host, port)
        client = self.ssh_factory()
        try:
            client.load_host_keys(str(self.known_hosts))
            client.set_missing_host_key_policy(_OldHostKeyPolicy(old_keys))
            client.connect(
                hostname=self.new_ip,
                port=port,
                username=str(self.node.get("user") or "root"),
                password=self.node.get("password") or None,
                key_filename=self.node.get("key_path") or None,
                allow_agent=False,
                look_for_keys=False,
                timeout=12,
                banner_timeout=12,
                auth_timeout=12,
            )
            key = client.get_transport().get_remote_server_key()
            if not any(key.get_name() == known.get_name() and key.asbytes() == known.asbytes() for known in old_keys):
                raise ChangeError("The new host key does not match the trusted current host.")
        except ChangeError:
            client.close()
            raise
        except Exception:
            client.close()
            raise ChangeError("Strict SSH connection to the new IP failed.") from None
        self.client, self.host_key = client, key
        return self

    def run_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.client is None:
            raise ChangeError("SSH connection is not open.")
        command = "sudo -n python3 -c " + shlex.quote(REMOTE_CODE)
        try:
            stdin, stdout, _stderr = self.client.exec_command(command, timeout=240)
            stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
            response = stdout.read().decode("utf-8", "strict")
            status = stdout.channel.recv_exit_status()
            parsed = json.loads(response)
        except Exception:
            raise ChangeError("Remote AWG operation returned no safe status report.") from None
        if not isinstance(parsed, dict):
            raise ChangeError("Remote AWG operation returned an invalid status report.")
        if status:
            raise RemoteOperationFailure("Remote AWG operation failed; inspect the reported rollback status.", parsed)
        if parsed.get("error"):
            raise RemoteOperationFailure("Remote AWG runtime or profile validation failed.", parsed)
        return parsed

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None


def _atomic_write(path: Path, content: bytes) -> None:
    if path.is_symlink() or not path.is_file():
        raise ChangeError("Refusing to replace a missing or symlinked control file.")
    st = path.stat(follow_symlinks=False)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.change-exit-ip-", dir=str(path.parent))
    temporary = Path(name)
    try:
        if hasattr(os, "fchown"):
            os.fchown(fd, st.st_uid, st.st_gid)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, st.st_mode & 0o7777)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _known_host_bytes(path: Path, alias: str, key: paramiko.PKey) -> bytes:
    if path.is_symlink():
        raise ChangeError("Refusing to update a symlinked known_hosts file.")
    old = path.read_bytes() if path.exists() else b""
    if path.exists():
        try:
            current = paramiko.HostKeys(str(path))
            entries = current.lookup(alias)
        except (OSError, paramiko.SSHException):
            raise ChangeError("Trusted SSH known_hosts file could not be read.") from None
        if entries:
            existing = entries.get(key.get_name())
            if existing and existing.asbytes() == key.asbytes():
                return old
            if existing:
                raise ChangeError("A conflicting SSH host key is already registered for the new IP.")
    line = f"{alias} {key.get_name()} {key.get_base64()}\n".encode("ascii")
    if old and not old.endswith(b"\n"):
        old += b"\n"
    return old + line


def _create_control_backup(root: Path, env_path: Path, known_path: Path) -> Path:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ChangeError("Applying an exit migration requires root on the control server.")
    if root.is_symlink():
        raise ChangeError("Private control backup root cannot be a symlink.")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if hasattr(os, "geteuid") and root.stat().st_uid != 0:
        raise ChangeError("Private control backup root must be owned by root.")
    os.chmod(root, 0o700)
    backup = Path(tempfile.mkdtemp(prefix="change-exit-ip-", dir=str(root)))
    os.chmod(backup, 0o700)
    try:
        shutil.copy2(env_path, backup / "vpn-wizard.env")
        os.chmod(backup / "vpn-wizard.env", 0o600)
        if known_path.exists():
            if known_path.is_symlink():
                raise ChangeError("Refusing to back up a symlinked known_hosts file.")
            shutil.copy2(known_path, backup / "known_hosts")
            os.chmod(backup / "known_hosts", 0o600)
        else:
            (backup / "known_hosts.absent").touch(mode=0o600)
        return backup
    except Exception:
        shutil.rmtree(backup, ignore_errors=True)
        raise


def _restore_control_backup(backup: Path, env_path: Path, known_path: Path) -> bool:
    try:
        _atomic_write(env_path, (backup / "vpn-wizard.env").read_bytes())
        if (backup / "known_hosts.absent").exists():
            known_path.unlink(missing_ok=True)
        elif (backup / "known_hosts").exists():
            if not known_path.exists():
                known_path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(known_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            _atomic_write(known_path, (backup / "known_hosts").read_bytes())
        return True
    except Exception:
        return False


def _systemctl(action: str, unit: str, runner: Callable[..., Any] = subprocess.run) -> None:
    try:
        timeout = 120 if unit == "vpn-wizard-awg-health.service" else 45
        result = runner(["systemctl", action, unit], capture_output=True, text=True, timeout=timeout, check=False)
    except Exception:
        raise ChangeError("A required control-server service operation failed.") from None
    if result.returncode != 0:
        raise ChangeError("A required control-server service operation failed.")


def build_controller_command(server_id: str, new_ip: str, apply: bool, *, env_path: str = DEFAULT_ENV_POSIX) -> str:
    if server_id not in LAUNCHER_SERVER_IDS:
        raise ChangeError("Only nl, fi, us, or tr servers can be migrated.")
    new_ip = validate_public_ipv4(new_ip)
    if server_id == "nl":
        args = [
            "cd /opt/vpn-wizard/app && /opt/vpn-wizard/venv/bin/python deploy/scripts/change-controller-ip.py",
            "--new-ip", shlex.quote(new_ip), "--env", shlex.quote(env_path),
        ]
    else:
        args = [
            "cd /opt/vpn-wizard/app && /opt/vpn-wizard/venv/bin/python deploy/scripts/change-exit-ip.py",
            "--server", shlex.quote(server_id), "--new-ip", shlex.quote(new_ip),
            "--env", shlex.quote(env_path),
        ]
    if apply:
        args.append("--apply")
    return " ".join(args)


def read_ssh_alias_config(alias: str, config_path: Path | None = None, *, home: Path | None = None) -> dict[str, Any]:
    home = home or Path.home()
    config_path = config_path or (home / ".ssh" / "config")
    if config_path.is_symlink() or not config_path.is_file():
        raise ChangeError("Local SSH config was not found.")
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            ssh_config = paramiko.SSHConfig.from_file(handle)
        entry = ssh_config.lookup(alias)
    except Exception:
        raise ChangeError("Local SSH config could not be read.") from None
    hostname = str(entry.get("hostname") or "").strip()
    host_key_alias = str(entry.get("hostkeyalias") or "").strip()
    port_raw = entry.get("port", 22)
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        raise ChangeError("Controller SSH config has an invalid port.") from None
    user = str(entry.get("user") or "").strip()
    identity_files = entry.get("identityfile") or []
    if isinstance(identity_files, str):
        identity_files = [identity_files]
    identity_files = [os.path.expanduser(str(path)) for path in identity_files]
    if not hostname or not user or not 1 <= port <= 65535:
        raise ChangeError(f"SSH alias {alias} needs HostName, User, and a valid Port.")
    return {
        "hostname": hostname, "hostkeyalias": host_key_alias,
        "port": port, "user": user, "identityfile": identity_files,
    }


def read_controller_ssh_config(config_path: Path | None = None, *, home: Path | None = None) -> dict[str, Any]:
    config = read_ssh_alias_config("rodnya", config_path, home=home)
    if not config["hostkeyalias"]:
        raise ChangeError("Controller alias rodnya needs HostKeyAlias for strict validation.")
    return config


class SSHController:
    def __init__(self, client: paramiko.SSHClient, jump_client: paramiko.SSHClient | None = None):
        self.client, self.jump_client = client, jump_client

    def run(self, command: str) -> tuple[int, str, str | None]:
        try:
            timeout = 1200 if "change-controller-ip.py" in command and "--apply" in command else 300
            _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            result = stdout.read().decode("utf-8", "strict")
            error_text = stderr.read(4096).decode("utf-8", "replace")
            status = stdout.channel.recv_exit_status()
            diagnostic = next((line.strip()[:400] for line in error_text.splitlines()
                               if line.strip().startswith("ERROR: ")), None)
            return status, result, diagnostic
        except Exception:
            raise ChangeError("The controller did not return a safe status report.") from None

    def close(self) -> None:
        self.client.close()
        if self.jump_client is not None:
            self.jump_client.close()


def connect_controller(*, config_path: Path | None = None, known_hosts_path: Path | None = None,
                       home: Path | None = None, socket_connect: Callable[..., Any] = socket.create_connection,
                       ssh_factory: Callable[[], paramiko.SSHClient] = paramiko.SSHClient,
                       server_id: str = "fi", candidate_ip: str | None = None) -> SSHController:
    home = home or Path.home()
    config = read_controller_ssh_config(config_path, home=home)
    target_host = validate_public_ipv4(candidate_ip) if server_id == "nl" and candidate_ip else config["hostname"]
    known_hosts = known_hosts_path or (home / ".ssh" / "known_hosts")
    if known_hosts.is_symlink() or not known_hosts.is_file():
        raise ChangeError("Strict local SSH known_hosts file is unavailable.")

    def strict_client() -> paramiko.SSHClient:
        client = ssh_factory()
        try:
            client.load_host_keys(str(known_hosts))
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        except Exception:
            client.close()
            raise ChangeError("Strict local SSH host-key validation could not be configured.") from None
        return client

    direct_socket = None
    try:
        direct_socket = socket_connect((target_host, config["port"]), timeout=6)
    except OSError:
        direct_socket = None
    if direct_socket is not None:
        client = strict_client()
        try:
            client.connect(
                hostname=config["hostkeyalias"], port=config["port"], username=config["user"],
                key_filename=config["identityfile"] or None, sock=direct_socket,
                allow_agent=False, look_for_keys=False, timeout=15, banner_timeout=15, auth_timeout=15,
            )
            return SSHController(client)
        except Exception:
            client.close()
            try:
                direct_socket.close()
            except Exception:
                pass
            raise ChangeError("Direct strict SSH authentication to controller alias rodnya failed.") from None

    try:
        gateway = read_ssh_alias_config("vpn-us", config_path, home=home)
    except ChangeError:
        raise ChangeError("Direct SSH timed out and SSH alias vpn-us is unavailable for the gateway fallback.") from None
    key_path = Path(gateway["identityfile"][0]) if gateway["identityfile"] else home / ".ssh" / "radiopp_github_deploy"
    if not key_path.is_file():
        raise ChangeError("Direct SSH timed out and the configured US gateway key is unavailable.")
    gateway_host = validate_public_ipv4(candidate_ip) if server_id == "us" and candidate_ip else gateway["hostname"]
    jump_client = strict_client()
    target_client = None
    try:
        try:
            gateway_socket = socket_connect((gateway_host, gateway["port"]), timeout=6)
        except OSError:
            raise ChangeError("The configured US gateway is not accepting a connection.") from None
        jump_client.connect(
            hostname=gateway["hostkeyalias"] or gateway_host, port=gateway["port"], username=gateway["user"], key_filename=str(key_path),
            sock=gateway_socket,
            allow_agent=False, look_for_keys=False, timeout=15, banner_timeout=15, auth_timeout=15,
        )
        transport = jump_client.get_transport()
        if transport is None or not transport.is_active():
            raise ChangeError("Strict SSH connection to the US gateway failed.")
        channel = transport.open_channel(
            "direct-tcpip", (target_host, config["port"]), ("127.0.0.1", 0), timeout=15
        )
        target_client = strict_client()
        target_client.connect(
            hostname=config["hostkeyalias"], port=config["port"], username=config["user"],
            key_filename=config["identityfile"] or None, sock=channel,
            allow_agent=False, look_for_keys=False, timeout=15, banner_timeout=15, auth_timeout=15,
        )
        return SSHController(target_client, jump_client)
    except ChangeError:
        if target_client is not None:
            target_client.close()
        jump_client.close()
        raise
    except Exception:
        if target_client is not None:
            target_client.close()
        jump_client.close()
        raise ChangeError("Strict SSH fallback through the US gateway failed.") from None


def _update_local_ssh_alias(alias: str, new_ip: str, *, config_path: Path | None = None,
                            home: Path | None = None, backup_root: Path | None = None) -> dict[str, Any]:
    home = home or Path.home()
    config_path = config_path or (home / ".ssh" / "config")
    if config_path.is_symlink() or not config_path.is_file():
        raise ChangeError("Cannot safely update a missing or symlinked SSH config.")
    try:
        text = config_path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise ChangeError("Local SSH config is not readable UTF-8.") from None
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if re.match(r"^\s*Host\s+", line, re.I)]
    target: tuple[int, int] | None = None
    for pos, start in enumerate(starts):
        end = starts[pos + 1] if pos + 1 < len(starts) else len(lines)
        names = re.split(r"\s+", lines[start].strip(), maxsplit=1)[1].split()
        if alias in names:
            target = (start, end)
            break
    if target is None:
        raise ChangeError(f"SSH alias {alias} was not found for safe update.")
    start, end = target
    host_name_line = next((i for i in range(start + 1, end) if re.match(r"^\s*HostName\s+", lines[i], re.I)), None)
    if host_name_line is None:
        lines.insert(start + 1, f"  HostName {new_ip}\n")
    else:
        old_line = lines[host_name_line]
        ending = "\r\n" if old_line.endswith("\r\n") else ("\n" if old_line.endswith("\n") else "")
        lines[host_name_line] = re.sub(r"(?i)(^\s*HostName\s+)\S+", r"\g<1>" + new_ip, old_line.rstrip("\r\n")) + ending
    updated = "".join(lines).encode("utf-8")
    old = text.encode("utf-8")
    if updated == old:
        return {"changed": False, "alias": alias}
    backup_root = backup_root or (home / ".ssh" / "backups")
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if backup_root.is_symlink():
        raise ChangeError("Local SSH backup directory cannot be a symlink.")
    os.chmod(backup_root, 0o700)
    backup = backup_root / f"config-before-{alias}-{int(time.time())}.bak"
    if backup.exists():
        raise ChangeError("Local SSH backup already exists; refusing to overwrite it.")
    backup.write_bytes(old)
    os.chmod(backup, 0o600)
    metadata = config_path.stat(follow_symlinks=False)
    fd, temp_name = tempfile.mkstemp(prefix=".config-nl-ip-", dir=str(config_path.parent))
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp, stat.S_IMODE(metadata.st_mode))
        except OSError:
            pass
        os.replace(temp, config_path)
    finally:
        temp.unlink(missing_ok=True)
    return {"changed": True, "alias": alias, "backup": str(backup)}


def _load_site_link_sync() -> Callable[..., dict[str, Any]]:
    path = Path(__file__).with_name("update-site-vpn-link.py")
    module_name = "_update_site_vpn_link"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ChangeError("Site VPN link synchronizer is unavailable.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.sync_site_link


def _load_server_age_sync() -> Callable[..., dict[str, Any]]:
    path = Path(__file__).with_name("update-site-vpn-link.py")
    module_name = "_update_site_vpn_link"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ChangeError("Public website server-age synchronizer is unavailable.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.sync_server_address_age


def _address_age_pending_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    directory = base / "FodderVPN"
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise ChangeError("The private VPN migration state directory is invalid.")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / "server-address-age.pending.json"
    if path.is_symlink():
        raise ChangeError("The private VPN migration state file is a symlink.")
    return path


def _read_address_age_pending(path: Path) -> dict[str, str] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ChangeError("The pending VPN website update file is not a regular file.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        phase = value.get("phase") if isinstance(value, dict) else None
        changed_on = value.get("changed_on", "") if isinstance(value, dict) else None
        if (not isinstance(value, dict) or value.get("schema") != 1
                or value.get("server") not in LAUNCHER_SERVER_IDS
                or phase not in ("prepared", "confirmed")
                or not isinstance(value.get("new_ip"), str)
                or (phase == "confirmed" and (not isinstance(changed_on, str)
                    or date.fromisoformat(changed_on).isoformat() != changed_on))
                or (phase == "prepared" and changed_on not in (None, ""))):
            raise ValueError("invalid pending migration record")
        validate_public_ipv4(value["new_ip"])
        return {"server": value["server"], "phase": phase, "new_ip": value["new_ip"], "changed_on": changed_on or ""}
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, ChangeError):
        raise ChangeError("The pending VPN website update file is invalid; no migration was started.") from None


def _write_address_age_pending(path: Path, value: dict[str, str]) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise ChangeError("The pending VPN website update path is unsafe.")
    payload = {"schema": 1, **value}
    encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    fd, raw_name = tempfile.mkstemp(prefix=".server-address-age-", dir=str(path.parent))
    temporary = Path(raw_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise ChangeError("The pending VPN website update could not be stored safely.") from None


def _clear_address_age_pending(path: Path) -> None:
    if path.is_symlink():
        raise ChangeError("The pending VPN website update file is a symlink.")
    path.unlink(missing_ok=True)


def _sync_address_age(server_id: str, changed_on: str, *, apply: bool,
                      age_sync: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    try:
        report = age_sync(server_id, changed_on, apply=apply)
    except Exception as exc:
        raise ChangeError("The VPN migration succeeded, but its website IP-age update did not verify. Repeat the same server/IP to retry.") from exc
    if report.get("verified") is not True or (apply and report.get("applied") is not True):
        raise ChangeError("The VPN migration succeeded, but its website IP-age update did not verify. Repeat the same server/IP to retry.")
    return report


def _windows_main(server_id: str, new_ip: str, apply: bool, env_path: str = DEFAULT_ENV_POSIX,
                  controller_factory: Callable[..., SSHController] = connect_controller,
                  site_sync: Callable[..., dict[str, Any]] | None = None,
                  age_sync: Callable[..., dict[str, Any]] | None = None,
                  alias_updater: Callable[..., dict[str, Any]] = _update_local_ssh_alias) -> int:
    pending_path: Path | None = None
    pending: dict[str, str] | None = None
    fresh_pending = False
    age_workflow_enabled = bool(apply and (controller_factory is connect_controller or age_sync is not None))
    if age_workflow_enabled:
        try:
            pending_path = _address_age_pending_path()
            pending = _read_address_age_pending(pending_path)
            if pending and (pending["server"] != server_id or pending["new_ip"] != new_ip):
                raise ChangeError(
                    "A previous VPN website IP-age update is still pending. Repeat that same server/IP first."
                )
            if pending is None:
                pending = {
                    "server": server_id,
                    "phase": "prepared",
                    "new_ip": new_ip,
                    "changed_on": "",
                }
                _write_address_age_pending(pending_path, pending)
                fresh_pending = True
        except ChangeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    try:
        command = build_controller_command(server_id, new_ip, apply, env_path=env_path)
        controller = (controller_factory(server_id=server_id, candidate_ip=new_ip) if controller_factory is connect_controller
                      else controller_factory())
        try:
            status, output, diagnostic = controller.run(command)
        finally:
            controller.close()
    except ChangeError as exc:
        if fresh_pending and pending_path is not None:
            _clear_address_age_pending(pending_path)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if status != 0:
        if fresh_pending and pending_path is not None:
            _clear_address_age_pending(pending_path)
        if output:
            print(output.strip())
        if diagnostic:
            print(diagnostic, file=sys.stderr)
        else:
            print("ERROR: The controller reported that the migration did not complete.", file=sys.stderr)
        return status or 1

    try:
        migration_report = json.loads(output) if output else {}
    except json.JSONDecodeError:
        migration_report = {}
    address_changed = False
    if isinstance(migration_report, dict) and migration_report.get("verified") is True and migration_report.get("applied") is True:
        reported_old_ip = migration_report.get("old_ip")
        reported_new_ip = migration_report.get("new_ip")
        address_changed = (
            isinstance(reported_old_ip, str)
            and isinstance(reported_new_ip, str)
            and reported_new_ip == new_ip
            and reported_old_ip != reported_new_ip
        )
    if age_workflow_enabled and address_changed and pending_path is not None and pending is not None:
        if pending.get("phase") != "confirmed":
            pending["phase"] = "confirmed"
            pending["changed_on"] = date.today().isoformat()
        try:
            _write_address_age_pending(pending_path, pending)
        except ChangeError as exc:
            print(f"ERROR: The VPN migration succeeded, but its retry marker could not be stored: {exc}", file=sys.stderr)
            return 1
    should_sync_age = bool(age_workflow_enabled and pending is not None
                           and pending.get("phase") == "confirmed")
    if age_workflow_enabled and not should_sync_age and pending is not None and pending.get("phase") == "prepared" and pending_path is not None:
        _clear_address_age_pending(pending_path)

    if server_id == "nl":
        try:
            report = migration_report
            if not isinstance(report, dict) or report.get("verified") is not True or (apply and report.get("applied") is not True):
                print("ERROR: NL controller did not confirm a verified migration result.", file=sys.stderr)
                return 1
            alias_name = "rodnya"
            alias_error = None
            try:
                alias_status = alias_updater(alias_name, new_ip) if apply else {"changed": False, "alias": alias_name, "would_change": True}
            except Exception as exc:
                alias_status = {"changed": False, "alias": alias_name, "error": str(exc)[:240]}
                alias_error = exc
            sync = site_sync or _load_site_link_sync()
            try:
                site_status = sync(new_ip, apply=apply)
                site_ok = site_status.get("verified") is True and (not apply or site_status.get("applied") is True)
            except Exception as exc:
                site_status = getattr(exc, "result", None) or {"verified": False, "applied": False, "error": str(exc)[:240]}
                site_ok = False
            report["local_source_alias"] = alias_status
            report["website"] = site_status
            age_status = None
            if should_sync_age and pending is not None and pending_path is not None:
                try:
                    sync = age_sync or _load_server_age_sync()
                    age_status = _sync_address_age(server_id, pending["changed_on"], apply=True, age_sync=sync)
                    _clear_address_age_pending(pending_path)
                except ChangeError:
                    age_status = {"verified": False, "applied": False, "retry_pending": True}
            report["address_age"] = age_status or {"verified": True, "applied": False, "changed": False}
            if apply and report.get("old_ip") != new_ip:
                domain = new_ip.replace(".", "-") + ".nip.io"
                report["botfather_actions"] = [f"/setdomain {domain}", f"MainAppURL https://{domain}/portal/"]
            print(json.dumps(report, separators=(",", ":")))
            if not site_ok:
                print("ERROR: NL migration succeeded, but the website link update or verification failed.", file=sys.stderr)
                return 1
            if should_sync_age and not (age_status and age_status.get("verified") is True and age_status.get("applied") is True):
                print("ERROR: NL migration succeeded, but its website IP-age update did not verify. Repeat the same server/IP to retry.", file=sys.stderr)
                return 1
            if alias_error is not None:
                print("ERROR: NL migration and website sync succeeded, but the local SSH alias update failed.", file=sys.stderr)
                return 1
        except Exception:
            print("ERROR: NL controller succeeded, but launcher status processing failed.", file=sys.stderr)
            if output:
                print(output.strip())
            return 1
    elif apply and server_id in {"fi", "us"}:
        alias_name = {"fi": "fi-new", "us": "vpn-us"}[server_id]
        try:
            alias_status = alias_updater(alias_name, new_ip)
        except Exception as exc:
            print(json.dumps({"server": server_id, "verified": True, "applied": True,
                              "local_source_alias": {"alias": alias_name, "error": str(exc)[:240]}}, separators=(",", ":")))
            print(f"ERROR: {server_id} migration succeeded, but local SSH alias update failed.", file=sys.stderr)
            return 1
        report = json.loads(output) if output else {"server": server_id, "verified": True, "applied": True}
        report["local_source_alias"] = alias_status
        age_status = None
        if should_sync_age and pending is not None and pending_path is not None:
            try:
                sync = age_sync or _load_server_age_sync()
                age_status = _sync_address_age(server_id, pending["changed_on"], apply=True, age_sync=sync)
                _clear_address_age_pending(pending_path)
            except ChangeError:
                age_status = {"verified": False, "applied": False, "retry_pending": True}
        report["address_age"] = age_status or {"verified": True, "applied": False, "changed": False}
        print(json.dumps(report, separators=(",", ":")))
        if should_sync_age and not (age_status and age_status.get("verified") is True and age_status.get("applied") is True):
            print(f"ERROR: {server_id} migration succeeded, but its website IP-age update did not verify. Repeat the same server/IP to retry.", file=sys.stderr)
            return 1
    elif output:
        report = migration_report
        age_status = None
        if should_sync_age and pending is not None and pending_path is not None:
            try:
                sync = age_sync or _load_server_age_sync()
                age_status = _sync_address_age(server_id, pending["changed_on"], apply=True, age_sync=sync)
                _clear_address_age_pending(pending_path)
            except ChangeError:
                age_status = {"verified": False, "applied": False, "retry_pending": True}
        if isinstance(report, dict):
            report["address_age"] = age_status or {"verified": True, "applied": False, "changed": False}
            print(json.dumps(report, separators=(",", ":")))
        else:
            print(output.strip())
        if should_sync_age and not (age_status and age_status.get("verified") is True and age_status.get("applied") is True):
            print(f"ERROR: {server_id} migration succeeded, but its website IP-age update did not verify. Repeat the same server/IP to retry.", file=sys.stderr)
            return 1
    return 0


def migrate(server_id: str, new_ip: str, *, env_path: Path = DEFAULT_ENV, apply: bool = False,
            transport_factory: Callable[..., Any] = ParamikoRemote,
            socket_connect: Callable[..., Any] = socket.create_connection,
            service_runner: Callable[..., Any] = subprocess.run,
            backup_root: Path = BACKUP_ROOT,
            known_hosts_path: Path | None = None,
            root_check: Callable[[], bool] | None = None,
            include_address_metadata: bool = False) -> dict[str, Any]:
    new_ip = validate_public_ipv4(new_ip)
    if env_path.is_symlink() or not env_path.is_file():
        raise ChangeError("Environment file is missing or symlinked.")
    raw = env_path.read_bytes()
    values, lines, registry_index = parse_env(raw)
    try:
        nodes = json.loads(values["VPNW_AWG_SERVERS"])
    except (KeyError, json.JSONDecodeError):
        raise ChangeError("VPNW_AWG_SERVERS is not valid JSON.") from None
    selected, old_host, old_endpoint = select_nodes(nodes, server_id, new_ip)
    secret = values.get("VPNW_SECRET_KEY", "").strip()
    if not secret:
        raise ChangeError("VPNW_SECRET_KEY is required to verify cached encrypted identities.")
    state_raw = values.get("VPNW_STATE_DB", "").strip()
    state_db = Path(state_raw) if state_raw and state_raw != ":memory:" else Path(__file__).resolve().parents[2] / ".vpnw" / "state.db"
    if state_raw == ":memory:":
        raise ChangeError("A file-backed VPNW_STATE_DB is required to verify cached identities.")
    identity_map = cached_identities(
        [state_db, state_db.with_name("public-access.db")], secret, selected, old_endpoint, new_ip
    )
    iface_data = interface_payload(selected, identity_map)
    control_after = update_registry_text(raw, lines, registry_index, nodes, selected, new_ip, old_endpoint)
    ssh_port = int(selected[0].get("port") or 22)
    known_path = known_hosts_path or (Path.home() / ".ssh" / "known_hosts")
    transport = transport_factory(
        selected[0], old_host, new_ip, known_hosts=known_path, socket_connect=socket_connect
    )
    try:
        transport.connect()
        inspect = transport.run_payload({
            "mode": "inspect", "old_ip": old_endpoint, "new_ip": new_ip, "interfaces": iface_data,
        })
        profile_count = int(inspect.get("profiles_to_update", -1))
        if profile_count < 0:
            raise ChangeError("Remote AWG inspection returned invalid metadata.")
        host_alias = new_ip if ssh_port == 22 else f"[{new_ip}]:{ssh_port}"
        known_after = _known_host_bytes(known_path, host_alias, transport.host_key)
        control_changed = control_after != raw
        known_before = known_path.read_bytes() if known_path.exists() else b""
        known_changed = known_after != known_before
        changed = control_changed or known_changed or profile_count > 0
        address_metadata = {"old_ip": old_endpoint, "new_ip": new_ip} if include_address_metadata else {}
        if not apply:
            return {
                "server": server_id, "selected_profiles": len(selected),
                **address_metadata,
                "remote_profiles_to_update": profile_count, "registry_would_change": control_changed,
                "host_key_would_register": known_changed, "verified": True, "applied": False,
            }
        if not changed:
            return {
                "server": server_id, "selected_profiles": len(selected),
                **address_metadata,
                "remote_profiles_changed": 0, "verified": True, "applied": True, "changed": False,
                "service_restarted": False,
            }
        if root_check is not None and not root_check():
            raise ChangeError("Applying an exit migration requires root on the control server.")
        backup: Path | None = None
        remote_backup: str | None = None
        remote_rollback_report: bool | None = None
        service_touched = False
        if root_check is None and hasattr(os, "geteuid") and os.geteuid() != 0:
            raise ChangeError("Applying an exit migration requires root on the control server.")
        backup = _create_control_backup(backup_root, env_path, known_path)
        try:
            if profile_count:
                try:
                    remote_result = transport.run_payload({
                        "mode": "apply", "old_ip": old_endpoint, "new_ip": new_ip, "interfaces": iface_data,
                    })
                except RemoteOperationFailure as remote_failure:
                    remote_backup = remote_failure.report.get("backup_id")
                    if "rollback_ok" in remote_failure.report:
                        remote_rollback_report = remote_failure.report.get("rollback_ok") is True
                    raise
                if remote_result.get("applied") is not True or remote_result.get("keys_and_peers_unchanged") is not True:
                    remote_backup = remote_result.get("backup_id")
                    raise ChangeError("Remote endpoint update or runtime identity verification failed.")
                remote_backup = remote_result.get("backup_id")
            if control_changed:
                _atomic_write(env_path, control_after)
            if known_changed:
                _atomic_write(known_path, known_after)
            service_touched = True
            _systemctl("restart", "vpn-wizard", service_runner)
            _systemctl("start", "vpn-wizard-awg-health.service", service_runner)
            return {
                "server": server_id, "selected_profiles": len(selected),
                **address_metadata,
                "remote_profiles_changed": profile_count, "registry_updated": control_changed,
                "host_key_registered": known_changed, "verified": True, "applied": True,
                "changed": True, "service_restarted": True,
                "backup": backup.name, "remote_backup": remote_backup,
            }
        except Exception as failure:
            remote_rollback = remote_rollback_report
            if remote_backup:
                try:
                    remote_rollback = transport.run_payload({"mode": "restore", "backup_id": remote_backup})
                    remote_rollback = bool(remote_rollback.get("rollback_ok") is True)
                except Exception:
                    remote_rollback = False
            control_rollback = _restore_control_backup(backup, env_path, known_path) if backup else True
            service_rollback = None
            if service_touched:
                try:
                    _systemctl("restart", "vpn-wizard", service_runner)
                    service_rollback = True
                except Exception:
                    service_rollback = False
            if isinstance(failure, ChangeError):
                message = str(failure)
            else:
                message = "Exit migration failed after changes began."
            raise ChangeError(
                f"{message} Rollback status: remote={remote_rollback}, control={control_rollback}, service={service_rollback}."
            ) from None
    finally:
        transport.close()


def _run_linux(args: argparse.Namespace) -> int:
    if args.server == "nl":
        path = Path(__file__).with_name("change-controller-ip.py")
        spec = importlib.util.spec_from_file_location("_change_controller_ip", path)
        if spec is None or spec.loader is None:
            print("ERROR: NL controller migration helper is unavailable.", file=sys.stderr)
            return 1
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            result = module.migrate_controller(args.new_ip, env_path=args.env, apply=args.apply)
        except module.ChangeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, separators=(",", ":")))
        return 0
    try:
        result = migrate(args.server, args.new_ip, env_path=args.env, apply=args.apply,
                         include_address_metadata=True)
    except ChangeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, choices=sorted(LAUNCHER_SERVER_IDS))
    parser.add_argument("--new-ip", required=True)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--apply", action="store_true", help="apply after verification; default is dry-run")
    args = parser.parse_args(argv)
    try:
        args.new_ip = validate_public_ipv4(args.new_ip)
    except ChangeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if os.name == "nt":
        return _windows_main(args.server, args.new_ip, args.apply, args.env.as_posix())
    return _run_linux(args)


if __name__ == "__main__":
    raise SystemExit(main())
