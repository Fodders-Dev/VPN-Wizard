"""Swap FI awg9/awg0 ports, preserving keys/peers with private rollback copies."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path('/etc/amnezia/amneziawg')
DESIRED = {'awg0': 443, 'awg9': 3478}


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, timeout=10).strip()


def replace_port(text: str, port: int) -> str:
    if len(re.findall(r'^ListenPort\s*=', text, re.M)) != 1:
        raise ValueError('Expected exactly one ListenPort')
    return re.sub(r'^(ListenPort\s*=\s*)\d+', lambda m: m[1] + str(port), text, flags=re.M)


def replace_endpoint(text: str, port: int) -> str:
    return re.sub(r'^(Endpoint\s*=\s*)[^\s#;]+',
                  lambda m: m[1] + f'46.38.156.229:{port}', text, flags=re.M)


def atomic(path: Path, content: str) -> None:
    temp = path.with_name(path.name + '.port-swap-new')
    with temp.open('x', encoding='utf-8') as handle:
        os.chmod(temp, 0o600)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    shutil.copystat(path, temp)
    temp.replace(path)


def identity(iface: str) -> tuple[str, str]:
    # Public identity only; never show runtime private keys or client profiles.
    return run('awg', 'show', iface, 'public-key'), hashlib.sha256(
        run('awg', 'show', iface, 'peers').encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup-dir', type=Path)
    args = parser.parse_args()
    ports = {r.split()[0]: int(r.split()[1]) for r in run('awg', 'show', 'all', 'listen-port').splitlines()}
    before = {iface: ports[iface] for iface in DESIRED}
    if before not in ({'awg0': 3478, 'awg9': 443}, DESIRED):
        raise ValueError('Unexpected FI listeners')
    if any(port in (443, 3478, 34780) for iface, port in ports.items() if iface not in DESIRED):
        raise ValueError('Another interface occupies a required port')
    if 34780 in ports.values():
        raise ValueError('Temporary swap port occupied')
    saved = {iface: identity(iface) for iface in DESIRED}
    changes = {}
    for iface, port in DESIRED.items():
        server = ROOT / (iface + '.conf')
        changes[server] = replace_port(server.read_text(), port)
        clients = ROOT / ('clients' if iface == 'awg0' else 'clients_awg9')
        for path in sorted(clients.glob('*.conf*')):
            if path.name.endswith(('.conf', '.conf.suspended')):
                changes[path] = replace_endpoint(path.read_text(), port)
    changes = {p: c for p, c in changes.items() if p.read_text() != c}
    print(json.dumps({'ports_before': before, 'ports_after': DESIRED, 'files_to_update': len(changes), 'apply': args.apply}))
    if not args.apply:
        return
    if not args.backup_dir:
        raise ValueError('A private backup directory is required')
    backup = args.backup_dir.resolve()
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    for path in changes:
        assert path.resolve().is_relative_to(ROOT) and not path.is_symlink()
        dest = backup / path.relative_to(ROOT)
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        dest.chmod(0o600)
    try:
        if before != DESIRED:
            run('awg', 'set', 'awg0', 'listen-port', '34780')
            run('awg', 'set', 'awg9', 'listen-port', '3478')
            run('awg', 'set', 'awg0', 'listen-port', '443')
        for path, text in changes.items():
            atomic(path, text)
        assert all(identity(iface) == saved[iface] for iface in DESIRED), 'Keys/peers changed'
        assert all(int(run('awg', 'show', i, 'listen-port')) == p for i, p in DESIRED.items())
    except Exception:
        run('awg', 'set', 'awg0', 'listen-port', '34780')
        run('awg', 'set', 'awg9', 'listen-port', str(before['awg9']))
        run('awg', 'set', 'awg0', 'listen-port', str(before['awg0']))
        for path in changes:
            shutil.copy2(backup / path.relative_to(ROOT), path)
        raise
    print(json.dumps({'verified': True, 'keys_and_peers_unchanged': True, 'backup': str(backup)}))


if __name__ == '__main__':
    main()
