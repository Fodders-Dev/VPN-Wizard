from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest


PATH = Path(__file__).resolve().parents[1] / "deploy" / "scripts" / "move-nl-endpoint.py"
SPEC = importlib.util.spec_from_file_location("move_nl_endpoint", PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_replace_endpoints_changes_only_complete_tokens_and_preserves_other_bytes() -> None:
    original = (
        b"[Interface]\r\n"
        b"PrivateKey = AQIDBAUGBwgJCgsMDQ4PEA==\r\n"
        b"PresharedKey = 1234567890abcdef\r\n"
        b"ListenPort = 3478\r\n"
        b"[Peer]\r\n"
        b"PublicKey = Q0RFRkdISUpLTE1OT1BRUg==\r\n"
        b"Endpoint = 77.67.89.164:3478\r\n"
        b"ServerName = 77-67-89-164.nip.io\r\n"
        b"VPNW_AWG_SERVERS='[{\"id\":\"nl\",\"host\":\"77.67.89.164\",\"listen_port\":3478,\"key_path\":\"/root/keys/nl\",\"password\":\"fixture-secret\"}]'\r\n"
        b"NearIp = 77.67.89.1640\r\n"
        b"NearIp2 = 177.67.89.164\r\n"
        b"NearIp3 = _77.67.89.164\r\n"
        b"DomainPanel = panel-vpn.77-67-89-164.nip.io\r\n"
        b"DomainSub = sub-vpn.77-67-89-164.nip.io\r\n"
        b"NearDomain = child77-67-89-164.nip.io\r\n"
        b"NearDomainPrefix = child-77-67-89-164.nip.io\r\n"
        b"NearDomain2 = 77-67-89-164.nip.io.attacker.example\r\n"
        b"NearDomain3 = _77-67-89-164.nip.io\r\n"
    )

    updated = MODULE.replace_endpoints(original)

    assert updated == (
        b"[Interface]\r\n"
        b"PrivateKey = AQIDBAUGBwgJCgsMDQ4PEA==\r\n"
        b"PresharedKey = 1234567890abcdef\r\n"
        b"ListenPort = 3478\r\n"
        b"[Peer]\r\n"
        b"PublicKey = Q0RFRkdISUpLTE1OT1BRUg==\r\n"
        b"Endpoint = 82.25.60.19:3478\r\n"
        b"ServerName = 82-25-60-19.nip.io\r\n"
        b"VPNW_AWG_SERVERS='[{\"id\":\"nl\",\"host\":\"82.25.60.19\",\"listen_port\":3478,\"key_path\":\"/root/keys/nl\",\"password\":\"fixture-secret\"}]'\r\n"
        b"NearIp = 77.67.89.1640\r\n"
        b"NearIp2 = 177.67.89.164\r\n"
        b"NearIp3 = _77.67.89.164\r\n"
        b"DomainPanel = panel-vpn.82-25-60-19.nip.io\r\n"
        b"DomainSub = sub-vpn.82-25-60-19.nip.io\r\n"
        b"NearDomain = child77-67-89-164.nip.io\r\n"
        b"NearDomainPrefix = child-77-67-89-164.nip.io\r\n"
        b"NearDomain2 = 77-67-89-164.nip.io.attacker.example\r\n"
        b"NearDomain3 = _77-67-89-164.nip.io\r\n"
    )
    assert MODULE.replace_endpoints(updated) == updated


def test_client_dir_selects_only_direct_conf_and_suspended_profiles(tmp_path: Path) -> None:
    clients = tmp_path / "clients"
    nested = clients / "nested"
    nested.mkdir(parents=True)
    active = clients / "sub-1.conf"
    suspended = clients / "sub-2.conf.suspended"
    ignored = clients / "notes.txt"
    nested_profile = nested / "sub-3.conf"
    payload = b"Endpoint = 77.67.89.164:3478\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEA==\n"
    active.write_bytes(payload)
    suspended.write_bytes(payload)
    ignored.write_bytes(payload)
    nested_profile.write_bytes(payload)

    plans = MODULE.plan_files([], [clients])

    assert [plan.path.name for plan in plans] == ["sub-1.conf", "sub-2.conf.suspended"]
    assert all(plan.client_profile and plan.changed for plan in plans)
    assert active.read_bytes() == payload
    assert suspended.read_bytes() == payload
    assert nested_profile.read_bytes() == payload


def test_dry_run_emits_counts_only_and_does_not_change_profiles(tmp_path: Path, capsys) -> None:
    clients = tmp_path / "clients"
    clients.mkdir()
    profile = clients / "sub-7.conf.suspended"
    original = b"Endpoint = 77.67.89.164:3478\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEA==\n"
    profile.write_bytes(original)

    assert MODULE.main(["--client-dir", str(clients)]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output == {
        "applied": False,
        "files_changed": 1,
        "files_scanned": 1,
        "profiles_changed": 1,
    }
    assert profile.read_bytes() == original


def test_invalid_utf8_is_rejected_without_a_partial_plan(tmp_path: Path) -> None:
    source = tmp_path / "not-utf8.conf"
    source.write_bytes(b"Endpoint = 77.67.89.164:3478\n\xff\xfe")

    with pytest.raises(ValueError, match="UTF-8"):
        MODULE.plan_files([source], [])

    assert source.read_bytes().endswith(b"\xff\xfe")


def test_all_allowlisted_files_validate_before_any_apply_write(tmp_path: Path) -> None:
    valid = tmp_path / "first.conf"
    invalid = tmp_path / "second.conf"
    original = b"Endpoint = 77.67.89.164:3478\n"
    valid.write_bytes(original)
    invalid.write_bytes(b"Endpoint = 77.67.89.164:3478\n\xff")
    backup_parent = tmp_path / "backups"
    backup_parent.mkdir()
    backup = backup_parent / "run-1"

    with pytest.raises(ValueError, match="UTF-8"):
        MODULE.plan_files([valid, invalid], [])

    assert valid.read_bytes() == original
    assert not backup.exists()


def test_symlink_file_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "outside.conf"
    source.write_bytes(b"Endpoint = 77.67.89.164:3478\n")
    link = tmp_path / "clients" / "sub-1.conf"
    link.parent.mkdir()
    real_lstat = MODULE._lstat

    def lstat_with_link(candidate: Path):
        if candidate == link:
            return SimpleNamespace(st_mode=stat.S_IFLNK)
        return real_lstat(candidate)

    monkeypatch.setattr(MODULE, "_lstat", lstat_with_link)

    with pytest.raises(ValueError, match="Symlink"):
        MODULE.plan_files([link], [])

    assert source.read_bytes() == b"Endpoint = 77.67.89.164:3478\n"


def test_apply_requires_a_new_absolute_backup_before_writing(tmp_path: Path) -> None:
    source = tmp_path / "client.conf"
    original = b"Endpoint = 77.67.89.164:3478\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEA==\n"
    source.write_bytes(original)
    plans = MODULE.plan_files([source], [])

    with pytest.raises(ValueError, match="required"):
        MODULE.apply_plan(plans, None)
    with pytest.raises(ValueError, match="absolute"):
        MODULE.apply_plan(plans, Path("relative-backup"))

    existing = tmp_path / "existing-backup"
    existing.mkdir()
    with pytest.raises(ValueError, match="new"):
        MODULE.apply_plan(plans, existing)

    assert source.read_bytes() == original


def test_successful_apply_backs_up_bytes_and_preserves_source_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clients = tmp_path / "clients"
    clients.mkdir()
    source = clients / "sub-19.conf"
    original = b"Endpoint = 77.67.89.164:3478\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEA==\n"
    source.write_bytes(original)
    source.chmod(0o640)
    before = source.stat()
    plans = MODULE.plan_files([], [clients])
    backup_parent = tmp_path / "backups"
    backup_parent.mkdir()
    backup = backup_parent / "run-1"

    # Root ownership is enforced by the production checks. These hooks let the
    # filesystem behavior run on the Windows developer workstation too.
    monkeypatch.setattr(MODULE, "_running_as_root", lambda: True)
    monkeypatch.setattr(MODULE, "_root_private_directory", lambda _path: True)

    assert MODULE.apply_plan(plans, backup) is True

    assert source.read_bytes() == original.replace(b"77.67.89.164", b"82.25.60.19")
    assert source.read_bytes().splitlines()[1] == b"PrivateKey = AQIDBAUGBwgJCgsMDQ4PEA=="
    assert stat.S_IMODE(source.stat().st_mode) == stat.S_IMODE(before.st_mode)
    saved = list(backup.rglob("sub-19.conf"))
    assert len(saved) == 1
    assert saved[0].read_bytes() == original
    assert stat.S_IMODE(saved[0].stat().st_mode) == stat.S_IMODE(before.st_mode)
    assert saved[0].stat().st_mtime_ns == before.st_mtime_ns
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    if os.name == "posix":
        assert saved[0].stat().st_uid == before.st_uid
        assert saved[0].stat().st_gid == before.st_gid
        assert source.stat().st_uid == before.st_uid
        assert source.stat().st_gid == before.st_gid


def test_noop_apply_is_idempotent_and_needs_no_backup(tmp_path: Path) -> None:
    source = tmp_path / "client.conf"
    source.write_bytes(b"Endpoint = 82.25.60.19:3478\n")
    plans = MODULE.plan_files([source], [])

    assert MODULE.apply_plan(plans, None) is False
    assert source.read_bytes() == b"Endpoint = 82.25.60.19:3478\n"
