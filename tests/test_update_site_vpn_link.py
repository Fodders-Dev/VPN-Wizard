from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "scripts" / "update-site-vpn-link.py"
SPEC = importlib.util.spec_from_file_location("update_site_vpn_link", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
site_link = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = site_link
SPEC.loader.exec_module(site_link)


def test_target_and_snippet_are_strict_and_injection_safe():
    domain, target = site_link.target_for_ip("8.8.8.8")

    assert domain == "8-8-8-8.nip.io"
    assert target == "https://8-8-8-8.nip.io/connect/join.html"
    assert site_link.build_caddy_snippet("8.8.8.8") == (
        b"@fodderVpnEntry path /vpn /vpn/\n"
        b"handle @fodderVpnEntry {\n"
        b'    header Cache-Control "no-store"\n'
        b"    redir https://8-8-8-8.nip.io/connect/join.html 302\n"
        b"}\n"
    )

    for invalid in ("127.0.0.1", "192.168.1.1", "224.0.0.1", "2001:4860:4860::8888",
                    "8.8.8.8\nredir https://attacker.example", "not-an-ip"):
        with pytest.raises(site_link.SiteLinkSyncError):
            site_link.target_for_ip(invalid)


def test_public_verification_checks_both_exact_paths_headers_and_drops_query():
    requested: list[str] = []
    target = "https://8-8-8-8.nip.io/connect/join.html"

    def get(url: str, *, timeout: float):
        requested.append(url)
        if url == target:
            return site_link.HttpResult(200, {})
        return site_link.HttpResult(302, {"location": target, "cache-control": "no-store"})

    site_link._verify_public_shortcut(target, get)

    assert requested == [
        "https://fodders.ru/vpn",
        "https://fodders.ru/vpn/",
        "https://fodders.ru/vpn?codex_probe=must-drop",
        "https://fodders.ru/vpn/?codex_probe=must-drop",
        target,
    ]


def test_public_verification_rejects_query_carry_or_missing_no_store():
    target = "https://8-8-8-8.nip.io/connect/join.html"

    def carries_query(url: str, *, timeout: float):
        location = target + "?codex_probe=must-drop"
        return site_link.HttpResult(302, {"Location": location, "Cache-Control": "no-store"})

    with pytest.raises(site_link.SiteLinkSyncError, match="unexpected destination"):
        site_link._verify_public_shortcut(target, carries_query)

    def cacheable(url: str, *, timeout: float):
        return site_link.HttpResult(302, {"Location": target, "Cache-Control": "public, max-age=60"})

    with pytest.raises(site_link.SiteLinkSyncError, match="Cache-Control"):
        site_link._verify_public_shortcut(target, cacheable)


def test_dry_run_checks_endpoint_and_inspects_site_without_mutation():
    requested: list[str] = []

    def get(url: str, *, timeout: float):
        requested.append(url)
        return site_link.HttpResult(200, {}, b'{"servers":[{"id":"nl"}]}')

    class Stdin:
        def __init__(self):
            self.script = ""
            self.channel = SimpleNamespace(shutdown_write=lambda: None)

        def write(self, value: str):
            self.script += value

        def flush(self):
            pass

    class Stdout:
        channel = SimpleNamespace(recv_exit_status=lambda: 0)

        def read(self):
            return b'{"ok":true,"would_change":true,"missing_route":true,"target_current":false}'

    class Client:
        def __init__(self):
            self.stdin = Stdin()
            self.closed = False

        def exec_command(self, command: str, *, timeout: int):
            assert command == "python3 -"
            return self.stdin, Stdout(), SimpleNamespace(read=lambda size: b"")

        def close(self):
            self.closed = True

    client = Client()
    result = site_link.sync_site_link("8.8.8.8", http_get=get, ssh_connect=lambda: client)

    assert result["site_updated"] is False
    assert result["verified"] is False
    assert result["applied"] is False
    assert result["dry_run"] is True
    assert result["endpoint_verified"] is True
    assert result["would_change"] is True
    assert result["missing_route"] is True
    assert requested == [
        "https://8-8-8-8.nip.io/connect/join.html",
        "https://8-8-8-8.nip.io/api/awg/servers?include_unavailable=true",
    ]
    assert '"mode":"inspect"' in client.stdin.script
    assert '"mode":"apply"' not in client.stdin.script
    assert client.closed is True


def _main_file(desk_marker: str = "desk-file-server", radio_marker: str = "radio-proxy") -> bytes:
    return (
        "{\n    admin off\n}\n"
        "fodders.ru, www.fodders.ru {\n"
        "    import /etc/caddy/fodders-desk.caddy\n"
        f"    handle {{\n        respond {desk_marker}\n    }}\n"
        "}\n"
        "radioatlas.example {\n"
        f"    respond {radio_marker}\n"
        "}\n"
    ).encode("ascii")


def _remote(tmp_path: Path, main_data: bytes, snippet_data: bytes | None = None):
    caddy_dir = tmp_path / "etc-caddy"
    caddy_dir.mkdir()
    backup_parent = tmp_path / "var" / "backups"
    backup_parent.mkdir(parents=True)
    backup_root = backup_parent / "fodders-site"
    backup_root.mkdir(mode=0o700)
    main_path = caddy_dir / "Caddyfile"
    main_path.write_bytes(main_data)
    main_path.chmod(0o640)
    snippet_path = caddy_dir / "fodder-vpn-link.caddy"
    if snippet_data is not None:
        snippet_path.write_bytes(snippet_data)
        snippet_path.chmod(0o640)
    lock_dir = tmp_path / "run" / "lock"
    lock_dir.mkdir(parents=True)

    class FakeFcntl:
        LOCK_EX = 1
        LOCK_UN = 2

        def __init__(self):
            self.calls: list[tuple[int, int]] = []

        def flock(self, fd: int, operation: int):
            self.calls.append((fd, operation))

    class TestOS:
        name = "nt"

        def __getattr__(self, name: str):
            return getattr(os, name)

        @staticmethod
        def geteuid():
            return 0

        @staticmethod
        def fchown(fd: int, uid: int, gid: int):
            return None

    namespace: dict[str, object] = {"__name__": "remote_site_link_test"}
    exec(compile(site_link.REMOTE_SCRIPT, "<remote-site-vpn-link>", "exec"), namespace)
    namespace["MAIN_PATH"] = main_path
    namespace["SNIPPET_PATH"] = snippet_path
    namespace["BACKUP_ROOT"] = backup_root
    namespace["LOCK_PATH"] = lock_dir / "fodders-site-vpn-link.lock"
    namespace["os"] = TestOS()
    fake_fcntl = FakeFcntl()
    namespace["fcntl"] = fake_fcntl
    namespace["test_fcntl"] = fake_fcntl
    return namespace, main_path, snippet_path, backup_root


def _success_command(args, **kwargs):
    return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_remote_validates_full_candidate_then_changes_only_the_fodders_import(tmp_path: Path):
    original = _main_file()
    namespace, main_path, snippet_path, backup_root = _remote(tmp_path, original)
    validations: list[tuple[Path, bytes, bytes | None]] = []

    def command(args, **kwargs):
        if args[0] == "caddy" and args[1] == "validate":
            candidate = Path(args[args.index("--config") + 1])
            candidate_data = candidate.read_bytes()
            if candidate != main_path:
                lines = candidate_data.splitlines()
                import_line = next(line for line in lines if b"import " in line and b"fodder-vpn-link" in line)
                staged_snippet = Path(import_line.split(b"import ", 1)[1].decode("ascii").strip())
                validations.append((candidate, candidate_data, staged_snippet.read_bytes()))
                assert staged_snippet != snippet_path
                assert main_path.read_bytes() == original
                assert not snippet_path.exists()
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    namespace["run_command"] = command
    result = namespace["run"]({"mode": "apply", "domain": "8-8-8-8.nip.io"})

    assert result["ok"] is True
    assert result["changed"] is True
    assert len(validations) == 1
    candidate_main = validations[0][1]
    candidate_snippet = validations[0][2]
    assert candidate_snippet == site_link.build_caddy_snippet("8.8.8.8")
    assert b"import /etc/caddy/fodder-vpn-link.caddy" not in candidate_main
    assert b".fodder-vpn-link-candidate-" in candidate_main

    actual_main = main_path.read_bytes()
    expected_main = original.replace(
        b"    import /etc/caddy/fodders-desk.caddy\n",
        b"    import /etc/caddy/fodder-vpn-link.caddy\n"
        b"    import /etc/caddy/fodders-desk.caddy\n",
    )
    assert actual_main == expected_main
    assert snippet_path.read_bytes() == candidate_snippet
    assert b"respond desk-file-server" in actual_main
    assert b"respond radio-proxy" in actual_main
    assert backup_root.is_dir()
    if os.name == "posix":
        assert stat.S_IMODE(main_path.stat().st_mode) == 0o640
        assert stat.S_IMODE(snippet_path.stat().st_mode) == 0o640


@pytest.mark.parametrize("rollback_reload_fails, expected_rolled_back", [(False, True), (True, False)])
def test_failed_reload_reports_rollback_truth_and_restores_file_snapshots(
    tmp_path: Path, rollback_reload_fails: bool, expected_rolled_back: bool,
):
    original = _main_file("desk-original", "radio-original")
    namespace, main_path, snippet_path, _backup_root = _remote(tmp_path, original)
    reload_calls = 0

    def command(args, **kwargs):
        nonlocal reload_calls
        if args[:2] == ["systemctl", "reload"]:
            reload_calls += 1
            if reload_calls == 1 or (rollback_reload_fails and reload_calls == 2):
                return SimpleNamespace(returncode=1, stdout="", stderr="private diagnostics")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    namespace["run_command"] = command
    result = namespace["run"]({"mode": "apply", "domain": "8-8-8-8.nip.io"})

    assert result["ok"] is False
    assert result["error"] == "caddy_reload_failed"
    assert result["rolled_back"] is expected_rolled_back
    assert main_path.read_bytes() == original
    assert not snippet_path.exists()
    assert "private diagnostics" not in json.dumps(result)
    assert reload_calls == 2


def test_identical_remote_state_skips_backups_and_reload_but_checks_runtime(tmp_path: Path):
    original = _main_file()
    existing_import = original.replace(
        b"    import /etc/caddy/fodders-desk.caddy\n",
        b"    import /etc/caddy/fodder-vpn-link.caddy\n"
        b"    import /etc/caddy/fodders-desk.caddy\n",
    )
    snippet = site_link.build_caddy_snippet("8.8.8.8")
    namespace, main_path, snippet_path, backup_root = _remote(tmp_path, existing_import, snippet)
    commands: list[list[str]] = []

    def command(args, **kwargs):
        commands.append(list(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    namespace["run_command"] = command
    result = namespace["run"]({"mode": "apply", "domain": "8-8-8-8.nip.io"})

    assert result == {
        "ok": True, "changed": False, "runtime_verified": True,
        "runtime_active": True, "runtime_reloaded": False, "backup_path": None,
    }
    assert commands == [
        ["caddy", "validate", "--config", str(main_path), "--adapter", "caddyfile"],
        ["systemctl", "is-active", "--quiet", "caddy"],
    ]
    assert not list(backup_root.iterdir())
    assert main_path.read_bytes() == existing_import
    assert snippet_path.read_bytes() == snippet


def test_endpoint_readiness_uses_only_mocked_tls_gets():
    requested: list[str] = []

    def get(url: str, *, timeout: float):
        requested.append(url)
        if url.endswith("/connect/join.html"):
            return site_link.HttpResult(200, {})
        return site_link.HttpResult(200, {}, b'{"servers":[{"id":"nl"}]}')

    site_link._check_endpoint_readiness("8-8-8-8.nip.io", get)

    assert requested == [
        "https://8-8-8-8.nip.io/connect/join.html",
        "https://8-8-8-8.nip.io/api/awg/servers?include_unavailable=true",
    ]


def test_remote_inspection_is_read_only_and_reports_missing_route(tmp_path: Path):
    original = _main_file()
    namespace, main_path, snippet_path, backup_root = _remote(tmp_path, original)

    def forbidden_command(*args, **kwargs):
        raise AssertionError("read-only inspection must not run service commands")

    namespace["run_command"] = forbidden_command
    result = namespace["run"]({"mode": "inspect", "domain": "8-8-8-8.nip.io"})

    assert result == {
        "ok": True,
        "would_change": True,
        "missing_route": True,
        "target_current": False,
    }
    assert main_path.read_bytes() == original
    assert not snippet_path.exists()
    assert list(backup_root.iterdir()) == []


def test_remote_inspection_distinguishes_stale_target_from_missing_route(tmp_path: Path):
    original = _main_file().replace(
        b"    import /etc/caddy/fodders-desk.caddy\n",
        b"    import /etc/caddy/fodder-vpn-link.caddy\n"
        b"    import /etc/caddy/fodders-desk.caddy\n",
    )
    old_route = site_link.build_caddy_snippet("1.1.1.1")
    namespace, main_path, snippet_path, _backup_root = _remote(tmp_path, original, old_route)

    result = namespace["run"]({"mode": "inspect", "domain": "8-8-8-8.nip.io"})

    assert result == {
        "ok": True,
        "would_change": True,
        "missing_route": False,
        "target_current": False,
    }
    assert main_path.read_bytes() == original
    assert snippet_path.read_bytes() == old_route


class _FakeRemoteClient:
    def __init__(self, responses: list[dict[str, object]]):
        self.responses = responses
        self.scripts: list[str] = []
        self.closed = False

    def exec_command(self, command: str, *, timeout: int):
        assert command == "python3 -"
        index = len(self.scripts)
        stdin = SimpleNamespace(script="", flush=lambda: None, channel=SimpleNamespace(shutdown_write=lambda: None))
        stdin.write = lambda value: setattr(stdin, "script", stdin.script + value)
        self.scripts.append("")

        class Stdout:
            channel = SimpleNamespace(recv_exit_status=lambda: 0)

            def read(inner_self):
                return json.dumps(self.responses[index]).encode("utf-8")

        original_write = stdin.write
        stdin.write = lambda value: (original_write(value), self.scripts.__setitem__(index, stdin.script))[-1]
        return stdin, Stdout(), SimpleNamespace(read=lambda size: b"")

    def close(self):
        self.closed = True


def _integration_get(requested: list[str], *, fail_public: bool = False):
    target = "https://8-8-8-8.nip.io/connect/join.html"

    def get(url: str, *, timeout: float):
        requested.append(url)
        if url.endswith("/connect/join.html") or url == target:
            return site_link.HttpResult(200, {})
        if url.endswith("/api/awg/servers?include_unavailable=true"):
            return site_link.HttpResult(200, {}, b'{"servers":[{"id":"nl"}]}')
        if fail_public:
            return site_link.HttpResult(503, {})
        return site_link.HttpResult(302, {"Location": target, "Cache-Control": "no-store"})

    return get


def test_apply_returns_verified_site_metadata_with_mocked_http_and_ssh():
    requested: list[str] = []
    backup = "/var/backups/fodders-site/vpn-link-20261026-120000-0123456789ab"
    client = _FakeRemoteClient([{
        "ok": True, "changed": True, "runtime_verified": True,
        "runtime_reloaded": True, "backup_path": backup,
    }])

    result = site_link.sync_site_link(
        "8.8.8.8", apply=True, http_get=_integration_get(requested), ssh_connect=lambda: client,
    )

    assert result == {
        "site_url": "https://fodders.ru/vpn/",
        "target_url": "https://8-8-8-8.nip.io/connect/join.html",
        "site_updated": True,
        "verified": True,
        "applied": True,
        "dry_run": False,
        "runtime_reloaded": True,
        "backup_path": backup,
    }
    assert len(client.scripts) == 1
    assert '"mode":"apply"' in client.scripts[0]
    assert len(requested) == 7
    assert client.closed is True


def test_failed_public_verification_attempts_rollback_and_reports_final_site_state():
    requested: list[str] = []
    backup = "/var/backups/fodders-site/vpn-link-20261026-120000-0123456789ab"
    client = _FakeRemoteClient([
        {"ok": True, "changed": True, "runtime_verified": True,
         "runtime_reloaded": True, "backup_path": backup},
        {"ok": True, "rolled_back": True, "runtime_reloaded": True},
    ])

    with pytest.raises(site_link.SiteLinkSyncError, match="site changes were rolled back") as caught:
        site_link.sync_site_link(
            "8.8.8.8", apply=True, http_get=_integration_get(requested, fail_public=True),
            ssh_connect=lambda: client,
        )

    assert caught.value.result["site_updated"] is False
    assert caught.value.result["attempted_update"] is True
    assert caught.value.result["rollback_succeeded"] is True
    assert caught.value.result["runtime_reloaded"] is True
    assert caught.value.result["rollback_reloaded"] is True
    assert len(client.scripts) == 2
    assert '"mode":"rollback"' in client.scripts[1]
    assert client.closed is True


def test_true_noop_verifies_public_route_without_reloading_caddy():
    requested: list[str] = []
    client = _FakeRemoteClient([{
        "ok": True, "changed": False, "runtime_verified": True,
        "runtime_active": True, "runtime_reloaded": False, "backup_path": None,
    }])

    result = site_link.sync_site_link(
        "8.8.8.8", apply=True, http_get=_integration_get(requested), ssh_connect=lambda: client,
    )

    assert result["site_updated"] is False
    assert result["runtime_reloaded"] is False
    assert result["verified"] is True
    assert len(client.scripts) == 1
    assert '"mode":"reconcile"' not in client.scripts[0]
    assert len(requested) == 7


def test_noop_with_stale_public_runtime_reconciles_once_then_verifies():
    requested: list[str] = []
    target = "https://8-8-8-8.nip.io/connect/join.html"
    old_target = "https://9-9-9-9.nip.io/connect/join.html"
    public_requests = 0

    def get(url: str, *, timeout: float):
        nonlocal public_requests
        requested.append(url)
        if url.endswith("/connect/join.html") or url == target:
            return site_link.HttpResult(200, {})
        if url.endswith("/api/awg/servers?include_unavailable=true"):
            return site_link.HttpResult(200, {}, b'{"servers":[{"id":"nl"}]}')
        public_requests += 1
        location = old_target if public_requests == 1 else target
        return site_link.HttpResult(302, {"Location": location, "Cache-Control": "no-store"})

    client = _FakeRemoteClient([
        {"ok": True, "changed": False, "runtime_verified": True,
         "runtime_active": True, "runtime_reloaded": False, "backup_path": None},
        {"ok": True, "changed": False, "runtime_reloaded": True},
    ])

    result = site_link.sync_site_link("8.8.8.8", apply=True, http_get=get, ssh_connect=lambda: client)

    assert result["site_updated"] is False
    assert result["runtime_reloaded"] is True
    assert result["verified"] is True
    assert len(client.scripts) == 2
    assert '"mode":"apply"' in client.scripts[0]
    assert '"mode":"reconcile"' in client.scripts[1]
    assert len(requested) == 8


def test_remote_reconcile_reloads_matching_disk_config_without_file_changes(tmp_path: Path):
    original = _main_file().replace(
        b"    import /etc/caddy/fodders-desk.caddy\n",
        b"    import /etc/caddy/fodder-vpn-link.caddy\n"
        b"    import /etc/caddy/fodders-desk.caddy\n",
    )
    snippet = site_link.build_caddy_snippet("8.8.8.8")
    namespace, main_path, snippet_path, backup_root = _remote(tmp_path, original, snippet)
    commands: list[list[str]] = []

    def command(args, **kwargs):
        commands.append(list(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    namespace["run_command"] = command
    before_main = main_path.read_bytes()
    before_snippet = snippet_path.read_bytes()
    result = namespace["run"]({"mode": "reconcile", "domain": "8-8-8-8.nip.io"})

    assert result == {"ok": True, "changed": False, "runtime_reloaded": True}
    assert commands == [
        ["caddy", "validate", "--config", str(main_path), "--adapter", "caddyfile"],
        ["systemctl", "reload", "caddy"],
    ]
    assert main_path.read_bytes() == before_main
    assert snippet_path.read_bytes() == before_snippet
    assert list(backup_root.iterdir()) == []


def test_rollback_cas_preserves_later_main_and_snippet_edits(tmp_path: Path):
    original = _main_file()
    namespace, main_path, snippet_path, _backup_root = _remote(tmp_path, original)
    commands: list[list[str]] = []

    def command(args, **kwargs):
        commands.append(list(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    namespace["run_command"] = command
    applied = namespace["run"]({"mode": "apply", "domain": "8-8-8-8.nip.io"})
    assert applied["ok"] is True
    assert applied["changed"] is True
    assert applied["runtime_reloaded"] is True
    backup_path = applied["backup_path"]

    later_main = main_path.read_bytes().replace(b"desk-file-server", b"desk-later-edit")
    later_snippet = site_link.build_caddy_snippet("1.1.1.1")
    main_path.write_bytes(later_main)
    snippet_path.write_bytes(later_snippet)
    reload_count_before = sum(args[:2] == ["systemctl", "reload"] for args in commands)
    assert reload_count_before == 1

    rolled_back = namespace["run"]({"mode": "rollback", "backup_path": backup_path})

    assert rolled_back["ok"] is False
    assert rolled_back["rolled_back"] is False
    assert rolled_back["rollback_conflict"] is True
    assert main_path.read_bytes() == later_main
    assert snippet_path.read_bytes() == later_snippet
    assert namespace["test_fcntl"].calls[-2][1] == namespace["test_fcntl"].LOCK_EX
    assert namespace["test_fcntl"].calls[-1][1] == namespace["test_fcntl"].LOCK_UN
    assert sum(args[:2] == ["systemctl", "reload"] for args in commands) == reload_count_before


def test_apply_rechecks_source_hash_after_candidate_validation(tmp_path: Path):
    original = _main_file()
    namespace, main_path, snippet_path, backup_root = _remote(tmp_path, original)
    later_main = _main_file("another-editor", "radio-still-here")
    changed_source = False

    def command(args, **kwargs):
        nonlocal changed_source
        if args[:2] == ["caddy", "validate"] and not changed_source:
            candidate = Path(args[args.index("--config") + 1])
            if candidate != main_path:
                main_path.write_bytes(later_main)
                changed_source = True
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    namespace["run_command"] = command
    result = namespace["run"]({"mode": "apply", "domain": "8-8-8-8.nip.io"})

    assert result["ok"] is False
    assert result["error"] == "caddy_source_changed"
    assert result["rolled_back"] is None
    assert main_path.read_bytes() == later_main
    assert not snippet_path.exists()
    assert list(backup_root.iterdir()) == []
