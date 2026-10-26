from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vpn_wizard.account import AccountStore


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "scripts" / "change-controller-ip.py"
SPEC = importlib.util.spec_from_file_location("change_controller_ip", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)

OLD_IP = "77.67.89.164"
NEW_IP = "82.25.60.19"
OLD_DOMAIN = "77-67-89-164.nip.io"
NEW_DOMAIN = "82-25-60-19.nip.io"
SECRET = "nl-migration-test-secret"


def _key(fill: int) -> str:
    import base64
    return base64.b64encode(bytes([fill]) * 32).decode("ascii")


def _profile(key: str, endpoint: str, port: int) -> str:
    return ("[Interface]\r\nPrivateKey = NEVER-CHANGE-THIS\r\n[Peer]\r\n"
            f"PublicKey = {key}\r\nEndpoint = {endpoint}:{port} # retain comment\r\n")


def _nodes(host: str = "127.0.0.1", public_host: str = OLD_IP) -> list[dict[str, Any]]:
    return [
        {"id": "nl", "host": host, "public_host": public_host, "listen_port": 443,
         "interface": None, "default": True, "password": "DO_NOT_PRINT"},
        {"id": "nl-alt", "host": host, "public_host": public_host, "listen_port": 3478,
         "interface": None, "default": False, "alt_of": "nl", "key_path": "/root/nl-key"},
        {"id": "fi", "host": "185.202.207.126", "public_host": "185.202.207.126", "listen_port": 3478,
         "interface": "awg9", "password": "KEEP-OTHER-NODE"},
    ]


def _env(db_path: Path, *, public_ip: str = OLD_IP, host: str = "127.0.0.1") -> bytes:
    registry = json.dumps(_nodes(host, public_ip), separators=(",", ":"), ensure_ascii=True)
    return (
        "KEEP_UNCHANGED='secret-value-bytes'\r\n"
        f"VPNW_SECRET_KEY='{SECRET}'\r\n"
        f"VPNW_STATE_DB='{db_path}'\r\n"
        "VPNW_AWG_DEFAULT_SERVER=nl\r\n"
        f"VPNW_PUBLIC_BASE_URL='https://{public_ip.replace('.', '-')}.nip.io'\r\n"
        f"VPNW_MINIAPP_URL='https://{public_ip.replace('.', '-')}.nip.io/miniapp/'\r\n"
        f"VPNW_AWG_SERVERS='{registry}'\r\n"
    ).encode()


def _dbs(state_db: Path, *, cached_endpoint: str = "77.67.89.164", cached_ports=(1199, 5511)) -> dict[str, str]:
    keys = {"nl": _key(1), "nl-alt": _key(2)}
    paid = AccountStore(state_db, SECRET)
    paid.awg_save_peer(77, client_name="legacy", remnawave_uuid=None,
                       config=_profile(keys["nl"], cached_endpoint, cached_ports[0]))
    public = AccountStore(state_db.with_name("public-access.db"), SECRET)
    public.awg_save_server_peer(88, "nl-alt", client_name="alternate", remnawave_uuid=None,
                                config=_profile(keys["nl-alt"], cached_endpoint, cached_ports[1]))
    return keys


def _runtime(keys: dict[str, str], *, count: int = 0, fail_after: bool = False):
    baseline = {
        "awg0": {"listen_port": 443, "public_key_verified": True, "public_key_fingerprint": "default-pub",
                 "peer_count": 64, "peer_fingerprint": "all-default-peers"},
        "awg1": {"listen_port": 3478, "public_key_verified": True, "public_key_fingerprint": "alt-pub",
                 "peer_count": 4, "peer_fingerprint": "all-alt-peers"},
        "awg8": {"listen_port": 4500, "public_key_verified": False, "public_key_fingerprint": "other-pub",
                 "peer_count": 1, "peer_fingerprint": "other-peers"},
    }
    calls: list[dict[str, Any]] = []

    def run(payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(payload)
        if payload["mode"] in {"inspect", "runtime"}:
            return {"interfaces": baseline, "profiles_to_update": count}
        if payload["mode"] == "apply":
            return {"applied": True, "profiles_changed": count, "backup_id": "exit-ip-nl-test",
                    "keys_and_peers_unchanged": not fail_after, "interfaces": baseline}
        if payload["mode"] == "restore":
            return {"rollback_ok": True, "restored": count}
        raise AssertionError(payload)

    return run, calls, baseline


def _paths(tmp_path: Path, *, current: bool = False) -> dict[str, Path]:
    old_ip = NEW_IP if current else OLD_IP
    old_domain = NEW_DOMAIN if current else OLD_DOMAIN
    paths = {name: tmp_path / name for name in controller.DEFAULT_PATHS}
    paths["caddy"].write_text(
        f"{old_domain} {{ reverse_proxy 127.0.0.1:8000 }}\n"
        f"panel-vpn.{old_domain} {{ reverse_proxy 127.0.0.1:3000 }}\n"
        "radio.example.com { reverse_proxy 127.0.0.1:8080 }\n"
        "import subpage_caddy\n",
        encoding="utf-8",
    )
    paths["subpage_caddy"].write_text(
        f"sub-vpn.{old_domain} {{ reverse_proxy 127.0.0.1:3010 }}\n", encoding="utf-8"
    )
    paths["bedolaga_env"].write_text(
        "BOT_TOKEN='fixture-bot-token'\n"
        f"FODDERS_PORTAL_URL='https://{old_domain}/portal/'\n"
        f"FODDERS_VPN1_MINIAPP_URL='https://{old_domain}/wizard/'\n"
        f"VPNW_AWG_PUBLIC_URL='https://{old_domain}'\nOTHER_TOKEN='unchanged-secret'\n",
        encoding="utf-8",
    )
    paths["remnawave_env"].write_text(
        f"PANEL_DOMAIN=panel-vpn.{old_domain}\nFRONT_END_DOMAIN={old_domain}\n"
        f"WEBHOOK_URL=https://{old_domain}/api/integrations/remnawave/webhook\n"
        "POSTGRES_PASSWORD='unchanged-password'\n",
        encoding="utf-8",
    )
    paths["subpage_env"].write_text(
        f"REMNAWAVE_PANEL_URL=http://remnawave:3000\nPUBLIC_URL=https://{old_domain}/\n", encoding="utf-8"
    )
    _ = old_ip
    return paths


def _pg_runner(old_ip: str = OLD_IP, *, rows: bool = True):
    events: list[str] = []
    def run(args, **kwargs):
        joined = " ".join(args)
        if "pg_dump" in joined:
            container = "bedolaga" if "remnawave_bot_db" in joined else "remnawave"
            events.append("dump:" + container)
            return SimpleNamespace(returncode=0, stdout=b"\x00private-binary-" + container.encode() + b"\xff", stderr=b"")
        if "psql" in joined:
            sql = kwargs.get("input") or ""
            if sql.startswith("SELECT '"):
                events.append("pg-select")
                if rows:
                    return SimpleNamespace(returncode=0, stdout=(
                        f"hosts|123e4567-e89b-12d3-a456-426614174000|{old_ip}\n"
                        f"nodes|123e4567-e89b-12d3-a456-426614174001|{old_ip}\n"), stderr="")
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            events.append("pg-write")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[0] == "caddy":
            events.append("caddy-validate")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[0] == "/usr/local/bin/xray":
            events.append("xray-validate")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(args)
    return run, events


def _menu_test_hooks(domain: str):
    state: dict[str, Any] = {
        "layout": {"buttons": {"free": {"action": f"https://{domain}/connect/join.html"}},
                   "rows": [{"id": "free-row", "buttons": ["free"]}]},
        "button": {"type": "web_app", "text": "Fodder VPN", "web_app": {"url": f"https://{domain}/portal/"}},
    }
    initial_layout = json.loads(json.dumps(state["layout"]))

    def layout(mode: str, payload: dict[str, Any]):
        if mode == "read":
            return {"config": json.loads(json.dumps(state["layout"])), "digest": controller._menu_digest(state["layout"])}
        if mode == "apply":
            state["layout"] = controller._rewrite_menu_config(state["layout"], OLD_IP, NEW_IP)
            return {"changed": True, "digest": controller._menu_digest(state["layout"])}
        if mode == "restore":
            state["layout"] = json.loads(json.dumps(payload["config"]))
            return {"restored": True}
        raise AssertionError(mode)

    def telegram(_token: str, method: str, payload: dict[str, Any]):
        if method == "getChatMenuButton":
            return json.loads(json.dumps(state["button"]))
        if method == "setChatMenuButton":
            state["button"] = payload["menu_button"]
            return {}
        raise AssertionError(method)

    return layout, telegram, state, initial_layout


def test_nl_cache_maps_default_legacy_table_and_alt_server_with_stale_profile_endpoints(tmp_path: Path):
    state = tmp_path / "state.db"
    keys = _dbs(state, cached_endpoint="46.38.156.229", cached_ports=(12345, 55111))

    identities = controller.cached_nl_identities([state, state.with_name("public-access.db")], SECRET)

    assert identities == keys
    env = controller._transform_env(_env(state), "vpn", OLD_IP, NEW_IP, registry=True)[0]
    nodes = json.loads(next(line.split("=", 1)[1].strip("'\r\n") for line in env.decode().splitlines()
                            if line.startswith("VPNW_AWG_SERVERS=")))
    selected = [row for row in nodes if row["id"] in {"nl", "nl-alt"}]
    assert [(row["host"], row["public_host"], row["listen_port"]) for row in selected] == [
        ("127.0.0.1", NEW_IP, 443), ("127.0.0.1", NEW_IP, 3478)]
    assert nodes[2]["host"] == "185.202.207.126"
    assert "secret-value-bytes" in env.decode()


def test_caddy_transforms_only_old_nip_ip_tokens_and_preserves_other_host_blocks():
    source = (
        f"77.67.89.164, panel-vpn.{OLD_DOMAIN} {{ reverse_proxy 127.0.0.1:8000 }}\n"
        "radio.example.com { reverse_proxy 127.0.0.1:8080 }\n"
        f"literal 77.67.89.1640 and {OLD_DOMAIN}.evil must remain\n"
    ).encode()

    updated, count = controller.transform_caddy(source, OLD_IP, NEW_IP)

    assert count == 1
    assert f"82.25.60.19, panel-vpn.{NEW_DOMAIN}".encode() in updated
    assert b"radio.example.com { reverse_proxy 127.0.0.1:8080 }" in updated
    assert b"77.67.89.1640" in updated and f"{OLD_DOMAIN}.evil".encode() in updated


@pytest.mark.parametrize("status, expected", [
    ("HTTP/1.1 200 OK", True),
    ("HTTP/1.1 302 Found", False),
    ("HTTP/1.1 503 Service Unavailable", False),
    ("not-http", False),
])
def test_public_catalog_requires_exact_success_status(status: str, expected: bool):
    assert controller._catalog_status_ok(status) is expected


def test_xray_update_changes_only_9443_tls_xhttp_hostnames():
    source = {
        "inbounds": [
            {"port": 9443, "protocol": "vless", "settings": {"clients": [{"id": "KEEP-UUID"}]},
             "streamSettings": {"security": "tls", "tlsSettings": {"serverName": OLD_DOMAIN},
                                "xhttpSettings": {"host": OLD_DOMAIN, "path": "/KEEP-PATH"}}},
            {"port": 443, "protocol": "vless", "streamSettings": {
                "security": "reality", "realitySettings": {"serverNames": [OLD_DOMAIN], "privateKey": "KEEP-REALITY"}}},
        ],
        "outbounds": [{"protocol": "freedom"}],
    }

    updated, count = controller.transform_xray(json.dumps(source, indent=2).encode(), OLD_IP, NEW_IP)
    config = json.loads(updated)

    assert count == 2
    assert config["inbounds"][0]["settings"]["clients"][0]["id"] == "KEEP-UUID"
    assert config["inbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] == NEW_DOMAIN
    assert config["inbounds"][0]["streamSettings"]["xhttpSettings"] == {"host": NEW_DOMAIN, "path": "/KEEP-PATH"}
    assert config["inbounds"][1]["streamSettings"]["realitySettings"] == {
        "serverNames": [OLD_DOMAIN], "privateKey": "KEEP-REALITY"}
    assert config["outbounds"] == source["outbounds"]


def test_staged_xray_config_keeps_json_suffix_and_cleans_temporary_file(tmp_path: Path):
    observed = {}

    def runner(args, **_kwargs):
        observed["path"] = args[-1]
        assert args[:4] == ["/usr/local/bin/xray", "run", "-test", "-config"]
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    controller._validate_staged_xray(tmp_path / "config.json", b'{"inbounds":[]}', runner)

    assert observed["path"].endswith(".json")
    assert not Path(observed["path"]).exists()


def test_rejects_non_public_ip_loopback_registry_or_unassigned_nic_before_runtime(tmp_path: Path):
    state = tmp_path / "state.db"
    _dbs(state)
    env = tmp_path / "vpn.env"
    env.write_bytes(_env(state))
    paths = _paths(tmp_path)
    called = []

    with pytest.raises(controller.ChangeError, match="globally routable"):
        controller.migrate_controller("224.0.0.1", env, paths=paths, address_checker=lambda _ip: True,
                                      runtime_runner=lambda _p: called.append("runtime"))
    env.write_bytes(_env(state, host="8.8.8.8"))
    with pytest.raises(controller.ChangeError, match="loopback"):
        controller.migrate_controller(NEW_IP, env, paths=paths, address_checker=lambda _ip: True,
                                      runtime_runner=lambda _p: called.append("runtime"))
    env.write_bytes(_env(state))
    with pytest.raises(controller.ChangeError, match="not assigned"):
        controller.migrate_controller(NEW_IP, env, paths=paths, address_checker=lambda _ip: False,
                                      runtime_runner=lambda _p: called.append("runtime"))
    assert called == []


def test_rejects_runtime_key_or_listener_mismatch_before_any_backup_or_write(tmp_path: Path):
    state = tmp_path / "state.db"
    keys = _dbs(state)
    env = tmp_path / "vpn.env"
    original = _env(state)
    env.write_bytes(original)
    paths = _paths(tmp_path)
    backup_root = tmp_path / "backups"
    run, _, baseline = _runtime(keys, count=2)

    def mismatch(payload):
        report = run(payload)
        report["interfaces"]["awg0"]["public_key_verified"] = False
        return report

    with pytest.raises(controller.ChangeError, match="cached identity"):
        controller.migrate_controller(NEW_IP, env, paths=paths, backup_root=backup_root,
                                      address_checker=lambda _ip: True, runtime_runner=mismatch)
    assert env.read_bytes() == original
    assert not backup_root.exists()

    def listener_mismatch(payload):
        report = run(payload)
        report["interfaces"]["awg0"]["listen_port"] = 3478
        return report

    with pytest.raises(controller.ChangeError, match="listener"):
        controller.migrate_controller(NEW_IP, env, paths=paths, backup_root=backup_root,
                                      address_checker=lambda _ip: True, runtime_runner=listener_mismatch)


def test_same_ip_apply_is_verified_noop_without_restarts_or_backups(tmp_path: Path):
    state = tmp_path / "state.db"
    keys = _dbs(state)
    env = tmp_path / "vpn.env"
    env.write_bytes(_env(state, public_ip=NEW_IP))
    paths = _paths(tmp_path, current=True)
    with __import__("sqlite3").connect(state) as connection:
        connection.execute(
            "INSERT INTO saved_servers (id,user_id,label,host,ssh_user,ssh_port,created_at,updated_at,last_used_at) "
            "VALUES ('current-nl','owner','NL test',?, 'root',22,0,0,0)", (NEW_IP,)
        )
    runtime, calls, baseline = _runtime(keys, count=0)
    services: list[list[str]] = []
    tls_calls: list[str] = []
    layout_updater, telegram, _menu_state, _initial_layout = _menu_test_hooks(NEW_DOMAIN)
    result = controller.migrate_controller(
        NEW_IP, env, apply=True, paths=paths, backup_root=tmp_path / "backups",
        address_checker=lambda _ip: True, runtime_runner=runtime,
        command_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
        service_runner=lambda args, **_kwargs: services.append(args) or SimpleNamespace(returncode=0),
        tls_checker=lambda domain: tls_calls.append(domain) or {"tls_verified": True, "catalog_status": "200"},
        xray_tls_checker=lambda _domain: {"tls_verified": True}, root_check=lambda: True,
        menu_layout_updater=layout_updater, telegram_client=telegram,
    )

    assert result["changed"] is False and result["verified"] is True
    assert calls[0]["interfaces"] == [
        {"id": "nl", "interface": None, "listen_port": 443, "public_key": keys["nl"]},
        {"id": "nl-alt", "interface": None, "listen_port": 3478, "public_key": keys["nl-alt"]},
    ]
    assert tls_calls == [NEW_DOMAIN]
    assert services == []
    assert not (tmp_path / "backups").exists()
    with __import__("sqlite3").connect(state) as connection:
        assert connection.execute("SELECT host FROM saved_servers WHERE id='current-nl'").fetchone()[0] == NEW_IP


def _seed_pending_journal(backup_root: Path, *, old_ip: str = OLD_IP, new_ip: str = NEW_IP,
                          service_needs: dict[str, bool] | None = None) -> Path:
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = backup_root / "change-nl-ip-recovery-seed"
    backup.mkdir(mode=0o700)
    controller._write_pending_journal(
        backup_root, old_ip, new_ip, backup.name,
        service_needs or {"caddy": False, "api": False, "bedolaga": False, "remnawave": False, "xray": False},
    )
    return controller._pending_journal_path(backup_root)


def test_interrupted_apply_resumes_from_journal_after_registry_and_some_files_are_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    state = tmp_path / "state.db"
    keys = _dbs(state)
    env = tmp_path / "vpn.env"
    original_env = _env(state)
    env.write_bytes(original_env)
    paths = _paths(tmp_path)
    runtime, runtime_calls, _baseline = _runtime(keys, count=2)
    command_runner, _events = _pg_runner(rows=True)
    layout_updater, telegram, _menu_state, _initial_layout = _menu_test_hooks(OLD_DOMAIN)
    backup_root = tmp_path / "backups"
    atomic_write = controller._atomic_write
    writes = 0

    def interrupt_after_two(path: Path, data: bytes, metadata=None):
        nonlocal writes
        atomic_write(path, data, metadata)
        writes += 1
        if writes == 2:
            raise KeyboardInterrupt("simulated process interruption")

    monkeypatch.setattr(controller, "_atomic_write", interrupt_after_two)
    with pytest.raises(KeyboardInterrupt):
        controller.migrate_controller(
            NEW_IP, env, apply=True, paths=paths, backup_root=backup_root,
            address_checker=lambda _ip: True, runtime_runner=runtime, command_runner=command_runner,
            service_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
            tls_checker=lambda _domain: {"tls_verified": True, "catalog_status": "200"},
            root_check=lambda: True, menu_layout_updater=layout_updater, telegram_client=telegram,
        )

    journal_path = controller._pending_journal_path(backup_root)
    assert journal_path.is_file()
    assert env.read_bytes() != original_env
    assert OLD_DOMAIN in paths["remnawave_env"].read_text(encoding="utf-8")
    assert runtime_calls == [{"mode": "inspect", "old_ip": OLD_IP, "new_ip": NEW_IP, "interfaces": runtime_calls[0]["interfaces"]}]

    monkeypatch.setattr(controller, "_atomic_write", atomic_write)
    result = controller.migrate_controller(
        NEW_IP, env, apply=True, paths=paths, backup_root=backup_root,
        address_checker=lambda _ip: True, runtime_runner=runtime, command_runner=command_runner,
        service_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
        tls_checker=lambda _domain: {"tls_verified": True, "catalog_status": "200"},
        root_check=lambda: True, menu_layout_updater=layout_updater, telegram_client=telegram,
    )

    assert result["recovered"] is True
    assert result["old_ip"] == OLD_IP and result["new_ip"] == NEW_IP
    assert [call["mode"] for call in runtime_calls] == ["inspect", "inspect", "apply"]
    assert not journal_path.exists()
    assert NEW_DOMAIN in paths["remnawave_env"].read_text(encoding="utf-8")


def test_pending_journal_rejects_different_target_without_writes(tmp_path: Path):
    state = tmp_path / "state.db"
    keys = _dbs(state)
    env = tmp_path / "vpn.env"
    original_env = _env(state)
    env.write_bytes(original_env)
    paths = _paths(tmp_path)
    backup_root = tmp_path / "backups"
    journal_path = _seed_pending_journal(backup_root)
    runtime, calls, _baseline = _runtime(keys)

    with pytest.raises(controller.ChangeError, match="different IP"):
        controller.migrate_controller(
            "82.25.60.20", env, apply=True, paths=paths, backup_root=backup_root,
            address_checker=lambda _ip: True, runtime_runner=runtime, root_check=lambda: True,
        )

    assert env.read_bytes() == original_env
    assert calls == []
    assert journal_path.is_file()
    assert sorted(path.name for path in backup_root.iterdir()) == ["change-nl-ip-recovery-seed", journal_path.name]


def test_recovery_reconciles_xray_certificate_when_config_is_already_new(tmp_path: Path):
    state = tmp_path / "state.db"
    keys = _dbs(state, cached_endpoint=NEW_IP)
    env = tmp_path / "vpn.env"
    env.write_bytes(_env(state, public_ip=NEW_IP))
    paths = _paths(tmp_path, current=True)
    paths["xray"].write_text(json.dumps({"inbounds": [{"port": 9443, "streamSettings": {
        "security": "tls", "tlsSettings": {"serverName": NEW_DOMAIN},
        "xhttpSettings": {"host": NEW_DOMAIN, "path": "/keep"}}}]}), encoding="utf-8")
    paths["cert"].write_bytes(b"stale-old-certificate")
    paths["key"].write_bytes(b"stale-old-private-key")
    backup_root = tmp_path / "backups"
    journal = _seed_pending_journal(backup_root, service_needs={
        "caddy": False, "api": False, "bedolaga": False, "remnawave": False, "xray": True,
    })
    runtime, calls, _baseline = _runtime(keys, count=0)
    command_runner, _events = _pg_runner(rows=False)
    layout_updater, telegram, _menu_state, _initial_layout = _menu_test_hooks(NEW_DOMAIN)
    cert_sync_calls: list[str] = []

    def cert_sync(domain: str):
        cert_sync_calls.append(domain)
        paths["cert"].write_bytes(b"renewed-certificate")
        paths["key"].write_bytes(b"renewed-private-key")

    result = controller.migrate_controller(
        NEW_IP, env, apply=True, paths=paths, backup_root=backup_root,
        address_checker=lambda _ip: True, runtime_runner=runtime, command_runner=command_runner,
        service_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
        tls_checker=lambda _domain: {"tls_verified": True, "catalog_status": "200"},
        xray_tls_checker=lambda _domain: {"tls_verified": True}, certificate_sync=cert_sync,
        root_check=lambda: True, menu_layout_updater=layout_updater, telegram_client=telegram,
    )

    assert result["recovered"] is True
    assert cert_sync_calls == [NEW_DOMAIN]
    assert paths["cert"].read_bytes() == b"renewed-certificate"
    assert paths["key"].read_bytes() == b"renewed-private-key"
    assert not journal.exists()
    assert [call["mode"] for call in calls] == ["inspect"]


def test_same_ip_repair_journal_resumes_after_env_write_and_forces_api_reconcile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    state = tmp_path / "state.db"
    keys = _dbs(state, cached_endpoint=NEW_IP)
    env = tmp_path / "vpn.env"
    original_env = _env(state, public_ip=NEW_IP).replace(
        f"VPNW_PUBLIC_BASE_URL='https://{NEW_DOMAIN}'\r\n".encode(), b""
    )
    env.write_bytes(original_env)
    paths = _paths(tmp_path, current=True)
    backup_root = tmp_path / "backups"
    journal = _seed_pending_journal(
        backup_root, old_ip=NEW_IP, new_ip=NEW_IP,
        service_needs={"caddy": False, "api": True, "bedolaga": False, "remnawave": False, "xray": False},
    )
    runtime, runtime_calls, _baseline = _runtime(keys, count=0)
    command_runner, _events = _pg_runner(rows=False)
    layout_updater, telegram, _menu_state, _initial_layout = _menu_test_hooks(NEW_DOMAIN)
    atomic_write = controller._atomic_write

    def interrupt_after_env(path: Path, data: bytes, metadata=None):
        atomic_write(path, data, metadata)
        if path == env:
            raise KeyboardInterrupt("simulated process interruption")

    monkeypatch.setattr(controller, "_atomic_write", interrupt_after_env)
    with pytest.raises(KeyboardInterrupt):
        controller.migrate_controller(
            NEW_IP, env, apply=True, paths=paths, backup_root=backup_root,
            address_checker=lambda _ip: True, runtime_runner=runtime, command_runner=command_runner,
            service_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
            tls_checker=lambda _domain: {"tls_verified": True, "catalog_status": "200"},
            root_check=lambda: True, menu_layout_updater=layout_updater, telegram_client=telegram,
        )
    assert b"VPNW_PUBLIC_BASE_URL='https://82-25-60-19.nip.io'" in env.read_bytes()
    assert journal.is_file()

    monkeypatch.setattr(controller, "_atomic_write", atomic_write)
    service_calls: list[list[str]] = []
    result = controller.migrate_controller(
        NEW_IP, env, apply=True, paths=paths, backup_root=backup_root,
        address_checker=lambda _ip: True, runtime_runner=runtime, command_runner=command_runner,
        service_runner=lambda args, **_kwargs: service_calls.append(args) or SimpleNamespace(returncode=0),
        tls_checker=lambda _domain: {"tls_verified": True, "catalog_status": "200"},
        root_check=lambda: True, menu_layout_updater=layout_updater, telegram_client=telegram,
    )

    assert result["old_ip"] == result["new_ip"] == NEW_IP
    assert result["recovered"] is True
    assert [call["mode"] for call in runtime_calls] == ["inspect", "inspect"]
    assert [call for call in service_calls if call[:3] == ["systemctl", "restart", "vpn-wizard"]]
    assert not journal.exists()


def test_apply_updates_all_endpoint_files_and_preserves_registry_identity_and_other_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state = tmp_path / "state.db"
    keys = _dbs(state)
    env = tmp_path / "vpn.env"
    original_env = _env(state)
    env.write_bytes(original_env)
    paths = _paths(tmp_path)
    runtime, runtime_calls, baseline = _runtime(keys, count=2)
    command_runner, command_events = _pg_runner(rows=True)
    layout_updater, telegram, menu_state, _initial_layout = _menu_test_hooks(OLD_DOMAIN)
    order: list[str] = []
    real_atomic_write = controller._atomic_write
    def tracked_write(path, data, metadata=None):
        order.append("write:" + path.name)
        return real_atomic_write(path, data, metadata)
    monkeypatch.setattr(controller, "_atomic_write", tracked_write)
    def tracked_command(args, **kwargs):
        if args[0] == "caddy":
            order.append("caddy-validate:" + " ".join(args))
        return command_runner(args, **kwargs)
    service_calls: list[list[str]] = []
    result = controller.migrate_controller(
        NEW_IP, env, apply=True, paths=paths, backup_root=tmp_path / "backups",
        address_checker=lambda _ip: True, runtime_runner=runtime, command_runner=tracked_command,
        service_runner=lambda args, **_kwargs: service_calls.append(args) or SimpleNamespace(returncode=0),
        tls_checker=lambda domain: {"tls_verified": True, "catalog_status": "200", "domain": domain},
        root_check=lambda: True,
        menu_layout_updater=layout_updater, telegram_client=telegram,
    )

    values, _, _ = controller._exit_helper().parse_env(env.read_bytes())
    nodes = json.loads(values["VPNW_AWG_SERVERS"])
    assert [(row["host"], row["public_host"], row["listen_port"]) for row in nodes[:2]] == [
        ("127.0.0.1", NEW_IP, 443), ("127.0.0.1", NEW_IP, 3478)]
    assert nodes[2]["host"] == "185.202.207.126"
    assert values["VPNW_AWG_DEFAULT_SERVER"] == "nl"
    assert values["KEEP_UNCHANGED"] == "secret-value-bytes"
    assert f"panel-vpn.{NEW_DOMAIN}" in paths["caddy"].read_text(encoding="utf-8")
    assert "radio.example.com { reverse_proxy 127.0.0.1:8080 }" in paths["caddy"].read_text(encoding="utf-8")
    assert f"sub-vpn.{NEW_DOMAIN}" in paths["subpage_caddy"].read_text(encoding="utf-8")
    assert f"PANEL_DOMAIN=panel-vpn.{NEW_DOMAIN}" in paths["remnawave_env"].read_text(encoding="utf-8")
    assert "unchanged-password" in paths["remnawave_env"].read_text(encoding="utf-8")
    assert runtime_calls[0]["old_ip"] == OLD_IP
    assert runtime_calls[1]["mode"] == "apply"
    assert runtime_calls[1]["interfaces"] == runtime_calls[0]["interfaces"]
    first_live_write = next(i for i, event in enumerate(order) if event.startswith("write:"))
    first_stage_validation = next(i for i, event in enumerate(order) if event.startswith("caddy-validate:"))
    assert first_stage_validation < first_live_write
    assert "--adapter caddyfile" in order[first_stage_validation]
    assert {"caddy", "api", "bot", "remna"} <= {"caddy" if call[0] == "systemctl" and "caddy" in call[-1]
                                                      else "api" if call[0] == "systemctl" and "vpn-wizard" in call[-1]
                                                      else "bot" if "/opt/bedolaga/" in " ".join(call)
                                                      else "remna" if "/opt/remnawave/" in " ".join(call)
                                                      else "other" for call in service_calls}
    assert not any("awg-quick" in " ".join(call) for call in service_calls)
    assert result["verified"] and result["applied"] and result["changed"]
    assert result["tls"]["catalog_status"] == "200"
    assert menu_state["layout"]["buttons"]["free"]["action"] == f"https://{NEW_DOMAIN}/connect/join.html"
    assert menu_state["button"]["web_app"]["url"] == f"https://{NEW_DOMAIN}/portal/"
    assert "DO_NOT_PRINT" not in json.dumps(result)
    backup = tmp_path / "backups" / result["backup"]
    assert (backup / "remnawave.dump").read_bytes().startswith(b"\x00private-binary-remnawave")
    assert (backup / "bedolaga.dump").read_bytes().startswith(b"\x00private-binary-bedolaga")


@pytest.mark.parametrize(("fail_xray_rollback", "expected_services"), [(False, "services=True"), (True, "services=False")])
def test_certificate_failure_restores_both_cert_files_profiles_configs_and_services(
    tmp_path: Path, fail_xray_rollback: bool, expected_services: str
):
    state = tmp_path / "state.db"
    keys = _dbs(state)
    env = tmp_path / "vpn.env"
    original_env = _env(state)
    env.write_bytes(original_env)
    paths = _paths(tmp_path)
    xray_original = json.dumps({"inbounds": [{"port": 9443, "streamSettings": {
        "security": "tls", "tlsSettings": {"serverName": OLD_DOMAIN},
        "xhttpSettings": {"host": OLD_DOMAIN, "path": "/keep"}}}], "outbounds": [{"protocol": "freedom"}]}, indent=2).encode()
    paths["xray"].write_bytes(xray_original)
    paths["cert"].write_bytes(b"old-fullchain-private-test")
    paths["key"].write_bytes(b"old-private-key-test")
    cert_original, key_original = paths["cert"].read_bytes(), paths["key"].read_bytes()
    runtime, runtime_calls, baseline = _runtime(keys, count=2)
    command_runner, _ = _pg_runner(rows=False)
    layout_updater, telegram, menu_state, initial_layout = _menu_test_hooks(OLD_DOMAIN)
    service_calls: list[list[str]] = []

    def service_runner(args, **_kwargs):
        service_calls.append(args)
        if fail_xray_rollback and args == ["systemctl", "restart", "xray"]:
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)

    def fail_certificate(domain: str):
        assert domain == NEW_DOMAIN
        paths["cert"].write_bytes(b"rotated-cert")
        paths["key"].write_bytes(b"rotated-key")
        raise controller.ChangeError("simulated certificate sync failure")

    with pytest.raises(controller.ChangeError, match="files=True, profiles=True") as failure:
        controller.migrate_controller(
            NEW_IP, env, apply=True, paths=paths, backup_root=tmp_path / "backups",
            address_checker=lambda _ip: True, runtime_runner=runtime, command_runner=command_runner,
            service_runner=service_runner,
            tls_checker=lambda _domain: {"tls_verified": True, "catalog_status": "200"},
            certificate_sync=fail_certificate, xray_tls_checker=lambda _domain: {"tls_verified": True},
            root_check=lambda: True,
            menu_layout_updater=layout_updater, telegram_client=telegram,
        )

    assert expected_services in str(failure.value)
    assert env.read_bytes() == original_env
    assert paths["cert"].read_bytes() == cert_original
    assert paths["key"].read_bytes() == key_original
    assert paths["xray"].read_bytes() == xray_original
    assert runtime_calls[-1] == {"mode": "restore", "backup_id": "exit-ip-nl-test"}
    assert any(call == ["systemctl", "restart", "xray"] for call in service_calls)
    assert menu_state["layout"] == initial_layout
    assert menu_state["button"]["web_app"]["url"] == f"https://{OLD_DOMAIN}/portal/"
