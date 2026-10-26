from __future__ import annotations

import base64
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
from types import SimpleNamespace

import paramiko
import pytest

from vpn_wizard.account import AccountStore


SCRIPT = Path(__file__).parents[1] / "deploy/scripts/change-exit-ip.py"
SPEC = importlib.util.spec_from_file_location("change_exit_ip", SCRIPT)
change_ip = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(change_ip)

OLD_IP = "46.38.156.229"
NEW_IP = "185.202.207.126"
SECRET = "fixture-secret-that-must-not-be-printed"


def _key(fill: int) -> str:
    return base64.b64encode(bytes([fill]) * 32).decode("ascii")


def _profile(public_key: str, endpoint: str, port: int) -> str:
    return (
        "[Interface]\r\nPrivateKey = PRIVATE-MUST-STAY-ENCRYPTED\r\n"
        f"[Peer]\r\nPublicKey = {public_key}\r\nEndpoint = {endpoint}:{port} # keep comment\r\n"
    )


def _nodes(host: str = OLD_IP, endpoint: str | None = None) -> list[dict]:
    endpoint = endpoint or host
    return [
        {"id": "nl", "host": "77.67.89.164", "interface": "awg0", "listen_port": 3479,
         "password": "NL_PASSWORD", "default": True},
        {"id": "fi", "host": host, "public_host": endpoint, "user": "root", "port": 22,
         "password": "FI_PASSWORD_DO_NOT_PRINT", "interface": "awg9", "listen_port": 3478,
         "enabled": True, "label": "Finland", "flag": "🇫🇮", "default": False},
        {"id": "fi-alt", "host": host, "public_host": endpoint, "user": "root", "port": 22,
         "password": "ALT_PASSWORD_DO_NOT_PRINT", "key_path": "/root/alt-key",
         "interface": "awg8", "listen_port": 4500, "alt_port": True, "alt_of": "fi"},
        {"id": "tr", "host": "193.222.97.50", "interface": "awg1", "listen_port": 3479,
         "password": "TR_PASSWORD"},
    ]


def _env_text(db_path: Path, nodes: list[dict]) -> bytes:
    registry = json.dumps(nodes, ensure_ascii=True, separators=(",", ":"))
    return (
        "KEEP_THIS=unmodified\r\n"
        f"VPNW_SECRET_KEY='{SECRET}'\r\n"
        f"VPNW_STATE_DB='{db_path}'\r\n"
        f"VPNW_AWG_SERVERS='{registry}'\r\n"
        "OTHER_SECRET=untouched-secret-value\r\n"
    ).encode("utf-8")


def _write_databases(db_path: Path, endpoint: str = OLD_IP, *, disagree: bool = False,
                     ports: tuple[int, int] = (3478, 4500)) -> dict[str, str]:
    keys = {"fi": _key(1), "fi-alt": _key(2)}
    store = AccountStore(db_path, SECRET)
    store.awg_save_server_peer(1001, "fi", client_name="fi-a", remnawave_uuid=None,
                               config=_profile(keys["fi"], endpoint, ports[0]))
    public = AccountStore(db_path.with_name("public-access.db"), SECRET)
    public.awg_save_server_peer(2002, "fi-alt", client_name="fi-b", remnawave_uuid=None,
                                config=_profile(_key(3) if disagree else keys["fi-alt"], endpoint, ports[1]))
    if disagree:
        store.awg_save_server_peer(1003, "fi", client_name="fi-c", remnawave_uuid=None,
                                  config=_profile(_key(4), endpoint, ports[0]))
    return keys


def _known_hosts(path: Path, *aliases: str) -> paramiko.RSAKey:
    key = paramiko.RSAKey.generate(1024)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{alias} {key.get_name()} {key.get_base64()}\n" for alias in aliases), encoding="ascii")
    return key


class FakeTransport:
    def __init__(self, profile_count: int = 0, *, rollback_ok: bool = True,
                 apply_ok: bool = True, host_key: paramiko.PKey | None = None):
        self.profile_count = profile_count
        self.rollback_ok = rollback_ok
        self.apply_ok = apply_ok
        self.host_key = host_key or paramiko.RSAKey.generate(1024)
        self.payloads: list[dict] = []
        self.closed = False

    def connect(self):
        return self

    def run_payload(self, payload: dict) -> dict:
        self.payloads.append(payload)
        if payload["mode"] == "inspect":
            return {"profiles_to_update": self.profile_count, "interfaces": {}}
        if payload["mode"] == "apply":
            return {
                "applied": self.apply_ok,
                "profiles_changed": self.profile_count,
                "backup_id": "exit-ip-test-backup",
                "keys_and_peers_unchanged": self.apply_ok,
                "rollback_ok": self.rollback_ok,
            }
        if payload["mode"] == "restore":
            return {"rollback_ok": self.rollback_ok, "restored": self.profile_count}
        raise AssertionError(payload)

    def close(self):
        self.closed = True


def _migration(tmp_path: Path, *, host: str = OLD_IP, endpoint: str | None = None,
               cached_endpoint: str | None = None, profile_count: int = 2,
               cached_ports: tuple[int, int] = (3478, 4500),
               rollback_ok: bool = True, apply_ok: bool = True):
    db = tmp_path / "state.db"
    keys = _write_databases(db, cached_endpoint or endpoint or host, ports=cached_ports)
    env = tmp_path / "vpn-wizard.env"
    original_env = _env_text(db, _nodes(host, endpoint))
    env.write_bytes(original_env)
    key_file = tmp_path / "known_hosts"
    remote_key = _known_hosts(key_file, host)
    transport = FakeTransport(profile_count, rollback_ok=rollback_ok, apply_ok=apply_ok, host_key=remote_key)
    service_calls: list[list[str]] = []

    def factory(*_args, **_kwargs):
        return transport

    def service_runner(args, **_kwargs):
        service_calls.append(args)
        return SimpleNamespace(returncode=0)

    result = lambda apply=False, root=True: change_ip.migrate(
        "fi", NEW_IP, env_path=env, apply=apply, transport_factory=factory,
        service_runner=service_runner, backup_root=tmp_path / "private-backups",
        known_hosts_path=key_file, root_check=lambda: root,
    )
    return result, env, original_env, key_file, remote_key, transport, service_calls, db, keys


def test_dry_run_validates_and_selects_both_fi_interfaces_without_leaking_credentials(tmp_path: Path):
    migrate, _env, original, _known, _key_value, transport, _calls, _db, keys = _migration(tmp_path)

    report = migrate()

    assert report == {
        "server": "fi", "selected_profiles": 2, "remote_profiles_to_update": 2,
        "registry_would_change": True, "host_key_would_register": True,
        "verified": True, "applied": False,
    }
    assert _env_text(_db, _nodes()) == original
    payload = transport.payloads[0]
    assert payload["mode"] == "inspect"
    assert [(item["id"], item["interface"], item["listen_port"], item["public_key"])
            for item in payload["interfaces"]] == [
                ("fi", "awg9", 3478, keys["fi"]),
                ("fi-alt", "awg8", 4500, keys["fi-alt"]),
            ]
    assert all("password" not in item and "key_path" not in item for item in payload["interfaces"])
    assert SECRET not in json.dumps(report)
    assert "PASSWORD_DO_NOT_PRINT" not in json.dumps(report)
    assert transport.closed


def test_registry_rewrite_preserves_other_entries_defaults_ports_and_secrets(tmp_path: Path):
    nodes = _nodes()
    raw = _env_text(tmp_path / "state.db", nodes)
    values, lines, index = change_ip.parse_env(raw)
    selected, _old, endpoint = change_ip.select_nodes(nodes, "fi", NEW_IP)

    rewritten = change_ip.update_registry_text(raw, lines, index, nodes, selected, NEW_IP, endpoint)
    updated_values, _updated_lines, _index = change_ip.parse_env(rewritten)
    updated_nodes = json.loads(updated_values["VPNW_AWG_SERVERS"])

    assert b"KEEP_THIS=unmodified\r\n" in rewritten
    assert b"OTHER_SECRET=untouched-secret-value\r\n" in rewritten
    assert updated_values["VPNW_SECRET_KEY"] == SECRET
    legacy_registry = json.loads(
        next(line for line in rewritten.decode().splitlines() if line.startswith("VPNW_AWG_SERVERS="))
        .partition("=")[2].strip().strip("'\"")
    )
    assert legacy_registry == updated_nodes
    assert updated_nodes[0] == nodes[0]
    assert updated_nodes[3] == nodes[3]
    for before, after in zip(nodes[1:3], updated_nodes[1:3]):
        assert after["host"] == after["public_host"] == NEW_IP
        assert {key: value for key, value in after.items() if key not in {"host", "public_host"}} == {
            key: value for key, value in before.items() if key not in {"host", "public_host"}
        }
    assert [node["listen_port"] for node in updated_nodes[1:3]] == [3478, 4500]
    assert [node["interface"] for node in updated_nodes[1:3]] == ["awg9", "awg8"]
    assert SECRET not in json.dumps({"result": "metadata-only"})


def test_endpoint_byte_replacement_keeps_port_comments_and_unrelated_lines():
    before = (
        b"# unchanged\r\n[Peer]\r\nEndpoint = 46.38.156.229:3478 # keep me\r\n"
        b"Endpoint = 46.38.156.2290:3478\r\nEndpoint = 10.0.0.4:4500\r\n"
    )
    after = change_ip.replace_endpoint_bytes(before, OLD_IP, NEW_IP)

    assert after == before.replace(
        b"Endpoint = 46.38.156.229:3478", b"Endpoint = 185.202.207.126:3478", 1
    )
    assert b"Endpoint = 46.38.156.2290:3478" in after
    assert b":3478 # keep me\r\n" in after


def test_cached_profile_identity_mismatch_fails_closed(tmp_path: Path):
    db = tmp_path / "state.db"
    _write_databases(db, OLD_IP, disagree=True)
    selected = _nodes()[1:3]

    with pytest.raises(change_ip.ChangeError, match="disagree"):
        change_ip.cached_identities([db, db.with_name("public-access.db")], SECRET,
                                    selected, OLD_IP, NEW_IP)


def test_cached_identity_allows_historical_endpoint_and_port_after_prior_moves(tmp_path: Path):
    db = tmp_path / "state.db"
    keys = _write_databases(db, "193.222.97.50", ports=(443, 443))
    selected = _nodes(NEW_IP, NEW_IP)[1:3]

    assert change_ip.cached_identities(
        [db, db.with_name("public-access.db")], SECRET, selected, NEW_IP, NEW_IP
    ) == keys


def test_noop_apply_rechecks_without_backup_or_service_restart(tmp_path: Path):
    migrate, env, original, known, remote_key, transport, service_calls, _db, _keys = _migration(
        tmp_path, host=NEW_IP, endpoint=NEW_IP, cached_endpoint="193.222.97.50",
        cached_ports=(443, 443), profile_count=0
    )

    # Register the current, already-verified host key so this is a true no-op.
    known.write_text(f"{NEW_IP} {remote_key.get_name()} {remote_key.get_base64()}\n", encoding="ascii")
    original = env.read_bytes()
    report = migrate(apply=True)

    assert report["changed"] is False
    assert report["remote_profiles_changed"] == 0
    assert env.read_bytes() == original
    assert len(transport.payloads) == 1 and transport.payloads[0]["mode"] == "inspect"
    assert service_calls == []
    assert not (tmp_path / "private-backups").exists()


def test_remote_runtime_listener_mismatch_rejects_before_profile_scan(monkeypatch, capsys):
    fake_subprocess = types.ModuleType("subprocess")
    calls = []

    def fake_run(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="awg9 3477\nawg8 4500\n", stderr="")

    fake_subprocess.run = fake_run
    monkeypatch.setitem(sys.modules, "subprocess", fake_subprocess)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({
        "mode": "inspect", "old_ip": OLD_IP, "new_ip": NEW_IP,
        "interfaces": [{"id": "fi", "interface": "awg9", "listen_port": 3478, "public_key": _key(1)}],
    })))

    with pytest.raises(SystemExit) as exit_info:
        exec(compile(change_ip.REMOTE_CODE, "remote-change-exit-ip", "exec"), {})

    report = json.loads(capsys.readouterr().out)
    assert exit_info.value.code == 2
    assert report == {"error": "runtime_listener_mismatch"}
    assert calls == [["awg", "show", "all", "listen-port"]]


def test_remote_post_rename_failure_restores_profile_and_reports_rollback(monkeypatch, capsys, tmp_path: Path):
    root = tmp_path / "etc" / "amnezia" / "amneziawg"
    client_dir = root / "clients_awg9"
    client_dir.mkdir(parents=True)
    profile = client_dir / "phone.conf"
    original = (
        b"[Interface]\nPrivateKey = KEEP_PRIVATE_BYTES\n[Peer]\n"
        b"PublicKey = peer-public-key\nEndpoint = 46.38.156.229:3478 # keep this\n"
    )
    profile.write_bytes(original)
    backups = tmp_path / "private-backups"
    source = change_ip.REMOTE_CODE
    source = source.replace(
        "ROOT = Path('/etc/amnezia/amneziawg')", f"ROOT = Path({str(root)!r})"
    ).replace(
        "BACKUPS = Path('/var/backups/vpn-wizard')", f"BACKUPS = Path({str(backups)!r})"
    )
    assert "ROOT = Path('/etc/amnezia/amneziawg')" not in source
    assert "BACKUPS = Path('/var/backups/vpn-wizard')" not in source

    fake_subprocess = types.ModuleType("subprocess")

    def fake_run(args, **_kwargs):
        if args == ["awg", "show", "all", "listen-port"]:
            output = "awg9 3478\n"
        elif args == ["awg", "show", "awg9", "public-key"]:
            output = _key(1)
        elif args == ["awg", "show", "awg9", "peers"]:
            output = ""
        else:
            raise AssertionError(args)
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    fake_subprocess.run = fake_run
    monkeypatch.setitem(sys.modules, "subprocess", fake_subprocess)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({
        "mode": "apply", "old_ip": OLD_IP, "new_ip": NEW_IP,
        "interfaces": [{"id": "fi", "interface": "awg9", "listen_port": 3478, "public_key": _key(1)}],
    })))
    real_replace = change_ip.os.replace
    injected = {"done": False}

    def fail_after_rename(source_path, destination_path):
        result = real_replace(source_path, destination_path)
        if Path(destination_path) == profile and not injected["done"]:
            injected["done"] = True
            raise OSError("simulated directory fsync failure after rename")
        return result

    monkeypatch.setattr(change_ip.os, "replace", fail_after_rename)
    with pytest.raises(SystemExit) as exit_info:
        exec(compile(source, "remote-change-exit-ip", "exec"), {})

    report = json.loads(capsys.readouterr().out)
    assert exit_info.value.code == 2
    assert injected["done"] is True
    assert profile.read_bytes() == original
    assert report["applied"] is False
    assert report["rollback_ok"] is True
    assert report["profiles_changed"] == 1
    assert (backups / report["backup_id"] / "clients_awg9" / "phone.conf").read_bytes() == original
    assert "KEEP_PRIVATE_BYTES" not in json.dumps(report)


def _execute_remote_runtime(monkeypatch, capsys, payload, listener_text):
    fake_subprocess = types.ModuleType("subprocess")
    calls = []
    public_keys = {"awg9": _key(1), "awg8": _key(2), "awg0": _key(3), "awg1": _key(4)}
    peer_key = _key(9)

    def fake_run(args, **_kwargs):
        calls.append(args)
        if args == ["awg", "show", "all", "listen-port"]:
            output = listener_text
        elif len(args) == 4 and args[0:2] == ["awg", "show"] and args[3] == "public-key":
            output = public_keys[args[2]]
        elif len(args) == 4 and args[0:2] == ["awg", "show"] and args[3] == "peers":
            output = peer_key + "\n"
        else:
            raise AssertionError(args)
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    fake_subprocess.run = fake_run
    monkeypatch.setitem(sys.modules, "subprocess", fake_subprocess)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    with pytest.raises(SystemExit) as exit_info:
        exec(compile(change_ip.REMOTE_CODE, "remote-change-exit-ip", "exec"), {})
    output = capsys.readouterr().out
    return exit_info.value.code, json.loads(output), calls


def test_runtime_infers_only_one_interface_for_registry_without_interface(monkeypatch, capsys):
    payload = {
        "mode": "runtime", "interfaces": [
            {"id": "us", "interface": None, "listen_port": 3478, "public_key": _key(1)},
        ],
    }
    ports = "awg9 3478\nawg8 4500\nawg0 443\nawg1 3479\n"

    code, report, calls = _execute_remote_runtime(monkeypatch, capsys, payload, ports)

    assert code == 0
    assert report["interfaces"]["awg9"]["public_key_verified"] is True
    assert report["interfaces"]["awg9"]["listen_port"] == 3478
    assert report["interfaces"]["awg0"]["peer_count"] == 1
    assert len([call for call in calls if call[-1] == "peers"]) == 4


def test_runtime_rejects_ambiguous_interface_inference(monkeypatch, capsys):
    payload = {
        "mode": "runtime", "interfaces": [
            {"id": "us", "interface": None, "listen_port": 3478, "public_key": _key(1)},
        ],
    }

    code, report, calls = _execute_remote_runtime(
        monkeypatch, capsys, payload, "awg9 3478\nawg1 3478\n"
    )

    assert code == 2
    assert report == {"error": "runtime_interface_ambiguous"}
    assert calls == [["awg", "show", "all", "listen-port"]]


def test_registry_without_interface_is_accepted_for_port_based_identity_check():
    nodes = [{"id": "nl", "host": "77.67.89.164"},
             {"id": "us", "host": OLD_IP, "public_host": OLD_IP, "listen_port": 3478,
              "interface": None, "password": "secret"}]

    selected, host, endpoint = change_ip.select_nodes(nodes, "us", NEW_IP)
    payload = change_ip.interface_payload(selected, {"us": _key(1)})

    assert host == endpoint == OLD_IP
    assert payload == [{"id": "us", "interface": None, "listen_port": 3478, "public_key": _key(1)}]


def test_strict_host_key_policy_accepts_only_the_previous_host_key():
    trusted = paramiko.RSAKey.generate(1024)
    unknown = paramiko.RSAKey.generate(1024)

    class Client:
        def __init__(self):
            self.host_keys = paramiko.HostKeys()

        def get_host_keys(self):
            return self.host_keys

    client = Client()
    policy = change_ip._OldHostKeyPolicy([trusted])
    policy.missing_host_key(client, NEW_IP, trusted)
    assert client.host_keys.lookup(NEW_IP)[trusted.get_name()].asbytes() == trusted.asbytes()
    with pytest.raises(paramiko.SSHException):
        policy.missing_host_key(client, "other", unknown)


def test_paramiko_connection_uses_new_ip_but_pins_old_host_alias(tmp_path: Path):
    trusted = _known_hosts(tmp_path / "known_hosts", OLD_IP)
    observed = {}

    class Transport:
        def get_remote_server_key(self):
            return trusted

    class Client:
        def load_host_keys(self, _path):
            pass

        def set_missing_host_key_policy(self, policy):
            observed["policy"] = policy

        def connect(self, **kwargs):
            observed["connect"] = kwargs
            self.policy.missing_host_key(self, kwargs["hostname"], trusted)

        def get_host_keys(self):
            return paramiko.HostKeys()

        def get_transport(self):
            return Transport()

        def close(self):
            observed["closed"] = True

    client = Client()
    client.policy = None
    real_set_policy = Client.set_missing_host_key_policy

    def set_policy(self, policy):
        self.policy = policy
        real_set_policy(self, policy)

    client.set_missing_host_key_policy = types.MethodType(set_policy, client)
    remote = change_ip.ParamikoRemote(
        {"port": 22, "user": "root", "password": "DO_NOT_PRINT"}, OLD_IP, NEW_IP,
        known_hosts=tmp_path / "known_hosts", socket_connect=lambda *_args, **_kwargs: _NullSocket(),
        ssh_factory=lambda: client,
    ).connect()

    assert observed["connect"]["hostname"] == NEW_IP
    assert observed["connect"]["password"] == "DO_NOT_PRINT"
    assert isinstance(observed["policy"], change_ip._OldHostKeyPolicy)
    assert remote.host_key.asbytes() == trusted.asbytes()
    remote.close()


class _NullSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_windows_remote_command_is_shell_safe_and_never_carries_credentials():
    command = change_ip.build_controller_command(
        "fi", NEW_IP, True, env_path="/tmp/vpn env; touch /tmp/nope"
    )

    assert "--apply" in command
    assert "--server fi --new-ip 185.202.207.126" in command
    assert "'/tmp/vpn env; touch /tmp/nope'" in command
    assert "PASSWORD" not in command and SECRET not in command
    with pytest.raises(change_ip.ChangeError):
        change_ip.build_controller_command("fi;touch", NEW_IP, False)
    with pytest.raises(change_ip.ChangeError):
        change_ip.build_controller_command("fi", "185.202.207.126;whoami", False)


def test_windows_direct_connection_uses_stock_alias_hostkeyalias_and_strict_policy(tmp_path: Path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    config_file = ssh_dir / "config"
    config_file.write_text(
        "Host rodnya\n  HostName controller.example\n  User root\n  Port 2222\n"
        f"  HostKeyAlias 77.67.89.164\n  IdentityFile {ssh_dir / 'controller_key'}\n",
        encoding="utf-8",
    )
    known_hosts = ssh_dir / "known_hosts"
    known_hosts.write_text("77.67.89.164 ssh-rsa AAAA\n", encoding="ascii")
    observed = {}

    class Client:
        def load_host_keys(self, path): observed["known_hosts"] = path
        def set_missing_host_key_policy(self, policy): observed["policy"] = policy
        def connect(self, **kwargs): observed["connect"] = kwargs
        def close(self): observed["closed"] = True

    client = Client()
    controller = change_ip.connect_controller(
        config_path=config_file, known_hosts_path=known_hosts, home=tmp_path,
        socket_connect=lambda address, **kwargs: observed.update(socket=(address, kwargs)) or _NullSocket(),
        ssh_factory=lambda: client,
    )

    assert observed["socket"] == (("controller.example", 2222), {"timeout": 6})
    assert observed["connect"]["hostname"] == "77.67.89.164"
    assert observed["connect"]["sock"] is not None
    assert observed["connect"]["key_filename"] == [str(ssh_dir / "controller_key")]
    assert isinstance(observed["policy"], paramiko.RejectPolicy)
    controller.close()


def test_windows_direct_timeout_uses_paramiko_us_gateway_fallback(tmp_path: Path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    config_file = ssh_dir / "config"
    config_file.write_text(
        "Host rodnya\n  HostName 77.67.89.164\n  User root\n  Port 22\n"
        f"  HostKeyAlias 77.67.89.164\n  IdentityFile {ssh_dir / 'controller_key'}\n",
        encoding="utf-8",
    )
    known_hosts = ssh_dir / "known_hosts"
    known_hosts.write_text("77.67.89.164 ssh-rsa AAAA\n147.45.125.36 ssh-rsa BBBB\n", encoding="ascii")
    (ssh_dir / "radiopp_github_deploy").write_text("fixture key path only", encoding="ascii")
    clients = []
    observed = {"channels": []}

    class JumpTransport:
        def is_active(self): return True
        def open_channel(self, kind, destination, origin, timeout):
            channel = object()
            observed["channels"].append((kind, destination, origin, timeout, channel))
            return channel

    class Client:
        def __init__(self): clients.append(self)
        def load_host_keys(self, path): observed.setdefault("known", []).append(path)
        def set_missing_host_key_policy(self, policy): observed.setdefault("policies", []).append(policy)
        def connect(self, **kwargs): observed.setdefault("connects", []).append(kwargs)
        def get_transport(self): return JumpTransport()
        def close(self): observed.setdefault("closed", 0); observed["closed"] += 1

    def socket_timeout(*_args, **_kwargs):
        raise TimeoutError("direct timeout")

    controller = change_ip.connect_controller(
        config_path=config_file, known_hosts_path=known_hosts, home=tmp_path,
        socket_connect=socket_timeout, ssh_factory=Client,
    )

    assert len(clients) == 2
    assert observed["connects"][0]["hostname"] == "147.45.125.36"
    assert observed["connects"][0]["username"] == "root"
    assert observed["connects"][0]["key_filename"] == str(ssh_dir / "radiopp_github_deploy")
    target = observed["connects"][1]
    assert target["hostname"] == "77.67.89.164"
    assert target["sock"] is observed["channels"][0][4]
    assert observed["channels"][0][1] == ("77.67.89.164", 22)
    assert all(isinstance(policy, paramiko.RejectPolicy) for policy in observed["policies"])
    controller.close()


def test_paramiko_remote_preserves_failure_metadata_from_nonzero_channel():
    report = {"applied": False, "backup_id": "exit-ip-recovery", "rollback_ok": False,
              "error": "apply_or_runtime_verification_failed"}

    class Channel:
        def shutdown_write(self): pass
        def recv_exit_status(self): return 2

    class Stdin:
        channel = Channel()
        def write(self, _value): pass
        def flush(self): pass

    class Stdout:
        channel = Channel()
        def read(self): return json.dumps(report).encode("utf-8")

    class Client:
        def exec_command(self, command, timeout):
            assert "sudo -n python3 -c" in command
            return Stdin(), Stdout(), object()

    remote = change_ip.ParamikoRemote({"port": 22}, OLD_IP, NEW_IP)
    remote.client = Client()

    with pytest.raises(change_ip.RemoteOperationFailure) as failure:
        remote.run_payload({"mode": "apply"})

    assert failure.value.report == report
    assert failure.value.report["backup_id"] == "exit-ip-recovery"
    assert failure.value.report["rollback_ok"] is False


def test_apply_controller_captures_remote_nonzero_rollback_report(tmp_path: Path):
    migrate, env, original, known, _key, transport, service_calls, _db, _keys = _migration(
        tmp_path, profile_count=1, rollback_ok=False
    )
    known_before = known.read_bytes()
    original_run = transport.run_payload

    def fail_with_remote_report(payload):
        if payload["mode"] == "apply":
            transport.payloads.append(payload)
            raise change_ip.RemoteOperationFailure(
                "Remote AWG operation failed; inspect the reported rollback status.",
                {"applied": False, "backup_id": "exit-ip-test-backup", "rollback_ok": False},
            )
        return original_run(payload)

    transport.run_payload = fail_with_remote_report
    with pytest.raises(change_ip.ChangeError) as failure:
        migrate(apply=True)

    assert "remote=False, control=True, service=None" in str(failure.value)
    assert env.read_bytes() == original
    assert known.read_bytes() == known_before
    assert [payload["mode"] for payload in transport.payloads] == ["inspect", "apply", "restore"]
    assert service_calls == []


def test_windows_controller_forwards_only_validated_metadata(capsys):
    observed = {}

    class Controller:
        def run(self, command):
            observed["command"] = command
            return 0, '{"verified":true,"applied":false}', None
        def close(self): observed["closed"] = True

    def factory():
        return Controller()

    assert change_ip._windows_main("fi", NEW_IP, False, controller_factory=factory) == 0
    assert "--server fi --new-ip 185.202.207.126" in observed["command"]
    assert "--env /etc/vpn-wizard.env" in observed["command"]
    assert "\\etc\\vpn-wizard.env" not in observed["command"]
    assert "--apply" not in observed["command"]
    assert observed["closed"] is True
    assert "verified" in capsys.readouterr().out


def test_windows_caller_receives_only_bounded_backend_error_diagnostic(capsys):
    diagnostic = "ERROR: Cached encrypted profiles disagree about the fi interface identity."

    class Controller:
        def run(self, _command):
            return 1, "", diagnostic
        def close(self): pass

    assert change_ip._windows_main(
        "fi", NEW_IP, True, controller_factory=lambda: Controller()
    ) == 1
    captured = capsys.readouterr()
    assert diagnostic in captured.err
    assert SECRET not in captured.err
    assert "PASSWORD_DO_NOT_PRINT" not in captured.err


def test_ssh_controller_filters_stderr_to_one_backend_error_line():
    channel = SimpleNamespace(recv_exit_status=lambda: 1)
    stdout = SimpleNamespace(read=lambda: b"", channel=channel)
    stderr = SimpleNamespace(read=lambda _size: (
        b"Traceback (most recent call last):\n"
        b"ERROR: No cached encrypted AWG identity exists for fi; refusing to guess.\n"
        b"password=must-not-leak\n"
    ))

    class Client:
        def exec_command(self, _command, timeout):
            assert timeout == 300
            return object(), stdout, stderr
        def close(self): pass

    status, output, diagnostic = change_ip.SSHController(Client()).run("safe-command")

    assert status == 1 and output == ""
    assert diagnostic == "ERROR: No cached encrypted AWG identity exists for fi; refusing to guess."
    assert "password" not in diagnostic


def test_partial_control_restart_failure_reports_each_rollback_result_truthfully(tmp_path: Path):
    migrate, env, original, known, _key, transport, _service_calls, _db, _keys = _migration(
        tmp_path, profile_count=1, rollback_ok=False
    )
    before_known = known.read_bytes()
    calls = []

    def failing_restart(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=1 if len(calls) == 1 else 0)

    # Rebind the injected runner on this call.
    def factory(*_args, **_kwargs):
        return transport

    with pytest.raises(change_ip.ChangeError) as error:
        change_ip.migrate(
            "fi", NEW_IP, env_path=env, apply=True, transport_factory=factory,
            service_runner=failing_restart, backup_root=tmp_path / "private-backups",
            known_hosts_path=known, root_check=lambda: True,
        )

    message = str(error.value)
    assert "remote=False, control=True, service=True" in message
    assert "all changes were rolled back" not in message.lower()
    assert env.read_bytes() == original
    assert known.read_bytes() == before_known
    assert [payload["mode"] for payload in transport.payloads] == ["inspect", "apply", "restore"]
    assert calls == [["systemctl", "restart", "vpn-wizard"], ["systemctl", "restart", "vpn-wizard"]]
    assert SECRET not in message and "PASSWORD_DO_NOT_PRINT" not in message


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.5", "224.0.0.1", "2001:4860:4860::8888", "185.202.207.126;whoami"])
def test_rejects_non_public_or_non_ipv4_targets(value: str):
    with pytest.raises(change_ip.ChangeError, match="globally routable IPv4"):
        change_ip.validate_public_ipv4(value)


def test_refuses_control_node_even_when_requested_country_is_remote():
    nodes = _nodes()
    nodes[0]["host"] = OLD_IP
    with pytest.raises(change_ip.ChangeError, match="Netherlands control server"):
        change_ip.select_nodes(nodes, "fi", NEW_IP)

