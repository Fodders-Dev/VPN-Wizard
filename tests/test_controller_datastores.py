"""Regression coverage for the controller-IP migration's config and datastore edges."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "scripts" / "change-controller-ip.py"
SPEC = importlib.util.spec_from_file_location("change_controller_ip_datastore_tests", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

OLD_IP = "77.67.89.164"
NEW_IP = "185.202.207.126"
OLD_DOMAIN = "77-67-89-164.nip.io"
NEW_DOMAIN = "185-202-207-126.nip.io"


def test_environment_url_scopes_cover_bedolaga_remnawave_and_subpage_without_touching_secrets():
    cases = (
        (
            "vpn",
            (
                f"VPNW_PUBLIC_BASE_URL='https://{OLD_DOMAIN}/'\r\n"
                f"VPNW_MINIAPP_URL='https://{OLD_DOMAIN}/miniapp/'\r\n"
                f"VPNW_CORS_ORIGINS='https://{OLD_DOMAIN},https://panel.{OLD_DOMAIN}'\r\n"
                "VPNW_SECRET_KEY='unchanged-secret-bytes'\r\n"
            ),
        ),
        (
            "bedolaga_env",
            (
                f"FODDERS_PORTAL_URL='https://{OLD_DOMAIN}/portal/'\n"
                f"FODDERS_VPN1_MINIAPP_URL=https://{OLD_DOMAIN}/wizard/\n"
                "BOT_TOKEN='unchanged-bot-secret'\n"
            ),
        ),
        (
            "remnawave_env",
            (
                f"FRONT_END_DOMAIN={OLD_DOMAIN}\n"
                f"WEBHOOK_URL=https://{OLD_DOMAIN}/api/integrations/remnawave/webhook\n"
                "POSTGRES_PASSWORD='unchanged-db-secret'\n"
            ),
        ),
        (
            "subpage_env",
            (
                f"API_URL=https://{OLD_DOMAIN}/api\n"
                f"WEBHOOK_URL=https://{OLD_IP}:9443/hook\n"
                "JWT_SECRET='unchanged-jwt-secret'\n"
            ),
        ),
    )

    for key, source in cases:
        updated, count = MODULE._transform_env(
            source.encode("utf-8"), key, OLD_IP, NEW_IP
        )
        result = updated.decode("utf-8")
        assert OLD_DOMAIN not in result, key
        assert OLD_IP not in result, key
        assert result.count(NEW_DOMAIN) >= 1, key
        assert count > 0, key
        for line in source.splitlines(keepends=True):
            if any(secret in line for secret in ("unchanged-secret", "unchanged-bot", "unchanged-db", "unchanged-jwt")):
                assert line.encode("utf-8") in updated, key


def _saved_server_db(path: Path) -> None:
    with MODULE.sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE saved_servers ("
            "id TEXT PRIMARY KEY, host TEXT, relay_host TEXT, relay_public_host TEXT, "
            "password_enc TEXT, relay_password_enc TEXT)"
        )
        connection.executemany(
            "INSERT INTO saved_servers VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("host-old", OLD_IP, "relay.example", "relay.public.example", "host-secret", "relay-secret"),
                ("relay-old", "server.example", OLD_IP, OLD_IP, "host-secret-2", "relay-secret-2"),
                ("other-address", NEW_IP, "relay.other", "public.other", "host-secret-3", "relay-secret-3"),
                ("embedded-old", f"node-{OLD_IP}.example", "relay.example", "public.example", "host-secret-4", "relay-secret-4"),
            ],
        )


def test_sqlite_captures_exact_old_host_and_relay_columns_and_restores_them(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    _saved_server_db(database)

    rows = MODULE._sqlite_rows(database, OLD_IP)

    assert set(rows) == {
        ("host-old", "host", OLD_IP),
        ("relay-old", "relay_host", OLD_IP),
        ("relay-old", "relay_public_host", OLD_IP),
    }
    MODULE._sqlite_apply(database, rows, OLD_IP, NEW_IP)
    with MODULE.sqlite3.connect(database) as connection:
        host, relay_host, relay_public, host_secret, relay_secret = connection.execute(
            "SELECT host, relay_host, relay_public_host, password_enc, relay_password_enc "
            "FROM saved_servers WHERE id='host-old'"
        ).fetchone()
        assert (host, relay_host, relay_public) == (NEW_IP, "relay.example", "relay.public.example")
        assert (host_secret, relay_secret) == ("host-secret", "relay-secret")
        host, relay_host, relay_public = connection.execute(
            "SELECT host, relay_host, relay_public_host FROM saved_servers WHERE id='relay-old'"
        ).fetchone()
        assert (host, relay_host, relay_public) == ("server.example", NEW_IP, NEW_IP)
        assert connection.execute(
            "SELECT host FROM saved_servers WHERE id='embedded-old'"
        ).fetchone()[0] == f"node-{OLD_IP}.example"

    assert MODULE._sqlite_restore(database, rows, OLD_IP, NEW_IP) is True
    with MODULE.sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT host, relay_host, relay_public_host FROM saved_servers WHERE id='relay-old'"
        ).fetchone() == ("server.example", OLD_IP, OLD_IP)


def test_sqlite_restore_accepts_old_preimages_and_refuses_concurrent_values(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    _saved_server_db(database)
    rows = [
        ("host-old", "host", OLD_IP),
        ("relay-old", "relay_host", OLD_IP),
        ("relay-old", "relay_public_host", OLD_IP),
    ]
    MODULE._sqlite_apply(database, rows, OLD_IP, NEW_IP)
    with MODULE.sqlite3.connect(database) as connection:
        connection.execute("UPDATE saved_servers SET host=? WHERE id='host-old'", (OLD_IP,))
        connection.execute(
            "UPDATE saved_servers SET relay_public_host='operator-edit.example' WHERE id='relay-old'"
        )

    assert MODULE._sqlite_restore(database, rows, OLD_IP, NEW_IP) is False
    with MODULE.sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT host FROM saved_servers WHERE id='host-old'"
        ).fetchone()[0] == OLD_IP
        assert connection.execute(
            "SELECT relay_host, relay_public_host FROM saved_servers WHERE id='relay-old'"
        ).fetchone() == (NEW_IP, "operator-edit.example")

    with MODULE.sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE saved_servers SET relay_public_host=? WHERE id='relay-old'", (NEW_IP,)
        )
    assert MODULE._sqlite_restore(database, rows, OLD_IP, NEW_IP) is True


def test_postgres_rows_are_read_as_text_and_only_old_ip_rows_are_selected() -> None:
    seen: list[dict[str, Any]] = []
    output = (
        "hosts|123e4567-e89b-12d3-a456-426614174000|77.67.89.164\n"
        "nodes|123e4567-e89b-12d3-a456-426614174001|77.67.89.164\n"
    )

    def runner(args, **kwargs):
        seen.append(kwargs)
        assert "psql" in " ".join(args)
        assert kwargs["text"] is True
        assert "address = '77.67.89.164'" in kwargs["input"]
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    rows = MODULE._pg_rows(OLD_IP, runner)

    assert rows == [
        ("hosts", "123e4567-e89b-12d3-a456-426614174000", OLD_IP),
        ("nodes", "123e4567-e89b-12d3-a456-426614174001", OLD_IP),
    ]
    assert len(seen) == 1


def test_postgres_apply_updates_only_rows_still_at_the_old_ip() -> None:
    statements: list[str] = []

    def runner(_args, **kwargs):
        statements.append(kwargs["input"])
        assert kwargs["text"] is True
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    row = ("hosts", "123e4567-e89b-12d3-a456-426614174000", OLD_IP)
    MODULE._pg_apply([row], OLD_IP, NEW_IP, runner)

    sql = statements[0]
    assert "BEGIN;" in sql and "COMMIT;" in sql
    assert f"SET address='{NEW_IP}'" in sql
    assert f"AND address='{OLD_IP}'" in sql
    assert "IF NOT FOUND THEN RAISE EXCEPTION 'row_changed'" in sql


@pytest.mark.parametrize(
    ("current_state", "runner_code", "expected"),
    (("old", 0, True), ("new", 0, True), ("concurrent", 1, False)),
)
def test_postgres_restore_is_idempotent_and_guarded_against_concurrent_values(
    current_state: str, runner_code: int, expected: bool
) -> None:
    statements: list[str] = []

    def runner(_args, **kwargs):
        statements.append(kwargs["input"])
        assert kwargs["text"] is True
        return SimpleNamespace(returncode=runner_code, stdout="", stderr="")

    row = ("nodes", "123e4567-e89b-12d3-a456-426614174099", OLD_IP)

    assert MODULE._pg_restore([row], OLD_IP, NEW_IP, runner) is expected
    sql = statements[0]
    assert "BEGIN;" in sql and "COMMIT;" in sql
    assert f"SET address='{OLD_IP}'" in sql
    assert f"AND address='{NEW_IP}'" in sql
    assert f"ELSIF NOT EXISTS (SELECT 1 FROM public.nodes WHERE uuid='{row[1]}' AND address='{OLD_IP}')" in sql
    assert "RAISE EXCEPTION 'row_changed'" in sql


def test_controller_takes_both_binary_postgres_dumps_before_any_mutation_or_menu_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_path = tmp_path / "vpn.env"
    bedolaga = tmp_path / "bedolaga.env"
    remnawave = tmp_path / "remnawave.env"
    env_path.write_bytes(b"fixture vpn env\n")
    bedolaga.write_text("BOT_TOKEN='test-only-token'\nFODDERS_PORTAL_URL='https://old.example/portal'\n", encoding="utf-8")
    remnawave.write_text("FRONT_END_DOMAIN=old.example\nWEBHOOK_URL=https://old.example/hook\n", encoding="utf-8")
    paths = {name: tmp_path / name for name in MODULE.DEFAULT_PATHS}
    paths.update({"bedolaga_env": bedolaga, "remnawave_env": remnawave})
    state_db = tmp_path / "state.db"
    values = {
        "VPNW_AWG_SERVERS": json.dumps([
            {"id": "nl", "host": "127.0.0.1", "public_host": OLD_IP, "listen_port": 443},
            {"id": "nl-alt", "host": "127.0.0.1", "public_host": OLD_IP, "listen_port": 3478},
        ]),
        "VPNW_AWG_DEFAULT_SERVER": "nl",
        "VPNW_SECRET_KEY": "test-only-secret-key",
        "VPNW_STATE_DB": str(state_db),
    }
    fake_helper = SimpleNamespace(parse_env=lambda _raw: (values, [], {}))
    monkeypatch.setattr(MODULE, "_exit_helper", lambda: fake_helper)
    monkeypatch.setattr(MODULE, "cached_nl_identities", lambda *_args: {"nl": "pub-nl", "nl-alt": "pub-nl-alt"})
    monkeypatch.setattr(MODULE, "_sqlite_rows", lambda *_args: [])
    monkeypatch.setattr(MODULE, "_pg_rows", lambda *_args: [("hosts", "123e4567-e89b-12d3-a456-426614174000", OLD_IP)])
    monkeypatch.setattr(
        MODULE,
        "_read_candidates",
        lambda *_args: (
            {
                env_path: b"updated vpn env\n",
                bedolaga: b"BOT_TOKEN='test-only-token'\nFODDERS_PORTAL_URL='https://new.example/portal'\n",
                remnawave: b"FRONT_END_DOMAIN=new.example\nWEBHOOK_URL=https://new.example/hook\n",
            },
            {"vpn_env": 1},
            {"old_domain": OLD_DOMAIN, "new_domain": NEW_DOMAIN},
        ),
    )

    events: list[str] = []
    dump_payloads: dict[str, bytes] = {}

    def command_runner(args, **kwargs):
        joined = " ".join(args)
        if "pg_dump" in joined:
            container = "bot" if "remnawave_bot_db" in joined else "remnawave"
            events.append(f"dump:{container}")
            assert kwargs.get("capture_output") is True
            assert kwargs.get("text") is not True, "custom-format pg_dump must stay binary"
            binary = b"\x00\xff" + container.encode("ascii") + b"\x00"
            dump_payloads[container] = binary
            return SimpleNamespace(returncode=0, stdout=binary, stderr=b"")
        raise AssertionError(f"Unexpected command_runner call: {args[0]}")

    def service_runner(args, **kwargs):
        events.append("service:" + " ".join(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def atomic_write(path: Path, data: bytes, _metadata=None):
        events.append("write:" + path.name)
        path.write_bytes(data)

    monkeypatch.setattr(MODULE, "_atomic_write", atomic_write)
    monkeypatch.setattr(MODULE, "_pg_apply", lambda *_args: events.append("pg_apply"))
    monkeypatch.setattr(MODULE, "_tls_wait", lambda domain, *_args, **_kwargs: {"domain": domain})

    def menu_updater(mode, _payload):
        events.append("menu:" + mode)
        if mode == "read":
            return {"config": {"rows": []}, "digest": "read-digest"}
        if mode == "apply":
            return {"changed": True, "digest": "apply-digest"}
        return {"restored": True}

    def telegram(_token, method, _payload):
        events.append("telegram:" + method)
        return {"type": "default"} if method == "getChatMenuButton" else {}

    result = MODULE.migrate_controller(
        NEW_IP,
        env_path=env_path,
        apply=True,
        command_runner=command_runner,
        service_runner=service_runner,
        backup_root=tmp_path / "backups",
        paths=paths,
        address_checker=lambda _ip: True,
        runtime_runner=lambda _payload: {
            "interfaces": {
                "awg0": {"listen_port": 443, "public_key_verified": True},
                "awg1": {"listen_port": 3478, "public_key_verified": True},
            },
            "profiles_to_update": 0,
        },
        menu_layout_updater=menu_updater,
        telegram_client=telegram,
        root_check=lambda: True,
    )

    assert result["verified"] is True
    assert set(dump_payloads) == {"remnawave", "bot"}
    backup = tmp_path / "backups" / result["backup"]
    dumped = {path.read_bytes() for path in backup.glob("*.dump")}
    assert dumped == set(dump_payloads.values())
    dump_positions = [i for i, event in enumerate(events) if event.startswith("dump:")]
    assert len(dump_positions) == 2
    first_mutation = min(
        i
        for i, event in enumerate(events)
        if event.startswith(("write:", "service:", "telegram:setChatMenuButton", "menu:apply"))
        or event == "pg_apply"
    )
    assert max(dump_positions) < first_mutation
    assert "telegram:getChatMenuButton" in events
    assert "telegram:setChatMenuButton" in events
