from __future__ import annotations

import re
import sqlite3
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKUP_SCRIPT = REPO_ROOT / "deploy" / "scripts" / "remnawave-backup"


def _script_text() -> str:
    return BACKUP_SCRIPT.read_text(encoding="utf-8")


def _sqlite_backup_python() -> str:
    match = re.search(
        r'python3 - "\$sqlite_snapshot_dir".*?<<\'PY\'\r?\n(.*?)\r?\nPY',
        _script_text(),
        re.DOTALL,
    )
    assert match, "the script must provide an inline stdlib SQLite backup helper"
    return match.group(1)


def test_backup_uses_sqlite_online_backup_for_both_databases() -> None:
    script = _script_text()

    assert "sqlite_sources+=(/opt/vpn-wizard/shared/state.db)" in script
    assert "sqlite_sources+=(/opt/vpn-wizard/shared/public-access.db)" in script
    assert "source.backup(target)" in _sqlite_backup_python()
    assert 'target.execute("PRAGMA quick_check")' in _sqlite_backup_python()
    assert 'source_uri = Path(source_path).resolve().as_uri() + "?mode=ro"' in script


def test_tar_keeps_canonical_restore_paths_and_excludes_live_state_db() -> None:
    script = _script_text()
    config_paths_block = script.split("config_paths=(", 1)[1].split("\n)", 1)[0]

    assert "opt/vpn-wizard/shared/state.db" not in config_paths_block
    assert 'sqlite_snapshot_paths+=("opt/vpn-wizard/shared/$filename")' in script
    assert 'tar_args=(-C / -czf "$config_tmp" "${config_paths[@]}")' in script
    assert 'sqlite_tar_args=(-C "$sqlite_snapshot_dir" "${sqlite_snapshot_paths[@]}")' in script
    assert 'tar_args+=("${sqlite_tar_args[@]}")' in script


def test_snapshot_cleanup_only_removes_a_validated_generated_temp_directory() -> None:
    script = _script_text()

    assert 'mktemp -d "$backup_dir/.sqlite-snapshot.XXXXXXXX"' in script
    assert '[[ "${candidate%/*}" == "$backup_dir" ]]' in script
    assert '[[ "$base" =~ ^\\.sqlite-snapshot\\.[[:alnum:]]{8}$ ]]' in script
    assert 'rm -rf -- "$sqlite_snapshot_dir"' in script
    assert script.count("rm -rf") == 1
    assert 'rm -rf -- "$backup_dir"' not in script


def test_existing_postgres_and_config_backup_commands_remain() -> None:
    script = _script_text()

    assert "docker exec remnawave-db" in script
    assert "pg_dump -U postgres -d postgres --clean --if-exists" in script
    assert "docker exec remnawave_bot_db" in script
    assert "pg_dump -U remnawave_user -d remnawave_bot --clean --if-exists" in script
    assert "-name 'remnawave-*.sql.gz'" in script
    assert "-name 'bedolaga-*.sql.gz'" in script
    assert "-name 'vpn-stack-*-config.tgz'" in script


def test_inline_online_backup_produces_consistent_snapshot_while_source_is_open(tmp_path: Path) -> None:
    source_path = tmp_path / "state.db"
    snapshot_root = tmp_path / "snapshot"
    destination_path = snapshot_root / "opt/vpn-wizard/shared/state.db"
    destination_path.parent.mkdir(parents=True)

    source = sqlite3.connect(source_path)
    source.execute("PRAGMA journal_mode=WAL")
    source.execute("CREATE TABLE values_to_keep (value TEXT NOT NULL)")
    source.execute("INSERT INTO values_to_keep VALUES ('committed-before-snapshot')")
    source.commit()
    try:
        subprocess.run(
            [
                sys.executable,
                "-c",
                _sqlite_backup_python(),
                str(snapshot_root),
                str(source_path),
                str(destination_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        snapshot = sqlite3.connect(destination_path)
        try:
            assert snapshot.execute("PRAGMA quick_check").fetchone() == ("ok",)
            assert snapshot.execute("SELECT value FROM values_to_keep").fetchall() == [
                ("committed-before-snapshot",)
            ]
        finally:
            snapshot.close()
    finally:
        source.close()
