from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
from typing import Any

import pytest


PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "refresh-xhttp-test-certificate.py"
)
SPEC = importlib.util.spec_from_file_location("refresh_xhttp_test_certificate", PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


OLD_CERT = b"OLD PUBLIC CERTIFICATE BYTES\n"
OLD_KEY = b"OLD PRIVATE KEY MATERIAL\n"
NEW_CERT = b"NEW PUBLIC CERTIFICATE BYTES\n"
NEW_KEY = b"NEW PRIVATE KEY MATERIAL\n"


@pytest.fixture(autouse=True)
def reset_runtime_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VPNW_PUBLIC_BASE_URL", raising=False)
    monkeypatch.setattr(MODULE, "DOMAIN", MODULE.LEGACY_DOMAIN)
    monkeypatch.setattr(MODULE, "SOURCE_ROOT", MODULE.SOURCE_ROOT_DEFAULT)
    monkeypatch.setattr(MODULE, "SOURCE", MODULE.SOURCE_ROOT_DEFAULT / MODULE.LEGACY_DOMAIN)


def config_for(domain: str, cert_path: Path, key_path: Path) -> bytes:
    config = {
        "inbounds": [
            {
                "tag": "trial",
                "listen": "0.0.0.0",
                "port": 9443,
                "protocol": "vless",
                "settings": {"clients": [{"id": "fixture-id"}], "decryption": "none"},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {"path": "/fixture"},
                    "tlsSettings": {
                        "serverName": domain,
                        "certificates": [
                            {
                                "certificateFile": str(cert_path),
                                "keyFile": str(key_path),
                                "oneTimeLoading": False,
                            }
                        ],
                    },
                },
            }
        ],
        "routing": {"rules": [{"type": "field", "outboundTag": "direct"}]},
    }
    return (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def setup_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    target_cert: bytes = OLD_CERT,
    target_key: bytes = OLD_KEY,
    target_domain: str = "old-nl.example",
    source_domain: str | None = None,
    target_dir: bool = True,
) -> dict[str, Any]:
    xray = tmp_path / "xray"
    xray.mkdir()
    config_path = xray / "config.json"
    cert_dir = xray / "fvpn-test-certs"
    if target_domain == MODULE.DOMAIN:
        prior_cert_path = cert_dir / "fullchain.pem"
        prior_key_path = cert_dir / "key.pem"
    else:
        prior_cert_path = tmp_path / "previous" / "fullchain.pem"
        prior_key_path = tmp_path / "previous" / "key.pem"
    old_config = config_for(
        target_domain,
        prior_cert_path,
        prior_key_path,
    )
    config_path.write_bytes(old_config)

    source_domain = source_domain or MODULE.DOMAIN
    source_root = tmp_path / "caddy"
    source_dir = source_root / source_domain
    source_dir.mkdir(parents=True)
    source_cert = source_dir / (source_domain + ".crt")
    source_key = source_dir / (source_domain + ".key")
    source_cert.write_bytes(NEW_CERT)
    source_key.write_bytes(NEW_KEY)

    if target_dir:
        cert_dir.mkdir()
        (cert_dir / "fullchain.pem").write_bytes(target_cert)
        (cert_dir / "key.pem").write_bytes(target_key)

    backups = tmp_path / "backups"
    monkeypatch.setattr(MODULE, "CONFIG", config_path)
    monkeypatch.setattr(MODULE, "SOURCE_ROOT", source_root)
    monkeypatch.setattr(MODULE, "SOURCE", source_dir)
    monkeypatch.setattr(MODULE, "CERT_DIR", cert_dir)
    monkeypatch.setattr(MODULE, "BACKUPS", backups)
    monkeypatch.setattr(MODULE, "_nobody_gid", lambda: 0)
    monkeypatch.setattr(MODULE, "_running_as_root", lambda: True)
    monkeypatch.setattr(MODULE, "_private_root_directory", lambda _path: True)
    return {
        "config": config_path,
        "original_config": old_config,
        "source_cert": source_cert,
        "source_key": source_key,
        "cert_dir": cert_dir,
        "backups": backups,
        "old_cert": target_cert,
        "old_key": target_key,
    }


def mock_tools(
    monkeypatch: pytest.MonkeyPatch,
    state: dict[str, Any],
) -> list[list[str]]:
    calls: list[list[str]] = []

    def checked(command: list[str]) -> bytes:
        calls.append(command)
        if command[0] == "openssl":
            if "-pubkey" in command or "-pubout" in command:
                return b"matched-public-key\n"
            return b""
        if command[0] == "/usr/local/bin/xray":
            staged_config = Path(command[-1])
            assert staged_config.suffix == ".json"
            assert command[1:4] == ["run", "-test", "-config"]
            staged = json.loads(staged_config.read_bytes())
            inbound = staged["inbounds"][0]
            tls = inbound["streamSettings"]["tlsSettings"]
            assert tls["serverName"] == MODULE.DOMAIN
            assert (state["cert_dir"] / "fullchain.pem").read_bytes() == NEW_CERT
            assert (state["cert_dir"] / "key.pem").read_bytes() == NEW_KEY
            return b""
        if command[0] == "systemctl":
            return b""
        raise AssertionError(f"Unexpected external command: {command[0]}")

    monkeypatch.setattr(MODULE, "checked", checked)
    return calls


def test_rotation_backs_up_old_private_material_and_restarts_only_xray(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    state = setup_case(tmp_path, monkeypatch)
    calls = mock_tools(monkeypatch, state)
    monkeypatch.setattr(MODULE, "_certificate_metadata_matches", lambda *_args: True)
    monkeypatch.setattr(
        MODULE,
        "verified_tls",
        lambda server_name=MODULE.DOMAIN: {
            "tls_verified": True,
            "alpn": "h2",
            "not_after": "Jun 30 12:00:00 2027 GMT",
        },
    )

    assert MODULE.main(["--apply"]) == 0

    output = capsys.readouterr().out
    status = json.loads(output)
    assert status["applied"] is True
    assert status["changed"] is True
    assert status["certificates_changed"] is True
    assert status["config_changed"] is True
    assert status["tls_verified"] is True
    assert state["config"].read_bytes() != state["original_config"]
    assert (state["cert_dir"] / "fullchain.pem").read_bytes() == NEW_CERT
    assert (state["cert_dir"] / "key.pem").read_bytes() == NEW_KEY

    backup = Path(status["backup"])
    assert (backup / "config.json").read_bytes() == state["original_config"]
    assert (backup / "fullchain.pem").read_bytes() == OLD_CERT
    assert (backup / "key.pem").read_bytes() == OLD_KEY
    assert [call[1] for call in calls if call[0] == "systemctl"] == [
        "restart",
        "is-active",
    ]
    assert all("xray" in call for call in calls if call[0] == "systemctl")
    assert OLD_KEY.decode().strip() not in output
    assert NEW_KEY.decode().strip() not in output


def test_unchanged_certificate_still_verifies_tls_without_backup_or_restart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    state = setup_case(
        tmp_path,
        monkeypatch,
        target_cert=NEW_CERT,
        target_key=NEW_KEY,
        target_domain=MODULE.DOMAIN,
    )
    calls = mock_tools(monkeypatch, state)
    monkeypatch.setattr(MODULE, "_certificate_metadata_matches", lambda *_args: True)
    verified: list[str] = []

    def verify(server_name: str = MODULE.DOMAIN) -> dict[str, Any]:
        verified.append(server_name)
        return {"tls_verified": True, "alpn": "h2", "not_after": "Jun 30 2027 GMT"}

    monkeypatch.setattr(MODULE, "verified_tls", verify)

    assert MODULE.main(["--apply"]) == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["applied"] is False
    assert result["changed"] is False
    assert result["tls_verified"] is True
    assert verified == [MODULE.DOMAIN]
    assert not state["backups"].exists()
    assert not any(call[0] in {"systemctl", "/usr/local/bin/xray"} for call in calls)


def test_runtime_public_base_selects_certificate_domain_and_repeats_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    domain = "nl-current.example"
    state = setup_case(tmp_path, monkeypatch, source_domain=domain)
    monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", f"https://{domain}/api")
    calls = mock_tools(monkeypatch, state)
    monkeypatch.setattr(MODULE, "_certificate_metadata_matches", lambda *_args: True)
    verified: list[str | None] = []

    def verify(server_name: str | None = None) -> dict[str, Any]:
        verified.append(server_name)
        return {"tls_verified": True, "alpn": "h2", "not_after": "Jun 30 2027 GMT"}

    monkeypatch.setattr(MODULE, "verified_tls", verify)

    assert MODULE.main(["--apply"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["domain"] == domain
    assert first["config_changed"] is True
    assert json.loads(state["config"].read_bytes())["inbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] == domain

    assert MODULE.main(["--apply"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["domain"] == domain
    assert second["changed"] is False
    assert verified == [domain, domain]
    assert [call[1] for call in calls if call[0] == "systemctl"] == [
        "restart",
        "is-active",
    ]


def test_runtime_domain_failure_rolls_back_and_verifies_previous_domain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    domain = "nl-new.example"
    previous_domain = "nl-previous.example"
    state = setup_case(
        tmp_path,
        monkeypatch,
        target_domain=previous_domain,
        source_domain=domain,
    )
    monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", f"https://{domain}")
    calls = mock_tools(monkeypatch, state)
    monkeypatch.setattr(MODULE, "_certificate_metadata_matches", lambda *_args: True)
    verified: list[str | None] = []

    def verify(server_name: str | None = None) -> dict[str, Any]:
        verified.append(server_name)
        if server_name == domain:
            raise RuntimeError("new certificate verification failed")
        return {"tls_verified": True}

    monkeypatch.setattr(MODULE, "verified_tls", verify)

    assert MODULE.main(["--apply"]) == 1

    result = json.loads(capsys.readouterr().out)
    assert result["rolled_back"] is True
    assert verified == [domain, previous_domain]
    assert state["config"].read_bytes() == state["original_config"]
    assert (state["cert_dir"] / "fullchain.pem").read_bytes() == OLD_CERT
    assert (state["cert_dir"] / "key.pem").read_bytes() == OLD_KEY
    assert [call[1] for call in calls if call[0] == "systemctl"].count("restart") == 2


def test_configure_domain_accepts_helper_argument_and_rejects_non_dns_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert MODULE.configure_domain("New-NL.Example.") == "new-nl.example"
    assert MODULE.SOURCE == MODULE.SOURCE_ROOT / "new-nl.example"
    for invalid in (
        "https://nl.example",
        "../outside",
        "127.0.0.1",
        "localhost",
        "trial.localhost",
    ):
        with pytest.raises(ValueError):
            MODULE.configure_domain(invalid)


def test_configure_domain_rejects_invalid_public_base_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for value in (
        "ftp://nl.example",
        "https://127.0.0.1",
        "https://user:secret@nl.example",
        "https://localhost",
        "https://nl.example:invalid",
    ):
        monkeypatch.setenv("VPNW_PUBLIC_BASE_URL", value)
        with pytest.raises(ValueError):
            MODULE.configure_domain()


def test_main_domain_option_uses_matching_caddy_source_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    domain = "manual-nl.example"
    state = setup_case(tmp_path, monkeypatch, source_domain=domain)
    calls = mock_tools(monkeypatch, state)

    assert MODULE.main(["--domain", domain]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["ready"] is True
    assert result["domain"] == domain
    assert state["source_cert"].name == domain + ".crt"
    assert not any(call[0] in {"systemctl", "/usr/local/bin/xray"} for call in calls)


def test_tls_verifiers_use_runtime_domain_when_server_name_is_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    domain = MODULE.configure_domain("runtime-nl.example")
    verified_names: list[str] = []

    class FakeRaw:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class FakeSecure:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def selected_alpn_protocol(self):
            return "h2"

        def getpeercert(self):
            return {"notAfter": "Jun 30 2027 GMT"}

    class FakeContext:
        def set_alpn_protocols(self, _protocols):
            return None

        def wrap_socket(self, raw, *, server_hostname):
            verified_names.append(server_hostname)
            return FakeSecure()

    monkeypatch.setattr(MODULE.ssl, "create_default_context", FakeContext)
    monkeypatch.setattr(MODULE.socket, "create_connection", lambda *_args, **_kwargs: FakeRaw())

    assert MODULE.verified_tls()["tls_verified"] is True
    assert MODULE._verify_after_restart()["tls_verified"] is True
    assert verified_names == [domain, domain]


def test_certificate_sync_service_loads_runtime_public_base_environment() -> None:
    service = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "xhttp-certificate-sync.service"
    ).read_text(encoding="utf-8")
    assert "EnvironmentFile=/etc/vpn-wizard.env" in service
    assert "refresh-xhttp-test-certificate.py --apply" in service


def test_failed_new_tls_restores_both_cert_files_and_config_then_verifies_rollback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    state = setup_case(tmp_path, monkeypatch)
    calls = mock_tools(monkeypatch, state)
    monkeypatch.setattr(MODULE, "_certificate_metadata_matches", lambda *_args: True)
    tls_names: list[str] = []

    def verify(server_name: str = MODULE.DOMAIN) -> dict[str, Any]:
        tls_names.append(server_name)
        if len(tls_names) == 1:
            raise RuntimeError("new certificate verification failed")
        if len(tls_names) == 2:
            raise ConnectionRefusedError("old listener is still restarting")
        return {"tls_verified": True, "alpn": "h2", "not_after": "old certificate"}

    monkeypatch.setattr(MODULE, "verified_tls", verify)
    monkeypatch.setattr(MODULE.time, "sleep", lambda _seconds: None)

    assert MODULE.main(["--apply"]) == 1

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["applied"] is False
    assert result["rolled_back"] is True
    assert state["config"].read_bytes() == state["original_config"]
    assert (state["cert_dir"] / "fullchain.pem").read_bytes() == OLD_CERT
    assert (state["cert_dir"] / "key.pem").read_bytes() == OLD_KEY
    assert tls_names == [MODULE.DOMAIN, "old-nl.example", "old-nl.example"]
    assert [call[1] for call in calls if call[0] == "systemctl"].count("restart") == 2
    assert OLD_KEY.decode().strip() not in output


def test_failed_previous_service_restart_does_not_claim_rollback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    state = setup_case(tmp_path, monkeypatch)
    calls = mock_tools(monkeypatch, state)
    monkeypatch.setattr(MODULE, "_certificate_metadata_matches", lambda *_args: True)
    tls_calls = 0

    def verify(server_name: str = MODULE.DOMAIN) -> dict[str, Any]:
        nonlocal tls_calls
        tls_calls += 1
        if tls_calls == 1:
            raise RuntimeError("new certificate verification failed")
        return {"tls_verified": True}

    monkeypatch.setattr(MODULE, "verified_tls", verify)
    real_checked = MODULE.checked
    restarts = 0

    def fail_rollback_restart(command: list[str]) -> bytes:
        nonlocal restarts
        if command[:2] == ["systemctl", "restart"]:
            restarts += 1
            if restarts == 2:
                raise RuntimeError("previous Xray restart failed")
        return real_checked(command)

    monkeypatch.setattr(MODULE, "checked", fail_rollback_restart)

    assert MODULE.main(["--apply"]) == 1

    result = json.loads(capsys.readouterr().out)
    assert result["rolled_back"] is False
    assert state["config"].read_bytes() == state["original_config"]
    assert (state["cert_dir"] / "fullchain.pem").read_bytes() == OLD_CERT
    assert (state["cert_dir"] / "key.pem").read_bytes() == OLD_KEY
    assert restarts == 2


def test_unsafe_backup_rejects_rotation_before_target_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    state = setup_case(tmp_path, monkeypatch)
    calls = mock_tools(monkeypatch, state)
    monkeypatch.setattr(MODULE, "_certificate_metadata_matches", lambda *_args: True)
    monkeypatch.setattr(MODULE, "_private_root_directory", lambda _path: False)

    assert MODULE.main(["--apply"]) == 1

    result = json.loads(capsys.readouterr().out)
    assert result == {"applied": False, "error": "certificate preflight failed"}
    assert state["config"].read_bytes() == state["original_config"]
    assert (state["cert_dir"] / "fullchain.pem").read_bytes() == OLD_CERT
    assert (state["cert_dir"] / "key.pem").read_bytes() == OLD_KEY
    assert not any(call[0] == "systemctl" for call in calls)

def test_unexpected_target_file_is_rejected_before_backup_or_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    state = setup_case(tmp_path, monkeypatch)
    extra = state["cert_dir"] / "unexpected.pem"
    extra.write_bytes(b"do not touch")
    calls = mock_tools(monkeypatch, state)

    assert MODULE.main(["--apply"]) == 1

    result = json.loads(capsys.readouterr().out)
    assert result == {"applied": False, "error": "certificate preflight failed"}
    assert not state["backups"].exists()
    assert (state["cert_dir"] / "fullchain.pem").read_bytes() == OLD_CERT
    assert (state["cert_dir"] / "key.pem").read_bytes() == OLD_KEY
    assert extra.read_bytes() == b"do not touch"
    assert not any(call[0] == "systemctl" for call in calls)


def test_symlink_in_target_certificate_directory_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    state = setup_case(tmp_path, monkeypatch)
    calls = mock_tools(monkeypatch, state)
    real_lstat = MODULE._lstat
    symlink = state["cert_dir"] / "key.pem"

    def lstat_with_symlink(path: Path):
        if path == symlink:
            return SimpleNamespace(st_mode=stat.S_IFLNK)
        return real_lstat(path)

    monkeypatch.setattr(MODULE, "_lstat", lstat_with_symlink)

    assert MODULE.main(["--apply"]) == 1

    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "certificate preflight failed"
    assert not state["backups"].exists()
    assert not any(call[0] == "systemctl" for call in calls)
