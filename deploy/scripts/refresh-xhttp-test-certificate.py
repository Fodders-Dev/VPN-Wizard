"""Synchronize the NL XHTTP trial certificate from Caddy; never touch AWG."""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:  # Windows test workstation; production runs on Linux.
    pwd = None
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from typing import Any, Sequence


CONFIG = Path("/usr/local/etc/xray/config.json")
DOMAIN = "82-25-60-19.nip.io"
SOURCE = Path(
    "/var/lib/caddy/.local/share/caddy/certificates/"
    "acme-v02.api.letsencrypt.org-directory"
) / DOMAIN
CERT_DIR = Path("/usr/local/etc/xray/fvpn-test-certs")
BACKUPS = Path("/opt/vpn-wizard/shared/backups")
_EXPECTED_CERT_FILES = {"fullchain.pem", "key.pem"}


@dataclass(frozen=True)
class Snapshot:
    path: Path
    data: bytes
    metadata: os.stat_result


def checked(command: list[str]) -> bytes:
    try:
        result = subprocess.run(command, capture_output=True, timeout=20)
    except Exception:
        raise RuntimeError("Command failed: " + command[0]) from None
    if result.returncode:
        # Never emit config, private material or command diagnostics.
        raise RuntimeError("Command failed: " + command[0])
    return result.stdout


def verified_tls(server_name: str = DOMAIN) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection(("127.0.0.1", 9443), timeout=8) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as secure:
            return {
                "tls_verified": True,
                "alpn": secure.selected_alpn_protocol(),
                "not_after": secure.getpeercert()["notAfter"],
            }


def _lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_mode,
        getattr(metadata, "st_uid", -1),
        getattr(metadata, "st_gid", -1),
    )


def _read_snapshot(path: Path, label: str) -> Snapshot:
    try:
        before = _lstat(path)
    except OSError:
        raise RuntimeError(f"Missing {label}") from None
    if stat_is_symlink(before.st_mode):
        raise RuntimeError(f"Symlink is not allowed: {label}")
    if not stat_is_regular(before.st_mode):
        raise RuntimeError(f"Expected a regular file: {label}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise RuntimeError(f"Unable to read {label}") from None
    try:
        opened = os.fstat(descriptor)
        if not stat_is_regular(opened.st_mode) or _fingerprint(opened) != _fingerprint(before):
            raise RuntimeError(f"File changed during validation: {label}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read()
    finally:
        os.close(descriptor)
    return Snapshot(path, data, opened)


def _assert_snapshot_unchanged(snapshot: Snapshot, label: str) -> None:
    current = _read_snapshot(snapshot.path, label)
    if current.data != snapshot.data or _fingerprint(current.metadata) != _fingerprint(
        snapshot.metadata
    ):
        raise RuntimeError(f"File changed during synchronization: {label}")


def stat_is_symlink(mode: int) -> bool:
    return stat.S_ISLNK(mode)


def stat_is_regular(mode: int) -> bool:
    return stat.S_ISREG(mode)


def stat_is_directory(mode: int) -> bool:
    return stat.S_ISDIR(mode)


def _validate_certificate_directory() -> tuple[bool, dict[str, Snapshot]]:
    if not os.path.lexists(CERT_DIR):
        return False, {}
    try:
        directory_metadata = _lstat(CERT_DIR)
    except OSError:
        raise RuntimeError("Unable to inspect trial certificate directory") from None
    if stat_is_symlink(directory_metadata.st_mode):
        raise RuntimeError("Trial certificate directory must not be a symlink")
    if not stat_is_directory(directory_metadata.st_mode):
        raise RuntimeError("Trial certificate path must be a directory")
    try:
        children = list(CERT_DIR.iterdir())
    except OSError:
        raise RuntimeError("Unable to inspect trial certificate directory") from None
    if {child.name for child in children} != _EXPECTED_CERT_FILES:
        raise RuntimeError("Unexpected entries in trial certificate directory")
    snapshots = {
        name: _read_snapshot(CERT_DIR / name, "trial certificate file")
        for name in sorted(_EXPECTED_CERT_FILES)
    }
    return True, snapshots


def _nobody_gid() -> int:
    if pwd is None:
        raise RuntimeError("The nobody group is available only on the Linux deployment host")
    try:
        return pwd.getpwnam("nobody").pw_gid
    except KeyError:
        raise RuntimeError("The nobody group is not available") from None


def _certificate_metadata_matches(snapshot: Snapshot, nobody_gid: int) -> bool:
    return (
        getattr(snapshot.metadata, "st_uid", -1) == 0
        and getattr(snapshot.metadata, "st_gid", -1) == nobody_gid
        and stat.S_IMODE(snapshot.metadata.st_mode) == 0o640
    )


def _validate_source(source_cert: Path, source_key: Path) -> tuple[Snapshot, Snapshot]:
    cert = _read_snapshot(source_cert, "Caddy certificate")
    key = _read_snapshot(source_key, "Caddy private key")
    checked(["openssl", "x509", "-in", str(source_cert), "-noout", "-checkend", "604800"])
    checked(["openssl", "x509", "-in", str(source_cert), "-noout", "-checkhost", DOMAIN])
    cert_public = checked(["openssl", "x509", "-in", str(source_cert), "-pubkey", "-noout"])
    key_public = checked(["openssl", "pkey", "-in", str(source_key), "-pubout"])
    if cert_public != key_public:
        raise RuntimeError("Certificate and private key do not match")
    _assert_snapshot_unchanged(cert, "Caddy certificate")
    _assert_snapshot_unchanged(key, "Caddy private key")
    return cert, key


def _build_config(original: Snapshot) -> tuple[dict[str, Any], bytes, bool]:
    try:
        conf = json.loads(original.data)
        inbounds = conf["inbounds"]
    except (json.JSONDecodeError, KeyError, TypeError):
        raise RuntimeError("Invalid Xray configuration") from None
    candidates: list[tuple[int, dict[str, Any]]] = []
    for index, inbound in enumerate(inbounds):
        stream = inbound.get("streamSettings", {}) if isinstance(inbound, dict) else {}
        if (
            inbound.get("port") == 9443
            and inbound.get("protocol") == "vless"
            and isinstance(stream, dict)
            and stream.get("network") == "xhttp"
            and stream.get("security") == "tls"
        ):
            candidates.append((index, inbound))
    if len(candidates) != 1:
        raise RuntimeError("Expected exactly one existing XHTTP/TLS trial")

    index, _incoming = candidates[0]
    updated = copy.deepcopy(conf)
    trial = updated["inbounds"][index]
    try:
        tls = trial["streamSettings"]["tlsSettings"]
    except (KeyError, TypeError):
        raise RuntimeError("Invalid XHTTP/TLS trial configuration") from None
    if not isinstance(tls, dict):
        raise RuntimeError("Invalid XHTTP/TLS trial configuration")
    tls["serverName"] = DOMAIN
    tls["certificates"] = [
        {
            "certificateFile": str(CERT_DIR / "fullchain.pem"),
            "keyFile": str(CERT_DIR / "key.pem"),
            "oneTimeLoading": False,
        }
    ]

    before_other = copy.deepcopy(conf)
    after_other = copy.deepcopy(updated)
    for candidate in (before_other, after_other):
        candidate["inbounds"][index]["streamSettings"].pop("tlsSettings", None)
    if before_other != after_other:
        raise RuntimeError("Unexpected change outside the trial TLS settings")
    serialized = (json.dumps(updated, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return updated, serialized, conf != updated


def _running_as_root() -> bool:
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0


def _private_root_directory(path: Path) -> bool:
    try:
        metadata = _lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and getattr(metadata, "st_uid", -1) == 0
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _restore_times(path: Path, metadata: os.stat_result) -> None:
    times = (metadata.st_atime_ns, metadata.st_mtime_ns)
    try:
        os.utime(path, ns=times, follow_symlinks=False)
    except NotImplementedError:
        os.utime(path, ns=times)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix" or not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_private_backup_snapshot(snapshot: Snapshot, destination: Path) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        _write_all(descriptor, snapshot.data)
        if hasattr(os, "fchown"):
            os.fchown(
                descriptor,
                getattr(snapshot.metadata, "st_uid", -1),
                getattr(snapshot.metadata, "st_gid", -1),
            )
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IMODE(snapshot.metadata.st_mode))
        else:
            os.chmod(destination, stat.S_IMODE(snapshot.metadata.st_mode))
        _restore_times(destination, snapshot.metadata)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_backup(snapshots: dict[str, Snapshot]) -> Path:
    if not _running_as_root():
        raise RuntimeError("Applying requires root")
    if os.path.lexists(BACKUPS) and stat_is_symlink(_lstat(BACKUPS).st_mode):
        raise RuntimeError("Backup parent must not be a symlink")
    try:
        BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        raise RuntimeError("Unable to create backup parent") from None
    if stat_is_symlink(_lstat(BACKUPS).st_mode) or not stat_is_directory(_lstat(BACKUPS).st_mode):
        raise RuntimeError("Backup parent must be a directory")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup = BACKUPS / ("xhttp-tls-" + stamp)
    try:
        backup.mkdir(mode=0o700, parents=False, exist_ok=False)
        os.chmod(backup, 0o700)
    except OSError:
        raise RuntimeError("Unable to create a new private backup directory") from None
    if not _private_root_directory(backup):
        raise RuntimeError("Backup directory is not root-owned with mode 700")

    for name, snapshot in snapshots.items():
        _write_private_backup_snapshot(snapshot, backup / name)
    _fsync_directory(backup)
    return backup


def _stage_bytes(
    directory: Path,
    prefix: str,
    data: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
    times: tuple[int, int] | None = None,
    suffix: str = "",
) -> Path:
    descriptor, raw_temp = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
    temporary = Path(raw_temp)
    try:
        _write_all(descriptor, data)
        if hasattr(os, "fchown"):
            os.fchown(descriptor, uid, gid)
        elif os.name == "posix":
            raise OSError("Cannot preserve required ownership")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        else:
            os.chmod(temporary, mode)
        if times is not None:
            try:
                os.utime(temporary, ns=times, follow_symlinks=False)
            except NotImplementedError:
                os.utime(temporary, ns=times)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    os.close(descriptor)
    return temporary


def _atomic_replace_snapshot(snapshot: Snapshot) -> None:
    path = snapshot.path
    try:
        current = _lstat(path)
        if stat_is_symlink(current.st_mode):
            raise RuntimeError("Refusing symlink while restoring previous files")
    except FileNotFoundError:
        pass
    temporary = _stage_bytes(
        path.parent,
        "." + path.name + ".restore-",
        snapshot.data,
        uid=getattr(snapshot.metadata, "st_uid", 0),
        gid=getattr(snapshot.metadata, "st_gid", 0),
        mode=stat.S_IMODE(snapshot.metadata.st_mode),
        times=(snapshot.metadata.st_atime_ns, snapshot.metadata.st_mtime_ns),
    )
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _rollback(
    *,
    config: Snapshot,
    old_certificate_dir_existed: bool,
    old_certificates: dict[str, Snapshot],
    cert_mutated: bool,
    config_mutated: bool,
    previous_domain: str,
) -> bool:
    errors: list[Exception] = []
    if cert_mutated:
        try:
            if old_certificate_dir_existed:
                try:
                    directory_metadata = _lstat(CERT_DIR)
                except OSError:
                    raise RuntimeError("Cannot restore missing certificate directory") from None
                if stat_is_symlink(directory_metadata.st_mode) or not stat_is_directory(
                    directory_metadata.st_mode
                ):
                    raise RuntimeError("Cannot restore unsafe certificate directory")
                child_names = {child.name for child in CERT_DIR.iterdir()}
                if not child_names.issubset(_EXPECTED_CERT_FILES):
                    raise RuntimeError("Unexpected files prevent certificate rollback")
                for name in sorted(_EXPECTED_CERT_FILES):
                    _atomic_replace_snapshot(old_certificates[name])
            elif os.path.lexists(CERT_DIR):
                directory_metadata = _lstat(CERT_DIR)
                if stat_is_symlink(directory_metadata.st_mode) or not stat_is_directory(
                    directory_metadata.st_mode
                ):
                    raise RuntimeError("Cannot remove unsafe new certificate directory")
                for name in sorted(_EXPECTED_CERT_FILES):
                    path = CERT_DIR / name
                    if os.path.lexists(path):
                        metadata = _lstat(path)
                        if stat_is_symlink(metadata.st_mode) or not stat_is_regular(metadata.st_mode):
                            raise RuntimeError("Cannot remove unexpected certificate entry")
                        path.unlink()
                CERT_DIR.rmdir()
                _fsync_directory(CERT_DIR.parent)
        except Exception as exc:
            errors.append(exc)

    if config_mutated or cert_mutated:
        try:
            _atomic_replace_snapshot(config)
        except Exception as exc:
            errors.append(exc)

    try:
        checked(["systemctl", "restart", "xray"])
        checked(["systemctl", "is-active", "--quiet", "xray"])
        _verify_after_restart(previous_domain)
    except Exception as exc:
        errors.append(exc)
    return not errors


def _verify_after_restart(server_name: str = DOMAIN) -> dict[str, Any]:
    for attempt in range(10):
        try:
            return verified_tls(server_name=server_name)
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
            if attempt == 9:
                raise
            time.sleep(0.3)
    raise RuntimeError("Local TLS verification failed")


def _configured_trial_domain(snapshot: Snapshot) -> str:
    try:
        conf = json.loads(snapshot.data)
        for inbound in conf["inbounds"]:
            stream = inbound.get("streamSettings", {})
            tls = stream.get("tlsSettings", {}) if isinstance(stream, dict) else {}
            if (
                inbound.get("port") == 9443
                and inbound.get("protocol") == "vless"
                and stream.get("network") == "xhttp"
                and isinstance(tls, dict)
                and isinstance(tls.get("serverName"), str)
            ):
                return tls["serverName"]
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
        pass
    return DOMAIN


def _sync(apply: bool) -> tuple[int, dict[str, Any]]:
    original_config = _read_snapshot(CONFIG, "Xray configuration")
    original_conf, updated_bytes, config_changed = _build_config(original_config)
    source_cert = SOURCE / (DOMAIN + ".crt")
    source_key = SOURCE / (DOMAIN + ".key")
    cert, key = _validate_source(source_cert, source_key)
    certificate_dir_existed, old_certificates = _validate_certificate_directory()
    nobody_gid = _nobody_gid()

    certificates_changed = not certificate_dir_existed
    if certificate_dir_existed:
        certificates_changed = any(
            old_certificates[name].data != source.data
            or not _certificate_metadata_matches(old_certificates[name], nobody_gid)
            for name, source in (("fullchain.pem", cert), ("key.pem", key))
        )
    changed = certificates_changed or config_changed

    if not changed:
        if apply:
            try:
                tls = verified_tls()
            except Exception:
                return 1, {
                    "applied": False,
                    "changed": False,
                    "error": "local TLS verification failed",
                }
            return 0, {
                "applied": False,
                "changed": False,
                "trial_port": 9443,
                "domain": DOMAIN,
                **tls,
            }
        return 0, {
            "ready": True,
            "changed": False,
            "trial_port": 9443,
            "domain": DOMAIN,
        }

    if not apply:
        return 0, {
            "ready": True,
            "changed": True,
            "certificates_changed": certificates_changed,
            "config_changed": config_changed,
            "trial_port": 9443,
            "domain": DOMAIN,
        }

    snapshots = {"config.json": original_config}
    if certificates_changed:
        snapshots.update({name: old_certificates[name] for name in sorted(old_certificates)})
    backup = _create_backup(snapshots)

    cert_mutated = False
    config_mutated = False
    staged_certificates: list[Path] = []
    staged_config: Path | None = None
    try:
        for snapshot in (original_config, cert, key, *old_certificates.values()):
            _assert_snapshot_unchanged(snapshot, "synchronization input")
        if not certificate_dir_existed:
            CERT_DIR.mkdir(mode=0o750, parents=False, exist_ok=False)
            cert_mutated = True
            os.chown(CERT_DIR, 0, nobody_gid)
            os.chmod(CERT_DIR, 0o750)
            _fsync_directory(CERT_DIR.parent)

        if certificates_changed:
            for name, source in (("fullchain.pem", cert), ("key.pem", key)):
                staged_certificates.append(
                    _stage_bytes(
                        CERT_DIR,
                        "." + name + ".sync-",
                        source.data,
                        uid=0,
                        gid=nobody_gid,
                        mode=0o640,
                        times=(source.metadata.st_atime_ns, source.metadata.st_mtime_ns),
                    )
                )
            for snapshot in (cert, key, *old_certificates.values()):
                _assert_snapshot_unchanged(snapshot, "certificate synchronization input")
            for temporary, name in zip(staged_certificates, ("fullchain.pem", "key.pem")):
                os.replace(temporary, CERT_DIR / name)
                cert_mutated = True
                _fsync_directory(CERT_DIR)

        staged_config = _stage_bytes(
            CONFIG.parent,
            ".config.json.xhttp-stage-",
            updated_bytes,
            uid=getattr(original_config.metadata, "st_uid", 0),
            gid=getattr(original_config.metadata, "st_gid", 0),
            mode=stat.S_IMODE(original_config.metadata.st_mode),
            times=(original_config.metadata.st_atime_ns, original_config.metadata.st_mtime_ns),
            suffix=".json",
        )
        checked(["/usr/local/bin/xray", "run", "-test", "-config", str(staged_config)])
        if config_changed:
            _assert_snapshot_unchanged(original_config, "Xray configuration")
            os.replace(staged_config, CONFIG)
            staged_config = None
            config_mutated = True
            _fsync_directory(CONFIG.parent)

        checked(["systemctl", "restart", "xray"])
        checked(["systemctl", "is-active", "--quiet", "xray"])
        tls = _verify_after_restart()
        return 0, {
            "applied": True,
            "changed": True,
            "certificates_changed": certificates_changed,
            "config_changed": config_changed,
            "backup": str(backup),
            "trial_port": 9443,
            "domain": DOMAIN,
            **tls,
        }
    except Exception:
        stage_cleanup_failed = False
        for temporary in staged_certificates:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                stage_cleanup_failed = True
        if staged_config is not None:
            try:
                staged_config.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                stage_cleanup_failed = True
        rolled_back = False
        if cert_mutated or config_mutated:
            rolled_back = _rollback(
                config=original_config,
                old_certificate_dir_existed=certificate_dir_existed,
                old_certificates=old_certificates,
                cert_mutated=cert_mutated,
                config_mutated=config_mutated,
                previous_domain=_configured_trial_domain(original_config),
            ) and not stage_cleanup_failed
        status: dict[str, Any] = {
            "applied": False,
            "changed": True,
            "error": "certificate synchronization failed",
            "backup": str(backup),
        }
        if cert_mutated or config_mutated:
            status["rolled_back"] = rolled_back
        return 1, status
    finally:
        for temporary in staged_certificates:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        if staged_config is not None:
            try:
                staged_config.unlink()
            except FileNotFoundError:
                pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        status, result = _sync(args.apply)
    except Exception:
        # No command diagnostics, config, or private key bytes reach stdout or
        # systemd's journal.
        print(json.dumps({"applied": False, "error": "certificate preflight failed"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
