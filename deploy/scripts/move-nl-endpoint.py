"""Replace the retired NL public endpoint in an explicitly selected file set.

Dry-run is the default. Client directories contribute only direct ``*.conf``
and ``*.conf.suspended`` files. Applying requires root and a new private
backup directory. Backups mirror each source's absolute path below that
directory and retain its bytes, owner, mode, and timestamps.

This tool does not roll changes back automatically. To restore manually on
Linux, copy each saved file from BACKUP_DIR/<path-below-filesystem-root> back
to its original absolute path with ``cp -a``.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Iterable, Sequence


_OLD_IP = re.compile(rb"(?<![A-Za-z0-9_.-])77\.67\.89\.164(?![A-Za-z0-9_.-])")
_OLD_DOMAIN = re.compile(
    rb"(?<![A-Za-z0-9_-])77-67-89-164\.nip\.io(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_NEW_IP = b"82.25.60.19"
_NEW_DOMAIN = b"82-25-60-19.nip.io"


@dataclass(frozen=True)
class FilePlan:
    path: Path
    original: bytes
    updated: bytes
    metadata: os.stat_result
    client_profile: bool

    @property
    def changed(self) -> bool:
        return self.original != self.updated


def replace_endpoints(data: bytes) -> bytes:
    """Return UTF-8 bytes with only complete retired endpoint tokens changed."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Selected file is not valid UTF-8") from None
    return _OLD_DOMAIN.sub(_NEW_DOMAIN, _OLD_IP.sub(_NEW_IP, data))


def _absolute(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return Path(os.path.abspath(os.fspath(candidate)))


def _lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _reject_symlink_components(path: str | Path) -> Path:
    """Normalize a path and reject symlinks in it or any parent component."""
    absolute = _absolute(path)
    current = Path(absolute.anchor)
    for component in absolute.parts[len(Path(absolute.anchor).parts):]:
        current = current / component
        try:
            metadata = _lstat(current)
        except FileNotFoundError:
            raise ValueError(f"Path does not exist: {absolute}") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"Symlink paths are not allowed: {absolute}")
    return absolute


def _read_regular_file(path: Path) -> tuple[bytes, os.stat_result]:
    before = _lstat(path)
    if stat.S_ISLNK(before.st_mode):
        raise ValueError(f"Symlink files are not allowed: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"Selected path is not a regular file: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _fingerprint(opened) != _fingerprint(before):
            raise ValueError(f"File changed while it was being validated: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read()
    finally:
        os.close(descriptor)
    return data, opened


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


def plan_files(files: Iterable[str | Path], client_dirs: Iterable[str | Path]) -> list[FilePlan]:
    """Validate and plan every explicitly selected file before any writes."""
    selected: dict[str, tuple[Path, bool]] = {}

    def add(candidate: str | Path, *, client_profile: bool) -> None:
        path = _reject_symlink_components(candidate)
        key = os.path.normcase(os.fspath(path))
        previous = selected.get(key)
        selected[key] = (path, client_profile or (previous[1] if previous else False))

    for path in files:
        add(path, client_profile=False)

    for directory_arg in client_dirs:
        directory = _reject_symlink_components(directory_arg)
        directory_metadata = _lstat(directory)
        if not stat.S_ISDIR(directory_metadata.st_mode):
            raise ValueError(f"Client directory is not a directory: {directory}")
        for pattern in ("*.conf", "*.conf.suspended"):
            for candidate in sorted(directory.glob(pattern), key=lambda item: os.fspath(item)):
                if candidate.parent != directory:
                    raise ValueError(f"Client profile escaped its directory: {candidate}")
                add(candidate, client_profile=True)

    plans: list[FilePlan] = []
    for _, (path, client_profile) in sorted(selected.items()):
        # Client-directory entries are direct children by construction. Resolve
        # no paths and never follow a selected symlink while reading contents.
        data, metadata = _read_regular_file(path)
        updated = replace_endpoints(data)
        plans.append(FilePlan(path, data, updated, metadata, client_profile))
    return plans


def _running_as_root() -> bool:
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0


def _root_private_directory(path: Path) -> bool:
    try:
        metadata = _lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and getattr(metadata, "st_uid", -1) == 0
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _validate_backup_target(backup_dir: str | Path | None) -> Path:
    if backup_dir is None:
        raise ValueError("--backup-dir is required when applying changed files")
    backup = Path(backup_dir)
    if not backup.is_absolute():
        raise ValueError("--backup-dir must be an absolute path")
    backup = Path(os.path.abspath(os.fspath(backup)))
    if os.path.lexists(backup):
        raise ValueError("--backup-dir must name a new, non-existing directory")
    parent = _reject_symlink_components(backup.parent)
    if not stat.S_ISDIR(_lstat(parent).st_mode):
        raise ValueError("--backup-dir parent must already be a directory")
    if not _running_as_root():
        raise ValueError("Applying requires root so backups can be root-owned")
    return backup


def _backup_relative_path(path: Path) -> Path:
    """Map an absolute source path beneath the backup root without losing roots."""
    absolute = _absolute(path)
    if os.name == "nt":
        drive = absolute.drive
        if drive.startswith("\\\\"):
            prefix = ("__unc__", *[part for part in drive.strip("\\").split("\\") if part])
        else:
            prefix = (drive.rstrip(":\\/") or "__root__",)
        relative = absolute.relative_to(Path(absolute.anchor))
        return Path(*prefix, *relative.parts)
    return Path(*absolute.parts[1:])


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
        # The caller already rejected symlinks; some platforms lack this flag.
        os.utime(path, ns=times)


def _backup_file(plan: FilePlan, backup_root: Path) -> None:
    destination = backup_root / _backup_relative_path(plan.path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        _write_all(descriptor, plan.original)
        if hasattr(os, "fchown"):
            os.fchown(
                descriptor,
                getattr(plan.metadata, "st_uid", -1),
                getattr(plan.metadata, "st_gid", -1),
            )
        elif os.name == "posix":
            raise OSError("Cannot preserve backup ownership on this platform")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IMODE(plan.metadata.st_mode))
        else:
            os.chmod(destination, stat.S_IMODE(plan.metadata.st_mode))
        _restore_times(destination, plan.metadata)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(destination.parent)


def _assert_unchanged(plan: FilePlan) -> None:
    path = _reject_symlink_components(plan.path)
    current, metadata = _read_regular_file(path)
    if current != plan.original or _fingerprint(metadata) != _fingerprint(plan.metadata):
        raise ValueError(f"Selected file changed after validation: {path}")


def _stage_replacement(plan: FilePlan) -> Path:
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{plan.path.name}.nl-move-", dir=plan.path.parent)
    temporary = Path(raw_temp)
    try:
        _write_all(descriptor, plan.updated)
        if hasattr(os, "fchown"):
            os.fchown(
                descriptor,
                getattr(plan.metadata, "st_uid", -1),
                getattr(plan.metadata, "st_gid", -1),
            )
        elif os.name == "posix":
            raise OSError("Cannot preserve file ownership on this platform")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IMODE(plan.metadata.st_mode))
        else:
            os.chmod(temporary, stat.S_IMODE(plan.metadata.st_mode))
        _restore_times(temporary, plan.metadata)
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


def _fsync_directory(path: Path) -> None:
    if os.name != "posix" or not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def apply_plan(plans: Sequence[FilePlan], backup_dir: str | Path | None) -> bool:
    """Back up and atomically replace planned files; return whether any changed."""
    changes = [plan for plan in plans if plan.changed]
    if not changes:
        return False

    # Revalidate every selected input before creating the backup directory or
    # writing any files. All source data was already validated by plan_files.
    for plan in plans:
        _assert_unchanged(plan)
    backup_root = _validate_backup_target(backup_dir)
    os.mkdir(backup_root, 0o700)
    os.chmod(backup_root, 0o700)
    if not _root_private_directory(backup_root):
        raise ValueError("Created backup directory is not root-owned with mode 700")

    for plan in changes:
        _backup_file(plan, backup_root)

    staged: dict[Path, Path] = {}
    replaced: list[Path] = []
    try:
        for plan in changes:
            staged[plan.path] = _stage_replacement(plan)
        # Catch edits made while backups/staging were being written before any
        # original is atomically replaced.
        for plan in plans:
            _assert_unchanged(plan)
        for plan in changes:
            os.replace(staged[plan.path], plan.path)
            replaced.append(plan.path)
            _fsync_directory(plan.path.parent)
    except Exception as exc:
        for temporary in staged.values():
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        if replaced:
            raise RuntimeError(
                f"Partial apply; manually restore originals from {backup_root}"
            ) from exc
        raise
    return True


def _summary(plans: Sequence[FilePlan], *, applied: bool) -> dict[str, int | bool]:
    changes = [plan for plan in plans if plan.changed]
    return {
        "applied": applied,
        "files_scanned": len(plans),
        "files_changed": len(changes),
        "profiles_changed": sum(1 for plan in changes if plan.client_profile),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", default=[], metavar="PATH",
                        help="one explicitly allowlisted UTF-8 file; repeat as needed")
    parser.add_argument("--client-dir", action="append", default=[], metavar="DIR",
                        help="one client directory; only direct *.conf and *.conf.suspended files are selected")
    parser.add_argument("--apply", action="store_true", help="apply changes; dry-run is the default")
    parser.add_argument("--backup-dir", type=Path,
                        help="new absolute root-owned mode-700 directory required with --apply")
    args = parser.parse_args(argv)
    if not args.file and not args.client_dir:
        parser.error("provide at least one --file or --client-dir allowlist entry")

    try:
        plans = plan_files(args.file, args.client_dir)
        changed = any(plan.changed for plan in plans)
        applied = apply_plan(plans, args.backup_dir) if args.apply and changed else False
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        print(f"move-nl-endpoint: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(_summary(plans, applied=applied), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
