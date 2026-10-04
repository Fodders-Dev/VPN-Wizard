"""Promote the existing NL 3478 exit without remapping peer identities/ports."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil


def promote(text: str) -> str:
    lines = text.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines)
               if line.partition("=")[0].strip() == "VPNW_AWG_SERVERS"]
    if len(matches) != 1:
        raise ValueError("Expected one VPNW_AWG_SERVERS entry")
    index = matches[0]
    raw = lines[index].partition("=")[2].strip()
    if raw[:1] in ("'", '"') and raw[-1:] == raw[:1]:
        raw = raw[1:-1]
    try:
        nodes = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("Invalid server registry JSON") from None
    if not isinstance(nodes, list) or not all(isinstance(n, dict) for n in nodes):
        raise ValueError("Expected a server registry list")
    legacy = next((n for n in nodes if n.get("id") == "nl"), None)
    primary = next((n for n in nodes if n.get("id") == "nl-alt"), None)
    if not legacy or not primary or sum(n.get("id") in {"nl", "nl-alt"} for n in nodes) != 2:
        raise ValueError("Expected existing nl and nl-alt entries")
    if (legacy.get("host") != primary.get("host")
            or legacy.get("listen_port") != 443 or primary.get("listen_port") != 3478
            or legacy.get("enabled") is False or primary.get("enabled") is False):
        raise ValueError("Expected enabled NL exits on the same host, ports 443 and 3478")
    primary["alt_port"] = False
    primary.pop("alt_of", None)
    legacy["alt_port"] = True
    legacy["alt_of"] = "nl-alt"
    # Explicit legacy default and IDs stay untouched: they select encrypted rows.
    nodes = [primary] + [n for n in nodes if n is not primary]
    encoded = json.dumps(nodes, ensure_ascii=True, separators=(",", ":"))
    lines[index] = "VPNW_AWG_SERVERS='" + encoded + "'\n"
    return "".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path("/etc/vpn-wizard.env"))
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    source = args.env.resolve(strict=True)
    original = source.read_text(encoding="utf-8")
    updated = promote(original)
    if args.apply and updated != original:
        if not args.backup_dir:
            raise ValueError("--backup-dir is required to apply")
        backup_dir = args.backup_dir.resolve()
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        shutil.copy2(source, backup_dir / "vpn-wizard.env")
        temporary = source.with_name(source.name + ".nl-3478-new")
        with temporary.open("x", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        shutil.copystat(source, temporary)
        temporary.replace(source)
    print(json.dumps({"applied": args.apply, "changed": updated != original,
                      "primary": "nl-alt", "port": 3478,
                      "legacy_default_unchanged": True}))


if __name__ == "__main__":
    main()
