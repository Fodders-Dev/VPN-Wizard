"""Update FI registry endpoints after verifying exit identity/listeners over SSH."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil


def migrate(text: str, port: int | None = None) -> str:
    if port is not None and port not in (443, 3478):
        raise ValueError("Expected FI public port 443 or 3478")
    lines = text.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines)
               if line.partition("=")[0].strip() == "VPNW_AWG_SERVERS"]
    if len(matches) != 1:
        raise ValueError("Expected one registry")
    index = matches[0]
    raw = lines[index].partition("=")[2].strip().strip("'\"")
    try:
        nodes = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("Invalid registry") from None
    if not isinstance(nodes, list) or not all(isinstance(n, dict) for n in nodes):
        raise ValueError("Invalid registry list")
    fi = [n for n in nodes if n.get("id") in {"fi", "fi-alt"}]
    if {n.get("id") for n in fi} != {"fi", "fi-alt"} or len(fi) != 2:
        raise ValueError("Expected unique fi and fi-alt")
    for node in fi:
        expected = "awg9" if node["id"] == "fi" else "awg8"
        if node.get("host") not in {"193.222.97.50", "46.38.156.229"}:
            raise ValueError("Unexpected FI host; inspect before migrating")
        if node.get("interface") != expected:
            raise ValueError("Unexpected FI interface; keys must not be remapped")
        node["host"] = "46.38.156.229"
        if node["id"] == "fi" and port is not None:
            node["listen_port"] = port
    updated = "VPNW_AWG_SERVERS='" + json.dumps(nodes, separators=(",", ":"), ensure_ascii=True) + "'\n"
    # Preserve byte-identical environment on a repeated migration.
    original_nodes = json.loads(raw)
    if nodes == original_nodes:
        return text
    lines[index] = updated
    return "".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path("/etc/vpn-wizard.env"))
    parser.add_argument("--port", type=int)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    source = args.env.resolve(strict=True)
    original = source.read_text(encoding="utf-8")
    updated = migrate(original, args.port)
    if args.apply and updated != original:
        if not args.backup_dir:
            raise ValueError("A new private backup directory is required")
        backup = args.backup_dir.resolve()
        backup.mkdir(mode=0o700, parents=True, exist_ok=False)
        shutil.copy2(source, backup / "vpn-wizard.env")
        temporary = source.with_name(source.name + ".fi-endpoint-new")
        with temporary.open("x", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        shutil.copystat(source, temporary)
        temporary.replace(source)
    print(json.dumps({"changed": updated != original, "applied": args.apply,
                      "host": "46.38.156.229", "port": args.port,
                      "identities_preserved": True}))


if __name__ == "__main__":
    main()
