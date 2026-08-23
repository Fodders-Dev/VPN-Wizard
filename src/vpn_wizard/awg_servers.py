"""Registry of AmneziaWG exit servers and per-operator obfuscation presets.

The AWG fallback started as a single box wired through ``VPNW_AWG_FALLBACK_*``
env vars. Users now pick an exit country, and RF mobile operators need different
obfuscation parameters, so both dimensions live here:

    server  -> WHERE the traffic exits (a VPS we provision peers on over SSH)
    preset  -> HOW the tunnel is obfuscated (client-side AWG junk/mimicry params)

A config is therefore identified by ``(server_id, preset_id)``. The server decides
which machine holds the peer keys; the preset only re-renders the client file, so
switching presets never touches the server.

Both are configured from the environment:

    VPNW_AWG_SERVERS   JSON list, e.g.
        [{"id":"nl","label":"Нидерланды","flag":"🇳🇱","host":"1.2.3.4",
          "user":"root","password":"...","listen_port":443}]
    VPNW_AWG_PRESETS   JSON list, optional; defaults to DEFAULT_PRESETS below.

If ``VPNW_AWG_SERVERS`` is absent we synthesise a one-entry registry from the
legacy ``VPNW_AWG_FALLBACK_*`` vars, so an existing deployment keeps working
untouched and its already-issued configs keep resolving to the same machine.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
from typing import Any, Optional

# Ids end up in filenames, peer bookkeeping and URLs — keep them boring.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,15}$")

LEGACY_SERVER_ID = "main"


class AwgRegistryError(ValueError):
    """Raised when the configured registry is malformed."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _opt_int(value: Any) -> Optional[int]:
    text = _clean(value)
    return int(text) if text.isdigit() else None


# An interface name goes straight into shell paths and systemd unit names, so it
# is validated as strictly as an id — a stray slash or space would let a registry
# entry write outside /etc/amnezia/amneziawg.
_IFACE_RE = re.compile(r"^[a-z][a-z0-9]{1,14}$")


def _require_iface(raw: Any) -> Optional[str]:
    value = _clean(raw).lower()
    if not value:
        return None
    if not _IFACE_RE.match(value):
        raise AwgRegistryError(
            f"Invalid interface {value!r}: use 2-15 chars of a-z and 0-9, e.g. 'awg9'."
        )
    return value


def _require_id(raw: Any, *, kind: str) -> str:
    value = _clean(raw).lower()
    if not _ID_RE.match(value):
        raise AwgRegistryError(
            f"Invalid {kind} id {value!r}: use 1-16 chars of a-z, 0-9 or '-'."
        )
    return value


# Which AWG knobs a preset may touch. Verified against the source of all three
# official implementations (amneziawg-go, amneziawg-tools, the kernel module):
#
#   S1-S4, H1-H4 live on the *device*, not the peer. The receiver identifies a
#   packet by an exact size match against its OWN padding plus a header-range
#   check, so a client that differs on any of them is dropped before any crypto
#   runs. There is no error and no log the user can see — it looks like a dead
#   server. awg-tools also refuses these keys outside [Interface], and the
#   per-peer `AdvancedSecurity` flag that once hinted otherwise is dead code in
#   AWG 2.0. Varying them needs a SEPARATE interface: own port, keypair, subnet.
#
#   Jc/Jmin/Jmax and I1-I5 are sender-side-only instructions. The receiver drops
#   those packets as unrecognized, so they may differ freely per client — this is
#   the whole reason per-operator presets are possible on one shared interface.
INTERFACE_WIDE_PARAMS = frozenset({"s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"})
PER_CLIENT_PARAMS = ("jc", "jmin", "jmax", "i1", "i2", "i3", "i4", "i5")
# awg-quick is case-sensitive about these: "JC" is not "Jc".
_PARAM_NAMES = {name: name.capitalize() for name in PER_CLIENT_PARAMS}


@dataclass(frozen=True)
class AwgPreset:
    """Per-client obfuscation parameters. ``None`` means 'keep server default'.

    Restricted by construction to parameters that are safe to vary per client;
    see INTERFACE_WIDE_PARAMS for why the rest cannot live here.
    """

    id: str
    label: str
    jc: Optional[int] = None
    jmin: Optional[int] = None
    jmax: Optional[int] = None
    # I1-I5: scripted "signature" packets (<b 0x..>, <r n>, <rd n>, <rc n>, <t>)
    # sent before the handshake to mimic QUIC/DNS/STUN. The real per-operator
    # lever, and free — the server never parses them.
    i1: Optional[str] = None
    i2: Optional[str] = None
    i3: Optional[str] = None
    i4: Optional[str] = None
    i5: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AwgPreset":
        unsafe = sorted(INTERFACE_WIDE_PARAMS.intersection(key.lower() for key in data))
        if unsafe:
            raise AwgRegistryError(
                f"Preset {data.get('id')!r} sets interface-wide parameter(s) "
                f"{', '.join(unsafe)}. These must match the server byte-for-byte; "
                "a client-side override silently fails to connect. Run a separate "
                "AWG interface on its own port instead."
            )
        return cls(
            id=_require_id(data.get("id"), kind="preset"),
            label=_clean(data.get("label")) or _clean(data.get("id")),
            jc=_opt_int(data.get("jc")),
            jmin=_opt_int(data.get("jmin")),
            jmax=_opt_int(data.get("jmax")),
            i1=_clean(data.get("i1")) or None,
            i2=_clean(data.get("i2")) or None,
            i3=_clean(data.get("i3")) or None,
            i4=_clean(data.get("i4")) or None,
            i5=_clean(data.get("i5")) or None,
        )

    @property
    def overrides(self) -> dict[str, Any]:
        """Only the parameters this preset actually pins.

        Empty values are dropped rather than emitted: ``awg-quick`` strips empty
        ``I1=``..``I5=`` lines and then fails at ``awg setconf`` (amneziawg-tools
        issue #40), so a blank key is worse than an absent one.
        """
        pairs = {key: getattr(self, key) for key in PER_CLIENT_PARAMS}
        return {key: value for key, value in pairs.items() if value not in (None, "")}


# Field-reported presets from deploy/remnawave/awg-hardening.md. "default" must
# stay first: it is what everyone gets until they tell us their network is broken.
DEFAULT_PRESETS: tuple[AwgPreset, ...] = (
    AwgPreset(id="default", label="Обычный"),
    AwgPreset(id="mts", label="МТС", jc=3, i1="<r 48>"),
    AwgPreset(id="tele2", label="Tele2", jc=3, jmin=40, jmax=70, i1="<r 48>"),
    AwgPreset(id="megafon", label="Мегафон", jc=3, jmin=80, jmax=268),
    AwgPreset(id="yota", label="Yota", jmax=261, i1="<b 0xce>"),
)


@dataclass(frozen=True)
class AwgServer:
    """One AWG exit box we can provision peers on."""

    id: str
    label: str
    flag: str
    host: str
    user: str
    port: int
    password: Optional[str]
    key_path: Optional[str]
    key_content: Optional[str]
    listen_port: Optional[int]
    # Name a dedicated AWG interface (e.g. "awg9") when the box's awg0/awg1
    # belong to somebody else — our peers then live in their own interface and
    # clients_<iface> directory, and a rebuild can never wipe the owner's peers.
    interface: Optional[str] = None
    # Ceiling on free accounts this exit may be assigned. Meant for a box that
    # is somebody's personal server: free users fill it up to the cap, then new
    # signups go elsewhere instead of eating its traffic allowance. A soft cap —
    # it never refuses a signup, it only stops preferring a full exit.
    max_free: Optional[int] = None
    # Set false to stop OFFERING an exit while keeping it fully operational, so
    # peers already issued there can still be suspended/resumed on expiry. Use it
    # when a box is unreachable (e.g. the provider blocks its UDP port) — dropping
    # the entry outright would strand those peers with permanent access.
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AwgServer":
        host = _clean(data.get("host"))
        if not host:
            raise AwgRegistryError(f"AWG server {data.get('id')!r} has no host.")
        server_id = _require_id(data.get("id"), kind="server")
        return cls(
            enabled=bool(data.get("enabled", True)),
            id=server_id,
            # Never fall back to the host: labels are served unauthenticated by
            # /api/awg/servers, so a missing label must not publish the IP.
            label=_clean(data.get("label")) or server_id,
            flag=_clean(data.get("flag")),
            host=host,
            user=_clean(data.get("user")) or "root",
            port=_opt_int(data.get("port")) or 22,
            password=_clean(data.get("password")) or None,
            key_path=_clean(data.get("key_path")) or None,
            key_content=_clean(data.get("key_content")) or None,
            listen_port=_opt_int(data.get("listen_port")),
            interface=_require_iface(data.get("interface")),
            max_free=_opt_int(data.get("max_free")),
        )

    @property
    def usable(self) -> bool:
        """SSH provisioning needs some credential."""
        return bool(self.host and (self.password or self.key_path or self.key_content))

    @property
    def display(self) -> str:
        return f"{self.flag} {self.label}".strip()

    def public(self) -> dict[str, Any]:
        """Safe to expose to the bot/website — never leaks host or credentials."""
        return {"id": self.id, "label": self.label, "flag": self.flag, "display": self.display}


def _legacy_server() -> Optional[AwgServer]:
    """One-entry registry built from the original single-server env vars."""
    host = _clean(os.getenv("VPNW_AWG_FALLBACK_HOST"))
    if not host:
        return None
    server_id = _clean(os.getenv("VPNW_AWG_FALLBACK_ID")).lower() or LEGACY_SERVER_ID
    return AwgServer(
        id=server_id,
        # Same rule as AwgServer.from_dict: an unlabelled server must not leak its IP.
        label=_clean(os.getenv("VPNW_AWG_FALLBACK_LABEL")) or server_id,
        flag=_clean(os.getenv("VPNW_AWG_FALLBACK_FLAG")),
        host=host,
        user=_clean(os.getenv("VPNW_AWG_FALLBACK_SSH_USER")) or "root",
        port=_opt_int(os.getenv("VPNW_AWG_FALLBACK_SSH_PORT")) or 22,
        password=_clean(os.getenv("VPNW_AWG_FALLBACK_SSH_PASSWORD")) or None,
        key_path=_clean(os.getenv("VPNW_AWG_FALLBACK_SSH_KEY")) or None,
        key_content=_clean(os.getenv("VPNW_AWG_FALLBACK_SSH_KEY_CONTENT")) or None,
        listen_port=_opt_int(os.getenv("VPNW_AWG_FALLBACK_LISTEN_PORT")),
    )


def _parse_json_list(raw: str, *, var: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AwgRegistryError(f"{var} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        raise AwgRegistryError(f"{var} must be a JSON list of objects.")
    return parsed


def apply_preset(config_text: str, preset: Optional[AwgPreset]) -> str:
    """Rewrite a client config for one operator's DPI.

    Only the sender-side knobs are touched — Jc/Jmin/Jmax and the I1-I5 signature
    packets. S1-S4 and H1-H4 belong to the interface and must stay byte-identical
    to the server, so they are never rewritten here: a mismatch is dropped before
    any crypto runs and the user just sees a tunnel that never connects.
    """
    if preset is None:
        return config_text
    overrides = preset.overrides
    if not overrides:
        return config_text

    lines = config_text.splitlines()
    out: list[str] = []
    seen: set[str] = set()
    in_interface = False
    insert_at = None

    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        if stripped.startswith("["):
            if in_interface and insert_at is None:
                insert_at = len(out)
            in_interface = lowered == "[interface]"
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip().lower() if "=" in stripped else ""
        if in_interface and key in overrides:
            # Replace in place so the parameter keeps its position in the file.
            out.append(f"{_PARAM_NAMES[key]} = {overrides[key]}")
            seen.add(key)
            continue
        out.append(line)

    missing = [key for key in PER_CLIENT_PARAMS if key in overrides and key not in seen]
    if missing:
        position = insert_at if insert_at is not None else len(out)
        # Never emit an empty I-key: awg-quick strips the line and then fails at
        # `awg setconf` (amneziawg-tools #40). `overrides` already drops blanks.
        addition = [f"{_PARAM_NAMES[key]} = {overrides[key]}" for key in missing]
        out[position:position] = addition

    return "\n".join(out) + ("\n" if config_text.endswith("\n") else "")


@dataclass(frozen=True)
class AwgRegistry:
    servers: tuple[AwgServer, ...]
    presets: tuple[AwgPreset, ...]
    default_server_id: Optional[str]

    @classmethod
    def from_env(cls) -> "AwgRegistry":
        raw_servers = _clean(os.getenv("VPNW_AWG_SERVERS"))
        if raw_servers:
            servers = tuple(AwgServer.from_dict(item) for item in _parse_json_list(raw_servers, var="VPNW_AWG_SERVERS"))
        else:
            legacy = _legacy_server()
            servers = (legacy,) if legacy else ()

        seen: set[str] = set()
        for server in servers:
            if server.id in seen:
                raise AwgRegistryError(f"Duplicate AWG server id {server.id!r}.")
            seen.add(server.id)

        raw_presets = _clean(os.getenv("VPNW_AWG_PRESETS"))
        if raw_presets:
            presets = tuple(AwgPreset.from_dict(item) for item in _parse_json_list(raw_presets, var="VPNW_AWG_PRESETS"))
        else:
            presets = DEFAULT_PRESETS

        requested_default = _clean(os.getenv("VPNW_AWG_DEFAULT_SERVER")).lower() or None
        return cls(servers=servers, presets=presets, default_server_id=requested_default)

    # --- lookups ----------------------------------------------------------
    @property
    def configured(self) -> bool:
        return any(server.usable for server in self.servers)

    @property
    def offerable(self) -> tuple[AwgServer, ...]:
        """Exits we are willing to hand out new configs for."""
        return tuple(s for s in self.servers if s.usable and s.enabled)

    @property
    def default_server(self) -> Optional[AwgServer]:
        """The server used when a caller does not name one.

        Old links (and the pre-multi-server bot) carry no ``server`` parameter,
        so this must stay stable: it decides where those users land. A disabled
        default would strand them on a known-dead exit, so fall through to the
        first offerable one.
        """
        if self.default_server_id:
            picked = self.get_server(self.default_server_id)
            if picked is not None and picked.enabled:
                return picked
        offerable = self.offerable
        if offerable:
            return offerable[0]
        return self.servers[0] if self.servers else None

    def get_server(self, server_id: Optional[str]) -> Optional[AwgServer]:
        if not _clean(server_id):
            return self.default_server
        wanted = _clean(server_id).lower()
        for server in self.servers:
            if server.id == wanted:
                return server
        return None

    def get_preset(self, preset_id: Optional[str]) -> Optional[AwgPreset]:
        if not _clean(preset_id):
            return self.presets[0] if self.presets else None
        wanted = _clean(preset_id).lower()
        for preset in self.presets:
            if preset.id == wanted:
                return preset
        return None

    def public(self) -> dict[str, Any]:
        """Payload for the bot/website server picker.

        Only offerable exits: a disabled one stays in the registry so its existing
        peers keep being suspended/resumed, but must never be presented as a choice.
        """
        default = self.default_server
        return {
            "servers": [server.public() for server in self.offerable],
            "presets": [{"id": preset.id, "label": preset.label} for preset in self.presets],
            "default_server": default.id if default else None,
            "default_preset": self.presets[0].id if self.presets else None,
        }
