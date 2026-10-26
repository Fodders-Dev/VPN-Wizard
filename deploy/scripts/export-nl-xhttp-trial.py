"""Export the existing owner's XHTTP trial privately, without creating server users."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import socket
from urllib.parse import urlencode, quote

import paramiko


def client() -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    return ssh


def rodnya_ssh_target(
    config_path: Path | None = None,
) -> tuple[str, str, str, int, list[str]]:
    """Return the current NL IP and pinned SSH identity from the launcher's alias."""
    path = config_path or (Path.home() / ".ssh" / "config")
    config = paramiko.SSHConfig()
    with path.open(encoding="utf-8") as handle:
        config.parse(handle)
    entry = config.lookup("rodnya")
    raw_host = entry.get("hostname", "")
    try:
        host = str(ipaddress.IPv4Address(raw_host))
    except ipaddress.AddressValueError:
        raise RuntimeError("SSH alias rodnya must define the current NL IPv4 HostName") from None

    host_key_alias = str(entry.get("hostkeyalias", "")).strip()
    if (
        not host_key_alias
        or len(host_key_alias) > 253
        or any(char.isspace() or char in "/\\" for char in host_key_alias)
    ):
        raise RuntimeError("SSH alias rodnya must define a pinned HostKeyAlias")
    username = str(entry.get("user") or "root").strip()
    if not username or any(char.isspace() for char in username):
        raise RuntimeError("SSH alias rodnya has an invalid user")
    raw_port = str(entry.get("port") or "22")
    if not re.fullmatch(r"[0-9]{1,5}", raw_port) or not 1 <= int(raw_port) <= 65535:
        raise RuntimeError("SSH alias rodnya has an invalid port")
    identities = entry.get("identityfile") or [
        str(Path.home() / ".ssh" / "radiopp_github_deploy")
    ]
    if isinstance(identities, str):
        identities = [identities]
    identity_files = [str(Path(item).expanduser()) for item in identities]
    return host, host_key_alias, username, int(raw_port), identity_files


def vpn_us_ssh_target(
    config_path: Path | None = None,
) -> tuple[str, str, str, int, list[str]]:
    """Return the US gateway destination and pinned identity from its SSH alias."""
    path = config_path or (Path.home() / ".ssh" / "config")
    config = paramiko.SSHConfig()
    with path.open(encoding="utf-8") as handle:
        config.parse(handle)
    entry = config.lookup("vpn-us")
    host = str(entry.get("hostname", "")).strip()
    if (
        not host
        or host.casefold() == "vpn-us"
        or len(host) > 253
        or any(char.isspace() or char in "/\\" for char in host)
    ):
        raise RuntimeError("SSH alias vpn-us must define a valid HostName")
    try:
        address = ipaddress.ip_address(host)
        if address.is_loopback or address.is_unspecified:
            raise RuntimeError("SSH alias vpn-us must define a public HostName")
    except ValueError:
        labels = host.removesuffix(".").split(".")
        label_pattern = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        if (
            not labels
            or labels[-1].casefold() == "localhost"
            or any(not re.fullmatch(label_pattern, item) for item in labels)
        ):
            raise RuntimeError("SSH alias vpn-us must define a valid HostName") from None

    host_key_alias = str(entry.get("hostkeyalias", "")).strip()
    if (
        not host_key_alias
        or len(host_key_alias) > 253
        or any(char.isspace() or char in "/\\" for char in host_key_alias)
    ):
        raise RuntimeError("SSH alias vpn-us must define a pinned HostKeyAlias")
    username = str(entry.get("user", "")).strip()
    if not username or any(char.isspace() for char in username):
        raise RuntimeError("SSH alias vpn-us must define a valid User")
    raw_port = str(entry.get("port") or "22")
    if not re.fullmatch(r"[0-9]{1,5}", raw_port) or not 1 <= int(raw_port) <= 65535:
        raise RuntimeError("SSH alias vpn-us has an invalid port")
    identities = entry.get("identityfile")
    if not identities:
        raise RuntimeError("SSH alias vpn-us must define an IdentityFile")
    if isinstance(identities, str):
        identities = [identities]
    identity_files = [str(Path(item).expanduser()) for item in identities]
    if any(not item for item in identity_files):
        raise RuntimeError("SSH alias vpn-us must define a valid IdentityFile")
    return host, host_key_alias, username, int(raw_port), identity_files


def nip_domain_for_ip(host: str) -> str:
    address = ipaddress.IPv4Address(host)
    return str(address).replace(".", "-") + ".nip.io"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve(strict=True)
    if not output.is_dir():
        raise RuntimeError("Output must be an existing private directory")
    gateway_host, gateway_host_key_alias, gateway_user, gateway_port, gateway_keys = vpn_us_ssh_target()
    nl_host, host_key_alias, nl_user, nl_port, nl_keys = rodnya_ssh_target()
    expected_domain = nip_domain_for_ip(nl_host)
    gateway, server = client(), client()
    gateway_socket = None
    try:
        gateway_socket = socket.create_connection((gateway_host, gateway_port), timeout=10)
        gateway.connect(
            gateway_host_key_alias,
            username=gateway_user,
            port=gateway_port,
            key_filename=gateway_keys,
            look_for_keys=False,
            allow_agent=False,
            sock=gateway_socket,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
        channel = gateway.get_transport().open_channel(
            "direct-tcpip", (nl_host, nl_port), ("127.0.0.1", 0), timeout=10)
        server.connect(
            host_key_alias,
            username=nl_user,
            port=nl_port,
            key_filename=nl_keys,
            look_for_keys=False,
            allow_agent=False,
            sock=channel,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
        with server.open_sftp() as sftp:
            with sftp.open("/usr/local/etc/xray/config.json", "r") as handle:
                conf = json.loads(handle.read())
    finally:
        server.close()
        gateway.close()
        if gateway_socket is not None:
            gateway_socket.close()
    trials = [b for b in conf["inbounds"] if b.get("port") == 9443
              and b.get("protocol") == "vless"
              and b.get("streamSettings", {}).get("network") == "xhttp"]
    if len(trials) != 1 or len(trials[0]["settings"].get("clients", [])) != 1:
        raise RuntimeError("Expected one existing private XHTTP trial client")
    trial = trials[0]
    stream = trial["streamSettings"]
    domain = stream["tlsSettings"]["serverName"]
    if domain != expected_domain or stream.get("security") != "tls":
        raise RuntimeError("Trial TLS certificate refresh is required first")
    uid = trial["settings"]["clients"][0]["id"]
    path = stream["xhttpSettings"]["path"]
    params = dict(encryption="none", security="tls", type="xhttp", sni=domain,
                  fp="firefox", alpn="h2", host=domain, path=path, mode="packet-up")
    link = (
        "vless://" + uid + "@" + nl_host + ":9443?" + urlencode(params)
        + "#" + quote("FVPN-NL-XHTTP-test")
    )
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "local-test", "listen": "127.0.0.1", "port": 10885,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"tag": "FVPN-NL-XHTTP-test", "protocol": "vless",
                       "settings": {"vnext": [{"address": nl_host, "port": 9443,
                                               "users": [{"id": uid, "encryption": "none"}]}]},
                       "streamSettings": {"network": "xhttp", "security": "tls",
                                          "tlsSettings": {"serverName": domain, "fingerprint": "firefox", "alpn": ["h2"]},
                                          "xhttpSettings": {"path": path, "host": domain, "mode": "packet-up"}}}]
    }
    # Artifacts contain an access credential: print only paths and safe metadata.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    stem = output / ("FVPN-NL-XHTTP-" + stamp)
    artifacts = []
    for suffix, contents in ((".txt", link + "\n"), (".json", json.dumps(config, indent=2) + "\n")):
        dest = stem.with_suffix(suffix)
        with dest.open("x", encoding="utf-8") as handle:
            handle.write(contents)
        artifacts.append(str(dest))
    print(json.dumps({"exported": artifacts, "server_users_unchanged": True,
                      "transport": "VLESS/XHTTP/TLS", "port": 9443,
                      "certificate_verification": True}))


if __name__ == "__main__":
    main()
