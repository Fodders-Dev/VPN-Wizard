"""Export the existing owner's XHTTP trial privately, without creating server users."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlencode, quote

import paramiko


def client() -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    return ssh


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve(strict=True)
    if not output.is_dir():
        raise RuntimeError("Output must be an existing private directory")
    key = str(Path.home() / ".ssh/radiopp_github_deploy")
    gateway, server = client(), client()
    try:
        gateway.connect("147.45.125.36", username="root", key_filename=key,
                        look_for_keys=False, allow_agent=False, timeout=10,
                        banner_timeout=10, auth_timeout=10)
        channel = gateway.get_transport().open_channel(
            "direct-tcpip", ("82.25.60.19", 22), ("127.0.0.1", 0), timeout=10)
        server.connect("82.25.60.19", username="root", key_filename=key,
                       look_for_keys=False, allow_agent=False, sock=channel,
                       timeout=10, banner_timeout=10, auth_timeout=10)
        with server.open_sftp() as sftp:
            with sftp.open("/usr/local/etc/xray/config.json", "r") as handle:
                conf = json.loads(handle.read())
    finally:
        server.close()
        gateway.close()
    trials = [b for b in conf["inbounds"] if b.get("port") == 9443
              and b.get("protocol") == "vless"
              and b.get("streamSettings", {}).get("network") == "xhttp"]
    if len(trials) != 1 or len(trials[0]["settings"].get("clients", [])) != 1:
        raise RuntimeError("Expected one existing private XHTTP trial client")
    trial = trials[0]
    stream = trial["streamSettings"]
    domain = stream["tlsSettings"]["serverName"]
    if domain != "82-25-60-19.nip.io" or stream.get("security") != "tls":
        raise RuntimeError("Trial TLS certificate refresh is required first")
    uid = trial["settings"]["clients"][0]["id"]
    path = stream["xhttpSettings"]["path"]
    params = dict(encryption="none", security="tls", type="xhttp", sni=domain,
                  fp="firefox", alpn="h2", host=domain, path=path, mode="packet-up")
    link = "vless://" + uid + "@82.25.60.19:9443?" + urlencode(params) + "#" + quote("FVPN-NL-XHTTP-test")
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "local-test", "listen": "127.0.0.1", "port": 10885,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"tag": "FVPN-NL-XHTTP-test", "protocol": "vless",
                       "settings": {"vnext": [{"address": "82.25.60.19", "port": 9443,
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
