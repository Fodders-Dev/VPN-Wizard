from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer

from vpn_wizard.core import SSHConfig, SSHRunner, WireGuardProvisioner
from vpn_wizard.qr import save_qr_png

app = typer.Typer(add_completion=False)
client_app = typer.Typer(add_completion=False)
app.add_typer(client_app, name="client")


def _build_provisioner(
    host: str,
    user: str,
    password: Optional[str],
    key: Optional[str],
    port: int,
    client: str,
    listen_port: int,
    client_ip: str,
    server_cidr: str,
    dns: str,
    mtu: Optional[int],
    auto_mtu: bool,
    tune: bool,
    quiet: bool,
    protocol: str = "amneziawg",
) -> WireGuardProvisioner:
    def log(msg: str) -> None:
        if not quiet:
            typer.echo(msg)

    cfg = SSHConfig(
        host=host,
        user=user,
        port=port,
        password=password,
        key_path=key,
    )
    ssh = SSHRunner(cfg, logger=log)
    ssh.connect()
    normalized_mtu = None if mtu is None or mtu <= 0 else mtu
    effective_auto_mtu = auto_mtu if mtu is None else False
    return WireGuardProvisioner(
        ssh,
        client_name=client,
        client_ip=client_ip,
        server_cidr=server_cidr,
        listen_port=listen_port,
        dns=dns,
        mtu=normalized_mtu,
        auto_mtu=effective_auto_mtu,
        tune=tune,
        protocol=protocol,
    )


def _print_checks(checks: list[dict]) -> None:
    for item in checks:
        typer.echo(
            f"check {item.get('name')}: {'ok' if item.get('ok') else 'fail'} ({item.get('details')})"
        )


def _has_critical_fail(checks: list[dict]) -> bool:
    critical = {"os_supported", "sudo", "port_available"}
    return any(item.get("name") in critical and not item.get("ok") for item in checks)


@app.command()
def provision(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    client: str = typer.Option("client1", help="Client name"),
    listen_port: int = typer.Option(3478, help="WireGuard listen port"),
    client_ip: str = typer.Option("10.10.0.2/32", help="Client IP/CIDR"),
    server_cidr: str = typer.Option("10.10.0.1/24", help="Server VPN CIDR"),
    dns: str = typer.Option("1.1.1.1, 1.0.0.1", help="DNS server for clients"),
    mtu: Optional[int] = typer.Option(None, help="WireGuard MTU (0 disables)"),
    auto_mtu: bool = typer.Option(True, "--auto-mtu/--no-auto-mtu", help="Auto-detect MTU"),
    tune: bool = typer.Option(True, "--tune/--no-tune", help="Enable network tuning"),
    check: bool = typer.Option(True, "--check/--no-check", help="Post-provision checks"),
    precheck: bool = typer.Option(True, "--precheck/--no-precheck", help="Pre-provision checks"),
    protocol: str = typer.Option("amneziawg", help="Protocol (amneziawg or wireguard)"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    prov = _build_provisioner(
        host,
        user,
        password,
        key,
        port,
        client,
        listen_port,
        client_ip,
        server_cidr,
        dns,
        mtu,
        auto_mtu,
        tune,
        quiet,
        protocol,
    )
    try:
        if precheck:
            checks = prov.pre_check()
            _print_checks(checks)
            if _has_critical_fail(checks):
                typer.echo("Precheck failed.")
                raise typer.Exit(code=1)
        prov.provision()
        if check:
            results = prov.post_check()
            ok = all(item.get("ok") for item in results)
            _print_checks(results)
            typer.echo("Checks: OK" if ok else "Checks: FAIL")
        typer.echo("Provisioned.")
    finally:
        prov.ssh.close()


@app.command()
def export(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    client: str = typer.Option("client1", help="Client name"),
    out: Optional[Path] = typer.Option(None, help="Output config path"),
    qr: Optional[Path] = typer.Option(None, help="Output QR PNG path"),
    print_config: bool = typer.Option(False, help="Print config to stdout"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    prov = _build_provisioner(
        host,
        user,
        password,
        key,
        port,
        client,
        3478,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1, 1.0.0.1",
        None,
        True,
        True,
        quiet,
    )
    try:
        config = prov.export_client_config()
    finally:
        prov.ssh.close()

    out_path = out or Path(f"{client}.conf")
    out_path.write_text(config, encoding="utf-8")
    typer.echo(f"Wrote {out_path}")

    if qr:
        save_qr_png(config, qr)
        typer.echo(f"Wrote {qr}")

    if print_config:
        typer.echo(config)


@app.command()
def status(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    client: str = typer.Option("client1", help="Client name"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    prov = _build_provisioner(
        host,
        user,
        password,
        key,
        port,
        client,
        3478,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1, 1.0.0.1",
        None,
        True,
        True,
        quiet,
    )
    try:
        info = prov.status()
    finally:
        prov.ssh.close()
    typer.echo(f"service: {info.get('service')}")
    if info.get("wg"):
        typer.echo(info.get("wg"))


@app.command()
def rollback(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    prov = _build_provisioner(
        host,
        user,
        password,
        key,
        port,
        "client1",
        3478,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1, 1.0.0.1",
        None,
        True,
        True,
        quiet,
    )
    try:
        backup = prov.rollback_last_backup()
    finally:
        prov.ssh.close()
    if backup:
        typer.echo(f"Rolled back to {backup}")
    else:
        typer.echo("No backup found.")


@client_app.command("list")
def client_list(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    prov = _build_provisioner(
        host,
        user,
        password,
        key,
        port,
        "client1",
        3478,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1, 1.0.0.1",
        None,
        True,
        True,
        quiet,
    )
    try:
        clients = prov.list_clients()
    finally:
        prov.ssh.close()
    for client in clients:
        typer.echo(f"{client.get('name')} {client.get('ip')}")


@client_app.command("add")
def client_add(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    name: Optional[str] = typer.Option(None, help="Client name"),
    client_ip: Optional[str] = typer.Option(None, help="Client IP/CIDR"),
    out: Optional[Path] = typer.Option(None, help="Output config path"),
    qr: Optional[Path] = typer.Option(None, help="Output QR PNG path"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    prov = _build_provisioner(
        host,
        user,
        password,
        key,
        port,
        "client1",
        3478,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1, 1.0.0.1",
        None,
        True,
        True,
        quiet,
    )
    try:
        result = prov.add_client(client_name=name, client_ip=client_ip)
    finally:
        prov.ssh.close()

    config = result.get("config", "")
    client_name = result.get("name", "client")
    out_path = out or Path(f"{client_name}.conf")
    out_path.write_text(config, encoding="utf-8")
    typer.echo(f"Wrote {out_path}")

    if qr:
        save_qr_png(config, qr)
        typer.echo(f"Wrote {qr}")


@client_app.command("remove")
def client_remove(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    name: str = typer.Option(..., help="Client name"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    prov = _build_provisioner(
        host,
        user,
        password,
        key,
        port,
        "client1",
        3478,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1, 1.0.0.1",
        None,
        True,
        True,
        quiet,
    )
    try:
        ok = prov.remove_client(name)
    finally:
        prov.ssh.close()
    typer.echo("Removed." if ok else "Client not found.")


@client_app.command("rotate")
def client_rotate(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    name: str = typer.Option(..., help="Client name"),
    out: Optional[Path] = typer.Option(None, help="Output config path"),
    qr: Optional[Path] = typer.Option(None, help="Output QR PNG path"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    prov = _build_provisioner(
        host,
        user,
        password,
        key,
        port,
        "client1",
        3478,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1, 1.0.0.1",
        None,
        True,
        True,
        quiet,
    )
    try:
        result = prov.rotate_client(name)
    finally:
        prov.ssh.close()

    config = result.get("config", "")
    out_path = out or Path(f"{name}.conf")
    out_path.write_text(config, encoding="utf-8")
    typer.echo(f"Wrote {out_path}")

    if qr:
        save_qr_png(config, qr)
        typer.echo(f"Wrote {qr}")


@app.command("wl-provision")
def wl_provision(
    host: str = typer.Option(..., help="Server hostname or IP"),
    user: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password"),
    key: Optional[str] = typer.Option(None, help="SSH private key path"),
    port: int = typer.Option(22, help="SSH port"),
    client: str = typer.Option("wl1", help="Client name on the WL profile"),
    listen_port: int = typer.Option(8443, help="VPS port for the WL inbound (Xray TLS)"),
    domain: Optional[str] = typer.Option(None, help="Override domain (default: <ip-dashes>.sslip.io)"),
    yc_oauth_token: Optional[str] = typer.Option(
        None,
        envvar="YC_OAUTH_TOKEN",
        help="Yandex Cloud OAuth token (default: YC_OAUTH_TOKEN env)",
    ),
    yc_folder_id: Optional[str] = typer.Option(
        None,
        envvar="YC_FOLDER_ID",
        help="Yandex Cloud folder id (default: auto-resolve first ACTIVE folder)",
    ),
    gateway_name: str = typer.Option("vpn-wl", help="Yandex API Gateway name"),
    quiet: bool = typer.Option(False, help="Less output"),
) -> None:
    """Provision a whitelist-friendly profile: VPS-side VLESS-XHTTP+TLS inbound + Yandex API Gateway front."""
    from vpn_wizard.whitelist import WhitelistProvisioner
    from vpn_wizard.yandex_cloud import provision_wl_gateway

    token = (yc_oauth_token or os.environ.get("YC_OAUTH_TOKEN", "")).strip()
    if not token:
        typer.echo("YC_OAUTH_TOKEN is required (env or --yc-oauth-token).", err=True)
        raise typer.Exit(code=2)

    def log(msg: str) -> None:
        if not quiet:
            typer.echo(msg)

    cfg = SSHConfig(host=host, user=user, port=port, password=password, key_path=key)
    ssh = SSHRunner(cfg, logger=log)
    ssh.connect()
    try:
        log("== Step 1: WL inbound on VPS ==")
        wl = WhitelistProvisioner(ssh, progress=log, listen_port=listen_port)
        inbound_info = wl.setup_inbound(client, domain=domain)
        log(f"VPS WL inbound ready at {inbound_info['backend_url']}{inbound_info['path']}")

        log("== Step 2: Yandex API Gateway ==")
        gw = provision_wl_gateway(
            oauth_token=token,
            backend_url=inbound_info["backend_url"],
            name=gateway_name,
            folder_id=yc_folder_id,
            progress=log,
        )
        log(f"Gateway domain: {gw['domain']} (id={gw['gateway_id']})")

        log("== Step 3: Client link ==")
        link = WhitelistProvisioner.build_client_link(
            gateway_domain=gw["domain"],
            client_uuid=inbound_info["client_uuid"],
            path=inbound_info["path"],
            client_name=inbound_info["client_name"],
        )
        typer.echo("\n--- WL profile ---")
        typer.echo(f"client:       {inbound_info['client_name']}")
        typer.echo(f"gateway:      https://{gw['domain']}")
        typer.echo(f"backend:      {inbound_info['backend_url']}{inbound_info['path']}")
        typer.echo(f"vless link:   {link}")
        typer.echo("------------------")
    finally:
        ssh.close()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
