from __future__ import annotations

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
    listen_port: int = typer.Option(51820, help="WireGuard listen port"),
    client_ip: str = typer.Option("10.10.0.2/32", help="Client IP/CIDR"),
    server_cidr: str = typer.Option("10.10.0.1/24", help="Server VPN CIDR"),
    dns: str = typer.Option("1.1.1.1", help="DNS server for clients"),
    mtu: Optional[int] = typer.Option(None, help="WireGuard MTU (0 disables)"),
    auto_mtu: bool = typer.Option(True, "--auto-mtu/--no-auto-mtu", help="Auto-detect MTU"),
    tune: bool = typer.Option(True, "--tune/--no-tune", help="Enable network tuning"),
    check: bool = typer.Option(True, "--check/--no-check", help="Post-provision checks"),
    precheck: bool = typer.Option(True, "--precheck/--no-precheck", help="Pre-provision checks"),
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
        51820,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1",
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
        51820,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1",
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
        51820,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1",
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
        51820,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1",
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
        51820,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1",
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
        51820,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1",
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
        51820,
        "10.10.0.2/32",
        "10.10.0.1/24",
        "1.1.1.1",
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
