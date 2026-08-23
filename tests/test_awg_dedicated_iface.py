"""A dedicated AWG interface on a box we do not own.

Some exits are somebody's personal server whose awg0/awg1 already carry their
own peers. Rebuilding a shared interface from OUR clients directory deletes
those peers — it happened once in production. A dedicated interface keeps our
peers in their own interface plus clients_<iface> directory, so every rebuild
touches only what the product created.
"""
from __future__ import annotations

import pytest

from vpn_wizard.awg_servers import AwgRegistryError, AwgServer
from vpn_wizard.core import WireGuardProvisioner


class FakeSSH:
    """Records every command instead of running it."""

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self.commands: list[str] = []
        self.responses = responses or {}
        self.config = type("Cfg", (), {"host": "203.0.113.9"})()

    def run(self, command: str, sudo: bool = False, check: bool = True) -> str:
        self.commands.append(command)
        for needle, reply in self.responses.items():
            if needle in command:
                return reply
        return ""


def _provisioner(**kwargs) -> tuple[WireGuardProvisioner, FakeSSH]:
    ssh = FakeSSH()
    return WireGuardProvisioner(ssh, **kwargs), ssh


# --- interface naming ------------------------------------------------------------

def test_dedicated_interface_has_its_own_clients_directory() -> None:
    prov, _ = _provisioner(iface="awg9")
    assert prov.dedicated_clients_dir == "/etc/amnezia/amneziawg/clients_awg9"


def test_without_an_interface_nothing_changes() -> None:
    prov, _ = _provisioner()
    assert prov.iface is None
    assert prov.dedicated_clients_dir is None


@pytest.mark.parametrize("bad", ["awg 9", "../etc", "AWG9;rm -rf /", "a", "awg9/x", "-awg"])
def test_registry_rejects_interface_names_that_could_escape_the_config_dir(bad) -> None:
    # The name lands in shell paths and a systemd unit name.
    with pytest.raises(AwgRegistryError):
        AwgServer.from_dict(
            {"id": "fi", "host": "203.0.113.9", "password": "p", "interface": bad}
        )


def test_registry_accepts_a_plain_interface_name_and_defaults_to_none() -> None:
    named = AwgServer.from_dict(
        {"id": "fi", "host": "203.0.113.9", "password": "p", "interface": "awg9"}
    )
    assert named.interface == "awg9"
    plain = AwgServer.from_dict({"id": "nl", "host": "203.0.113.10", "password": "p"})
    assert plain.interface is None


# --- the actual protection -------------------------------------------------------

def test_rebuild_touches_only_the_dedicated_interface() -> None:
    prov, ssh = _provisioner(iface="awg9")
    prov.rebuild_iface_from_clients("awg9", "/etc/amnezia/amneziawg/clients_awg9")

    script = "\n".join(ssh.commands)
    assert "/etc/amnezia/amneziawg/awg9.conf" in script
    assert "clients_awg9" in script
    assert "awg-quick@awg9" in script
    # The owner's interfaces must not appear anywhere in the rebuild.
    for foreign in ("awg0.conf", "awg1.conf", "clients_tyumen", "awg-quick@awg0", "awg-quick@awg1"):
        assert foreign not in script, foreign


def test_locate_client_never_looks_into_someone_elses_directory() -> None:
    # Same peer name could exist on the owner's awg0; matching it would rebuild
    # their interface from our directory.
    ssh = FakeSSH(responses={"test -f": "yes"})
    prov = WireGuardProvisioner(ssh, iface="awg9")
    prov.protocol = "amneziawg"
    prov._auto_detect_protocol = lambda: None

    location = prov._locate_client("sub-42-fi")
    assert location is not None
    clients_dir, _rebuild, iface = location
    assert (clients_dir, iface) == ("/etc/amnezia/amneziawg/clients_awg9", "awg9")
    assert not any("clients/" in cmd or "clients_tyumen" in cmd for cmd in ssh.commands)


def test_client_gets_the_dedicated_interfaces_own_server_key() -> None:
    # The generic server_public.key on a shared box belongs to whichever
    # interface created it. Handing that key to our client made every
    # handshake fail silently: packets arrived, nothing ever completed.
    conf_dir = "/etc/amnezia/amneziawg"
    prov, _ = _provisioner(iface="awg9")
    prov.protocol = "amneziawg"

    priv, pub = prov._server_key_paths(conf_dir, use_alt_iface=False)
    assert priv == f"{conf_dir}/server_private_awg9.key"
    assert pub == f"{conf_dir}/server_public_awg9.key"


def test_shared_interfaces_keep_their_original_key_files() -> None:
    conf_dir = "/etc/amnezia/amneziawg"
    prov, _ = _provisioner()
    prov.protocol = "amneziawg"

    assert prov._server_key_paths(conf_dir, use_alt_iface=False) == (
        f"{conf_dir}/server_private.key",
        f"{conf_dir}/server_public.key",
    )
    assert prov._server_key_paths(conf_dir, use_alt_iface=True) == (
        f"{conf_dir}/server_private_awg1.key",
        f"{conf_dir}/server_public_awg1.key",
    )


def test_client_ip_is_taken_from_the_dedicated_subnet() -> None:
    ssh = FakeSSH(responses={"grep -h '^Address'": "10.99.0.2\n10.99.0.3"})
    prov = WireGuardProvisioner(ssh, iface="awg9")
    prov.server_cidr = "10.99.0.1/24"

    assert prov.next_client_ip() == "10.99.0.4/32"
    assert any("clients_awg9" in cmd for cmd in ssh.commands)
