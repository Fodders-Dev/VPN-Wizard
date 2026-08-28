from __future__ import annotations

from vpn_wizard.core import SSHConfig, WireGuardProvisioner


class FakeSSH:
    def __init__(self, responses: dict[str, str] | None = None, password: str | None = None) -> None:
        self.responses = responses or {}
        self.commands: list[tuple[str, bool, bool]] = []
        self.config = SSHConfig(host="example.com", user="root", password=password)

    def run(self, command: str, sudo: bool = False, check: bool = True, pty: bool = True) -> str:
        self.commands.append((command, sudo, check))
        for key, value in self.responses.items():
            if key in command:
                return value
        return ""


class MtuSSH(FakeSSH):
    def __init__(self, max_payload: int) -> None:
        super().__init__()
        self.max_payload = max_payload

    def run(self, command: str, sudo: bool = False, check: bool = True, pty: bool = True) -> str:
        self.commands.append((command, sudo, check))
        if "command -v ping" in command:
            return "ok"
        if "ping -h" in command:
            return "ok"
        if "ping -c 1" in command and "-s" in command:
            size = int(command.split("-s")[1].split()[0])
            return "ok" if size <= self.max_payload else "fail"
        return ""


def _has_command(commands: list[tuple[str, bool, bool]], needle: str) -> bool:
    return any(needle in cmd for cmd, _, _ in commands)


def test_detect_os_parses_os_release() -> None:
    ssh = FakeSSH({"cat /etc/os-release": 'ID=ubuntu\nID_LIKE="debian"\nNAME="Ubuntu"\n'})
    prov = WireGuardProvisioner(ssh)
    info = prov.detect_os()
    assert info["ID"] == "ubuntu"
    assert info["ID_LIKE"] == "debian"


def test_install_wireguard_debian() -> None:
    ssh = FakeSSH()
    prov = WireGuardProvisioner(ssh)
    prov.install_wireguard({"ID": "ubuntu", "ID_LIKE": "debian"})
    assert _has_command(ssh.commands, "apt-get install -y wireguard")


def test_install_wireguard_rhel() -> None:
    ssh = FakeSSH({"command -v dnf": "dnf"})
    prov = WireGuardProvisioner(ssh)
    prov.install_wireguard({"ID": "centos", "ID_LIKE": "rhel"})
    assert _has_command(ssh.commands, "dnf install -y wireguard-tools")


def test_configure_sysctl_tuning_enabled() -> None:
    ssh = FakeSSH()
    prov = WireGuardProvisioner(ssh, tune=True)
    prov.configure_sysctl()
    assert _has_command(ssh.commands, "99-vpn-wizard-tuning.conf")
    assert _has_command(ssh.commands, "sysctl -p /etc/sysctl.d/99-vpn-wizard-tuning.conf")


def test_setup_wireguard_includes_mtu_and_iptables_wait() -> None:
    ssh = FakeSSH()
    prov = WireGuardProvisioner(ssh, mtu=1420)
    prov.setup_wireguard()
    combined = "\n".join(cmd for cmd, _, _ in ssh.commands)
    assert "MTU = 1420" in combined
    assert "iptables -w -I FORWARD" in combined


def test_amneziawg_defaults_use_stable_parameters() -> None:
    ssh = FakeSSH()
    prov = WireGuardProvisioner(ssh)
    assert prov.awg_jc == 2
    assert prov.awg_jmin == 40
    assert prov.awg_jmax == 70
    assert prov.awg_s1 == 130
    assert prov.awg_s2 == 37
    assert prov.awg_h1 == 1028292012
    assert prov.awg_h2 == 2027322962
    assert prov.awg_h3 == 1500253145
    assert prov.awg_h4 == 836814590


def test_detect_mtu_returns_value_from_probe() -> None:
    ssh = MtuSSH(max_payload=1432)
    prov = WireGuardProvisioner(ssh, mtu=None, auto_mtu=True, mtu_fallback=1420)
    mtu = prov.detect_mtu()
    assert mtu is not None
    assert 1280 <= mtu <= 1420


def test_resolve_mtu_uses_fallback_when_probe_unavailable() -> None:
    ssh = FakeSSH({"command -v ping": "missing"})
    prov = WireGuardProvisioner(ssh, mtu=None, auto_mtu=True, mtu_fallback=1420)
    assert prov.resolve_mtu() == 1420


def test_get_public_ip_keeps_public_ssh_ip() -> None:
    ssh = FakeSSH()
    ssh.config.host = "8.8.8.8"
    prov = WireGuardProvisioner(ssh)
    assert prov.get_public_ip() == "8.8.8.8"
    assert not _has_command(ssh.commands, "api.ipify.org")


def test_get_public_ip_replaces_private_ssh_ip_with_detected_public_ip() -> None:
    ssh = FakeSSH({"api.ipify.org": "1.2.3.4"})
    ssh.config.host = "10.0.0.5"
    prov = WireGuardProvisioner(ssh)
    assert prov.get_public_ip() == "1.2.3.4"
    assert _has_command(ssh.commands, "api.ipify.org")


def test_precheck_passes_on_supported_os() -> None:
    ssh = FakeSSH(
        {
            "cat /etc/os-release": "ID=ubuntu\nID_LIKE=debian\n",
            "ping -c 1": "ok",
            "sudo -n true": "ok",
            "ss -lun": "free",
            "test -f /etc/wireguard/wg0.conf": "missing",
        }
    )
    prov = WireGuardProvisioner(ssh)
    checks = prov.pre_check()
    assert any(item.get("name") == "os_supported" and item.get("ok") for item in checks)
    assert any(item.get("name") == "port_available" and item.get("ok") for item in checks)


def test_list_clients_includes_file_timestamps() -> None:
    ssh = FakeSSH(
        {
            "for conf in /etc/wireguard/clients/*.conf": "alice\t10.10.0.2/32\tPUBKEY\t1710000000|1710001234\n",
            "wg show wg0": "",
        }
    )
    prov = WireGuardProvisioner(ssh, protocol="wireguard")
    clients = prov.list_clients()
    assert clients[0]["name"] == "alice"
    assert clients[0]["created_at"] == 1710000000
    assert clients[0]["updated_at"] == 1710001234


def test_suspend_client_retains_keys_and_rebuilds_interface() -> None:
    ssh = FakeSSH(
        {
            "/etc/amnezia/amneziawg/awg0.conf": "yes",
            "/etc/wireguard/wg0.conf": "no",
            "/etc/amnezia/amneziawg/clients/sub-42.conf &&": "yes",
        }
    )
    prov = WireGuardProvisioner(ssh)
    assert prov.suspend_client("sub-42") is True
    assert _has_command(
        ssh.commands,
        "mv /etc/amnezia/amneziawg/clients/sub-42.conf "
        "/etc/amnezia/amneziawg/clients/sub-42.conf.suspended",
    )
    # Freezing a subscription must never destroy the client's keys - the
    # person gets the same profile back on resume.
    assert not _has_command(ssh.commands, "rm -f /etc/amnezia/amneziawg/clients/")
    assert _has_command(ssh.commands, "awg syncconf awg0")


def test_resume_client_restores_same_config_file() -> None:
    ssh = FakeSSH(
        {
            "/etc/amnezia/amneziawg/awg0.conf": "yes",
            "/etc/wireguard/wg0.conf": "no",
            "/etc/amnezia/amneziawg/clients/sub-42.conf &&": "no",
            "/etc/amnezia/amneziawg/clients_tyumen/sub-42.conf &&": "no",
            "/etc/amnezia/amneziawg/clients/sub-42.conf.suspended &&": "yes",
        }
    )
    prov = WireGuardProvisioner(ssh)
    assert prov.resume_client("sub-42") is True
    assert _has_command(
        ssh.commands,
        "mv /etc/amnezia/amneziawg/clients/sub-42.conf.suspended "
        "/etc/amnezia/amneziawg/clients/sub-42.conf",
    )
    assert _has_command(ssh.commands, "awg syncconf awg0")


def test_peer_changes_do_not_reset_everyone_elses_session() -> None:
    """Live measurement 28.08.2026 on a throwaway interface: restarting the
    unit cost 45 of 60 pings and zeroed every handshake, while syncconf cost
    0 of 120 and left them untouched.  One person getting a profile must not
    black out the other forty-seven."""
    ssh = FakeSSH(
        {
            "/etc/amnezia/amneziawg/awg0.conf": "yes",
            "/etc/wireguard/wg0.conf": "no",
        }
    )
    prov = WireGuardProvisioner(ssh)
    prov.rebuild_awg0_from_clients()

    script = "\n".join(cmd for cmd, _sudo, _check in ssh.commands)
    assert "awg-quick strip awg0" in script
    assert "awg syncconf awg0" in script
    # The restart survives only as the fallback, guarded by the syncconf branch.
    assert "systemctl restart awg-quick@awg0" in script
    assert script.index("awg syncconf awg0") < script.index(
        "systemctl restart awg-quick@awg0"
    )


def test_peer_sync_survives_a_posix_shell() -> None:
    """The script is handed to whatever /bin/sh the exit happens to ship, so
    process substitution and [[ ]] would fail there and nowhere in the tests."""
    prov = WireGuardProvisioner(FakeSSH({}))
    script = prov._apply_peers("awg0", "awg")
    assert "<(" not in script
    assert "[[" not in script
    # The temporary file holds the server private key; it must not be left behind.
    assert 'rm -f "$sync"' in script


def test_plain_wireguard_uses_its_own_tools() -> None:
    prov = WireGuardProvisioner(FakeSSH({}), protocol="wireguard")
    script = prov._apply_peers("wg0", "wg")
    assert "wg-quick strip wg0" in script
    assert "wg syncconf wg0" in script
    assert "awg" not in script


def test_next_client_ip_reserves_addresses_of_suspended_peers() -> None:
    ssh = FakeSSH({"*.conf.suspended": "10.10.0.2\n10.10.0.3\n"})
    prov = WireGuardProvisioner(ssh)
    assert prov.next_client_ip() == "10.10.0.4/32"
    assert _has_command(ssh.commands, "/clients/*.conf.suspended")
