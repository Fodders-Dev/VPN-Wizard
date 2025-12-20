from __future__ import annotations

from vpn_wizard.core import SSHConfig, WireGuardProvisioner


class FakeSSH:
    def __init__(self, responses: dict[str, str] | None = None, password: str | None = None) -> None:
        self.responses = responses or {}
        self.commands: list[tuple[str, bool, bool]] = []
        self.config = SSHConfig(host="example.com", user="root", password=password)

    def run(self, command: str, sudo: bool = False, check: bool = True) -> str:
        self.commands.append((command, sudo, check))
        for key, value in self.responses.items():
            if key in command:
                return value
        return ""


class MtuSSH(FakeSSH):
    def __init__(self, max_payload: int) -> None:
        super().__init__()
        self.max_payload = max_payload

    def run(self, command: str, sudo: bool = False, check: bool = True) -> str:
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
