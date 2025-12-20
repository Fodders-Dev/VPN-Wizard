from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import vpn_wizard.cli as cli


class DummySSH:
    def close(self) -> None:
        return None


class DummyProvisioner:
    def __init__(self, config: str) -> None:
        self._config = config
        self.ssh = DummySSH()

    def export_client_config(self) -> str:
        return self._config


def test_export_writes_config_and_qr(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    config = "[Interface]\nPrivateKey = test\n"
    monkeypatch.setattr(
        cli, "_build_provisioner", lambda *args, **kwargs: DummyProvisioner(config)
    )

    out_path = tmp_path / "client.conf"
    qr_path = tmp_path / "client.png"
    result = runner.invoke(
        cli.app,
        [
            "export",
            "--host",
            "1.1.1.1",
            "--user",
            "root",
            "--out",
            str(out_path),
            "--qr",
            str(qr_path),
        ],
    )

    assert result.exit_code == 0
    assert out_path.read_text(encoding="utf-8") == config
    assert qr_path.exists()
