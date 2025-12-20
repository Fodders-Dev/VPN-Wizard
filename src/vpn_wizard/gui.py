from __future__ import annotations

from pathlib import Path
from typing import Optional

import qrcode
from PIL.ImageQt import ImageQt
from PySide6 import QtCore, QtGui, QtWidgets

from vpn_wizard.core import SSHConfig, SSHRunner, WireGuardProvisioner


class ProvisionWorker(QtCore.QThread):
    log = QtCore.Signal(str)
    done = QtCore.Signal(str, object)
    error = QtCore.Signal(str)

    def __init__(
        self,
        host: str,
        user: str,
        password: Optional[str],
        key: Optional[str],
        port: int,
        client: str,
        parent: Optional[QtCore.QObject] = None,
    ) -> None:
        super().__init__(parent)
        self.host = host
        self.user = user
        self.password = password
        self.key = key
        self.port = port
        self.client = client

    def run(self) -> None:
        try:
            def logger(msg: str) -> None:
                self.log.emit(msg)

            cfg = SSHConfig(
                host=self.host,
                user=self.user,
                port=self.port,
                password=self.password,
                key_path=self.key,
            )
            with SSHRunner(cfg, logger=logger) as ssh:
                prov = WireGuardProvisioner(ssh, client_name=self.client)
                prov.provision()
                config = prov.export_client_config()
                checks = prov.post_check()
            self.done.emit(config, checks)
        except Exception as exc:
            self.error.emit(str(exc))


class Wizard(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("VPN Wizard")
        self.resize(760, 520)
        self.client_config: Optional[str] = None
        self.worker: Optional[ProvisionWorker] = None

        self.stack = QtWidgets.QStackedWidget()
        self.page_access = self._build_access_page()
        self.page_progress = self._build_progress_page()
        self.page_done = self._build_done_page()
        self.stack.addWidget(self.page_access)
        self.stack.addWidget(self.page_progress)
        self.stack.addWidget(self.page_done)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.stack)

    def _build_access_page(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget()
        form = QtWidgets.QFormLayout(page)

        intro = QtWidgets.QLabel("Step 1: enter server access, then click Configure.")
        intro.setWordWrap(True)
        form.addRow(intro)

        self.host_input = QtWidgets.QLineEdit()
        self.host_input.setPlaceholderText("1.2.3.4")
        self.user_input = QtWidgets.QLineEdit()
        self.user_input.setPlaceholderText("root")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setPlaceholderText("Optional if key auth")
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.key_input = QtWidgets.QLineEdit()
        self.key_input.setPlaceholderText("~/.ssh/id_rsa")
        self.port_input = QtWidgets.QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        self.client_input = QtWidgets.QLineEdit("client1")

        key_row = QtWidgets.QHBoxLayout()
        key_row.addWidget(self.key_input, 1)
        browse = QtWidgets.QPushButton("Browse")
        browse.clicked.connect(self._choose_key)
        key_row.addWidget(browse)

        form.addRow("Host", self.host_input)
        form.addRow("User", self.user_input)
        form.addRow("Password", self.password_input)
        form.addRow("SSH Key", key_row)
        form.addRow("Port", self.port_input)
        form.addRow("Client name", self.client_input)

        self.configure_btn = QtWidgets.QPushButton("Configure")
        self.configure_btn.clicked.connect(self._start_provision)
        form.addRow(self.configure_btn)
        return page

    def _build_progress_page(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(page)
        title = QtWidgets.QLabel("Provisioning...")
        title.setStyleSheet("font-size: 18px;")
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)
        self.log_output = QtWidgets.QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(title)
        layout.addWidget(self.progress)
        layout.addWidget(self.log_output)
        return page

    def _build_done_page(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(page)
        title = QtWidgets.QLabel("VPN ready.")
        title.setStyleSheet("font-size: 18px;")
        self.check_label = QtWidgets.QLabel()
        self.download_btn = QtWidgets.QPushButton("Download config")
        self.download_btn.clicked.connect(self._download_config)
        self.qr_label = QtWidgets.QLabel()
        self.qr_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)
        layout.addWidget(self.check_label)
        layout.addWidget(self.download_btn)
        layout.addWidget(self.qr_label, 1)
        return page

    def _choose_key(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select SSH key", "", "All Files (*)"
        )
        if path:
            self.key_input.setText(path)

    def _start_provision(self) -> None:
        host = self.host_input.text().strip()
        user = self.user_input.text().strip()
        if not host or not user:
            QtWidgets.QMessageBox.warning(self, "Missing data", "Host and User are required.")
            return

        password = self.password_input.text() or None
        key = self.key_input.text().strip() or None
        port = int(self.port_input.value())
        client = self.client_input.text().strip() or "client1"

        self.log_output.clear()
        self.stack.setCurrentWidget(self.page_progress)
        self.worker = ProvisionWorker(host, user, password, key, port, client)
        self.worker.log.connect(self._append_log)
        self.worker.done.connect(self._provision_done)
        self.worker.error.connect(self._provision_error)
        self.worker.start()

    def _append_log(self, msg: str) -> None:
        self.log_output.append(msg)

    def _provision_done(self, config: str, checks: object) -> None:
        self.client_config = config
        results = checks if isinstance(checks, list) else []
        ok = all(item.get("ok") for item in results) if results else True
        status_text = "Checks: OK" if ok else "Checks: Issues"
        self.check_label.setText(status_text)
        for item in results:
            self.log_output.append(
                f"check {item.get('name')}: {'ok' if item.get('ok') else 'fail'} ({item.get('details')})"
            )
        self._set_qr(config)
        self.stack.setCurrentWidget(self.page_done)

    def _provision_error(self, message: str) -> None:
        QtWidgets.QMessageBox.critical(self, "Provision failed", message)
        self.stack.setCurrentWidget(self.page_access)

    def _download_config(self) -> None:
        if not self.client_config:
            return
        default_name = f"{self.client_input.text().strip() or 'client1'}.conf"
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save WireGuard config", default_name, "Config (*.conf);;All Files (*)"
        )
        if path:
            Path(path).write_text(self.client_config, encoding="utf-8")

    def _set_qr(self, config: str) -> None:
        img = qrcode.make(config)
        qimg = ImageQt(img)
        pix = QtGui.QPixmap.fromImage(qimg)
        pix = pix.scaled(260, 260, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
        self.qr_label.setPixmap(pix)


def main() -> None:
    app = QtWidgets.QApplication([])
    window = Wizard()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
