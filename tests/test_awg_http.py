"""HTTP surface of the AmneziaWG delivery path.

Regression home for the client-side constraints that are invisible from Python:
the AmneziaWG Android client derives the tunnel name from the downloaded file's
base name and rejects anything outside ``[a-zA-Z0-9_=+.-]{1,15}`` instead of
truncating it, so a long filename silently makes a config unimportable.
"""
from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

import vpn_wizard.server as server_module
from vpn_wizard.awg_fallback import issue_token
from vpn_wizard.awg_servers import AwgServer
from vpn_wizard.server import _awg_file_slug, _awg_label_config, app


# Mirrors Tunnel.NAME_PATTERN in the AmneziaWG Android client.
ANDROID_TUNNEL_NAME = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")

_AWG_ENV = (
    "VPNW_AWG_SERVERS",
    "VPNW_AWG_PRESETS",
    "VPNW_AWG_DEFAULT_SERVER",
    "VPNW_AWG_FALLBACK_HOST",
    "VPNW_AWG_FALLBACK_ID",
    "VPNW_AWG_FALLBACK_LABEL",
    "VPNW_AWG_FALLBACK_FLAG",
    "VPNW_AWG_FALLBACK_SSH_PASSWORD",
    "VPNW_AWG_LINK_SECRET",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    for name in _AWG_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VPNW_STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("VPNW_SECRET_KEY", "test-secret-key")


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


def _configure_single_server(monkeypatch: pytest.MonkeyPatch, secret: str = "link-secret") -> None:
    monkeypatch.setenv("VPNW_AWG_FALLBACK_HOST", "212.69.84.167")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_SSH_PASSWORD", "hunter2")
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)


# --- tunnel name (the live import bug) ----------------------------------------

@pytest.mark.parametrize(
    "server_id",
    ["nl", "main", "us", "a-very-long-server-identifier", "..//etc/passwd", "🇳🇱", "", None],
)
def test_file_slug_always_importable_on_android(server_id) -> None:
    slug = _awg_file_slug(server_id)
    assert ANDROID_TUNNEL_NAME.match(slug), f"{slug!r} would be rejected by AmneziaWG Android"


def test_file_slug_names_the_server() -> None:
    assert _awg_file_slug("nl") == "FVPN-nl"
    assert _awg_file_slug("us") == "FVPN-us"
    # Different servers must yield different files, or a second download
    # overwrites the first instead of adding a tunnel.
    assert _awg_file_slug("nl") != _awg_file_slug("fi")


def test_file_slug_falls_back_when_id_is_unusable() -> None:
    assert _awg_file_slug("🇳🇱") == "FVPN"
    assert _awg_file_slug(None) == "FVPN"


# --- config labelling ----------------------------------------------------------

def _server(**kwargs) -> AwgServer:
    base = {
        "id": "nl", "label": "Нидерланды", "flag": "🇳🇱", "host": "1.1.1.1",
        "user": "root", "port": 22, "password": "p", "key_path": None,
        "key_content": None, "listen_port": 443,
    }
    return AwgServer(**{**base, **kwargs})


def test_label_is_whole_line_comments_above_interface() -> None:
    original = "[Interface]\nPrivateKey = abc\nAddress = 10.10.0.5/32\n"
    labelled = _awg_label_config(original, _server())

    lines = labelled.splitlines()
    assert lines[0] == "# Fodder VPN — 🇳🇱 Нидерланды"
    assert lines[1] == "# server: nl"
    assert lines[2] == "[Interface]"
    # Every comment must be a whole line: an inline one would be captured by the
    # `grep '^Address'` parsing that rebuilds server-side peer blocks.
    for line in lines:
        assert "#" not in line or line.startswith("#")
    # The original config must survive byte-for-byte after the header.
    assert labelled.endswith(original)


def test_label_adds_no_directives_that_break_import() -> None:
    labelled = _awg_label_config("[Interface]\nPrivateKey = abc\n", _server())
    keys = [
        line.split("=")[0].strip()
        for line in labelled.splitlines()
        if "=" in line and not line.startswith("#")
    ]
    # A non-whitelisted key such as `Name` or `Server` fails the whole import.
    assert keys == ["PrivateKey"]


def test_label_is_a_noop_without_a_server() -> None:
    original = "[Interface]\nPrivateKey = abc\n"
    assert _awg_label_config(original, None) == original


# --- endpoint behaviour --------------------------------------------------------

def test_config_download_filename_is_importable(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    # Guards the regression directly: the endpoint must never emit a name the
    # Android client refuses (the old one was `fodder-awg-<telegram_id>.conf`).
    monkeypatch.setattr(
        server_module,
        "_awg_issue_config",
        lambda telegram_id, token, server_id=None: ("[Interface]\nPrivateKey = k\n", _server()),
    )
    response = client.get("/api/awg/449066726/config", params={"token": "whatever"})

    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    name = re.search(r'filename="([^"]+)"', disposition).group(1)
    assert name.endswith(".conf")
    assert ANDROID_TUNNEL_NAME.match(name[: -len(".conf")])
    assert name == "FVPN-nl.conf"
    # Not text/plain, or the browser appends .txt and Android stops offering
    # "open with AmneziaWG".
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["cache-control"] == "no-store"


def test_config_requires_configuration_then_a_valid_token(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    unconfigured = client.get("/api/awg/1/config", params={"token": "x"})
    assert unconfigured.status_code == 503

    _configure_single_server(monkeypatch)
    assert client.get("/api/awg/1/config", params={"token": "wrong"}).status_code == 403
    # A token minted for a different user must not work either.
    other = issue_token("link-secret", 2)
    assert client.get("/api/awg/1/config", params={"token": other}).status_code == 403


# --- server picker -------------------------------------------------------------

def test_servers_endpoint_lists_choices_without_leaking_secrets(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "flag": "🇳🇱", "host": "212.69.84.167", "password": "hunter2"},
            {"id": "fi", "label": "Финляндия", "flag": "🇫🇮", "host": "2.2.2.2", "password": "hunter2"},
        ]),
    )
    response = client.get("/api/awg/servers")
    assert response.status_code == 200

    body = response.json()
    assert [s["id"] for s in body["servers"]] == ["nl", "fi"]
    assert body["default_server"] == "nl"
    raw = response.text
    for secret in ("212.69.84.167", "hunter2", "2.2.2.2"):
        assert secret not in raw


def test_servers_endpoint_reports_unconfigured_and_invalid(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    assert client.get("/api/awg/servers").status_code == 503

    monkeypatch.setenv("VPNW_AWG_SERVERS", "{not json")
    assert client.get("/api/awg/servers").status_code == 500


def test_servers_route_does_not_shadow_the_config_route(client: TestClient) -> None:
    # "/api/awg/servers" and "/api/awg/{telegram_id}/config" must stay distinct;
    # a greedy int path param would otherwise swallow it.
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/awg/servers" in paths
    assert "/api/awg/{telegram_id}/config" in paths


def test_selected_server_controls_real_provisioning(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "host": "127.0.0.1", "password": "p", "listen_port": 443},
            {"id": "fi", "label": "Финляндия", "host": "151.245.139.63", "password": "p", "listen_port": 3478},
        ]),
    )

    class ActiveRemnawave:
        def __init__(self, config) -> None:
            self.config = config

        def active_user(self, telegram_id: int):
            return {"uuid": "active-user"}

    captured: dict[str, object] = {}

    def issue(self, telegram_id: int, *, remnawave_uuid=None):
        captured.update(
            host=self.config.host,
            listen_port=self.config.listen_port,
            server_id=self.server_id,
            telegram_id=telegram_id,
        )
        return {"config": "[Interface]\nPrivateKey = k\n", "client_name": "x", "reused": False}

    monkeypatch.setattr(server_module, "RemnawaveClient", ActiveRemnawave)
    monkeypatch.setattr(server_module.AwgFallbackService, "issue", issue)
    token = issue_token(secret, 449066726)
    response = client.get(
        "/api/awg/449066726/config",
        params={"token": token, "server": "fi"},
    )

    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="FVPN-fi.conf"'
    assert captured == {
        "host": "151.245.139.63",
        "listen_port": 3478,
        "server_id": "fi",
        "telegram_id": 449066726,
    }
    assert "# server: fi" in response.text


def test_unknown_selected_server_is_rejected_before_provisioning(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    secret = "link-secret"
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    monkeypatch.setenv(
        "VPNW_AWG_SERVERS",
        json.dumps([
            {"id": "nl", "label": "Нидерланды", "host": "127.0.0.1", "password": "p"},
        ]),
    )
    token = issue_token(secret, 1)
    response = client.get("/api/awg/1/config", params={"token": token, "server": "moon"})
    assert response.status_code == 404
