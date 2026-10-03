from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

import vpn_wizard.awg_health as health
from vpn_wizard.awg_health import measure_latency, probe, public_catalog, refresh
from vpn_wizard.awg_servers import AwgRegistry, AwgServer, free_server_choice_enabled
import vpn_wizard.server as server


def node(**kw):
    return AwgServer.from_dict({"id": "nl", "host": "192.0.2.1", "password": "secret", "listen_port": 443, **kw})


class FakeService:
    def __init__(self, ports="awg0\t443\n", handshakes="public-key\t950\n", failure=False,
                 transfer="public-key\t123\t456\n"):
        self.ports, self.handshakes, self.failure = ports, handshakes, failure
        self.transfer = transfer
        self.commands = []

    @contextmanager
    def _ssh(self):
        if self.failure:
            raise RuntimeError("secret SSH error")
        yield self

    def run(self, cmd, **kwargs):
        self.commands.append(cmd)
        if cmd.endswith("listen-port"):
            return self.ports
        if cmd.endswith("transfer"):
            if isinstance(self.transfer, Exception):
                raise self.transfer
            return self.transfer
        return self.handshakes


def test_probe_requires_matching_interface_and_fresh_vpn_handshake():
    assert probe(node(), now=1000, service=FakeService())["state"] == "online"
    assert probe(node(), now=1000, service=FakeService(handshakes="k\t0\n"))["state"] == "ready"
    assert probe(node(interface="awg9"), now=1000, service=FakeService())["state"] == "unavailable"
    assert probe(node(listen_port=3478), now=1000, service=FakeService())["state"] == "unavailable"
    assert probe(node(), now=1000, service=FakeService(failure=True))["state"] == "unknown"
    assert probe(node(enabled=False), now=1000, service=FakeService(failure=True))["state"] == "maintenance"


def test_catalog_is_stale_aware_and_does_not_leak_credentials(tmp_path, monkeypatch):
    path=tmp_path / "health.json"
    monkeypatch.setenv("VPNW_AWG_HEALTH_PATH", str(path))
    monkeypatch.setenv("VPNW_SUPPORT_DETAILS", "СБП: реквизиты владельца")
    monkeypatch.setenv("VPNW_SUPPORT_URL", "javascript:alert(1)")
    registry=AwgRegistry((node(), node(id="tr", enabled=False)), (), "nl")
    path.write_text(json.dumps({"servers": {"nl": {"state": "online", "checked_at": 950, "private_key": "DO_NOT_LEAK"}}}))
    body=public_catalog(registry, include_unavailable=True, now=1000)
    assert [s["id"] for s in body["servers"]] == ["nl", "tr"]
    assert body["servers"][0]["health"]["state"] == "online"
    assert body["servers"][1]["enabled"] is False
    assert body["support"]["url"] == ""
    assert all(s not in json.dumps(body) for s in ("192.0.2.1", "secret", "DO_NOT_LEAK"))
    assert public_catalog(registry, now=2000)["servers"][0]["health"]["state"] == "unknown"
    path.write_text("not json")
    assert public_catalog(registry, now=1000)["servers"][0]["health"]["state"] == "unknown"


def test_snapshot_refresh_is_atomic_and_public_only(tmp_path, monkeypatch):
    monkeypatch.setattr(health, "probe", lambda s: {"state": "ready", "checked_at": 1000})
    monkeypatch.setattr(health, "measure_latency", lambda *args, **kwargs: {"ms": None})
    path=tmp_path / "health.json"
    registry=AwgRegistry((node(),), (), "nl")
    assert refresh(registry, path=path) == json.loads(path.read_text())
    assert list(tmp_path.iterdir()) == [path]


def catalog_with(monkeypatch, row, *, notice=None, servers=None):
    monkeypatch.setattr(health, "read_json", lambda path:
                        {"server_statuses": {"nl": notice or {}}} if path.name == "status.json"
                        else {"servers": {"nl": row}})
    return public_catalog(AwgRegistry(servers or (node(),), (), "nl"),
                          include_unavailable=True, now=1000)


@pytest.mark.parametrize("operator", ["degraded", "maintenance"])
@pytest.mark.parametrize("runtime,checked,expected", [
    ("online", 950, None), ("ready", 950, None),
    ("unavailable", 950, "unavailable"), ("unknown", 950, "unknown"),
    ("online", 399, "unknown"), ("online", 1001, "unknown"),
    ("unexpected", 950, "unknown"), ([], 950, "unknown"),
])
def test_operator_notices_cannot_hide_failed_or_stale_runtime(monkeypatch, operator, runtime, checked, expected):
    item = catalog_with(monkeypatch, {"state": runtime, "checked_at": checked},
                        notice={"state": operator})["servers"][0]["health"]
    assert item["state"] == (expected or operator)
    assert item["operator_state"] == operator
    assert item["runtime_state"] == (expected or runtime)


def test_disabled_server_is_maintenance_with_unknown_runtime(monkeypatch):
    item = catalog_with(monkeypatch, {}, servers=(node(enabled=False),))["servers"][0]["health"]
    assert item["state"] == "maintenance"
    assert item["runtime_state"] == "unknown"


@pytest.mark.parametrize("checked", [None, True, "950", 950.5, {}, [], 0, -1, 1001, 399])
def test_invalid_or_stale_timestamp_drops_aggregates(monkeypatch, checked):
    item = catalog_with(monkeypatch, {
        "state": "online", "checked_at": checked, "recent_connections": 3,
        "available_ports": [443], "traffic": {"received_bytes": 5, "sent_bytes": 10},
    })["servers"][0]["health"]
    assert item["state"] == "unknown"
    assert item["checked_at"] is None and item["stale"]
    assert item["recent_connections"] is None
    assert item["available_ports"] is None and item["traffic"] is None


def test_probe_only_keeps_aggregate_current_runtime_data():
    service = FakeService(
        ports="awg0\t443\nawg1\t3478\n",
        handshakes="peer-a\t950\npeer-a\t950\npeer-b\t700\npeer-c\t699\npeer-d\t1001\npeer-e\t0\n",
        transfer="peer-a\t100\t200\npeer-b\t30\t40\n",
    )
    result = probe(node(), now=1000, service=service)
    assert result["recent_connections"] == 2
    assert result["available_ports"] == [443]
    assert result["traffic"] == {"received_bytes": 130, "sent_bytes": 240}
    assert "peer-" not in json.dumps(result)
    assert service.commands == ["awg show all listen-port", "awg show awg0 latest-handshakes", "awg show awg0 transfer"]


@pytest.mark.parametrize("transfer", [RuntimeError("secret"), "peer\t-1\t2", "peer\tNaN\t2", "peer\t1",
                                      f"peer\t{2**64}\t2"])
def test_optional_invalid_transfer_does_not_change_health(transfer):
    result = probe(node(), now=1000, service=FakeService(transfer=transfer))
    assert result["state"] == "online"
    assert "traffic" not in result
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("ports", ["awg0;id\t443", "awg0\t65536", "awg0\t-1", "bad-output"])
def test_malformed_runtime_ports_are_unknown_and_never_interpolated(ports):
    service = FakeService(ports=ports)
    assert probe(node(), now=1000, service=service)["state"] == "unknown"
    assert service.commands == ["awg show all listen-port"]


def test_malformed_handshake_is_unknown_but_listen_port_is_observed():
    result = probe(node(), now=1000, service=FakeService(handshakes="peer\tbad"))
    assert result["state"] == "unknown"
    assert result["available_ports"] == [443]
    assert "recent_connections" not in result


def test_no_interface_is_unavailable_with_no_observed_ports():
    result = probe(node(), now=1000, service=FakeService(ports=""))
    assert result["state"] == "unavailable"
    assert result["available_ports"] == []


@pytest.mark.parametrize("returncode,received,expected", [(0, 3, 12.345), (1, 1, 12.345), (1, 0, None), (2, 3, None)])
def test_latency_is_bounded_real_nl_reference(monkeypatch, returncode, received, expected):
    monkeypatch.setattr(health.os, "name", "posix")
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=(
            f"3 packets transmitted, {received} received, 0% packet loss\n"
            "rtt min/avg/max/mdev = 10.000/12.345/15.000/1.000 ms\n"))
    monkeypatch.setattr(health.subprocess, "run", run)
    result = measure_latency("192.0.2.2", now=1000)
    assert result == {"ms": expected, "origin": "nl_monitor", "method": "icmp", "scope": "remote", "checked_at": 1000}
    argv, kwargs = calls[0]
    assert argv == ["ping", "-n", "-c", "3", "-W", "1", "-w", "4", "--", "192.0.2.2"]
    assert kwargs["timeout"] == 5 and kwargs["env"]["LC_ALL"] == "C"
    assert not kwargs.get("shell")
    assert "192.0.2.2" not in json.dumps(result)


@pytest.mark.parametrize("failure", [FileNotFoundError("secret"), subprocess.TimeoutExpired("ping", 5)])
def test_ping_failure_is_null(monkeypatch, failure):
    monkeypatch.setattr(health.os, "name", "posix")
    def run(*args, **kwargs):
        raise failure
    monkeypatch.setattr(health.subprocess, "run", run)
    result = measure_latency("192.0.2.2", now=1000)
    assert result["ms"] is None
    assert "state" not in result and "secret" not in json.dumps(result)


@pytest.mark.parametrize("host,local,scope", [
    ("127.0.0.1", False, "local"), ("::1", False, "local"),
    ("localhost", False, "local"), ("192.0.2.1", True, "local"),
    ("host; echo secret", False, "remote"), ("-evil", False, "remote"),
])
def test_local_or_invalid_host_never_runs_ping(monkeypatch, host, local, scope):
    def run(*args, **kwargs):
        pytest.fail("must not run ping")
    monkeypatch.setattr(health.subprocess, "run", run)
    result = measure_latency(host, local=local, now=1000)
    assert result["ms"] is None and result["scope"] == scope


def test_refresh_pings_shared_host_once_and_marks_nl_local(tmp_path, monkeypatch):
    calls = []
    def latency(host, *, local):
        calls.append((host, local))
        return {"ms": None, "origin": "nl_monitor", "method": "icmp", "scope": "local" if local else "remote", "checked_at": 1000}
    monkeypatch.setattr(health, "measure_latency", latency)
    monkeypatch.setattr(health, "probe", lambda s: {"state": "ready", "checked_at": 1000})
    monkeypatch.setenv("VPNW_AWG_MONITOR_SERVER_ID", "nl")
    registry = AwgRegistry((node(), node(id="nl-alt", alt_port=True, listen_port=3478),
                            node(id="fi", host="192.0.2.2"), node(id="off", host="192.0.2.3", enabled=False)), (), "nl")
    result = refresh(registry, path=tmp_path / "health.json")["servers"]
    assert sorted(calls) == [("192.0.2.1", True), ("192.0.2.2", False)]
    assert result["nl"]["latency"] == result["nl-alt"]["latency"]
    assert result["fi"]["state"] == "ready"  # ICMP silence is not VPN downtime.
    assert "latency" not in result["off"]


def test_public_aggregates_group_ports_and_drop_private_payload(monkeypatch):
    monkeypatch.setenv("VPNW_AWG_MONITOR_SERVER_ID", "monitor")
    item = {
        "state": "online", "checked_at": 950, "recent_connections": 3,
        "available_ports": [443, True, "443", 65536, -1, {}, 22, 443],
        "traffic": {"received_bytes": 123, "sent_bytes": 456, "peers": ["PRIVATE"]},
        "latency": {"ms": 12.5, "origin": "nl_monitor", "method": "icmp", "scope": "remote",
                    "checked_at": 950, "host": "PRIVATE", "stdout": "PRIVATE"},
        "private_key": "PRIVATE", "peers": ["PRIVATE"],
    }
    body = catalog_with(monkeypatch, item, servers=(node(id="nl-alt", alt_port=True), node()))
    assert [s["host_group"] for s in body["servers"]] == ["nl", "nl"]
    public = body["servers"][1]["health"]
    assert public["recent_connections"] == 3
    assert public["available_ports"] == [443]
    assert public["traffic"]["received_bytes"] == 123
    assert public["traffic"]["direction"] == "server"
    assert public["latency"]["ms"] == 12.5
    assert public["latency"]["local"] is False
    assert public["latency"]["origin"] == "nl_monitor"
    assert "не пинг с вашего устройства" in public["latency"]["label"]
    encoded = json.dumps(body)
    assert all(s not in encoded for s in ("PRIVATE", "192.0.2.1", "secret"))


@pytest.mark.parametrize("change", [
    {"ms": True}, {"ms": "12"}, {"ms": float("nan")}, {"ms": float("inf")},
    {"ms": -1}, {"ms": 60001}, {"scope": "local"}, {"scope": {}},
    {"origin": "PRIVATE"}, {"method": "ssh"}, {"checked_at": 399}, {"checked_at": 1001},
])
def test_public_latency_rejects_forged_stale_or_local_numbers(monkeypatch, change):
    monkeypatch.setenv("VPNW_AWG_MONITOR_SERVER_ID", "monitor")
    latency = {"ms": 12, "origin": "nl_monitor", "method": "icmp", "scope": "remote", "checked_at": 950, **change}
    result = catalog_with(monkeypatch, {"state": "online", "checked_at": 950, "latency": latency})
    public = result["servers"][0]["health"]["latency"]
    assert public["ms"] is None
    assert "PRIVATE" not in json.dumps(result)


def test_nl_and_same_host_alternatives_never_publish_comparable_latency(monkeypatch):
    monkeypatch.setenv("VPNW_AWG_MONITOR_SERVER_ID", "nl")
    row = {"state": "online", "checked_at": 950,
           "latency": {"ms": 0.03, "origin": "nl_monitor", "method": "icmp",
                       "scope": "remote", "checked_at": 950}}
    body = catalog_with(monkeypatch, row, servers=(node(), node(id="nl-alt", alt_port=True)))
    for server_row in body["servers"]:
        assert server_row["health"]["latency"]["ms"] is None
        assert server_row["health"]["latency"]["scope"] == "local"
        assert server_row["health"]["latency"]["local"] is True
        assert "Локальный сервер" in server_row["health"]["latency"]["label"]


def test_valid_empty_runtime_has_zero_measured_counters():
    result = probe(node(), now=1000, service=FakeService(handshakes="", transfer=""))
    assert result["state"] == "ready"
    assert result["recent_connections"] == 0
    assert result["traffic"] == {"received_bytes": 0, "sent_bytes": 0}


def test_valid_icmp_does_not_upgrade_unavailable_vpn(monkeypatch):
    monkeypatch.setenv("VPNW_AWG_MONITOR_SERVER_ID", "monitor")
    result = catalog_with(monkeypatch, {
        "state": "unavailable", "checked_at": 950, "recent_connections": 10,
        "latency": {"ms": 12, "origin": "nl_monitor", "method": "icmp", "scope": "remote", "checked_at": 950},
    }, notice={"state": "degraded"})["servers"][0]["health"]
    assert result["state"] == "unavailable"
    assert result["latency"]["ms"] == 12
    assert result["recent_connections"] is None


@pytest.mark.parametrize("bad", [True, -1, "5", 1.5, {}, [], 2**64])
def test_public_counters_are_strict_nonnegative_integers(monkeypatch, bad):
    public = catalog_with(monkeypatch, {
        "state": "online", "checked_at": 950, "recent_connections": bad,
        "traffic": {"received_bytes": bad, "sent_bytes": 10},
    })["servers"][0]["health"]
    assert public["recent_connections"] is None and public["traffic"] is None


def test_all_servers_endpoint_is_opt_in_and_never_claims_fake_availability(tmp_path, monkeypatch):
    monkeypatch.setenv("VPNW_AWG_HEALTH_PATH", str(tmp_path / "absent.json"))
    monkeypatch.setenv("VPNW_AWG_SERVERS", json.dumps([
        {"id": "nl", "host": "192.0.2.1", "password": "secret"},
        {"id": "tr", "host": "192.0.2.2", "password": "secret", "enabled": False},
    ]))
    client=TestClient(server.app)
    assert len(client.get("/api/awg/servers").json()["servers"]) == 1
    response=client.get("/api/awg/servers?include_unavailable=true")
    assert len(response.json()["servers"]) == 2
    assert response.json()["servers"][0]["health"]["state"] == "unknown"
    assert response.headers["cache-control"] == "no-store"
    assert "secret" not in response.text and "192.0.2.1" not in response.text


def test_free_country_choice_keeps_authentication_and_device_limit(monkeypatch):
    monkeypatch.setenv("VPNW_AWG_SERVERS", json.dumps([
        {"id": "nl", "host": "192.0.2.1", "password": "p"},
        {"id": "us", "host": "192.0.2.2", "password": "p"},
    ]))
    entitlement=server._AwgEntitlement(None, server.ChannelAccessStatus(configured=True, active=True, server_id="fi"))
    monkeypatch.setenv("VPNW_AWG_FREE_SERVER_CHOICE", "false")
    with pytest.raises(server.HTTPException):
        server._awg_authorise_entitlement(entitlement, server_id="nl", required_device_slot=1)
    monkeypatch.setenv("VPNW_AWG_FREE_SERVER_CHOICE", "true")
    assert free_server_choice_enabled()
    assert server._awg_authorise_entitlement(entitlement, server_id="nl", required_device_slot=1)[0] == 1
    for sid,slot in [("nl",2),("unknown",1)]:
        with pytest.raises(server.HTTPException):
            server._awg_authorise_entitlement(entitlement, server_id=sid, required_device_slot=slot)
    with pytest.raises(server.HTTPException):
        server._awg_authorise_entitlement(server._AwgEntitlement(None, server.ChannelAccessStatus(True,False)), server_id="nl", required_device_slot=1)


@pytest.mark.parametrize("active", [True, False])
def test_reconcile_country_switching_preserves_valid_peers_but_expires_access(active):
    from vpn_wizard.awg_reconcile import reconcile_awg_peers
    class Store:
        def awg_list_peers(self): return []
        def awg_list_server_peers(self):
            return [{"telegram_id": 7, "server_id": "nl", "status": "active"}]
    class Billing:
        def active_user(self, tid): return None
    class Service:
        def suspend(self, tid): assert tid == 7
    result=reconcile_awg_peers(Store(), Billing(), None, server_services={"nl": Service()},
        free_server_id="fi", free_server_choice=True,
        free_access_lookup=lambda tid: server.ChannelAccessStatus(True,active,server_id="fi"))
    assert result["suspended"] == (0 if active else 1)
    assert result["unchanged"] == (1 if active else 0)


def test_webhook_keeps_free_peer_on_selected_country(monkeypatch):
    resumed=[]
    class Service:
        server_id="nl"
        def resume(self, tid): resumed.append(tid)
        def suspend(self, tid): raise AssertionError("must not disable the selected country")
    monkeypatch.setenv("VPNW_AWG_FREE_SERVER_CHOICE", "true")
    monkeypatch.setattr(server,"_awg_all_services",lambda:[Service()])
    monkeypatch.setattr(server,"_awg_peer_ids_for_owner",lambda service,tid:[tid])
    entitlement=server._AwgEntitlement(None,server.ChannelAccessStatus(True,True,server_id="fi"))
    monkeypatch.setattr(server,"_awg_entitlement",lambda tid:entitlement)
    monkeypatch.setattr(server,"channel_access_status",lambda store,tid:entitlement.free)
    monkeypatch.setattr(server,"build_account_store",lambda:None)
    server._awg_webhook_apply("policy",7)
    assert resumed == [7]
