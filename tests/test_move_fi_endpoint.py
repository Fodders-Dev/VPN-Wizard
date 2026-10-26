import importlib.util
import json
from pathlib import Path

import pytest

path = Path(__file__).parents[1] / "deploy/scripts/move-fi-endpoint.py"
spec = importlib.util.spec_from_file_location("move_fi", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def env():
    nodes = [dict(id="nl", host="nl.example", listen_port=443, key_path="secret-path"),
             dict(id="fi", host="193.222.97.50", listen_port=443, interface="awg9"),
             dict(id="fi-alt", host="193.222.97.50", listen_port=4500, interface="awg8")]
    return "VPNW_AWG_DEFAULT_SERVER=nl\nVPNW_AWG_SERVERS='" + json.dumps(nodes) + "'\nKEEP=value\n"


def test_move_preserves_ids_alternate_port_and_legacy_default():
    result = module.migrate(env(), 3478)
    nodes = json.loads(result.splitlines()[1].partition("=")[2].strip("'"))
    assert nodes[0] == json.loads(env().splitlines()[1].partition("=")[2].strip("'"))[0]
    assert nodes[1]["host"] == nodes[2]["host"] == "185.202.207.126"
    assert nodes[1]["listen_port"] == 3478
    assert nodes[2]["listen_port"] == 4500
    assert result.startswith("VPNW_AWG_DEFAULT_SERVER=nl\n")
    assert result.endswith("KEEP=value\n")
    assert module.migrate(result, 3478) == result


def test_host_only_retains_listeners():
    result = module.migrate(env())
    assert '"host":"185.202.207.126"' in result
    assert '"listen_port":443,"interface":"awg9"' in result


def test_unexpected_host_or_interface_rejected():
    for source in (env().replace("193.222.97.50", "unexpected.example"),
                   env().replace("awg9", "awg0")):
        with pytest.raises(ValueError):
            module.migrate(source, 3478)


def test_new_ip_is_reusable_and_migration_remains_idempotent():
    result = module.migrate(env(), new_ip="203.0.113.42")
    assert '"host":"203.0.113.42"' in result
    assert module.migrate(result, new_ip="203.0.113.42") == result


def test_custom_new_ip_accepts_the_current_default_as_source():
    current = env().replace("193.222.97.50", module.DEFAULT_FI_IP)
    result = module.migrate(current, new_ip="203.0.113.42")
    assert result.count('"host":"203.0.113.42"') == 2


def test_historical_fi_hosts_remain_accepted():
    for historical in ("193.222.97.50", "46.38.156.229"):
        result = module.migrate(env().replace("193.222.97.50", historical))
        assert '"host":"185.202.207.126"' in result
