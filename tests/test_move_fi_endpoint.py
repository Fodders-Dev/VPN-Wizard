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
    assert nodes[1]["host"] == nodes[2]["host"] == "46.38.156.229"
    assert nodes[1]["listen_port"] == 3478
    assert nodes[2]["listen_port"] == 4500
    assert result.startswith("VPNW_AWG_DEFAULT_SERVER=nl\n")
    assert result.endswith("KEEP=value\n")
    assert module.migrate(result, 3478) == result


def test_host_only_retains_listeners():
    result = module.migrate(env())
    assert '"listen_port":443,"interface":"awg9"' in result


def test_unexpected_host_or_interface_rejected():
    for source in (env().replace("193.222.97.50", "unexpected.example"),
                   env().replace("awg9", "awg0")):
        with pytest.raises(ValueError):
            module.migrate(source, 3478)
