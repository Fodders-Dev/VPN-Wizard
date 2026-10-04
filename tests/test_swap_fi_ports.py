import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).parents[1] / 'deploy/scripts/swap-fi-ports.py'
spec = importlib.util.spec_from_file_location('swap_fi', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_port_swap_retains_keys_and_peers():
    text = '[Interface]\nPrivateKey = same-key\nListenPort = 443\n[Peer]\nPublicKey = same-peer\n'
    assert module.replace_port(text, 3478) == text.replace('ListenPort = 443', 'ListenPort = 3478')
    assert module.replace_port(module.replace_port(text, 3478), 3478) == module.replace_port(text, 3478)


def test_endpoint_keeps_all_other_profile_fields():
    text = '[Interface]\nPrivateKey = client-key\n[Peer]\nEndpoint = 193.222.97.50:443 # server\nPublicKey = same-key\n'
    assert module.replace_endpoint(text, 3478) == text.replace('193.222.97.50:443', '46.38.156.229:3478')


def test_port_swap_rejects_missing_or_duplicate_field():
    for text in ('PrivateKey = same-key\n', 'ListenPort = 443\nListenPort = 3478\n'):
        with pytest.raises(ValueError):
            module.replace_port(text, 3478)
