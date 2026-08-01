"""The panel client must never turn its own breakage into "this user has no rights"."""
from __future__ import annotations

import json
from urllib.error import HTTPError

import pytest

from vpn_wizard.remnawave import RemnawaveClient, RemnawaveConfig, RemnawaveError


def _client(monkeypatch, responder) -> RemnawaveClient:
    client = RemnawaveClient(
        RemnawaveConfig(api_url="https://panel.example", api_key="k", webhook_secret="s")
    )
    monkeypatch.setattr("vpn_wizard.remnawave.urlopen", responder)
    return client


class _Body:
    def __init__(self, payload: dict) -> None:
        self._payload = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_Body":
        return self

    def __exit__(self, *exc) -> None:
        return None


def test_unknown_user_is_an_empty_answer_not_an_error(monkeypatch) -> None:
    # This is how the panel really replies for a telegram id it has never seen.
    def responder(request, timeout=None):
        return _Body({"response": []})

    client = _client(monkeypatch, responder)
    assert client.users_by_telegram_id(1) == []
    assert client.active_user(1) is None


def test_a_404_is_raised_rather_than_read_as_no_rights(monkeypatch) -> None:
    # A 404 means the route is wrong — an upgrade moved it, a proxy swallowed it.
    # Returning "no users" instead made a broken panel look exactly like every
    # subscriber having expired, and reconcile then had no way to tell the
    # difference except to refuse to suspend anyone at all.
    def responder(request, timeout=None):
        raise HTTPError("https://panel.example", 404, "Not Found", {}, None)

    client = _client(monkeypatch, responder)
    with pytest.raises(RemnawaveError):
        client.users_by_telegram_id(1)


def test_other_http_errors_still_raise(monkeypatch) -> None:
    def responder(request, timeout=None):
        raise HTTPError("https://panel.example", 401, "Unauthorized", {}, None)

    client = _client(monkeypatch, responder)
    with pytest.raises(RemnawaveError):
        client.active_user(1)
