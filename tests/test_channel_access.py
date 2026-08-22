from __future__ import annotations

from vpn_wizard.account import AccountStore
from vpn_wizard.channel_access import ChannelAccessConfig, access_status
from vpn_wizard.web_signup import web_account_id


def _config() -> ChannelAccessConfig:
    return ChannelAccessConfig(
        enabled=True,
        channel_id="-1002358992995",
        channel_url="https://t.me/fodders_dev",
        free_server_ids=("nl",),
        web_grace_hours=12,
        membership_cache_seconds=300,
        bot_token="123:test",
    )


def test_website_grace_expires_after_twelve_hours(tmp_path) -> None:
    store = AccountStore(tmp_path / "state.db", "secret")
    access_id = web_account_id(10)
    store.channel_access_grant_grace(
        access_id,
        "ABCD-2345",
        expires_at=1_000 + 12 * 3600,
        now=1_000,
    )

    active = access_status(store, access_id, _config(), now=1_000 + 12 * 3600 - 1)
    expired = access_status(store, access_id, _config(), now=1_000 + 12 * 3600)

    assert active.active is True
    assert active.kind == "grace"
    assert expired.active is False


def test_membership_cache_then_forced_leave_suspends_access(monkeypatch, tmp_path) -> None:
    store = AccountStore(tmp_path / "state.db", "secret")
    store.channel_access_grant_member(10101, checked_at=1_000)
    calls: list[int] = []

    monkeypatch.setattr(
        "vpn_wizard.channel_access.telegram_channel_member",
        lambda _config, telegram_id: calls.append(telegram_id) or False,
    )

    cached = access_status(store, 10101, _config(), now=1_100)
    refreshed = access_status(
        store, 10101, _config(), refresh_membership=True, now=1_101
    )

    assert cached.active is True
    assert calls == [10101]
    assert refreshed.active is False
    assert store.channel_access_by_telegram(10101)["status"] == "suspended"
