from __future__ import annotations

from pathlib import Path

import pytest

from vpn_wizard.account import AccountStore
from vpn_wizard.awg_fallback import device_peer_id, family_guest_id
from vpn_wizard.metrics import (
    ACTIVE_WINDOW,
    alerts,
    audience_split,
    business_from_bot,
    collect,
    connection_funnel,
    invite_stats,
    owner_ids,
    usage_by_country,
)
from vpn_wizard.web_signup import create_invite, web_account_id

OWNER = 449066726
FRIEND = 7938373718
NOW = 1_800_000_000


def _store(tmp_path: Path) -> AccountStore:
    return AccountStore(tmp_path / "state.db", secret_key="unit-test-secret")


def _issue(store, peer_id, server_id, address="10.10.0.5", status="active"):
    config = f"[Interface]\nPrivateKey = k\nAddress = {address}/32\n"
    if server_id is None:
        store.awg_save_peer(peer_id, client_name=f"sub-{peer_id}", remnawave_uuid=None,
                            config=config, status=status)
    else:
        store.awg_save_server_peer(peer_id, server_id, client_name=f"sub-{peer_id}",
                                   remnawave_uuid=None, config=config, status=status)


class _Registry:
    class _S:
        def __init__(self, sid, label, enabled=True):
            self.id, self.display, self.enabled = sid, label, enabled

    servers = (_S("nl", "🇳🇱 Нидерланды"), _S("fi", "🇫🇮 Финляндия"), _S("tr", "🇹🇷 Турция", False))


# --- the funnel is about handshakes, not sign-ups --------------------------------

def test_funnel_counts_people_who_actually_connected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, None)
    _issue(store, OWNER, "fi")
    _issue(store, FRIEND, None)

    store.awg_record_usage("nl", OWNER, last_handshake_at=NOW - 60, rx_bytes=10, tx_bytes=20)
    # FRIEND has a key but has never completed a handshake.

    funnel = connection_funnel(store, "nl", paying_owners={OWNER}, now=NOW)
    assert funnel["issued_key"] == 2          # two people hold keys
    assert funnel["ever_connected"] == 1
    assert funnel["active_7d"] == 1
    assert funnel["paying"] == 1
    assert funnel["connect_rate"] == 50.0
    assert funnel["keys_never_used"] == 2     # FRIEND's, and OWNER's unused fi key


def test_a_key_that_never_carried_a_packet_is_not_a_user(tmp_path: Path) -> None:
    # The whole point: sign-ups look identical to real usage until you check this.
    store = _store(tmp_path)
    _issue(store, OWNER, None)
    funnel = connection_funnel(store, "nl", now=NOW)
    assert funnel["issued_key"] == 1
    assert funnel["ever_connected"] == 0
    assert funnel["connect_rate"] == 0.0


def test_stale_users_drop_out_of_the_active_window(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, None)
    store.awg_record_usage("nl", OWNER, last_handshake_at=NOW - ACTIVE_WINDOW - 1,
                           rx_bytes=1, tx_bytes=1)
    funnel = connection_funnel(store, "nl", now=NOW)
    assert funnel["ever_connected"] == 1
    assert funnel["active_7d"] == 0
    assert funnel["retention_rate"] == 0.0


def test_extra_device_and_family_keys_belong_to_one_person(tmp_path: Path) -> None:
    # Otherwise a 3-device subscriber would be counted as three customers.
    store = _store(tmp_path)
    _issue(store, OWNER, None)
    _issue(store, family_guest_id(OWNER), None)
    _issue(store, device_peer_id(OWNER, 3), None)
    assert connection_funnel(store, "nl", now=NOW)["issued_key"] == 1


# --- per country ------------------------------------------------------------------

def test_usage_by_country_ranks_by_real_activity(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, "fi")
    _issue(store, FRIEND, "fi")
    _issue(store, OWNER, "tr")
    store.awg_record_usage("fi", OWNER, last_handshake_at=NOW - 60, rx_bytes=1024, tx_bytes=2048)

    countries = usage_by_country(store, _Registry(), "nl", now=NOW)
    top = countries[0]
    assert top["id"] == "fi"
    assert top["label"] == "🇫🇮 Финляндия"
    assert top["keys"] == 2 and top["active_keys"] == 1
    assert top["bytes"] == 3072

    turkey = next(c for c in countries if c["id"] == "tr")
    assert turkey["enabled"] is False          # hidden from the picker, still reported
    assert turkey["connected_keys"] == 0


# --- audience ---------------------------------------------------------------------

def test_audience_splits_telegram_from_website_signups(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, None)
    _issue(store, web_account_id(1), None)
    _issue(store, web_account_id(2), "fi")

    split = audience_split(store, "nl")
    assert split == {"total": 3, "from_invite": 2, "from_telegram": 1}


# --- invites ----------------------------------------------------------------------

def test_invite_stats_separate_live_from_spent_and_expired(tmp_path: Path) -> None:
    store = _store(tmp_path)
    from vpn_wizard.web_signup import InviteConfig

    live = create_invite(store, OWNER, now=NOW)
    spent = create_invite(store, OWNER, now=NOW)
    store.invite_redeem(spent["code"], web_account_id(3), now=NOW)
    create_invite(store, OWNER, InviteConfig(ttl_days=1), now=NOW - 3 * 86400)

    stats = invite_stats(store, [OWNER], now=NOW)
    assert stats["issued"] == 3
    assert stats["redeemed"] == 1
    assert stats["outstanding"] == 1
    assert stats["expired"] == 1
    assert stats["redeem_rate"] == 33.3
    assert live["code"]


# --- reshaping the bot's numbers ---------------------------------------------------

BOT_STATS = {
    "overview": {"users": {"total": 3, "balance_rubles": 100.0}, "payments": {"today_rubles": 0.0}},
    "users": {"total_users": 3, "new_today": 1, "new_week": 2, "new_month": 3},
    "subscriptions": {
        "active_subscriptions": 2, "trial_subscriptions": 2, "paid_subscriptions": 0,
        "purchased_week": 0, "purchased_month": 0, "trial_to_paid_conversion": 0.0,
        "renewals_count": 0,
    },
}


def test_business_section_reads_the_bots_own_aggregates() -> None:
    business = business_from_bot(BOT_STATS)
    assert business["users_total"] == 3
    assert business["new_week"] == 2
    assert business["subs_trial"] == 2
    assert business["subs_paid"] == 0
    assert business["balance_rubles"] == 100.0


def test_business_section_survives_the_bot_being_down() -> None:
    # The dashboard must still render our own numbers if the bot API is unreachable.
    business = business_from_bot(None)
    assert business["users_total"] == 0 and business["subs_active"] == 0


# --- alerts -----------------------------------------------------------------------

def test_alerts_lead_with_nobody_ever_connecting(tmp_path: Path) -> None:
    funnel = {"issued_key": 5, "ever_connected": 0, "keys_never_used": 5}
    messages = alerts(funnel, [], business_from_bot(BOT_STATS))
    assert messages[0]["level"] == "critical"
    assert "ни один" in messages[0]["text"]


def test_alerts_name_a_country_that_answers_nobody() -> None:
    funnel = {"issued_key": 2, "ever_connected": 2, "keys_never_used": 0}
    countries = [{"label": "🇹🇷 Турция", "keys": 3, "connected_keys": 0, "enabled": False}]
    messages = alerts(funnel, countries, business_from_bot(BOT_STATS))
    assert any("Турция" in m["text"] and "отключена" in m["text"] for m in messages)


def test_alerts_stay_quiet_when_everything_works() -> None:
    funnel = {"issued_key": 4, "ever_connected": 4, "keys_never_used": 0}
    countries = [{"label": "🇫🇮", "keys": 4, "connected_keys": 4, "enabled": True}]
    healthy = dict(business_from_bot(BOT_STATS), subs_paid=3)
    assert alerts(funnel, countries, healthy) == []


# --- the whole payload --------------------------------------------------------------

def test_collect_assembles_every_section(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _issue(store, OWNER, None)
    store.awg_record_usage("nl", OWNER, last_handshake_at=NOW - 30, rx_bytes=5, tx_bytes=7)

    report = collect(store, _Registry(), BOT_STATS, legacy_server_id="nl",
                     paying_owners={OWNER}, now=NOW)
    assert report["ok"] is True
    assert report["bot_reachable"] is True
    assert report["generated_at"] == NOW
    assert set(report) >= {"business", "funnel", "audience", "countries", "invites", "alerts"}
    assert report["traffic_bytes"] == 12


def test_collect_still_works_without_the_bot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    report = collect(store, _Registry(), None, legacy_server_id="nl", now=NOW)
    assert report["bot_reachable"] is False
    assert report["business"]["users_total"] == 0


# --- access -------------------------------------------------------------------------

def test_owner_ids_parses_whatever_the_env_holds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VPNW_OWNER_IDS", " 449066726, 7938373718 ;abc,")
    assert owner_ids() == {449066726, 7938373718}
    monkeypatch.delenv("VPNW_OWNER_IDS")
    assert owner_ids() == set()


# --- the endpoint -------------------------------------------------------------------

def test_metrics_endpoint_is_owner_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    import vpn_wizard.server as server_module
    from vpn_wizard.awg_fallback import issue_token

    secret = "link-secret"
    monkeypatch.setenv("VPNW_STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("VPNW_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("VPNW_AWG_LINK_SECRET", secret)
    monkeypatch.setenv("VPNW_AWG_FALLBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("VPNW_AWG_FALLBACK_SSH_PASSWORD", "p")
    monkeypatch.setenv("VPNW_OWNER_IDS", str(OWNER))
    monkeypatch.setattr(server_module, "BotApiClient", lambda *a, **k: type(
        "B", (), {"config": type("C", (), {"configured": False})(), "_get": lambda self, p: None}
    )())

    client = TestClient(server_module.app)

    ok = client.get("/api/metrics", params={"telegram_id": OWNER, "token": issue_token(secret, OWNER)})
    assert ok.status_code == 200
    assert ok.json()["ok"] is True

    # A perfectly valid subscriber token must not open the books.
    other = client.get(
        "/api/metrics", params={"telegram_id": FRIEND, "token": issue_token(secret, FRIEND)}
    )
    assert other.status_code == 403

    # Nor a forged token for the owner.
    forged = client.get("/api/metrics", params={"telegram_id": OWNER, "token": "deadbeef"})
    assert forged.status_code == 403
