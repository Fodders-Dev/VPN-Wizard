"""Traffic has to survive the interface being rebuilt.

The device counters start again from zero every time the interface is torn down,
and the daily summary quoted them verbatim. On 28.08.2026 that made Finland look
like it carried 4.7 GB against the Netherlands' 26.8 GB, when measuring the live
rate showed Finland actually moving four times more traffic — the two interfaces
had simply been restarted six hours apart.
"""
from __future__ import annotations

import pytest

from vpn_wizard.account import AccountStore


@pytest.fixture()
def store(tmp_path) -> AccountStore:
    return AccountStore(tmp_path / "state.db", secret_key="unit-test-secret")


def record(store: AccountStore, rx: int, tx: int, *, seen: int | None = 1_000) -> None:
    store.awg_record_usage("fi", 42, last_handshake_at=seen, rx_bytes=rx, tx_bytes=tx)


def totals(store: AccountStore) -> tuple[int, int]:
    row = store.awg_get_usage([42])[("fi", 42)]
    return row["rx_total"], row["tx_total"]


def test_a_first_reading_is_taken_whole(store: AccountStore) -> None:
    record(store, 100, 200)
    assert totals(store) == (100, 200)


def test_climbing_counters_add_only_the_difference(store: AccountStore) -> None:
    record(store, 100, 200)
    record(store, 150, 260)
    record(store, 150, 260)  # a quiet minute must not double-count
    assert totals(store) == (150, 260)


def test_a_restart_does_not_erase_what_came_before(store: AccountStore) -> None:
    record(store, 1_000, 2_000)
    record(store, 30, 40)  # interface rebuilt: counters start over
    assert totals(store) == (1_030, 2_040)


def test_traffic_after_a_restart_keeps_accumulating(store: AccountStore) -> None:
    record(store, 1_000, 2_000)
    record(store, 30, 40)
    record(store, 90, 100)
    assert totals(store) == (1_090, 2_100)


def test_the_live_reading_is_still_available(store: AccountStore) -> None:
    # Useful on its own: it answers "how much since this interface came up".
    record(store, 1_000, 2_000)
    record(store, 30, 40)
    row = store.awg_get_usage([42])[("fi", 42)]
    assert (row["rx_bytes"], row["tx_bytes"]) == (30, 40)


def test_an_existing_database_keeps_the_traffic_it_had(tmp_path) -> None:
    import sqlite3

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE awg_peer_usage (
            server_id TEXT NOT NULL,
            telegram_id INTEGER NOT NULL,
            last_handshake_at INTEGER,
            rx_bytes INTEGER NOT NULL DEFAULT 0,
            tx_bytes INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (server_id, telegram_id)
        );
        INSERT INTO awg_peer_usage VALUES ('nl', 7, 111, 500, 600, 111);
        """
    )
    conn.commit()
    conn.close()

    store = AccountStore(path, secret_key="unit-test-secret")
    row = store.awg_get_usage([7])[("nl", 7)]
    assert (row["rx_total"], row["tx_total"]) == (500, 600)
    # The backfilled reading is the baseline, so the next poll adds only growth.
    store.awg_record_usage("nl", 7, last_handshake_at=222, rx_bytes=550, tx_bytes=700)
    row = store.awg_get_usage([7])[("nl", 7)]
    assert (row["rx_total"], row["tx_total"]) == (550, 700)


def test_metrics_report_the_lifetime_total(store: AccountStore) -> None:
    from vpn_wizard import metrics

    record(store, 1_000, 2_000)
    record(store, 30, 40)  # restart

    class Registry:
        servers: list = []

    peers = [{"server_id": "fi", "telegram_id": 42}]
    monkey = metrics._collect_peers
    metrics._collect_peers = lambda account, legacy: peers
    try:
        (bucket,) = metrics.usage_by_country(store, Registry(), None, now=2_000)
    finally:
        metrics._collect_peers = monkey
    assert bucket["bytes"] == 1_030 + 2_040
