"""The watchdog has to notice an interface that people stopped reaching.

Reachability and capacity both looked perfect on 22-28.08.2026 while sixty-one
profiles on awg1 sat unused: the migration rewrote them with the new address and
nobody handed the files out. Six days, zero handshakes, not a word from anything.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "watchdog" / "fodder-ru-watchdog"

HOUR = 3600
NOW = 1_800_000_000


@pytest.fixture(scope="module")
def watchdog():
    spec = importlib.util.spec_from_loader(
        "fodder_ru_watchdog",
        importlib.machinery.SourceFileLoader("fodder_ru_watchdog", str(SCRIPT)),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def row(**kwargs) -> dict:
    base = {
        "iface": "awg0",
        "peers": 48,
        "newest_handshake": NOW - 60,
        "up_since": NOW - 30 * 24 * HOUR,
        "has_mss_rule": True,
        "has_syncconf": True,
    }
    base.update(kwargs)
    return base


# --- parsing -------------------------------------------------------------------

def test_probe_lines_become_rows(watchdog) -> None:
    text = (
        "IFACE|awg0|48|1787948458|1787000000|1|1\n"
        "IFACE|awg1|61|0|1787000000|1|1\n"
    )
    rows = watchdog.parse_iface_probe(text)
    assert [r["iface"] for r in rows] == ["awg0", "awg1"]
    assert rows[0]["peers"] == 48
    assert rows[1]["newest_handshake"] == 0
    assert rows[0]["has_mss_rule"] is True


def test_noise_from_the_shell_is_ignored(watchdog) -> None:
    text = (
        "Warning: Permanently added 'x' to the list of known hosts.\n"
        "IFACE|awg0|48|1787948458|1787000000|1|1\n"
        "IFACE|broken|not-a-number|0|0|0|0\n"
        "IFACE|short|1|2\n"
    )
    assert [r["iface"] for r in watchdog.parse_iface_probe(text)] == ["awg0"]


# --- the judgement -------------------------------------------------------------

def test_an_interface_nobody_reaches_is_reported(watchdog) -> None:
    rows = [row(iface="awg1", peers=61, newest_handshake=0, up_since=NOW - 6 * 24 * HOUR)]
    (complaint,) = watchdog.interface_complaints(rows, NOW)
    assert "awg1" in complaint and "61" in complaint
    assert "144" in complaint  # six days, spelled out in hours


def test_a_busy_interface_says_nothing(watchdog) -> None:
    assert watchdog.interface_complaints([row()], NOW) == []


def test_a_freshly_restarted_interface_is_not_accused(watchdog) -> None:
    # Restarting zeroes every handshake, so a young interface always looks
    # abandoned. Crying then would train the owner to ignore the alert.
    rows = [row(iface="awg9", peers=32, newest_handshake=0, up_since=NOW - HOUR)]
    assert watchdog.interface_complaints(rows, NOW) == []


def test_an_interface_that_went_quiet_reports_how_long(watchdog) -> None:
    rows = [row(newest_handshake=NOW - 50 * HOUR)]
    (complaint,) = watchdog.interface_complaints(rows, NOW)
    assert "50 ч назад" in complaint


def test_small_interfaces_are_left_alone(watchdog) -> None:
    # Someone's personal tunnel on a shared box, or a test bed of ours.
    rows = [row(iface="awg0", peers=2, newest_handshake=0, has_mss_rule=False)]
    assert watchdog.interface_complaints(rows, NOW) == []


def test_a_missing_mss_rule_is_reported(watchdog) -> None:
    # The 28.08.2026 outage: tunnel up, handshakes fine, large TCP silently lost.
    (complaint,) = watchdog.interface_complaints([row(has_mss_rule=False)], NOW)
    assert "TCPMSS" in complaint


def test_tools_without_syncconf_are_reported(watchdog) -> None:
    (complaint,) = watchdog.interface_complaints([row(has_syncconf=False)], NOW)
    assert "syncconf" in complaint


def test_the_window_is_configurable(watchdog, monkeypatch) -> None:
    monkeypatch.setattr(watchdog, "SILENT_HOURS", 1)
    rows = [row(newest_handshake=NOW - 2 * HOUR, up_since=NOW - 10 * HOUR)]
    assert watchdog.interface_complaints(rows, NOW)
