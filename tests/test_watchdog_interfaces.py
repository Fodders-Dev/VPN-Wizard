"""The watchdog has to notice an interface that people stopped reaching.

Reachability and capacity both looked perfect on 22-28.08.2026 while sixty-one
profiles on awg1 sat unused: the migration rewrote them with the new address and
nobody handed the files out. Six days, zero handshakes, not a word from anything.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "watchdog" / "fodder-ru-watchdog"

HOUR = 3600
NOW = 1_800_000_000


@pytest.fixture(scope="module")
def watchdog():
    loader = importlib.machinery.SourceFileLoader("fodder_ru_watchdog", str(SCRIPT))
    spec = importlib.util.spec_from_loader("fodder_ru_watchdog", loader)
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


def kinds(complaints) -> list[str]:
    return [c["kind"] for c in complaints]


def texts(complaints) -> str:
    return " | ".join(c["text"] for c in complaints)


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


# --- whose interface is it -----------------------------------------------------

def test_a_dedicated_exit_owns_only_its_own_interface(watchdog) -> None:
    assert watchdog.own_interfaces({"interface": "awg9"}) == ("awg9",)


def test_a_box_of_ours_owns_the_usual_interfaces(watchdog) -> None:
    assert "awg0" in watchdog.own_interfaces()
    assert "awg1" in watchdog.own_interfaces({})


def test_somebody_elses_tunnel_is_none_of_our_business(watchdog) -> None:
    """The Finnish exit runs our awg9 beside the owner's personal awg0 and awg1.
    Theirs are MTU 1420 end to end and need no clamp; complaining about them
    would be both noise and wrong."""
    foreign = row(iface="awg0", peers=1, has_mss_rule=False, has_syncconf=False)
    assert watchdog.interface_complaints([foreign], NOW, own=("awg9",)) == []


# --- the judgement -------------------------------------------------------------

def test_an_interface_nobody_reaches_is_reported(watchdog) -> None:
    rows = [row(iface="awg1", peers=61, newest_handshake=0, up_since=NOW - 6 * 24 * HOUR)]
    complaints = watchdog.interface_complaints(rows, NOW)
    assert kinds(complaints) == ["silent"]
    assert "awg1" in texts(complaints) and "61" in texts(complaints)
    assert "144" in texts(complaints)  # six days, spelled out in hours


def test_a_busy_interface_says_nothing(watchdog) -> None:
    assert watchdog.interface_complaints([row()], NOW) == []


def test_a_freshly_restarted_interface_is_not_accused(watchdog) -> None:
    # Restarting zeroes every handshake, so a young interface always looks
    # abandoned. Crying then would train the owner to ignore the alert.
    rows = [row(iface="awg1", peers=32, newest_handshake=0, up_since=NOW - HOUR)]
    assert watchdog.interface_complaints(rows, NOW) == []


def test_an_interface_that_went_quiet_reports_how_long(watchdog) -> None:
    complaints = watchdog.interface_complaints([row(newest_handshake=NOW - 50 * HOUR)], NOW)
    assert "50 ч назад" in texts(complaints)


def test_a_thin_interface_is_not_called_abandoned(watchdog) -> None:
    rows = [row(iface="awg0", peers=2, newest_handshake=0, up_since=NOW - 6 * 24 * HOUR)]
    assert kinds(watchdog.interface_complaints(rows, NOW)) == []


def test_but_its_config_is_still_checked(watchdog) -> None:
    """A two-peer exit without the clamp loses large TCP exactly like a
    fifty-peer one — the 28.08.2026 outage does not care about headcount."""
    rows = [row(iface="awg0", peers=2, has_mss_rule=False)]
    assert kinds(watchdog.interface_complaints(rows, NOW)) == ["mss"]


def test_a_missing_mss_rule_is_reported(watchdog) -> None:
    (complaint,) = watchdog.interface_complaints([row(has_mss_rule=False)], NOW)
    assert complaint["kind"] == "mss"
    assert "TCPMSS" in complaint["text"]


def test_tools_without_syncconf_are_reported(watchdog) -> None:
    (complaint,) = watchdog.interface_complaints([row(has_syncconf=False)], NOW)
    assert complaint["kind"] == "syncconf"


def test_the_window_is_configurable(watchdog, monkeypatch) -> None:
    monkeypatch.setattr(watchdog, "SILENT_HOURS", 1)
    rows = [row(newest_handshake=NOW - 2 * HOUR, up_since=NOW - 10 * HOUR)]
    assert kinds(watchdog.interface_complaints(rows, NOW)) == ["silent"]


# --- what the owner actually receives ------------------------------------------

def _fire(watchdog, monkeypatch, probe_line: str, state: dict | None = None):
    sent: list[str] = []
    monkeypatch.setattr(watchdog, "notify", lambda text: sent.append(text))
    monkeypatch.setattr(watchdog, "remote_output", lambda script, target=None: (probe_line, ""))
    monkeypatch.setattr(watchdog, "exit_targets", lambda: [])
    state = {} if state is None else state
    watchdog.check_interfaces(state, NOW)
    return sent, state


def test_a_config_fault_does_not_send_people_hunting_for_users(watchdog, monkeypatch) -> None:
    """The old copy explained every complaint as "people are not reaching you",
    which for a missing TCPMSS rule points the owner at the wrong thing."""
    sent, _ = _fire(watchdog, monkeypatch, f"IFACE|awg0|48|{NOW - 60}|{NOW - 10 * 24 * HOUR}|0|1\n")
    assert len(sent) == 1
    assert "iptables" in sent[0]
    assert "роздали" not in sent[0]


def test_silence_still_reads_as_silence(watchdog, monkeypatch) -> None:
    sent, _ = _fire(watchdog, monkeypatch, f"IFACE|awg1|61|0|{NOW - 10 * 24 * HOUR}|1|1\n")
    assert len(sent) == 1
    assert "роздали" in sent[0]


def test_a_config_fault_outranks_silence(watchdog, monkeypatch) -> None:
    sent, state = _fire(watchdog, monkeypatch, f"IFACE|awg1|61|0|{NOW - 10 * 24 * HOUR}|0|1\n")
    assert state["ifaces:NL · панель и сайт"]["status"] == "mss"
    assert "iptables" in sent[0]
    assert "ни одного подключения" in sent[0]  # the silence is still named


def test_a_second_silent_interface_is_not_swallowed_by_the_first(watchdog, monkeypatch) -> None:
    """State is per box. If awg1 is already quiet and awg0 goes quiet too, a
    plain ok/silent flag never changes and nobody hears about awg0."""
    quiet1 = f"IFACE|awg1|61|0|{NOW - 10 * 24 * HOUR}|1|1\n"
    quiet2 = quiet1 + f"IFACE|awg0|48|0|{NOW - 10 * 24 * HOUR}|1|1\n"
    sent, state = _fire(watchdog, monkeypatch, quiet1)
    assert len(sent) == 1
    sent2, _ = _fire(watchdog, monkeypatch, quiet2, state)
    assert len(sent2) == 1, "the second interface going quiet has to be news"


def test_a_state_file_from_an_older_version_does_not_re_announce(watchdog, monkeypatch) -> None:
    # Entries written before this change carry no "culprits" key. Treating the
    # missing key as "nothing was wrong" invented a fresh alert for an incident
    # the owner had already been told about.
    old = {
        "ifaces:NL · панель и сайт": {
            "status": "silent",
            "since": NOW - HOUR,
            "last_alert": NOW - 60,
        }
    }
    sent, _ = _fire(watchdog, monkeypatch, f"IFACE|awg1|61|0|{NOW - 10 * 24 * HOUR}|1|1\n", old)
    assert sent == []


def test_recovery_is_announced_once(watchdog, monkeypatch) -> None:
    healthy = f"IFACE|awg1|61|{NOW - 60}|{NOW - 10 * 24 * HOUR}|1|1\n"
    state = {
        "ifaces:NL · панель и сайт": {
            "status": "silent",
            "since": NOW - HOUR,
            "last_alert": NOW - 60,
            "culprits": ["awg1:silent"],
        }
    }
    sent, state = _fire(watchdog, monkeypatch, healthy, state)
    assert len(sent) == 1 and "снова живые" in sent[0]
    sent2, _ = _fire(watchdog, monkeypatch, healthy, state)
    assert sent2 == []
