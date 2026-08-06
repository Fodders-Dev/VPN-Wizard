from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from vpn_wizard.account import AccountStore
from vpn_wizard.awg_fallback import (
    AwgFallbackService,
    device_owner_slot,
    device_peer_id,
    family_guest_id,
    family_issue_token,
    family_owner_id,
    issue_token,
    peer_name,
    verify_family_issue_token,
    verify_issue_token,
)
from vpn_wizard.awg_reconcile import reconcile_awg_peers
from vpn_wizard.remnawave import (
    device_limit_of,
    event_action,
    parse_event,
    telegram_id_of,
    user_is_active,
    verify_webhook_signature,
)


def _store(tmp_path: Path) -> AccountStore:
    return AccountStore(tmp_path / "state.db", secret_key="unit-test-secret")


# --- webhook signature --------------------------------------------------------

def test_verify_webhook_signature_roundtrip() -> None:
    secret = "s3cr3t"
    body = b'{"event":"user.disabled","data":{}}'
    good = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(secret, body, good) is True
    assert verify_webhook_signature(secret, body, good.upper()) is False
    assert verify_webhook_signature(secret, body, "deadbeef") is False
    assert verify_webhook_signature(secret, body, None) is False
    assert verify_webhook_signature("", body, good) is False


def test_parse_event_and_action() -> None:
    body = json.dumps({"event": "user.expired", "data": {"telegramId": "42", "status": "EXPIRED"}}).encode()
    event, user = parse_event(body)
    assert event == "user.expired"
    assert telegram_id_of(user) == 42
    assert event_action("user.expired") == "disable"
    assert event_action("user.enabled") == "enable"
    assert event_action("user.bandwidth_usage_threshold_reached") is None


# --- entitlement --------------------------------------------------------------

def test_user_is_active_variants() -> None:
    assert user_is_active({"status": "ACTIVE"}) is True
    assert user_is_active({"status": "DISABLED"}) is False
    assert user_is_active({"status": "LIMITED"}) is False
    assert user_is_active({"status": "ACTIVE", "expireAt": "2000-01-01T00:00:00Z"}) is False
    assert user_is_active({"status": "ACTIVE", "expireAt": "2999-01-01T00:00:00.000Z"}) is True


def test_device_limit_fails_closed_and_is_bounded() -> None:
    assert device_limit_of({}) == 1
    assert device_limit_of({"hwidDeviceLimit": None}) == 1
    assert device_limit_of({"hwidDeviceLimit": 0}) == 1
    assert device_limit_of({"hwidDeviceLimit": "5"}) == 5
    assert device_limit_of({"hwidDeviceLimit": 1000}) == 99


# --- link token ---------------------------------------------------------------

def test_issue_token_roundtrip() -> None:
    secret = "link-secret"
    token = issue_token(secret, 777)
    assert verify_issue_token(secret, 777, token) is True
    assert verify_issue_token(secret, 778, token) is False
    assert verify_issue_token(secret, 777, "nope") is False
    assert verify_issue_token("", 777, token) is False


def test_family_token_is_separate_and_guest_id_is_reversible() -> None:
    secret = "link-secret"
    personal = issue_token(secret, 777)
    family = family_issue_token(secret, 777)
    guest_id = family_guest_id(777)

    assert personal != family
    assert verify_family_issue_token(secret, 777, family) is True
    assert verify_family_issue_token(secret, 778, family) is False
    assert verify_issue_token(secret, 777, family) is False
    assert family_owner_id(guest_id) == 777
    assert family_owner_id(777) is None


def test_family_guest_id_rejects_non_telegram_ranges() -> None:
    for owner_id in (0, -1, 1_000_000_000_000):
        try:
            family_guest_id(owner_id)
        except ValueError:
            pass
        else:
            raise AssertionError(f"owner id {owner_id} must be rejected")


def test_paid_device_slots_are_independent_and_reversible() -> None:
    owner_id = 449066726
    assert device_peer_id(owner_id, 1) == owner_id
    second = device_peer_id(owner_id, 2)
    fifth = device_peer_id(owner_id, 5)
    assert second == family_guest_id(owner_id)
    assert fifth != second
    assert device_owner_slot(second) == (owner_id, 2)
    assert device_owner_slot(fifth) == (owner_id, 5)
    assert device_owner_slot(owner_id) is None


def test_paid_device_slot_rejects_invalid_owner_or_slot() -> None:
    for owner_id, slot in ((0, 1), (1, 0), (1, 100)):
        try:
            device_peer_id(owner_id, slot)
        except ValueError:
            pass
        else:
            raise AssertionError(f"owner={owner_id}, slot={slot} must be rejected")


def test_peer_name() -> None:
    assert peer_name(12345) == "sub-12345"
    assert peer_name(12345, "fi") == "sub-12345-fi"


# --- service orchestration ----------------------------------------------------

def test_issue_provisions_once_then_reuses(tmp_path: Path) -> None:
    store = _store(tmp_path)
    calls: list[str] = []

    def provision(name: str) -> str:
        calls.append(name)
        return f"[Interface]\n# {name}\n"

    service = AwgFallbackService(store, provision=provision, deprovision=lambda n: True)

    first = service.issue(999, remnawave_uuid="uuid-1")
    assert first["reused"] is False
    assert "sub-999" in first["config"]
    assert calls == ["sub-999"]

    second = service.issue(999)
    assert second["reused"] is True
    assert second["config"] == first["config"]
    assert calls == ["sub-999"]  # not provisioned again

    peer = store.awg_get_peer(999)
    assert peer is not None
    assert peer["client_name"] == "sub-999"
    assert peer["remnawave_uuid"] == "uuid-1"
    assert peer["status"] == "active"


def test_revoke_removes_peer(tmp_path: Path) -> None:
    store = _store(tmp_path)
    removed: list[str] = []
    service = AwgFallbackService(
        store,
        provision=lambda n: f"[Interface]\n# {n}\n",
        deprovision=lambda n: removed.append(n) or True,
    )

    service.issue(555)
    assert store.awg_get_peer(555) is not None

    assert service.revoke(555) is True
    assert removed == ["sub-555"]
    assert store.awg_get_peer(555) is None

    # idempotent: revoking an unknown user is a no-op
    assert service.revoke(555) is False


def test_suspend_and_resume_keep_the_same_config(tmp_path: Path) -> None:
    store = _store(tmp_path)
    suspended: list[str] = []
    resumed: list[str] = []
    service = AwgFallbackService(
        store,
        provision=lambda n: f"[Interface]\n# {n}\nPrivateKey = SAME\n",
        deprovision=lambda n: True,
        suspend=lambda n: suspended.append(n) or True,
        resume=lambda n: resumed.append(n) or True,
    )
    original = service.issue(808)["config"]

    assert service.suspend(808) is True
    assert store.awg_get_peer(808)["status"] == "suspended"
    assert suspended == ["sub-808"]

    restored = service.issue(808, remnawave_uuid="renewed")
    assert restored["config"] == original
    assert restored["reused"] is True
    assert restored["resumed"] is True
    assert resumed == ["sub-808"]
    assert store.awg_get_peer(808)["status"] == "active"


def test_reconcile_matches_remnawave_entitlements(tmp_path: Path) -> None:
    store = _store(tmp_path)
    suspended: list[str] = []
    resumed: list[str] = []
    service = AwgFallbackService(
        store,
        provision=lambda n: f"[Interface]\n# {n}\n",
        deprovision=lambda n: True,
        suspend=lambda n: suspended.append(n) or True,
        resume=lambda n: resumed.append(n) or True,
    )
    service.issue(1)
    service.issue(2)
    service.suspend(2)
    suspended.clear()

    class Entitlements:
        @staticmethod
        def active_user(telegram_id: int):
            return {"uuid": "active"} if telegram_id == 2 else None

    result = reconcile_awg_peers(store, Entitlements(), service)
    assert result == {
        "checked": 2,
        "suspended": 1,
        "resumed": 1,
        "unchanged": 0,
        "errors": [],
    }
    assert suspended == ["sub-1"]
    assert resumed == ["sub-2"]
    assert store.awg_get_peer(1)["status"] == "suspended"
    assert store.awg_get_peer(2)["status"] == "active"


def test_reconcile_family_peer_uses_owner_entitlement(tmp_path: Path) -> None:
    store = _store(tmp_path)
    owner_id = 777
    guest_id = family_guest_id(owner_id)
    lookups: list[int] = []
    service = AwgFallbackService(
        store,
        provision=lambda name: f"[Interface]\n# {name}\n",
        deprovision=lambda name: True,
        suspend=lambda name: True,
        resume=lambda name: True,
    )
    service.issue(guest_id)

    class Entitlements:
        @staticmethod
        def active_user(telegram_id: int):
            lookups.append(telegram_id)
            return {"uuid": "owner-active", "hwidDeviceLimit": 2} if telegram_id == owner_id else None

    result = reconcile_awg_peers(store, Entitlements(), service)

    assert result == {
        "checked": 1,
        "suspended": 0,
        "resumed": 0,
        "unchanged": 1,
        "errors": [],
    }
    assert lookups == [owner_id]
    assert store.awg_get_peer(guest_id)["status"] == "active"


def test_reconcile_enforces_paid_device_limit_and_restores_after_upgrade(tmp_path: Path) -> None:
    store = _store(tmp_path)
    owner_id = 777
    second = device_peer_id(owner_id, 2)
    third = device_peer_id(owner_id, 3)
    suspended: list[str] = []
    resumed: list[str] = []
    service = AwgFallbackService(
        store,
        provision=lambda name: f"[Interface]\n# {name}\n",
        deprovision=lambda name: True,
        suspend=lambda name: suspended.append(name) or True,
        resume=lambda name: resumed.append(name) or True,
    )
    service.issue(owner_id)
    service.issue(second)
    service.issue(third)

    class Entitlements:
        limit = 2

        @classmethod
        def active_user(cls, telegram_id: int):
            assert telegram_id == owner_id
            return {"uuid": "active", "hwidDeviceLimit": cls.limit}

    result = reconcile_awg_peers(store, Entitlements(), service)
    assert result["suspended"] == 1
    assert store.awg_get_peer(third)["status"] == "suspended"
    assert suspended == [peer_name(third)]

    Entitlements.limit = 3
    result = reconcile_awg_peers(store, Entitlements(), service)
    assert result["resumed"] == 1
    assert store.awg_get_peer(third)["status"] == "active"
    assert resumed == [peer_name(third)]


def _suspending_service(store, suspended: list[str]) -> AwgFallbackService:
    return AwgFallbackService(
        store,
        provision=lambda n: f"[Interface]\n# {n}\n",
        deprovision=lambda n: True,
        suspend=lambda n: suspended.append(n) or True,
        resume=lambda n: True,
    )


def test_reconcile_holds_when_the_panel_cannot_answer(tmp_path: Path) -> None:
    # A wrong URL, a revoked key, a dead host: the client raises, so no peer can
    # reach the suspend list at all. Nobody loses access over our outage.
    store = _store(tmp_path)
    suspended: list[str] = []
    service = _suspending_service(store, suspended)
    for tid in (1, 2, 3):
        service.issue(tid)

    class BrokenPanel:
        @staticmethod
        def active_user(telegram_id: int):
            raise RuntimeError("Remnawave API error 404 for /api/users/by-telegram-id/1")

    result = reconcile_awg_peers(store, BrokenPanel(), service)
    assert result["checked"] == 3
    assert result["suspended"] == 0
    assert suspended == []
    assert len(result["errors"]) == 3  # one per peer, saying why
    for tid in (1, 2, 3):
        assert store.awg_get_peer(tid)["status"] == "active"  # untouched


def test_reconcile_suspends_when_everyone_has_genuinely_expired(tmp_path: Path) -> None:
    # On a young service every subscriber lapsing at once is ordinary, not an
    # outage. This used to be read as a systemic failure, so expired keys kept
    # working and the VPN was quietly given away for free.
    store = _store(tmp_path)
    suspended: list[str] = []
    service = _suspending_service(store, suspended)
    for tid in (1, 2, 3):
        service.issue(tid)

    class HonestPanel:
        @staticmethod
        def active_user(telegram_id: int):
            return None  # answered fine: this person simply has not paid

    result = reconcile_awg_peers(store, HonestPanel(), service)
    assert result["checked"] == 3
    assert result["suspended"] == 3
    assert sorted(suspended) == sorted(peer_name(tid) for tid in (1, 2, 3))
    for tid in (1, 2, 3):
        assert store.awg_get_peer(tid)["status"] == "suspended"


def test_reconcile_still_refuses_an_implausible_mass_suspend(tmp_path: Path) -> None:
    # The remaining systemic risk is drift that keeps answering 200 while making
    # almost everyone look inactive. At real scale that is not churn.
    store = _store(tmp_path)
    suspended: list[str] = []
    service = _suspending_service(store, suspended)
    everyone = list(range(1, 13))
    for tid in everyone:
        service.issue(tid)

    class DriftedPanel:
        @staticmethod
        def active_user(telegram_id: int):
            return {"uuid": "active"} if telegram_id == 1 else None

    result = reconcile_awg_peers(store, DriftedPanel(), service)
    assert result["suspended"] == 0
    assert result["skipped_suspends"] == 11
    assert any("circuit_breaker" in str(item.get("error")) for item in result["errors"])
    assert suspended == []


def test_fallback_ssh_fails_fast_on_a_dead_exit(tmp_path: Path) -> None:
    # An HTTP caller waits on this SSH on a single worker; a blackholed exit must
    # not tie the connection up for ~2 minutes of banner/connect retries.
    import vpn_wizard.awg_fallback as fb

    assert fb.FALLBACK_SSH_TIMEOUT <= 10

    captured: dict[str, object] = {}

    class FakeRunner:
        def __init__(self, cfg, *args, **kwargs) -> None:
            captured["cfg"] = cfg

        def __enter__(self):
            raise RuntimeError("stop before connecting")

        def __exit__(self, *args) -> bool:
            return False

    import contextlib

    original = fb.SSHRunner
    fb.SSHRunner = FakeRunner
    try:
        service = fb.AwgFallbackService(
            account=object(),
            config=fb.AwgFallbackConfig(
                host="10.0.0.1", user="root", port=22, password="p",
                key_path=None, key_content=None, listen_port=443, link_secret="s",
            ),
        )
        with contextlib.suppress(RuntimeError):
            with service._ssh():
                pass
    finally:
        fb.SSHRunner = original

    cfg = captured["cfg"]
    assert cfg.timeout == fb.FALLBACK_SSH_TIMEOUT
    assert cfg.banner_timeout == fb.FALLBACK_SSH_TIMEOUT
    assert cfg.auth_timeout == fb.FALLBACK_SSH_TIMEOUT
    assert cfg.connect_retries == 1


def test_config_stored_encrypted_at_rest(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = AwgFallbackService(
        store, provision=lambda n: "SECRET-PRIVATE-KEY", deprovision=lambda n: True
    )
    service.issue(111)
    raw = (tmp_path / "state.db").read_bytes()
    assert b"SECRET-PRIVATE-KEY" not in raw  # Fernet-encrypted, not plaintext


def test_same_user_gets_independent_configs_on_multiple_servers(tmp_path: Path) -> None:
    store = _store(tmp_path)
    calls: list[tuple[str, str]] = []

    def service(server_id: str) -> AwgFallbackService:
        return AwgFallbackService(
            store,
            server_id=server_id,
            provision=lambda name: calls.append((server_id, name)) or f"CONFIG-{server_id}-{name}",
            deprovision=lambda name: True,
        )

    fi = service("fi")
    us = service("us")
    fi_config = fi.issue(449066726)["config"]
    us_config = us.issue(449066726)["config"]

    assert fi_config != us_config
    assert calls == [
        ("fi", "sub-449066726-fi"),
        ("us", "sub-449066726-us"),
    ]
    assert store.awg_get_server_peer(449066726, "fi")["config"] == fi_config
    assert store.awg_get_server_peer(449066726, "us")["config"] == us_config
    assert len(store.awg_list_server_peers()) == 2


def test_server_peer_suspend_resume_keeps_keys(tmp_path: Path) -> None:
    store = _store(tmp_path)
    suspended: list[str] = []
    resumed: list[str] = []
    service = AwgFallbackService(
        store,
        server_id="tr",
        provision=lambda name: f"CONFIG-{name}",
        deprovision=lambda name: True,
        suspend=lambda name: suspended.append(name) or True,
        resume=lambda name: resumed.append(name) or True,
    )
    original = service.issue(77)["config"]

    assert service.suspend(77) is True
    assert store.awg_get_server_peer(77, "tr")["status"] == "suspended"
    restored = service.issue(77)["config"]

    assert restored == original
    assert suspended == ["sub-77-tr"]
    assert resumed == ["sub-77-tr"]
    assert store.awg_get_server_peer(77, "tr")["status"] == "active"


def test_reconcile_applies_entitlement_to_every_installed_server(tmp_path: Path) -> None:
    store = _store(tmp_path)
    default_suspended: list[str] = []
    fi_suspended: list[str] = []
    default = AwgFallbackService(
        store,
        provision=lambda name: f"DEFAULT-{name}",
        deprovision=lambda name: True,
        suspend=lambda name: default_suspended.append(name) or True,
        resume=lambda name: True,
    )
    fi = AwgFallbackService(
        store,
        server_id="fi",
        provision=lambda name: f"FI-{name}",
        deprovision=lambda name: True,
        suspend=lambda name: fi_suspended.append(name) or True,
        resume=lambda name: True,
    )
    for telegram_id in (1, 2):
        default.issue(telegram_id)
        fi.issue(telegram_id)

    class Entitlements:
        @staticmethod
        def active_user(telegram_id: int):
            return {"uuid": "active"} if telegram_id == 2 else None

    result = reconcile_awg_peers(
        store,
        Entitlements(),
        default,
        server_services={"fi": fi},
    )

    assert result == {
        "checked": 4,
        "suspended": 2,
        "resumed": 0,
        "unchanged": 2,
        "errors": [],
    }
    assert default_suspended == ["sub-1"]
    assert fi_suspended == ["sub-1-fi"]


def test_reconcile_keeps_channel_member_only_on_free_netherlands(tmp_path: Path) -> None:
    store = _store(tmp_path)
    nl_suspended: list[str] = []
    us_suspended: list[str] = []
    nl = AwgFallbackService(
        store,
        provision=lambda name: f"NL-{name}",
        deprovision=lambda name: True,
        suspend=lambda name: nl_suspended.append(name) or True,
        resume=lambda name: True,
    )
    us = AwgFallbackService(
        store,
        server_id="us",
        provision=lambda name: f"US-{name}",
        deprovision=lambda name: True,
        suspend=lambda name: us_suspended.append(name) or True,
        resume=lambda name: True,
    )
    nl.issue(77)
    us.issue(77)

    class Inactive:
        @staticmethod
        def active_user(_telegram_id: int):
            return None

    result = reconcile_awg_peers(
        store,
        Inactive(),
        nl,
        server_services={"us": us},
        legacy_server_id="nl",
        free_server_id="nl",
        free_access_lookup=lambda _telegram_id: True,
    )

    assert result["suspended"] == 1
    assert result["unchanged"] == 1
    assert nl_suspended == []
    assert us_suspended == ["sub-77-us"]


def test_expired_web_bridge_suspends_without_querying_billing(tmp_path: Path) -> None:
    from vpn_wizard.web_signup import web_account_id

    store = _store(tmp_path)
    suspended: list[str] = []
    service = AwgFallbackService(
        store,
        provision=lambda name: f"NL-{name}",
        deprovision=lambda name: True,
        suspend=lambda name: suspended.append(name) or True,
        resume=lambda name: True,
    )
    guest = web_account_id(42)
    service.issue(guest)

    class BillingMustNotSeeWebIds:
        @staticmethod
        def active_user(_telegram_id: int):
            raise AssertionError("synthetic web id leaked to billing")

    result = reconcile_awg_peers(
        store,
        BillingMustNotSeeWebIds(),
        service,
        legacy_server_id="nl",
        free_server_id="nl",
        free_access_lookup=lambda _telegram_id: False,
    )

    assert result["suspended"] == 1
    assert result["errors"] == []
    assert suspended == [peer_name(guest)]
