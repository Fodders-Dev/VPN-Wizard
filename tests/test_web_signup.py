from __future__ import annotations

from pathlib import Path

import pytest

from vpn_wizard.account import AccountStore
from vpn_wizard.web_signup import (
    WEB_ACCOUNT_ID_BASE,
    WEB_ACCOUNT_ID_MAX,
    InviteConfig,
    InviteError,
    check_invite,
    check_shared_invite,
    create_invite,
    create_shared_invite,
    generate_code,
    is_web_account,
    mint_shared_redemption,
    normalize_code,
    outstanding_invites,
    resolve_invite,
    web_account_id,
)


OWNER = 449066726
NOW = 1_800_000_000


def _store(tmp_path: Path) -> AccountStore:
    return AccountStore(tmp_path / "state.db", secret_key="unit-test-secret")


# --- codes people have to read aloud and retype ---------------------------------

def test_generated_codes_avoid_lookalike_characters() -> None:
    for _ in range(200):
        code = generate_code()
        assert len(code) == 9 and code[4] == "-"
        # 0/O and 1/I are indistinguishable over the phone.
        assert not set(code) & set("O0I1")


@pytest.mark.parametrize(
    "typed,expected",
    [
        ("ABCD-2345", "ABCD-2345"),
        ("abcd2345", "ABCD-2345"),
        ("  abcd 2345 ", "ABCD-2345"),
        ("ABCD—2345", "ABCD-2345"),
        ("ABCD-234", None),
        ("", None),
    ],
)
def test_normalize_code_accepts_what_humans_type(typed, expected) -> None:
    assert normalize_code(typed) == expected


# --- the synthetic account id ----------------------------------------------------

def test_web_account_ids_cannot_collide_with_real_telegram_ids() -> None:
    # Real Telegram ids are orders of magnitude smaller; if they ever were not,
    # a website signup could hijack somebody's account.
    assert not is_web_account(OWNER)
    assert not is_web_account(7938373718)
    assert is_web_account(web_account_id())
    assert is_web_account(WEB_ACCOUNT_ID_BASE)


# --- minting invites -------------------------------------------------------------

def test_create_invite_stores_a_usable_code(tmp_path: Path) -> None:
    store = _store(tmp_path)
    invite = create_invite(store, OWNER, now=NOW)
    assert normalize_code(invite["code"]) == invite["code"]
    saved = store.invite_get(invite["code"])
    assert saved["issuer_telegram_id"] == OWNER
    assert saved["used_at"] is None


def test_outstanding_invites_are_capped(tmp_path: Path) -> None:
    # Otherwise one subscription becomes an unlimited trial factory.
    store = _store(tmp_path)
    config = InviteConfig(max_outstanding=2)
    create_invite(store, OWNER, config, now=NOW)
    create_invite(store, OWNER, config, now=NOW)
    with pytest.raises(InviteError, match="неиспользованных"):
        create_invite(store, OWNER, config, now=NOW)


def test_redeemed_and_expired_invites_free_up_the_cap(tmp_path: Path) -> None:
    store = _store(tmp_path)
    config = InviteConfig(max_outstanding=1, ttl_days=1)
    first = create_invite(store, OWNER, config, now=NOW)

    store.invite_redeem(first["code"], web_account_id(1), now=NOW)
    second = create_invite(store, OWNER, config, now=NOW)      # slot freed by use

    later = NOW + 2 * 86400
    assert outstanding_invites(store, OWNER, now=later) == []   # second has expired
    create_invite(store, OWNER, config, now=later)


def test_invites_are_scoped_to_their_issuer(tmp_path: Path) -> None:
    store = _store(tmp_path)
    create_invite(store, OWNER, now=NOW)
    assert outstanding_invites(store, 7938373718, now=NOW) == []
    assert len(outstanding_invites(store, OWNER, now=NOW)) == 1


# --- redeeming --------------------------------------------------------------------

def test_check_invite_explains_every_refusal(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(InviteError, match="8 символов"):
        check_invite(store, "nope", now=NOW)
    with pytest.raises(InviteError, match="не существует"):
        check_invite(store, "ABCD-2345", now=NOW)

    used = create_invite(store, OWNER, now=NOW)
    store.invite_redeem(used["code"], web_account_id(2), now=NOW)
    with pytest.raises(InviteError, match="уже активировано"):
        check_invite(store, used["code"], now=NOW)

    expiring = create_invite(store, OWNER, InviteConfig(ttl_days=1), now=NOW)
    with pytest.raises(InviteError, match="истёк"):
        check_invite(store, expiring["code"], now=NOW + 2 * 86400)


def test_check_invite_accepts_a_sloppily_typed_code(tmp_path: Path) -> None:
    store = _store(tmp_path)
    code = create_invite(store, OWNER, now=NOW)["code"]
    assert check_invite(store, code.lower().replace("-", " "), now=NOW)["code"] == code


def test_an_invite_can_only_be_claimed_once(tmp_path: Path) -> None:
    # Two people racing on the same SMS must not both get a trial.
    store = _store(tmp_path)
    code = create_invite(store, OWNER, now=NOW)["code"]
    assert store.invite_redeem(code, web_account_id(3), now=NOW) is True
    assert store.invite_redeem(code, web_account_id(4), now=NOW) is False
    assert store.invite_get(code)["used_by"] == web_account_id(3)


def test_expired_invites_cannot_be_redeemed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    code = create_invite(store, OWNER, InviteConfig(ttl_days=1), now=NOW)["code"]
    assert store.invite_redeem(code, web_account_id(5), now=NOW + 2 * 86400) is False


def test_unused_invites_can_be_withdrawn_by_their_issuer_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    code = create_invite(store, OWNER, now=NOW)["code"]
    assert store.invite_delete(code, 7938373718) is False   # not yours
    assert store.invite_delete(code, OWNER) is True
    assert store.invite_get(code) is None


def test_a_used_invite_is_kept_as_a_record(tmp_path: Path) -> None:
    # Deleting it would erase who invited whom.
    store = _store(tmp_path)
    code = create_invite(store, OWNER, now=NOW)["code"]
    store.invite_redeem(code, web_account_id(6), now=NOW)
    assert store.invite_delete(code, OWNER) is False
    assert store.invite_get(code)["used_at"] == NOW


# --- the ceilings the synthetic id has to respect ---------------------------------

def test_web_ids_survive_a_round_trip_through_json_numbers() -> None:
    # Remnawave is a Node service: JSON numbers there are float64, so an id above
    # 2^53 comes back rounded. That silently stored ...848 for our ...847 and made
    # every later lookup miss. Keep the whole range exactly representable.
    import json

    from vpn_wizard.web_signup import JS_MAX_SAFE_INTEGER

    assert WEB_ACCOUNT_ID_MAX < JS_MAX_SAFE_INTEGER
    for candidate in (WEB_ACCOUNT_ID_BASE, WEB_ACCOUNT_ID_MAX, web_account_id()):
        assert int(float(candidate)) == candidate, candidate
        assert json.loads(json.dumps(float(candidate))) == float(candidate)


def test_web_ids_stay_inside_the_peer_id_arithmetic() -> None:
    # device_peer_id/family_guest_id reject owners above this ceiling, which is
    # what produced "Invalid device owner Telegram id" on the first real signup.
    from vpn_wizard.awg_fallback import MAX_DEVICE_OWNER_ID, device_peer_id, family_guest_id

    assert WEB_ACCOUNT_ID_MAX <= MAX_DEVICE_OWNER_ID
    for candidate in (WEB_ACCOUNT_ID_BASE, WEB_ACCOUNT_ID_MAX, web_account_id()):
        assert device_peer_id(candidate, 1) == candidate
        assert device_peer_id(candidate, 5) > 0
        assert family_guest_id(candidate) > 0


def test_web_ids_stay_clear_of_real_telegram_ids() -> None:
    # Telegram ids are around 10^10 today; the window starts well above that.
    assert WEB_ACCOUNT_ID_BASE > 100_000_000_000
    for real in (449066726, 7938373718, 99_999_999_999):
        assert not is_web_account(real)


# --- an invited trial must not be able to invite ----------------------------------

def test_a_released_invite_can_be_used_again(tmp_path: Path) -> None:
    # Signup failing after the claim must not burn somebody's only way in.
    store = _store(tmp_path)
    code = create_invite(store, OWNER, now=NOW)["code"]
    claimer = web_account_id(7)

    assert store.invite_redeem(code, claimer, now=NOW) is True
    assert store.invite_release(code, claimer) is True
    assert check_invite(store, code, now=NOW)["code"] == code
    assert store.invite_redeem(code, web_account_id(8), now=NOW) is True


def test_release_is_scoped_to_the_claimer(tmp_path: Path) -> None:
    # A late failure from a losing racer must not free the winner's redemption.
    store = _store(tmp_path)
    code = create_invite(store, OWNER, now=NOW)["code"]
    winner = web_account_id(9)
    store.invite_redeem(code, winner, now=NOW)

    assert store.invite_release(code, web_account_id(10)) is False
    assert store.invite_get(code)["used_by"] == winner


# --- shared invites: one code for the whole family chat ---------------------------

def test_shared_invite_spends_uses_atomically_and_stops_at_the_cap(tmp_path: Path) -> None:
    store = _store(tmp_path)
    shared = create_shared_invite(store, OWNER, max_uses=2, now=NOW)

    assert store.shared_invite_consume(shared["code"], now=NOW) is True
    assert store.shared_invite_consume(shared["code"], now=NOW) is True
    assert store.shared_invite_consume(shared["code"], now=NOW) is False
    with pytest.raises(InviteError, match="Лимит"):
        check_shared_invite(store, shared["code"], now=NOW)


def test_shared_invite_release_refunds_but_never_goes_negative(tmp_path: Path) -> None:
    store = _store(tmp_path)
    shared = create_shared_invite(store, OWNER, max_uses=1, now=NOW)

    assert store.shared_invite_release(shared["code"]) is False
    assert store.shared_invite_consume(shared["code"], now=NOW) is True
    assert store.shared_invite_release(shared["code"]) is True
    # The refunded use is spendable again.
    assert store.shared_invite_consume(shared["code"], now=NOW) is True


def test_shared_invite_expiry_and_disable_close_the_door(tmp_path: Path) -> None:
    store = _store(tmp_path)
    aged = create_shared_invite(store, OWNER, max_uses=5, ttl_days=1, now=NOW)
    with pytest.raises(InviteError, match="истёк"):
        check_shared_invite(store, aged["code"], now=NOW + 2 * 86400)
    assert store.shared_invite_consume(aged["code"], now=NOW + 2 * 86400) is False

    fresh = create_shared_invite(store, OWNER, max_uses=5, now=NOW)
    assert store.shared_invite_disable(fresh["code"]) is True
    with pytest.raises(InviteError, match="не действует"):
        check_shared_invite(store, fresh["code"], now=NOW)
    assert store.shared_invite_consume(fresh["code"], now=NOW) is False


def test_resolve_invite_prefers_personal_codes_and_falls_back_to_shared(tmp_path: Path) -> None:
    store = _store(tmp_path)
    personal = create_invite(store, OWNER, now=NOW)
    shared = create_shared_invite(store, OWNER, max_uses=3, now=NOW)

    assert resolve_invite(store, personal["code"], now=NOW)["kind"] == "single"
    assert resolve_invite(store, shared["code"], now=NOW)["kind"] == "shared"
    with pytest.raises(InviteError, match="не существует"):
        resolve_invite(store, "ZZZZ-9999", now=NOW)


def test_each_shared_redemption_mints_its_own_hidden_single_use_code(tmp_path: Path) -> None:
    # The hidden per-use invite is what the bind flow and metrics key on.
    store = _store(tmp_path)
    shared = create_shared_invite(store, OWNER, max_uses=3, now=NOW)

    first = mint_shared_redemption(store, shared)
    second = mint_shared_redemption(store, shared)
    assert first["code"] != second["code"]
    assert first["note"] == f"shared:{shared['code']}"
    assert first["issuer_telegram_id"] == OWNER
