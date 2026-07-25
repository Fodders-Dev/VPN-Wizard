from __future__ import annotations

from pathlib import Path

import pytest

from vpn_wizard.account import AccountStore
from vpn_wizard.web_signup import (
    WEB_ACCOUNT_ID_BASE,
    InviteConfig,
    InviteError,
    check_invite,
    create_invite,
    generate_code,
    is_web_account,
    normalize_code,
    outstanding_invites,
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
