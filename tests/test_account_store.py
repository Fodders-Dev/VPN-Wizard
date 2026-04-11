from __future__ import annotations

from vpn_wizard.account import AccountStore


def test_rename_server_keeps_credentials_and_allows_reset(tmp_path) -> None:
    store = AccountStore(tmp_path / "state.db", "secret-key")
    user = store.upsert_user_from_telegram({"id": 1, "first_name": "Tema"})
    saved = store.save_server(
        user_id=user["id"],
        host="1.2.3.4",
        ssh_user="root",
        ssh_port=22,
        password="pass-123",
        key_content=None,
        mode="amneziawg",
        listen_port=None,
        proxy_sni=None,
        label=None,
    )

    renamed = store.rename_server(user["id"], saved["id"], "Home VPS")
    creds = store.resolve_server_credentials(
        user_id=user["id"],
        server_id=saved["id"],
        require_pin_unlocked=False,
    )

    assert renamed["label"] == "Home VPS"
    assert creds["password"] == "pass-123"

    reset = store.rename_server(user["id"], saved["id"], "")
    assert reset["label"] == "root@1.2.3.4"
