from __future__ import annotations

import os
import threading
import time

from telegram.error import Conflict
import uvicorn

from vpn_wizard.tg_bot import main as bot_main


def _run_api() -> None:
    host = os.getenv("VPNW_HOST", "0.0.0.0")
    port = int(os.getenv("VPNW_PORT") or os.getenv("PORT", "8000"))
    uvicorn.run("vpn_wizard.server:app", host=host, port=port, reload=False)


def _run_bot_loop() -> None:
    while True:
        try:
            bot_main(in_thread=True)
        except Conflict as exc:
            print(
                "Bot polling conflict: another process is already using getUpdates "
                f"for this token. Waiting before retrying. ({exc})"
            )
            time.sleep(30)
        except Exception as exc:
            print(f"Bot crashed: {exc}")
            time.sleep(5)


def main() -> None:
    if os.getenv("VPNW_BOT_TOKEN"):
        thread = threading.Thread(target=_run_bot_loop, daemon=True)
        thread.start()
        _run_api()
    else:
        _run_api()


if __name__ == "__main__":
    main()
