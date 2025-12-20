from __future__ import annotations

import os
import threading

import uvicorn

from vpn_wizard.tg_bot import main as bot_main


def _run_api() -> None:
    host = os.getenv("VPNW_HOST", "0.0.0.0")
    port = int(os.getenv("VPNW_PORT") or os.getenv("PORT", "8000"))
    uvicorn.run("vpn_wizard.server:app", host=host, port=port, reload=False)


def main() -> None:
    if os.getenv("VPNW_BOT_TOKEN"):
        thread = threading.Thread(target=_run_api, daemon=True)
        thread.start()
        bot_main()
    else:
        _run_api()


if __name__ == "__main__":
    main()
