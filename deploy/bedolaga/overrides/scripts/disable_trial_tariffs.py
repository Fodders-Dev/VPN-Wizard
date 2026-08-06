"""Disable new Bedolaga trials without cutting off already active subscriptions.

Free Netherlands access is enforced by VPN Wizard channel membership and must not
be represented as a Remnawave/Bedolaga trial. Existing trials are left untouched
so their published expiry and installed profiles keep behaving as promised.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import update

from app.database.database import AsyncSessionLocal
from app.database.models import ServerSquad, Tariff


async def main() -> None:
    async with AsyncSessionLocal() as db:
        tariffs = await db.execute(update(Tariff).values(is_trial_available=False))
        squads = await db.execute(update(ServerSquad).values(is_trial_eligible=False))
        await db.commit()

    print(f"trial_tariffs_disabled={tariffs.rowcount or 0}")
    print(f"trial_squads_disabled={squads.rowcount or 0}")
    print("active_trial_subscriptions_preserved=true")


if __name__ == "__main__":
    asyncio.run(main())
