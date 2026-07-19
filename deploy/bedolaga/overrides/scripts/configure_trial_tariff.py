"""Configure a hidden trial tariff and repair already active trial subscriptions."""

from __future__ import annotations

import asyncio
import os

from sqlalchemy import select, update

from app.database.crud.tariff import create_tariff, update_tariff
from app.database.database import AsyncSessionLocal
from app.database.models import ServerSquad, Subscription, Tariff
from app.services.subscription_service import SubscriptionService


TRIAL_NAME = "Fodder Trial 14d"
TRIAL_TRAFFIC_GB = 100
TRIAL_DEVICE_LIMIT = 1


async def main() -> None:
    squad_uuid = (os.getenv("SIMPLE_SUBSCRIPTION_SQUAD_UUID") or "").strip()
    if not squad_uuid:
        raise RuntimeError("SIMPLE_SUBSCRIPTION_SQUAD_UUID is required")

    async with AsyncSessionLocal() as db:
        squad = (
            await db.execute(select(ServerSquad).where(ServerSquad.squad_uuid == squad_uuid))
        ).scalar_one_or_none()
        if squad is None:
            raise RuntimeError("Configured Remnawave squad is missing from server_squads")
        squad.is_available = True
        squad.is_trial_eligible = True

        await db.execute(update(Tariff).values(is_trial_available=False))
        standard = (
            await db.execute(select(Tariff).where(Tariff.name == "Стандартный").limit(1))
        ).scalar_one_or_none()
        if standard is None:
            raise RuntimeError("Standard paid tariff is missing")
        await update_tariff(
            db,
            standard,
            allowed_squads=[squad_uuid],
            is_trial_available=False,
        )

        trial = (
            await db.execute(select(Tariff).where(Tariff.name == TRIAL_NAME).limit(1))
        ).scalar_one_or_none()
        if trial is None:
            trial = await create_tariff(
                db,
                TRIAL_NAME,
                description="Скрытый тариф для 14-дневного тестового доступа",
                display_order=999,
                is_active=False,
                traffic_limit_gb=TRIAL_TRAFFIC_GB,
                device_limit=TRIAL_DEVICE_LIMIT,
                max_device_limit=TRIAL_DEVICE_LIMIT,
                allowed_squads=[squad_uuid],
                period_prices={},
                is_trial_available=True,
                allow_traffic_topup=False,
                traffic_topup_enabled=False,
                show_in_gift=False,
            )
        else:
            trial = await update_tariff(
                db,
                trial,
                description="Скрытый тариф для 14-дневного тестового доступа",
                display_order=999,
                is_active=False,
                traffic_limit_gb=TRIAL_TRAFFIC_GB,
                device_limit=TRIAL_DEVICE_LIMIT,
                max_device_limit=TRIAL_DEVICE_LIMIT,
                allowed_squads=[squad_uuid],
                period_prices={},
                is_trial_available=True,
                allow_traffic_topup=False,
                traffic_topup_enabled=False,
                show_in_gift=False,
            )

        active_trials = list(
            (
                await db.execute(
                    select(Subscription).where(
                        Subscription.is_trial.is_(True),
                        Subscription.status.in_(("active", "trial", "limited")),
                    )
                )
            )
            .scalars()
            .all()
        )
        for subscription in active_trials:
            subscription.tariff_id = trial.id
            subscription.traffic_limit_gb = TRIAL_TRAFFIC_GB
            subscription.device_limit = TRIAL_DEVICE_LIMIT
            subscription.connected_squads = [squad_uuid]
        await db.commit()

        service = SubscriptionService()
        synced = 0
        for subscription in active_trials:
            await db.refresh(subscription)
            result = await service.update_remnawave_user(db, subscription, sync_squads=True)
            if result is None:
                raise RuntimeError(f"Failed to sync trial subscription {subscription.id} to Remnawave")
            synced += 1

        print(f"trial_tariff_id={trial.id}")
        print(f"active_trials_repaired={len(active_trials)}")
        print(f"remnawave_trials_synced={synced}")
        print(f"squad_uuid={squad_uuid}")


if __name__ == "__main__":
    asyncio.run(main())
