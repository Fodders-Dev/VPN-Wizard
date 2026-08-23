"""Create the production device/time tariff matrix idempotently."""

from __future__ import annotations

import asyncio
import os

from sqlalchemy import select

from app.database.crud.tariff import create_tariff, update_tariff
from app.database.database import AsyncSessionLocal
from app.database.models import ServerSquad, Tariff


PLANS = (
    {
        # Посуточный ключ: включил на день-другой, сделал дела. Плата списывается
        # с баланса раз в сутки штатным DailySubscriptionService; кончился баланс
        # — доступ ставится на паузу и сам возобновляется после пополнения.
        # 8 ₽/сутки — дороже помесячной пропорции (199/30 ≈ 6.6), чтобы подписка
        # оставалась выгоднее для тех, кто пользуется постоянно.
        "name": "На день · 1 устройство",
        "aliases": (),
        "description": (
            "Оплата с баланса по дням: 8 ₽ в сутки, пока хватает баланса. "
            "Удобно включить на пару дней; постоянно — выгоднее подписка."
        ),
        "devices": 1,
        "prices": {1: 800},
        # Show it after the monthly plans: a subscription is the better deal for
        # regulars, the daily key is the "just for a couple of days" option.
        "order": 10,
        "tier": 1,
        "is_daily": True,
        "daily_price_kopeks": 800,
    },
    {
        "name": "Личный · 1 устройство",
        "aliases": (),
        "description": "Один личный профиль, все платные локации и поддержка.",
        "devices": 1,
        "prices": {30: 19_900, 90: 49_900, 180: 89_900, 360: 149_000},
        "order": 0,
        "tier": 1,
    },
    {
        "name": "Вместе · 3 устройства",
        "aliases": ("Стандартный",),
        "description": (
            "Три отдельных профиля. Второй можно передать близкому семейной "
            "ссылкой без Telegram."
        ),
        "devices": 3,
        "prices": {30: 29_900, 90: 79_900, 180: 139_000, 360: 239_000},
        "order": 1,
        "tier": 2,
    },
    {
        "name": "Семья · 5 устройств",
        "aliases": (),
        "description": (
            "Пять отдельных профилей. Второй можно передать близкому семейной "
            "ссылкой без Telegram."
        ),
        "devices": 5,
        "prices": {30: 39_900, 90: 109_000, 180: 189_000, 360: 329_000},
        "order": 2,
        "tier": 3,
    },
)


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
        await db.commit()

        existing = list((await db.execute(select(Tariff))).scalars().all())
        by_name = {tariff.name: tariff for tariff in existing}
        configured: list[Tariff] = []

        for plan in PLANS:
            tariff = by_name.get(plan["name"])
            if tariff is None:
                tariff = next(
                    (by_name.get(alias) for alias in plan["aliases"] if by_name.get(alias)),
                    None,
                )
            values = dict(
                name=plan["name"],
                description=plan["description"],
                display_order=plan["order"],
                is_active=True,
                traffic_limit_gb=0,
                device_limit=plan["devices"],
                device_price_kopeks=None,
                max_device_limit=plan["devices"],
                allowed_squads=[squad_uuid],
                period_prices=plan["prices"],
                tier_level=plan["tier"],
                is_trial_available=False,
                allow_traffic_topup=False,
                traffic_topup_enabled=False,
                show_in_gift=not plan.get("is_daily", False),
                is_daily=plan.get("is_daily", False),
                daily_price_kopeks=plan.get("daily_price_kopeks", 0),
            )
            if tariff is None:
                tariff = await create_tariff(db, **values)
            else:
                tariff = await update_tariff(db, tariff, **values)
            configured.append(tariff)
            for alias in plan["aliases"]:
                stale = by_name.get(alias)
                if stale is not None and stale.id != tariff.id and stale.is_active:
                    await update_tariff(db, stale, is_active=False)

        print("paid_tariffs=" + ",".join(f"{item.id}:{item.name}" for item in configured))
        print("device_limits=" + ",".join(str(item.device_limit) for item in configured))
        print(f"squad_uuid={squad_uuid}")


if __name__ == "__main__":
    asyncio.run(main())
