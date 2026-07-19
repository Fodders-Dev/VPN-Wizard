"""Idempotently add the original Fodders VPN 1 mini-app to Bedolaga's menu."""

from __future__ import annotations

import asyncio
import copy
import os

from aiogram import Bot
from aiogram.types import BotCommand

from app.database.database import AsyncSessionLocal
from app.services.menu_layout.service import MenuLayoutService


BUTTON_ID = 'fodders_vpn1'
ROW_ID = 'fodders_vpn1_row'
AWG_BUTTON_ID = 'fodders_awg'
AWG_ROW_ID = 'fodders_awg_row'
DEFAULT_URL = 'https://212-69-84-167.nip.io/miniapp'


async def main() -> None:
    url = (os.getenv('FODDERS_VPN1_MINIAPP_URL') or DEFAULT_URL).strip()
    if not url.startswith('https://'):
        raise RuntimeError('FODDERS_VPN1_MINIAPP_URL must be an HTTPS URL')

    async with AsyncSessionLocal() as db:
        config = copy.deepcopy(await MenuLayoutService.get_config(db))
        buttons = config.setdefault('buttons', {})
        buttons[AWG_BUTTON_ID] = {
            'type': 'callback',
            'builtin_id': None,
            'text': {
                'ru': '🛡 AmneziaWG',
                'en': '🛡 AmneziaWG',
            },
            'icon': None,
            'action': 'fodders_awg',
            'enabled': True,
            'visibility': 'all',
            'conditions': {
                'has_active_subscription': True,
                'subscription_is_active': True,
            },
            'dynamic_text': False,
            'description': 'Managed AmneziaWG profile tied to the subscription',
        }
        buttons[BUTTON_ID] = {
            'type': 'mini_app',
            'builtin_id': None,
            'text': {
                'ru': '🛠 Fodders VPN 1',
                'en': '🛠 Fodders VPN 1',
            },
            'icon': None,
            'action': url,
            'enabled': True,
            'visibility': 'all',
            'conditions': None,
            'dynamic_text': False,
            'description': 'Original self-hosted VPS wizard',
        }

        rows = config.setdefault('rows', [])
        awg_row = next((row for row in rows if row.get('id') == AWG_ROW_ID), None)
        if awg_row:
            awg_row.update(
                {
                    'buttons': [AWG_BUTTON_ID],
                    'conditions': None,
                    'max_per_row': 1,
                }
            )
        else:
            row = {
                'id': AWG_ROW_ID,
                'buttons': [AWG_BUTTON_ID],
                'conditions': None,
                'max_per_row': 1,
            }
            insert_at = next(
                (index for index, item in enumerate(rows) if item.get('id') == 'support_info_row'),
                len(rows),
            )
            rows.insert(insert_at, row)

        legacy_row = next((row for row in rows if row.get('id') == ROW_ID), None)
        if legacy_row:
            legacy_row.update(
                {
                    'buttons': [BUTTON_ID],
                    'conditions': None,
                    'max_per_row': 1,
                }
            )
        else:
            row = {
                'id': ROW_ID,
                'buttons': [BUTTON_ID],
                'conditions': None,
                'max_per_row': 1,
            }
            insert_at = next(
                (index for index, item in enumerate(rows) if item.get('id') == 'support_info_row'),
                len(rows),
            )
            rows.insert(insert_at, row)

        validation = MenuLayoutService.validate_config(config)
        if not validation['is_valid']:
            raise RuntimeError(f'Invalid menu config: {validation["errors"]}')

        await MenuLayoutService.save_config(db, config)

    token = (os.getenv('BOT_TOKEN') or '').strip()
    if not token:
        raise RuntimeError('BOT_TOKEN is required to configure Telegram commands')
    bot = Bot(token=token)
    try:
        current = await bot.get_my_commands()
        descriptions = {command.command: command.description for command in current}
        descriptions['awg'] = 'AmneziaWG для активной подписки'
        order = ['start', 'awg', 'miniapp', 'vpn1', 'help']
        commands = [
            BotCommand(command=command, description=descriptions[command])
            for command in order
            if command in descriptions
        ]
        await bot.set_my_commands(commands)
    finally:
        await bot.session.close()

    print(f'legacy_menu=configured url={url} awg_command=configured')


if __name__ == '__main__':
    asyncio.run(main())
