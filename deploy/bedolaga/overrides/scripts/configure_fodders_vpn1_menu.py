"""Idempotently add the original Fodders VPN 1 mini-app to Bedolaga's menu."""

from __future__ import annotations

import asyncio
import copy
import os

from aiogram import Bot
from aiogram.types import (
    BotCommand,
    BotCommandScopeAllPrivateChats,
    BotCommandScopeDefault,
    MenuButtonWebApp,
    WebAppInfo,
)

from app.database.database import AsyncSessionLocal
from app.services.menu_layout.service import MenuLayoutService


BUTTON_ID = 'fodders_vpn1'
ROW_ID = 'fodders_vpn1_row'
AWG_BUTTON_ID = 'fodders_awg'
AWG_ROW_ID = 'fodders_awg_row'
INVITE_BUTTON_ID = 'referrals'
INVITE_ROW_ID = 'fodders_invite_row'
DEFAULT_PORTAL_URL = 'https://212-69-84-167.nip.io/portal/?v=20260722-3'
DEFAULT_LEGACY_URL = 'https://212-69-84-167.nip.io/wizard/?v=20260722-3'


async def main() -> None:
    portal_url = (os.getenv('FODDERS_PORTAL_URL') or DEFAULT_PORTAL_URL).strip()
    legacy_url = (os.getenv('FODDERS_VPN1_MINIAPP_URL') or DEFAULT_LEGACY_URL).strip()
    if not portal_url.startswith('https://'):
        raise RuntimeError('FODDERS_PORTAL_URL must be an HTTPS URL')
    if not legacy_url.startswith('https://'):
        raise RuntimeError('FODDERS_VPN1_MINIAPP_URL must be an HTTPS URL')

    async with AsyncSessionLocal() as db:
        config = copy.deepcopy(await MenuLayoutService.get_config(db))
        buttons = config.setdefault('buttons', {})
        buttons[AWG_BUTTON_ID] = {
            'type': 'callback',
            'builtin_id': None,
            'text': {
                'ru': '🛡 Подключиться · AmneziaWG',
                'en': '🛡 Connect · AmneziaWG',
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
        invite_button = buttons.get(INVITE_BUTTON_ID)
        if invite_button:
            invite_button.setdefault('text', {})
            invite_button['text'].update(
                {
                    'ru': '🎁 Поделиться VPN · получить бонус',
                    'en': '🎁 Share VPN · earn a bonus',
                }
            )
            invite_button['description'] = (
                'Create a personal invite link and view referral rewards'
            )
        legacy_connect = buttons.get('connect')
        if legacy_connect:
            legacy_connect.setdefault('text', {})
            legacy_connect['text'].update(
                {
                    'ru': '🌐 Happ / Reality · резерв',
                    'en': '🌐 Happ / Reality · fallback',
                }
            )
        happ_download = buttons.get('happ_download')
        if happ_download:
            happ_download.setdefault('text', {})
            happ_download['text'].update(
                {
                    'ru': '⬇️ Скачать Happ · резерв',
                    'en': '⬇️ Download Happ · fallback',
                }
            )
        buttons[BUTTON_ID] = {
            'type': 'mini_app',
            'builtin_id': None,
            'text': {
                'ru': '🛡 Открыть Fodder VPN',
                'en': '🛡 Open Fodder VPN',
            },
            'icon': None,
            'action': portal_url,
            'enabled': True,
            'visibility': 'all',
            'conditions': None,
            'dynamic_text': False,
            'description': 'Unified managed VPN and self-hosted server portal',
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
            awg_row = {
                'id': AWG_ROW_ID,
                'buttons': [AWG_BUTTON_ID],
                'conditions': None,
                'max_per_row': 1,
            }
            rows.append(awg_row)
        # The proven RF-safe path is the first action. The original Reality/Happ
        # connection remains directly below it as a fully preserved fallback.
        rows[:] = [row for row in rows if row.get('id') != AWG_ROW_ID]
        rows.insert(0, awg_row)

        # A two-column "Партнёрка" button looked like an internal sales
        # tool and hid the sharing action. Keep Bedolaga's complete referral
        # implementation, but expose it as one explicit full-width action.
        for row in rows:
            if row.get('id') == INVITE_ROW_ID:
                continue
            row['buttons'] = [
                button_id
                for button_id in row.get('buttons', [])
                if button_id != INVITE_BUTTON_ID
            ]
        rows[:] = [row for row in rows if row.get('buttons')]

        invite_row = next((row for row in rows if row.get('id') == INVITE_ROW_ID), None)
        if invite_row:
            invite_row.update(
                {
                    'buttons': [INVITE_BUTTON_ID],
                    'conditions': {'referral_enabled': True},
                    'max_per_row': 1,
                }
            )
        else:
            invite_row = {
                'id': INVITE_ROW_ID,
                'buttons': [INVITE_BUTTON_ID],
                'conditions': {'referral_enabled': True},
                'max_per_row': 1,
            }
        rows[:] = [row for row in rows if row.get('id') != INVITE_ROW_ID]
        promo_index = next(
            (index for index, row in enumerate(rows) if row.get('id') == 'promo_referral_row'),
            None,
        )
        if promo_index is not None:
            rows.insert(promo_index + 1, invite_row)
        else:
            insert_at = next(
                (index for index, row in enumerate(rows) if row.get('id') == 'support_info_row'),
                len(rows),
            )
            rows.insert(insert_at, invite_row)

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
        descriptions['awg'] = 'Подключиться: выбрать страну и получить конфиг'
        descriptions['devices'] = 'Мои устройства: кто подключён, отключить'
        descriptions['invite'] = 'Код для того, у кого не открывается Telegram'
        descriptions['family'] = 'Дать отдельный VPN-профиль близкому'
        descriptions['menu'] = 'Показать кнопки действий'
        descriptions['miniapp'] = 'Открыть единый портал Fodder VPN'
        descriptions['vpn1'] = 'Настроить собственный VPS через Wizard'
        order = [
            'start', 'awg', 'devices', 'invite', 'family',
            'menu', 'miniapp', 'vpn1', 'help',
        ]
        commands = [
            BotCommand(command=command, description=descriptions[command])
            for command in order
            if command in descriptions
        ]
        # Telegram picks the narrowest matching scope, and a stale
        # all_private_chats list (start/miniapp/cancel) was shadowing the default
        # one — so every command added here stayed invisible in private chats.
        # Write both, or the narrower one keeps winning.
        await bot.set_my_commands(commands, scope=BotCommandScopeDefault())
        await bot.set_my_commands(commands, scope=BotCommandScopeAllPrivateChats())
        await bot.set_chat_menu_button(
            menu_button=MenuButtonWebApp(
                text='Open Fodder VPN',
                web_app=WebAppInfo(url=portal_url),
            )
        )
    finally:
        await bot.session.close()

    print(
        f'portal_menu=configured url={portal_url} '
        f'legacy_wizard={legacy_url} awg_command=configured'
    )


if __name__ == '__main__':
    asyncio.run(main())
