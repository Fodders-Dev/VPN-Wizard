"""Idempotently add the original Fodders VPN 1 mini-app to Bedolaga's menu."""

from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

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


FREE_BUTTON_ID = 'fodders_free_vpn'
FREE_ROW_ID = 'fodders_free_vpn_row'
WIZARD_BUTTON_ID = 'fodders_vpn1'
WIZARD_ROW_ID = 'fodders_vpn1_row'
DEFAULT_PORTAL_URL = 'https://77-67-89-164.nip.io/portal/'
DEFAULT_LEGACY_URL = 'https://77-67-89-164.nip.io/wizard/'


async def main() -> None:
    portal_url = (os.getenv('FODDERS_PORTAL_URL') or DEFAULT_PORTAL_URL).strip()
    legacy_url = (os.getenv('FODDERS_VPN1_MINIAPP_URL') or DEFAULT_LEGACY_URL).strip()
    token = (os.getenv('BOT_TOKEN') or '').strip()
    portal = urlsplit(portal_url)
    wizard = urlsplit(legacy_url)
    if portal.scheme != 'https' or not portal.netloc:
        raise RuntimeError('FODDERS_PORTAL_URL must be an HTTPS URL')
    if wizard.scheme != 'https' or not wizard.netloc:
        raise RuntimeError('FODDERS_VPN1_MINIAPP_URL must be an HTTPS URL')
    if not token:
        raise RuntimeError('BOT_TOKEN is required to configure Telegram commands')

    free_url = urlunsplit((portal.scheme, portal.netloc, '/connect/join.html', '', ''))

    async with AsyncSessionLocal() as db:
        config = copy.deepcopy(await MenuLayoutService.get_config(db))
        backup_dir = Path(
            os.getenv('FODDERS_MENU_BACKUP_DIR') or '/var/backups/bedolaga'
        )
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup_path = backup_dir / (
            'fodders-menu-layout-'
            + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            + '.json'
        )
        backup_fd = os.open(
            backup_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(backup_fd, 'w', encoding='utf-8') as backup_file:
            json.dump(config, backup_file, ensure_ascii=False, indent=2)
            backup_file.write('\n')
            backup_file.flush()
            os.fsync(backup_file.fileno())

        buttons = config.setdefault('buttons', {})
        buttons[FREE_BUTTON_ID] = {
            'type': 'url',
            'builtin_id': None,
            'text': {
                'ru': 'Получить бесплатный VPN',
                'en': 'Get free VPN',
            },
            'icon': None,
            'action': free_url,
            'enabled': True,
            'visibility': 'all',
            'conditions': None,
            'dynamic_text': False,
            'description': 'Open the free VPN connection guide',
        }
        buttons[WIZARD_BUTTON_ID] = {
            'type': 'mini_app',
            'builtin_id': None,
            'text': {
                'ru': 'Настроить свой сервер',
                'en': 'Set up my own server',
            },
            'icon': None,
            'action': legacy_url,
            'enabled': True,
            'visibility': 'all',
            'conditions': None,
            'dynamic_text': False,
            'description': 'Open the self-hosted VPN server wizard',
        }

        # Preserve every existing button definition and its business data. Only
        # replace the active layout so paid and referral actions are hidden.
        config['rows'] = [
            {
                'id': FREE_ROW_ID,
                'buttons': [FREE_BUTTON_ID],
                'conditions': None,
                'max_per_row': 1,
            },
            {
                'id': WIZARD_ROW_ID,
                'buttons': [WIZARD_BUTTON_ID],
                'conditions': None,
                'max_per_row': 1,
            },
        ]

        validation = MenuLayoutService.validate_config(config)
        if not validation['is_valid']:
            raise RuntimeError(f'Invalid menu config: {validation["errors"]}')

        await MenuLayoutService.save_config(db, config)

    bot = Bot(token=token)
    try:
        current = await bot.get_my_commands()
        descriptions = {command.command: command.description for command in current}
        descriptions['free'] = 'Получить бесплатный VPN'
        descriptions['wizard'] = 'Настроить собственный сервер'
        descriptions['help'] = 'Помощь и инструкции'
        order = ['free', 'wizard', 'help']
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
                text='Fodder VPN',
                web_app=WebAppInfo(url=portal_url),
            )
        )
    finally:
        await bot.session.close()

    print(
        f'free_first_menu=configured free_url={free_url} '
        f'wizard_webapp={legacy_url} backup={backup_path}'
    )


if __name__ == '__main__':
    asyncio.run(main())
