"""Compatibility entry points for the original Fodders VPN 1 mini-app."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from urllib.parse import urlencode

from aiogram import Dispatcher, F, types
from aiogram.filters import Command


DEFAULT_MINIAPP_URL = 'https://212-69-84-167.nip.io/miniapp'
DEFAULT_AWG_PUBLIC_URL = 'https://212-69-84-167.nip.io'


def _miniapp_url() -> str:
    value = (os.getenv('FODDERS_VPN1_MINIAPP_URL') or DEFAULT_MINIAPP_URL).strip()
    if not value.startswith('https://'):
        return DEFAULT_MINIAPP_URL
    return value


def _is_russian(message: types.Message) -> bool:
    language = (message.from_user.language_code if message.from_user else '') or ''
    return not language or language.lower().startswith('ru')


_SERVER_ID_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,15}$')


def _public_servers() -> list[tuple[str, str]]:
    """Safe labels for direct Telegram buttons; no VPS credentials live in the bot."""
    raw = (os.getenv('VPNW_AWG_PUBLIC_SERVERS') or '').strip()
    try:
        items = json.loads(raw) if raw else []
    except (TypeError, json.JSONDecodeError):
        items = []
    servers: list[tuple[str, str]] = []
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            server_id = str(item.get('id') or '').strip().lower()
            if not _SERVER_ID_RE.match(server_id):
                continue
            label = str(item.get('display') or item.get('label') or server_id).strip()
            servers.append((server_id, label))
    if servers:
        return servers
    label = (os.getenv('VPNW_AWG_SERVER_LABEL') or 'Нидерланды').strip()
    return [('nl', label)]


def _awg_link_context(telegram_id: int) -> tuple[str, str] | None:
    secret = (os.getenv('VPNW_AWG_LINK_SECRET') or '').strip()
    base = (os.getenv('VPNW_AWG_PUBLIC_URL') or DEFAULT_AWG_PUBLIC_URL).strip().rstrip('/')
    if not secret or not base.startswith('https://'):
        return None
    token = hmac.new(
        secret.encode('utf-8'),
        str(int(telegram_id)).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return base, token


def _awg_urls(telegram_id: int, server_id: str | None = None) -> tuple[str, str] | None:
    context = _awg_link_context(telegram_id)
    if context is None:
        return None
    base, token = context
    prefix = f'{base}/api/awg/{int(telegram_id)}'
    query = {'token': token}
    if server_id:
        query['server'] = server_id
    encoded = urlencode(query)
    return f'{prefix}/config?{encoded}', f'{prefix}/qr?{encoded}'


def _awg_picker_url(telegram_id: int) -> str | None:
    context = _awg_link_context(telegram_id)
    if context is None:
        return None
    base, token = context
    query = urlencode({'tid': int(telegram_id), 'token': token})
    return f'{base}/connect/awg.html?{query}'


def _keyboard(message: types.Message) -> types.InlineKeyboardMarkup:
    text = '🛠 Открыть Fodders VPN 1' if _is_russian(message) else '🛠 Open Fodders VPN 1'
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text=text,
                    web_app=types.WebAppInfo(url=_miniapp_url()),
                )
            ]
        ]
    )


async def _send_awg(message: types.Message, user: types.User | None) -> None:
    if user is None:
        return
    picker_url = _awg_picker_url(user.id)
    if picker_url is None:
        await message.answer('AmneziaWG пока не настроен. Напишите в техподдержку.')
        return
    servers = _public_servers()
    if _is_russian(message):
        text = (
            '🛡 <b>AmneziaWG — основной режим для РФ</b>\n\n'
            'Этот профиль работает через обфусцированный AmneziaWG и предназначен '
            'для сетей, где Happ/Reality не подключается.\n\n'
            '🌍 <b>Выберите страну кнопкой ниже.</b> Можно скачать несколько стран: '
            'они появятся отдельными туннелями FVPN-nl, FVPN-fi, FVPN-tr и FVPN-us.\n\n'
            'Доступ работает только при активной подписке. Если срок закончится, '
            'сервер приостановит ключ; после продления уже установленный профиль '
            'заработает снова.\n\n'
            '1. Установите официальное приложение AmneziaWG для своего телефона.\n'
            '2. Нажмите страну и откройте скачанный .conf в AmneziaWG.\n'
            '3. Включите туннель нужной страны.'
        )
        picker_text = '📱 Инструкция и QR'
        android_text = '🤖 Android'
        ios_text = '🍎 iPhone'
        windows_text = '🪟 Windows'
    else:
        text = (
            '🛡 <b>AmneziaWG — primary mode for restricted networks</b>\n\n'
            'This profile uses obfuscated AmneziaWG for networks where Happ/Reality '
            'does not connect.\n\n'
            '🌍 <b>Choose a country below.</b> You may install several countries; '
            'each appears as its own FVPN tunnel.\n\n'
            'Access follows your subscription. When it expires the server suspends '
            'the key; renewing restores the already imported profile.\n\n'
            'Install the official AmneziaWG app, tap a country, open the downloaded '
            '.conf file, and enable that tunnel.'
        )
        picker_text = '📱 Guide and QR'
        android_text = '🤖 Android'
        ios_text = '🍎 iPhone'
        windows_text = '🪟 Windows'
    server_rows = []
    for server_id, label in servers:
        links = _awg_urls(user.id, server_id)
        if links is not None:
            server_rows.append([
                types.InlineKeyboardButton(text=f'📥 {label}', url=links[0])
            ])
    keyboard = types.InlineKeyboardMarkup(
        inline_keyboard=server_rows + [
            [
                types.InlineKeyboardButton(text=picker_text, url=picker_url),
            ],
            [
                types.InlineKeyboardButton(
                    text=android_text,
                    url='https://play.google.com/store/apps/details?id=org.amnezia.awg',
                ),
                types.InlineKeyboardButton(
                    text=ios_text,
                    url='https://apps.apple.com/app/amneziawg/id6478942365',
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text=windows_text,
                    url='https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest',
                ),
            ],
        ]
    )
    await message.answer(text, reply_markup=keyboard, parse_mode='HTML')


async def open_managed_awg_message(message: types.Message) -> None:
    await _send_awg(message, message.from_user)


async def open_managed_awg_callback(callback: types.CallbackQuery) -> None:
    if callback.message:
        await _send_awg(callback.message, callback.from_user)
    await callback.answer()


async def open_legacy_miniapp(message: types.Message) -> None:
    if _is_russian(message):
        text = (
            'Fodders VPN 1 сохранён и продолжает работать.\n\n'
            'В старом мастере доступны подключение собственного VPS, выпуск '
            'профилей AmneziaWG/Xray и диагностика сервера.\n'
            'Готовая подписка Fodder VPN, пробный период и оплата находятся в /start.'
        )
    else:
        text = (
            'Fodders VPN 1 is preserved and remains available.\n\n'
            'The original wizard still provides bring-your-own-VPS setup, '
            'AmneziaWG/Xray profiles, and server diagnostics.\n'
            'Use /start for the managed Fodder VPN subscription, trial, and payments.'
        )
    await message.answer(text, reply_markup=_keyboard(message))


async def show_help(message: types.Message) -> None:
    if _is_russian(message):
        text = (
            'Fodder VPN:\n'
            '• /start — подписка, пробный период, оплата и подключение\n'
            '• /awg — стабильное подключение через AmneziaWG\n'
            '• /miniapp — прежний мастер Fodders VPN 1\n'
            '• /vpn1 или /wizard — открыть прежний мастер\n\n'
            'AmneziaWG: https://amnezia.org/ru/downloads\n'
            'Гайд по VPS: '
            'https://telegra.ph/Kak-arendovat-minimalnyj-server-VPS-na-HostKey-dlya-VPN-12-28'
        )
    else:
        text = (
            'Fodder VPN:\n'
            '• /start — subscription, free trial, payments, and connection\n'
            '• /awg — stable connection through AmneziaWG\n'
            '• /miniapp — original Fodders VPN 1 wizard\n'
            '• /vpn1 or /wizard — open the original wizard\n\n'
            'AmneziaWG: https://amnezia.org/en/downloads'
        )
    await message.answer(text, reply_markup=_keyboard(message))


def register_handlers(dp: Dispatcher) -> None:
    dp.message.register(open_managed_awg_message, Command('awg', 'amnezia'))
    dp.callback_query.register(open_managed_awg_callback, F.data == 'fodders_awg')
    dp.message.register(open_legacy_miniapp, Command('miniapp', 'wizard', 'vpn1'))
    dp.message.register(show_help, Command('help'))
