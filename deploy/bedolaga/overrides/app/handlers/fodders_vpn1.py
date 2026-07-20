"""Compatibility entry points for the original Fodders VPN 1 mini-app."""

from __future__ import annotations

import hashlib
import hmac
import os

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


def _awg_urls(telegram_id: int) -> tuple[str, str] | None:
    secret = (os.getenv('VPNW_AWG_LINK_SECRET') or '').strip()
    base = (os.getenv('VPNW_AWG_PUBLIC_URL') or DEFAULT_AWG_PUBLIC_URL).strip().rstrip('/')
    if not secret or not base.startswith('https://'):
        return None
    token = hmac.new(
        secret.encode('utf-8'),
        str(int(telegram_id)).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    prefix = f'{base}/api/awg/{int(telegram_id)}'
    return f'{prefix}/config?token={token}', f'{prefix}/qr?token={token}'


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
    links = _awg_urls(user.id)
    if links is None:
        await message.answer('AmneziaWG пока не настроен. Напишите в техподдержку.')
        return
    config_url, qr_url = links
    if _is_russian(message):
        text = (
            '🛡 <b>AmneziaWG — основной режим для РФ</b>\n\n'
            'Этот профиль работает через обфусцированный UDP/443 и предназначен '
            'для сетей, где Happ/Reality не подключается.\n\n'
            'Доступ работает только при активной подписке. Если срок закончится, '
            'сервер приостановит ключ; после продления уже установленный профиль '
            'заработает снова.\n\n'
            '1. Установите официальное приложение AmneziaWG для своего телефона.\n'
            '2. Нажмите «Скачать мой конфиг» и откройте файл в AmneziaWG.\n'
            '3. Включите появившийся профиль Fodder VPN.'
        )
        config_text = '🧩 Скачать мой конфиг'
        qr_text = '▦ QR для второго экрана'
        android_text = '🤖 Android'
        ios_text = '🍎 iPhone'
        windows_text = '🪟 Windows'
    else:
        text = (
            '🛡 <b>AmneziaWG — primary mode for restricted networks</b>\n\n'
            'This profile uses obfuscated UDP/443 for networks where Happ/Reality '
            'does not connect.\n\n'
            'Access follows your subscription. When it expires the server suspends '
            'the key; renewing restores the already imported profile.\n\n'
            'Install the official AmneziaWG app, download your config, open it in '
            'the app, and enable the Fodder VPN profile.'
        )
        config_text = '🧩 Download my config'
        qr_text = '▦ QR for another screen'
        android_text = '🤖 Android'
        ios_text = '🍎 iPhone'
        windows_text = '🪟 Windows'
    keyboard = types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(text=config_text, url=config_url),
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
                types.InlineKeyboardButton(text=qr_text, url=qr_url),
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
