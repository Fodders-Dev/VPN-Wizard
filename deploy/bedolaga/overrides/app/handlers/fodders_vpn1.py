"""Compatibility entry points for the original Fodders VPN 1 mini-app."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from html import escape as html_escape
import json
import logging
import os
import re
import time
from urllib.parse import urlencode

import aiohttp
from aiogram import Dispatcher, F, types
from aiogram.filters import Command

logger = logging.getLogger(__name__)

# Telegram's WebView ignores <a download>, and a browser detour loses people on
# iOS, so the file is delivered as a chat document instead. Prefix is short:
# callback_data is capped at 64 bytes.
CONFIG_CALLBACK_PREFIX = 'fawg_get:'
FETCH_TIMEOUT_SECONDS = 20

DEVICES_CALLBACK = 'fodders_devices'
INVITE_CALLBACK = 'fodders_invite'
DEVICE_RENAME_PREFIX = 'fdev_rn:'
DEVICE_REVOKE_PREFIX = 'fdev_rk:'
DEVICE_REVOKE_CONFIRM_PREFIX = 'fdev_rky:'
RENAME_PROMPT_MARKER = '✏️ Введите новое название'

# Telegram replaces the "/" command list with the Mini App button whenever a
# WebApp menu button is set, so commands become invisible. A persistent reply
# keyboard is the discoverable surface for people who will never type a slash.
BTN_CONNECT = '🛡 Подключить VPN'
BTN_DEVICES = '📱 Мои устройства'
BTN_INVITE = '🎟 Пригласить'
BTN_HELP = '❓ Помощь'


def main_keyboard() -> types.ReplyKeyboardMarkup:
    return types.ReplyKeyboardMarkup(
        keyboard=[
            [types.KeyboardButton(text=BTN_CONNECT)],
            [types.KeyboardButton(text=BTN_DEVICES), types.KeyboardButton(text=BTN_INVITE)],
            [types.KeyboardButton(text=BTN_HELP)],
        ],
        resize_keyboard=True,
        is_persistent=True,
        input_field_placeholder='Выберите действие',
    )


def _format_bytes(total: int) -> str:
    value = float(max(0, int(total)))
    for unit in ('Б', 'КБ', 'МБ', 'ГБ'):
        if value < 1024 or unit == 'ГБ':
            return f'{value:.0f} {unit}' if unit in ('Б', 'КБ') else f'{value:.1f} {unit}'
        value /= 1024
    return f'{value:.1f} ГБ'


def _format_last_seen(timestamp: int | None) -> str:
    """Plain Russian for "when was this key last actually used"."""
    if not timestamp:
        return 'ни разу не подключалось'
    delta = max(0, int(time.time()) - int(timestamp))
    if delta < 120:
        return 'подключено только что'
    if delta < 3600:
        return f'было {delta // 60} мин назад'
    if delta < 86400:
        return f'было {delta // 3600} ч назад'
    days = delta // 86400
    if days == 1:
        return 'было вчера'
    if days < 30:
        return f'было {days} дн назад'
    return 'давно не подключалось'


DEFAULT_PORTAL_URL = 'https://212-69-84-167.nip.io/portal/?v=20260722-3'
DEFAULT_MINIAPP_URL = 'https://212-69-84-167.nip.io/wizard/?v=20260722-3'
DEFAULT_AWG_PUBLIC_URL = 'https://212-69-84-167.nip.io'


def _portal_url() -> str:
    value = (os.getenv('FODDERS_PORTAL_URL') or DEFAULT_PORTAL_URL).strip()
    if not value.startswith('https://'):
        return DEFAULT_PORTAL_URL
    return value


def _miniapp_url() -> str:
    value = (os.getenv('FODDERS_VPN1_MINIAPP_URL') or DEFAULT_MINIAPP_URL).strip()
    if not value.startswith('https://'):
        return DEFAULT_MINIAPP_URL
    return value


def _is_russian(message: types.Message) -> bool:
    return _user_is_russian(message.from_user)


def _user_is_russian(user: types.User | None) -> bool:
    language = (user.language_code if user else '') or ''
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


def _free_server_id() -> str:
    return (os.getenv('VPNW_CHANNEL_ACCESS_SERVER_ID') or 'nl').strip().lower()


def _channel_access_enabled() -> bool:
    return (os.getenv('VPNW_CHANNEL_ACCESS_ENABLED') or '').strip().lower() in {
        '1', 'true', 'yes', 'on',
    }


def _channel_url() -> str:
    return (os.getenv('VPNW_CHANNEL_ACCESS_CHANNEL_URL') or 'https://t.me/fodders_dev').strip()


class FamilyUnavailable(Exception):
    """The family link cannot be issued, with the API's own reason attached."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = (detail or '').strip()


async def _family_picker_url(telegram_id: int) -> str | None:
    """Ask the API for the link rather than signing it here.

    The family token now carries an epoch that the API bumps when the owner
    revokes the slot; signing locally would keep minting links against a stale
    epoch and hand out URLs that are already dead.
    """
    api = _devices_api(telegram_id)
    if api is None:
        return None
    url, token = api
    links_url = url.replace('/devices', '/family-link')
    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(links_url, params={'token': token}) as response:
                if response.status != 200:
                    # The API already says why in Russian — "Семейная ссылка
                    # доступна на тарифах от 3 устройств." Throwing that away and
                    # printing "не настроен, напишите в техподдержку" turns a
                    # normal plan limit into an apparent outage.
                    detail = ''
                    try:
                        detail = str((await response.json()).get('detail') or '')
                    except Exception:  # noqa: BLE001 - a body we cannot read is not a reason
                        detail = ''
                    raise FamilyUnavailable(detail)
                body = await response.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        raise FamilyUnavailable('')
    return body.get('url') or None


def _keyboard(message: types.Message) -> types.InlineKeyboardMarkup:
    text = '🛡 Открыть Fodder VPN' if _is_russian(message) else '🛡 Open Fodder VPN'
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text=text,
                    web_app=types.WebAppInfo(url=_portal_url()),
                )
            ]
        ]
    )


def _legacy_keyboard(message: types.Message) -> types.InlineKeyboardMarkup:
    text = '🛠 Открыть мастер своего сервера' if _is_russian(message) else '🛠 Open server wizard'
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
    if _user_is_russian(user):
        free_copy = (
            '🎁 <b>Нидерланды бесплатны, пока вы подписаны на Fodder’s Dev.</b> '
            'Один профиль — без срока окончания.\n\n'
            if _channel_access_enabled()
            else '🎁 Бесплатные Нидерланды готовятся к запуску.\n\n'
        )
        text = (
            '🛡 <b>AmneziaWG — основной режим для РФ</b>\n\n'
            'Этот профиль работает через обфусцированный AmneziaWG и предназначен '
            'для сетей, где Happ/Reality не подключается.\n\n'
            + free_copy +
            '🌍 Остальные страны и дополнительные устройства доступны по платной '
            'подписке. После продления уже установленный профиль заработает снова.\n\n'
            '1. Установите официальное приложение для Android, iPhone, Windows или Mac.\n'
            '2. Нажмите страну и откройте присланный файл в AmneziaWG.\n'
            '3. Включите туннель нужной страны.'
        )
        picker_text = '📱 Инструкция и QR'
        android_text = '🤖 Android'
        ios_text = '🍎 iPhone'
        windows_text = '🪟 Windows'
        mac_text = '🍎 Mac'
        family_text = '👵 Дать доступ близкому'
        devices_text = '📱 Мои устройства'
        invite_text = '🎟 Пригласить без Telegram'
    else:
        free_copy = (
            '🎁 <b>Netherlands is free while you follow Fodder’s Dev.</b> One profile, '
            'with no expiry date. '
            if _channel_access_enabled()
            else '🎁 Free Netherlands access is being prepared. '
        )
        text = (
            '🛡 <b>AmneziaWG — primary mode for restricted networks</b>\n\n'
            'This profile uses obfuscated AmneziaWG for networks where Happ/Reality '
            'does not connect.\n\n'
            + free_copy + 'Other countries and devices require a paid plan.\n\n'
            'Install the official AmneziaWG app, tap a country, open the downloaded '
            '.conf file, and enable that tunnel.'
        )
        picker_text = '📱 Guide and QR'
        android_text = '🤖 Android'
        ios_text = '🍎 iPhone'
        windows_text = '🪟 Windows'
        mac_text = '🍎 Mac'
        family_text = '👵 Share with family'
        devices_text = '📱 My devices'
        invite_text = '🎟 Invite without Telegram'
    server_rows = []
    for server_id, label in servers:
        if _awg_urls(user.id, server_id) is not None:
            # Callback, not a URL: the file comes back into this chat instead of
            # sending the user out to a download the WebView will swallow.
            server_rows.append([
                types.InlineKeyboardButton(
                    text=(
                        f'🎁 {label} · бесплатно'
                        if _channel_access_enabled() and server_id == _free_server_id()
                        else f'🔒 {label} · по подписке'
                    ),
                    callback_data=f'{CONFIG_CALLBACK_PREFIX}{server_id}',
                )
            ])
    keyboard = types.InlineKeyboardMarkup(
        inline_keyboard=server_rows + [
            [
                types.InlineKeyboardButton(text=picker_text, url=picker_url),
            ],
            [
                types.InlineKeyboardButton(
                    text=family_text,
                    callback_data='fodders_awg_family',
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text=devices_text,
                    callback_data=DEVICES_CALLBACK,
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text=invite_text,
                    callback_data=INVITE_CALLBACK,
                ),
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
                types.InlineKeyboardButton(
                    text=mac_text,
                    url='https://github.com/amnezia-vpn/amnezia-client/releases/latest',
                ),
            ],
        ]
    )
    await message.answer(text, reply_markup=keyboard, parse_mode='HTML')
    await _ensure_keyboard(message)


async def _send_family_link(message: types.Message, user: types.User | None) -> None:
    if user is None:
        return
    try:
        family_url = await _family_picker_url(user.id)
    except FamilyUnavailable as unavailable:
        await message.answer(
            unavailable.detail
            or 'Не удалось получить семейную ссылку. Попробуйте через минуту.',
            reply_markup=main_keyboard(),
        )
        return
    if family_url is None:
        await message.answer(
            'Семейный доступ пока не настроен. Напишите в техподдержку.',
            reply_markup=main_keyboard(),
        )
        return
    if _user_is_russian(user):
        text = (
            '👵 <b>Доступ для близкого — без Telegram</b>\n\n'
            'Отправьте ссылку по SMS, WhatsApp или любым другим способом. '
            'Она откроется в обычном браузере и выдаст <b>отдельный</b> профиль '
            'AmneziaWG — ваше устройство №1 продолжит работать.\n\n'
            'Семейный профиль работает, пока активна ваша подписка. '
            'Он занимает <b>устройство №2</b> и доступен на тарифах для 3 или 5 '
            'устройств — лишний бесплатный ключ не создаётся.\n\n'
            f'<code>{html_escape(family_url)}</code>'
        )
        button_text = '🌐 Открыть семейную ссылку'
    else:
        text = (
            '👵 <b>Family access — no Telegram required</b>\n\n'
            'Send this link by SMS, WhatsApp, or any other channel. It opens in '
            'a normal browser and issues a separate AmneziaWG profile, so your '
            'first device keeps working.\n\n'
            'The family profile follows your subscription and uses paid device '
            'slot 2 on the 3- or 5-device plan. It is not an extra free slot.\n\n'
            f'<code>{html_escape(family_url)}</code>'
        )
        button_text = '🌐 Open family link'
    keyboard = types.InlineKeyboardMarkup(
        inline_keyboard=[
            [types.InlineKeyboardButton(text=button_text, url=family_url)],
        ]
    )
    await message.answer(text, reply_markup=keyboard, parse_mode='HTML')


def _tunnel_name(server_id: str) -> str:
    """Base filename == the tunnel name shown in AmneziaWG.

    The Android client validates it against [a-zA-Z0-9_=+.-]{1,15} and refuses
    anything longer instead of truncating, so keep it short and plain.
    """
    clean = re.sub(r'[^A-Za-z0-9_=+.-]', '', (server_id or '').strip())[:10]
    return f'FVPN-{clean}' if clean else 'FVPN'


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[int, bytes]:
    async with session.get(url) as response:
        return response.status, await response.read()


def _download_failure_text(status: int) -> str:
    """Say what actually went wrong, in Russian, with a way forward."""
    if status == 403:
        if not _channel_access_enabled():
            return '🔒 Для этой страны нужен активный тариф.'
        return (
            '🔒 Для этой страны нет активного доступа.\n\n'
            'Нидерланды бесплатны подписчикам Fodder’s Dev; остальные страны '
            'открываются по платной подписке.'
        )
    if status == 503:
        return (
            '🌍 Эта страна сейчас недоступна.\n\n'
            'Выберите другую — остальные работают.'
        )
    if status == 404:
        return '🌍 Такой страны больше нет в списке. Откройте /awg заново.'
    return (
        '⚠️ Не удалось получить конфиг. Попробуйте ещё раз через минуту, '
        'а если повторится — напишите в поддержку.'
    )


async def _send_country_config(callback: types.CallbackQuery) -> None:
    """Deliver the .conf as a chat document plus a QR image."""
    user = callback.from_user
    data = callback.data or ''
    server_id = data[len(CONFIG_CALLBACK_PREFIX):].strip()
    if user is None or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,15}', server_id):
        await callback.answer('Неизвестная страна', show_alert=True)
        return

    links = _awg_urls(user.id, server_id)
    if links is None:
        await callback.answer('AmneziaWG пока не настроен', show_alert=True)
        return
    config_url, qr_url = links

    # Telegram expires a callback after ~10s; answer before doing any network work.
    await callback.answer('Готовлю конфиг…')
    message = callback.message
    if message is None:
        return

    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            (config_status, config_body), (qr_status, qr_body) = await asyncio.gather(
                _fetch(session, config_url),
                _fetch(session, qr_url),
            )
    except (aiohttp.ClientError, asyncio.TimeoutError) as error:
        logger.warning('awg.config.fetch_failed user=%s server=%s err=%s', user.id, server_id, error)
        await message.answer(_download_failure_text(0))
        return

    if config_status != 200 or not config_body:
        logger.info('awg.config.rejected user=%s server=%s status=%s', user.id, server_id, config_status)
        keyboard = None
        if config_status == 403:
            keyboard = types.InlineKeyboardMarkup(
                inline_keyboard=[[
                    types.InlineKeyboardButton(text='💎 Продлить подписку', callback_data='subscription_upgrade'),
                ]]
            )
        await message.answer(_download_failure_text(config_status), reply_markup=keyboard)
        return

    label = next((text for sid, text in _public_servers() if sid == server_id), server_id)
    name = _tunnel_name(server_id)
    caption = (
        f'🛡 <b>Ваш конфиг — {html_escape(label)}</b>\n\n'
        f'1. Установите <b>AmneziaWG</b> (кнопки под сообщением с выбором страны).\n'
        f'2. Нажмите на файл <b>прямо здесь</b> → «Открыть с помощью» → AmneziaWG.\n'
        f'3. Включите туннель <b>{name}</b>.\n\n'
        '📁 <b>Если открываете через файловый менеджер</b> — берите файл в папке '
        '«Загрузки». В разделе «Недавние» Android иногда теряет имя и показывает '
        'его как «BIN» — оттуда AmneziaWG его не откроет.\n\n'
        'Не пересылайте файл: это ключ от вашего устройства.'
    )
    await message.answer_document(
        types.BufferedInputFile(config_body, filename=f'{name}.conf'),
        caption=caption,
        parse_mode='HTML',
    )
    if qr_status == 200 and qr_body:
        await message.answer_photo(
            types.BufferedInputFile(qr_body, filename=f'{name}.png'),
            caption=(
                'Если файл не открывается — отсканируйте этот QR '
                'в AmneziaWG (кнопка «+»). Название туннеля введите '
                f'<b>{name}</b>.'
            ),
            parse_mode='HTML',
        )


async def send_country_config(callback: types.CallbackQuery) -> None:
    try:
        await _send_country_config(callback)
    except Exception as error:  # never leave the button spinning
        logger.exception('awg.config.unhandled err=%s', error)
        if callback.message:
            await callback.message.answer(_download_failure_text(0))


def _devices_api(telegram_id: int, suffix: str = '') -> tuple[str, str] | None:
    context = _awg_link_context(telegram_id)
    if context is None:
        return None
    base, token = context
    return f'{base}/api/awg/{int(telegram_id)}/devices{suffix}', token


async def _load_devices(telegram_id: int) -> tuple[int, dict | None]:
    api = _devices_api(telegram_id)
    if api is None:
        return 0, None
    url, token = api
    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, params={'token': token}) as response:
            if response.status != 200:
                return response.status, None
            return 200, await response.json()


def _device_line(device: dict, flags: dict[str, str]) -> str:
    label = html_escape(str(device.get('label') or ''))
    servers = device.get('servers') or []
    suspended = device.get('suspended_servers') or []
    if not servers and not suspended:
        return f'⚪️ <b>{label}</b>\n     свободно — можно подключить новое устройство'
    where = ' '.join(flags.get(sid, sid) for sid in servers) or '—'
    parts = [f'🟢 <b>{label}</b>', f'     страны: {where}']
    if suspended:
        parts.append('     ⏸ приостановлено: ' + ' '.join(flags.get(s, s) for s in suspended))
    parts.append(f'     {_format_last_seen(device.get("last_seen_at"))}')
    total = int(device.get('total_bytes') or 0)
    if total:
        parts.append(f'     трафик: {_format_bytes(total)}')
    return '\n'.join(parts)


async def _send_devices(message: types.Message, user: types.User | None) -> None:
    if user is None:
        return
    try:
        status, data = await _load_devices(user.id)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        await message.answer('⚠️ Не удалось получить список устройств. Попробуйте позже.')
        return

    if data is None:
        if status == 403:
            await message.answer(
                '🔒 Подписка неактивна — список устройств появится после продления.',
                reply_markup=types.InlineKeyboardMarkup(inline_keyboard=[[
                    types.InlineKeyboardButton(text='💎 Продлить', callback_data='subscription_upgrade'),
                ]]),
            )
            return
        await message.answer('⚠️ Не удалось получить список устройств. Попробуйте позже.')
        return

    flags = {sid: label.split(' ')[0] for sid, label in _public_servers()}
    devices = data.get('devices') or []
    limit = int(data.get('device_limit') or 1)
    # A suspended key is retained, not occupying a slot; counting it showed "2 из 1".
    active = sum(1 for d in devices if d.get('servers'))
    extra = sum(1 for d in devices if int(d.get('slot') or 0) > limit and d.get('servers'))

    body = '\n\n'.join(_device_line(d, flags) for d in devices) or 'Устройств пока нет.'
    text = (
        f'📱 <b>Мои устройства</b>  (активно {active} из {limit}'
        + (f' · {extra} сверх тарифа' if extra else '')
        + ')\n\n'
        f'{body}\n\n'
        'Каждое устройство — свой ключ. «Отключить» убивает ключ: '
        'у того, кому вы его отдали, VPN перестанет работать, а слот освободится.'
    )

    rows = []
    for device in devices:
        slot = int(device.get('slot'))
        label = str(device.get('label') or f'Слот {slot}')
        row = [types.InlineKeyboardButton(
            text=f'✏️ {label[:18]}', callback_data=f'{DEVICE_RENAME_PREFIX}{slot}',
        )]
        if device.get('in_use'):
            row.append(types.InlineKeyboardButton(
                text='🚫 Отключить', callback_data=f'{DEVICE_REVOKE_PREFIX}{slot}',
            ))
        rows.append(row)
    rows.append([types.InlineKeyboardButton(text='🛡 Получить конфиг', callback_data='fodders_awg')])

    await message.answer(
        text,
        reply_markup=types.InlineKeyboardMarkup(inline_keyboard=rows),
        parse_mode='HTML',
    )


async def open_devices_message(message: types.Message) -> None:
    await _send_devices(message, message.from_user)


async def open_devices_callback(callback: types.CallbackQuery) -> None:
    await callback.answer()
    if callback.message:
        await _send_devices(callback.message, callback.from_user)


async def ask_device_rename(callback: types.CallbackQuery) -> None:
    """Ask for a name with ForceReply, so we need no FSM state of our own."""
    slot = (callback.data or '')[len(DEVICE_RENAME_PREFIX):]
    await callback.answer()
    if not callback.message or not slot.isdigit():
        return
    await callback.message.answer(
        f'{RENAME_PROMPT_MARKER} для устройства №{slot}.\n'
        'Ответьте на это сообщение, например: «Телефон мамы».\n'
        'Чтобы вернуть название по умолчанию, ответьте знаком «-».',
        reply_markup=types.ForceReply(input_field_placeholder='Название устройства'),
    )


async def apply_device_rename(message: types.Message) -> None:
    reply = message.reply_to_message
    if not reply or RENAME_PROMPT_MARKER not in (reply.text or ''):
        return
    found = re.search(r'№(\d+)', reply.text or '')
    if not found or message.from_user is None:
        return
    slot = int(found.group(1))
    label = (message.text or '').strip()
    if label == '-':
        label = ''

    api = _devices_api(message.from_user.id, f'/{slot}/label')
    if api is None:
        return
    url, token = api
    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, params={'token': token}, json={'label': label}) as response:
                ok = response.status == 200
    except (aiohttp.ClientError, asyncio.TimeoutError):
        ok = False
    if not ok:
        await message.answer('⚠️ Не удалось переименовать. Попробуйте ещё раз.')
        return
    await message.answer(f'✅ Готово: устройство №{slot} теперь «{html_escape(label) or "по умолчанию"}».')
    await _send_devices(message, message.from_user)


async def confirm_device_revoke(callback: types.CallbackQuery) -> None:
    slot = (callback.data or '')[len(DEVICE_REVOKE_PREFIX):]
    await callback.answer()
    if not callback.message or not slot.isdigit():
        return
    await callback.message.answer(
        f'🚫 <b>Отключить устройство №{slot}?</b>\n\n'
        'Его ключ будет удалён на всех странах. Если вы отдавали этот профиль '
        'кому-то — у него VPN сразу перестанет работать.\n'
        'Слот освободится, и на него можно будет выдать новый ключ.',
        parse_mode='HTML',
        reply_markup=types.InlineKeyboardMarkup(inline_keyboard=[
            [types.InlineKeyboardButton(
                text='🚫 Да, отключить', callback_data=f'{DEVICE_REVOKE_CONFIRM_PREFIX}{slot}',
            )],
            [types.InlineKeyboardButton(text='← Отмена', callback_data=DEVICES_CALLBACK)],
        ]),
    )


async def apply_device_revoke(callback: types.CallbackQuery) -> None:
    slot = (callback.data or '')[len(DEVICE_REVOKE_CONFIRM_PREFIX):]
    await callback.answer('Отключаю…')
    if not callback.message or not slot.isdigit() or callback.from_user is None:
        return
    api = _devices_api(callback.from_user.id, f'/{slot}/revoke')
    if api is None:
        return
    url, token = api
    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, params={'token': token}) as response:
                status = response.status
    except (aiohttp.ClientError, asyncio.TimeoutError):
        status = 0
    if status == 200:
        await callback.message.answer(f'✅ Устройство №{slot} отключено. Слот свободен.')
    elif status == 502:
        # Partial revocation is a security problem: never imply it worked.
        await callback.message.answer(
            '⚠️ Не удалось отключить ключ на всех странах — часть доступа могла остаться. '
            'Попробуйте ещё раз через минуту.'
        )
    else:
        await callback.message.answer('⚠️ Не удалось отключить устройство. Попробуйте позже.')
    await _send_devices(callback.message, callback.from_user)


async def _send_invite(message: types.Message, user: types.User | None) -> None:
    """Mint a code the owner can pass to someone who cannot reach Telegram."""
    if user is None:
        return
    api = _devices_api(user.id)
    if api is None:
        await message.answer('Приглашения пока не настроены. Напишите в техподдержку.')
        return
    base_url, token = api
    invites_url = base_url.replace('/devices', '/invites')

    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(invites_url, params={'token': token}) as response:
                status = response.status
                body = await response.json() if status in (200, 409) else {}
    except (aiohttp.ClientError, asyncio.TimeoutError):
        await message.answer('⚠️ Не удалось создать приглашение. Попробуйте позже.')
        return

    if status == 409:
        await message.answer(
            f'🎟 {body.get("detail") or "Слишком много неиспользованных приглашений."}\n\n'
            'Посмотреть и удалить лишние можно в портале.'
        )
        return
    if status != 200 or not body.get('code'):
        if status == 403:
            await message.answer('🔒 Приглашения доступны при активной подписке.')
        else:
            await message.answer('⚠️ Не удалось создать приглашение. Попробуйте позже.')
        return

    code = body['code']
    link = body.get('url') or ''
    await message.answer(
        '🎟 <b>Приглашение готово</b>\n\n'
        f'Код: <code>{html_escape(code)}</code>\n'
        + (f'Ссылка: {html_escape(link)}\n' if link else '')
        + '\nОтправьте это тому, у кого <b>нет VPN и не открывается Telegram</b>. '
        'Сайт выдаст Нидерланды на 12 часов. За это время человек откроет Telegram, '
        'подпишется на Fodder’s Dev и сохранит тот же профиль навсегда.\n\n'
        'Код одноразовый и действует 14 дней.',
        parse_mode='HTML',
    )


async def open_invite_message(message: types.Message) -> None:
    await _send_invite(message, message.from_user)


async def open_invite_callback(callback: types.CallbackQuery) -> None:
    await callback.answer('Создаю приглашение…')
    if callback.message:
        await _send_invite(callback.message, callback.from_user)


async def _ensure_keyboard(message: types.Message) -> None:
    """Put the action buttons on screen once, quietly."""
    try:
        note = await message.answer('⁣', reply_markup=main_keyboard())
        await note.delete()
    except Exception:  # deletion is best-effort; the keyboard is what matters
        pass


async def show_menu(message: types.Message) -> None:
    if _is_russian(message):
        text = (
            '🛡 <b>Fodder VPN</b>\n\n'
            'Кнопки под полем ввода всегда на месте — ими и пользуйтесь:\n\n'
            f'{BTN_CONNECT} — выбрать страну и получить конфиг\n'
            f'{BTN_DEVICES} — кто подключён, переименовать, отключить\n'
            f'{BTN_INVITE} — код для того, у кого не открывается Telegram\n'
            f'{BTN_HELP} — все команды и ссылки'
        )
    else:
        text = '🛡 <b>Fodder VPN</b>\n\nUse the buttons below the input field.'
    await message.answer(text, reply_markup=main_keyboard(), parse_mode='HTML')


async def open_managed_awg_message(message: types.Message) -> None:
    await _send_awg(message, message.from_user)


async def open_managed_awg_callback(callback: types.CallbackQuery) -> None:
    if callback.message:
        await _send_awg(callback.message, callback.from_user)
    await callback.answer()


async def open_family_message(message: types.Message) -> None:
    await _send_family_link(message, message.from_user)


async def open_family_callback(callback: types.CallbackQuery) -> None:
    if callback.message:
        await _send_family_link(callback.message, callback.from_user)
    await callback.answer()


async def open_portal(message: types.Message) -> None:
    if _is_russian(message):
        offer = (
            'Нидерланды бесплатно подписчикам Fodder’s Dev. '
            if _channel_access_enabled()
            else 'Бесплатные Нидерланды готовятся к запуску. '
        )
        text = (
            '🛡 <b>Fodder VPN</b>\n\n'
            + offer + 'Другие страны, '
            'дополнительные устройства и прокси для приставок — по подписке. '
            'Мастер для собственного VPS тоже находится здесь.'
        )
    else:
        offer = (
            'Netherlands is free for Fodder’s Dev followers. '
            if _channel_access_enabled()
            else 'Free Netherlands access is being prepared. '
        )
        text = (
            '🛡 <b>Fodder VPN</b>\n\n'
            + offer + 'Other countries, '
            'additional devices, and console proxy setup are paid.'
        )
    await message.answer(text, reply_markup=_keyboard(message), parse_mode='HTML')


async def open_legacy_miniapp(message: types.Message) -> None:
    if _is_russian(message):
        text = (
            'Fodders VPN 1 сохранён и продолжает работать.\n\n'
            'В старом мастере доступны подключение собственного VPS, выпуск '
            'профилей AmneziaWG/Xray и диагностика сервера.\n'
            + ('Бесплатные Нидерланды, ' if _channel_access_enabled() else '')
            + 'Платные страны и оплата находятся в /start.'
        )
    else:
        text = (
            'Fodders VPN 1 is preserved and remains available.\n\n'
            'The original wizard still provides bring-your-own-VPS setup, '
            'AmneziaWG/Xray profiles, and server diagnostics.\n'
            'Use /start for '
            + ('free Netherlands access, ' if _channel_access_enabled() else '')
            + 'paid locations, and payments.'
        )
    await message.answer(text, reply_markup=_legacy_keyboard(message))


async def show_help(message: types.Message) -> None:
    if _is_russian(message):
        start_label = (
            'бесплатные Нидерланды, подписка, оплата и подключение'
            if _channel_access_enabled()
            else 'подписка, оплата и подключение'
        )
        text = (
            'Fodder VPN:\n'
            f'• /start — {start_label}\n'
            '• /awg — стабильное подключение через AmneziaWG\n'
            '• /miniapp — единый портал Fodder VPN\n'
            '• /vpn1 или /wizard — прежний мастер своего сервера\n\n'
            # Ссылка на amnezia.org отсюда убрана намеренно: это сайт компании,
            # которая продаёт свой VPN. Отправлять туда своего покупателя —
            # значит показывать ему витрину конкурента. Ссылка на приложение
            # выдаётся на шаге установки, где она к месту и ведёт в магазин.
            'Установка приложения и конфиг — в разделе «Подключить VPN».'
        )
    else:
        start_label = (
            'free Netherlands, paid plans, payments, and connection'
            if _channel_access_enabled()
            else 'paid plans, payments, and connection'
        )
        text = (
            'Fodder VPN:\n'
            f'• /start — {start_label}\n'
            '• /awg — stable connection through AmneziaWG\n'
            '• /miniapp — unified Fodder VPN portal\n'
            '• /vpn1 or /wizard — original server wizard\n\n'
            'App setup and config live under "Подключить VPN".'
        )
    await message.answer(text, reply_markup=_keyboard(message))


def _start_payload(text: str) -> str:
    """The bit after ``/start`` in a deep link, if any."""
    parts = (text or '').strip().split(maxsplit=1)
    return parts[1].strip() if len(parts) > 1 else ''


# The site sends people here with a payload saying what they came for, so the
# bot can answer that question instead of repeating a generic greeting.
START_TOPICS = {
    'plan': (
        '💳 <b>Оплата подписки</b>\n\n'
        'Оплата проходит в Telegram Stars. Откройте экран подписки — там видно '
        'сроки, число устройств и точную сумму.\n\n'
        'Профили сохраняются: после оплаты те же ключи включатся снова, '
        'переподключать устройства не нужно.'
    ),
    'help': (
        '❓ <b>Помощь</b>\n\n'
        'Опишите, что не получается — отвечу здесь же. '
        'Быстрые действия — на кнопках под полем ввода.'
    ),
    'portal': (
        '🛡 <b>Личный кабинет открыт.</b>\n\n'
        'Подписка, устройства и приглашения — на кнопках ниже.'
    ),
}


def _start_topic(payload: str) -> str:
    return payload.split('_')[0].lower() if payload else ''


def _start_followup_markup(topic: str) -> types.InlineKeyboardMarkup | None:
    """One tap from the website straight into Bedolaga's own subscription screen."""
    if topic != 'plan':
        return None
    return types.InlineKeyboardMarkup(
        inline_keyboard=[[
            types.InlineKeyboardButton(
                text='📊 Подписка и оплата', callback_data='menu_subscription'
            ),
        ]]
    )


def _start_followup_text(payload: str, russian: bool) -> str:
    if not russian:
        return (
            '🛡 <b>Fodder VPN</b>\n\nUse the buttons below the input field, '
            'or /help for every command.'
        )
    topic = _start_topic(payload)
    if topic in START_TOPICS:
        return START_TOPICS[topic]
    opening = (
        '✅ <b>Ссылка открыта.</b>\n\n'
        if payload
        else '🛡 <b>Fodder VPN</b>\n\n'
    )
    return (
        opening
        + 'Дальше всё делается этими кнопками:\n\n'
        + f'{BTN_CONNECT} — выбрать страну, получить конфиг и QR\n'
        + f'{BTN_DEVICES} — кто подключён, переименовать, отключить\n'
        + f'{BTN_INVITE} — код для того, у кого не открывается Telegram\n'
        + f'{BTN_HELP} — все команды и ссылки'
    )


async def _link_web_profile(message: types.Message, payload: str) -> None:
    """Make the 12-hour website key permanent after Telegram membership exists."""
    if message.from_user is None:
        return
    code = payload[len('web_'):].strip().upper()
    context = _awg_link_context(message.from_user.id)
    if not code or context is None:
        await message.answer('⚠️ Ссылка неполная. Вернитесь на сайт и откройте её ещё раз.')
        return
    base, token = context
    url = f'{base}/api/web/invite/{code}/link'
    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url,
                params={'telegram_id': message.from_user.id, 'token': token},
            ) as response:
                status = response.status
                try:
                    body = await response.json()
                except Exception:  # noqa: BLE001 - error bodies may be plain text
                    body = {}
    except (aiohttp.ClientError, asyncio.TimeoutError):
        status, body = 0, {}

    if status == 200 and body.get('personal_vpn_url'):
        text = (
            '✅ <b>Профиль сохранён навсегда</b>\n\n'
            'Подписка на Fodder’s Dev подтверждена. Ваши бесплатные Нидерланды '
            'продолжат работать без переустановки, пока вы остаётесь в канале.\n\n'
            'Другие страны и прокси для приставок доступны по платной подписке.'
        )
        markup = types.InlineKeyboardMarkup(inline_keyboard=[[
            types.InlineKeyboardButton(
                text='🛡 Открыть мой VPN', url=str(body['personal_vpn_url'])
            )
        ]])
        await message.answer(text, reply_markup=markup, parse_mode='HTML')
        return

    if status == 403:
        bot_username = (os.getenv('VPNW_BOT_USERNAME') or 'foddervpnbot').strip().lstrip('@')
        retry_url = f'https://t.me/{bot_username}?start=web_{code}'
        markup = types.InlineKeyboardMarkup(inline_keyboard=[
            [types.InlineKeyboardButton(text='➕ Подписаться на Fodder’s Dev', url=_channel_url())],
            [types.InlineKeyboardButton(text='✅ Я подписался — проверить', url=retry_url)],
        ])
        await message.answer(
            'Сначала подпишитесь на <b>Fodder’s Dev</b>, затем нажмите '
            '«Я подписался — проверить». Временный профиль пока продолжает работать.',
            reply_markup=markup,
            parse_mode='HTML',
        )
        return
    await message.answer(
        '⚠️ Не удалось сохранить профиль. Попробуйте открыть эту же ссылку ещё раз. '
        'Если 12 часов уже прошли — попросите новый код.'
    )


async def start_followup_middleware(handler, event, data):
    """Never let a deep link land in a silent chat.

    Bedolaga owns ``/start`` and registers it before this module, so it cannot be
    intercepted without breaking registration, referrals and campaigns. It also
    answers nothing when an already-registered person opens a link with a
    payload — they get dropped into an empty chat with no idea what to do next.
    So the original handler runs untouched and this adds one short message after
    it, which is also what finally puts the action buttons on their screen.
    """
    result = await handler(event, data)
    if not isinstance(event, types.Message):
        return result
    chat = getattr(event, 'chat', None)
    if chat is None or chat.type != 'private':
        return result
    text = (event.text or '').strip()
    if text.split(' ')[0].split('@')[0] != '/start':
        return result
    try:
        # A non-empty FSM state means registration, language choice or rules
        # acceptance is still running — Bedolaga is mid-conversation there and a
        # second voice would only confuse.
        state = data.get('state')
        if state is not None and await state.get_state():
            return result
        payload = _start_payload(text)
        if payload.lower().startswith('web_'):
            await _link_web_profile(event, payload)
            await _ensure_keyboard(event)
            return result
        await event.answer(
            _start_followup_text(payload, _is_russian(event)),
            reply_markup=main_keyboard(),
            parse_mode='HTML',
        )
        # A reply keyboard and an inline keyboard cannot ride on the same
        # message, so the shortcut into payment goes in a second, short one.
        markup = _start_followup_markup(_start_topic(payload))
        if markup is not None:
            await event.answer('Открыть экран оплаты:', reply_markup=markup)
    except Exception:  # a follow-up must never break the real /start
        logger.exception('Failed to send /start follow-up')
    return result


def register_handlers(dp: Dispatcher) -> None:
    dp.message.outer_middleware(start_followup_middleware)
    # Exact-text only: these run before Bedolaga's own text handlers, so a loose
    # filter here would swallow promocodes and support messages.
    dp.message.register(open_managed_awg_message, F.text == BTN_CONNECT)
    dp.message.register(open_devices_message, F.text == BTN_DEVICES)
    dp.message.register(open_invite_message, F.text == BTN_INVITE)
    dp.message.register(show_help, F.text == BTN_HELP)
    dp.message.register(show_menu, Command('menu', 'buttons'))
    dp.message.register(open_managed_awg_message, Command('awg', 'amnezia'))
    dp.callback_query.register(open_managed_awg_callback, F.data == 'fodders_awg')
    dp.callback_query.register(
        send_country_config, F.data.startswith(CONFIG_CALLBACK_PREFIX)
    )
    dp.message.register(open_devices_message, Command('devices', 'ustroystva'))
    dp.message.register(open_invite_message, Command('invite', 'priglasit'))
    dp.callback_query.register(open_invite_callback, F.data == INVITE_CALLBACK)
    dp.callback_query.register(open_devices_callback, F.data == DEVICES_CALLBACK)
    dp.callback_query.register(ask_device_rename, F.data.startswith(DEVICE_RENAME_PREFIX))
    # The confirm prefix extends the revoke prefix, so it must match first.
    dp.callback_query.register(apply_device_revoke, F.data.startswith(DEVICE_REVOKE_CONFIRM_PREFIX))
    dp.callback_query.register(confirm_device_revoke, F.data.startswith(DEVICE_REVOKE_PREFIX))
    dp.message.register(apply_device_rename, F.reply_to_message)
    dp.message.register(open_family_message, Command('family', 'share'))
    dp.callback_query.register(open_family_callback, F.data == 'fodders_awg_family')
    dp.message.register(open_portal, Command('miniapp', 'portal'))
    dp.message.register(open_legacy_miniapp, Command('wizard', 'vpn1'))
    dp.message.register(show_help, Command('help'))
