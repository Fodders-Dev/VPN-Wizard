from __future__ import annotations

import asyncio
import os
from pathlib import Path
import tempfile
from typing import Optional, Tuple
from urllib.parse import urlparse

from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    Update,
    WebAppInfo,
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ConversationHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

import qrcode

from vpn_wizard.core import SSHConfig, SSHRunner, WireGuardProvisioner
from vpn_wizard.urls import CANONICAL_API_BASE, resolve_public_miniapp_url


STATE_HOST, STATE_USER, STATE_AUTH, STATE_PASSWORD, STATE_KEY, STATE_PORT = range(6)
DEFAULT_PORT = 3478
REQUIRED_CHANNEL = os.getenv("VPNW_REQUIRED_CHANNEL", "@fodders_dev")

I18N = {
    "ru": {
        "start": "Привет! Выберите бесплатное подключение или настройте собственный сервер.",
        "help": (
            "Бесплатный VPN: выберите сервер и скачайте профиль — без промокода "
            "и ограничения по числу устройств.\n"
            "Свой сервер: /wizard. Пошаговая инструкция — кнопка ниже."
        ),
        "guide": "📖 Инструкция по подключению",
        "bot_use_miniapp": "Бот работает через миниапп. Нажмите кнопку ниже или используйте /miniapp.",
        "subscribe_required": "Подпишитесь на канал {channel} и нажмите /start, чтобы пользоваться ботом.",
        "subscribe_check_failed": (
            "Не могу проверить подписку. Добавьте бота в канал {channel} как администратора "
            "и снова нажмите /start."
        ),
        "ask_user": "SSH пользователь? (пример: root)",
        "choose_auth": "Выберите способ авторизации:",
        "auth_password": "пароль",
        "auth_key": "ключ",
        "ask_password": "Отправьте SSH пароль.",
        "ask_key": "Отправьте SSH приватный ключ (текстом).",
        "ask_port": "UDP порт для VPN? (по умолчанию 3478)",
        "port_invalid": "Введите число порта от 1 до 65535.",
        "port_default": "по умолчанию",
        "auth_retry": "Введите «пароль» или «ключ».",
        "provisioning": "Настраиваем... это может занять пару минут.",
        "provision_failed": "Не удалось настроить: {error}",
        "checks_ok": "Проверки: OK",
        "checks_fail": "Проверки: Есть проблемы",
        "canceled": "Отменено.",
        "open_wizard": "Открыть мастер",
        "free_vpn": "Получить бесплатный VPN",
        "own_server": "Настроить свой сервер",
        "miniapp_open": "Откройте мастер:",
        "miniapp_missing": "VPNW_MINIAPP_URL не настроен.",
    },
    "en": {
        "start": "Hi! Choose free VPN access or set up your own server.",
        "help": (
            "Free VPN: choose a server and download a profile — no promo code "
            "or device limit.\n"
            "Own server: /wizard. Step-by-step setup: button below."
        ),
        "guide": "📖 Connection guide",
        "bot_use_miniapp": "The bot works via the miniapp. Tap the button below or use /miniapp.",
        "subscribe_required": "Subscribe to {channel} and send /start to use the bot.",
        "subscribe_check_failed": (
            "I cannot verify the subscription. Add the bot to {channel} as an admin "
            "and send /start again."
        ),
        "ask_user": "SSH user? (example: root)",
        "choose_auth": "Choose auth method:",
        "auth_password": "password",
        "auth_key": "key",
        "ask_password": "Send SSH password.",
        "ask_key": "Send SSH private key content (paste as text).",
        "ask_port": "UDP port for VPN? (default 3478)",
        "port_invalid": "Enter a port number from 1 to 65535.",
        "port_default": "default",
        "auth_retry": "Type 'password' or 'key'.",
        "provisioning": "Provisioning... this can take a few minutes.",
        "provision_failed": "Provision failed: {error}",
        "checks_ok": "Checks: OK",
        "checks_fail": "Checks: Issues",
        "canceled": "Canceled.",
        "open_wizard": "Open VPN Wizard",
        "free_vpn": "Get free VPN",
        "own_server": "Set up my own server",
        "miniapp_open": "Open the wizard:",
        "miniapp_missing": "VPNW_MINIAPP_URL is not configured.",
    },
}


def _lang(update: Update) -> str:
    code = (update.effective_user.language_code or "").lower()
    if code and not code.startswith("ru"):
        return "en"
    return "ru"


def _t(update: Update, key: str) -> str:
    lang = _lang(update)
    return I18N.get(lang, I18N["ru"]).get(key, key)

def _channel_link() -> str:
    channel = REQUIRED_CHANNEL or ""
    if channel.startswith("http"):
        return channel
    if channel.startswith("@"):
        return f"https://t.me/{channel[1:]}"
    if channel:
        return f"https://t.me/{channel}"
    return ""

def _build_miniapp_keyboard(
    url: Optional[str], update: Update, *, label: Optional[str] = None
) -> Optional[ReplyKeyboardMarkup]:
    if not url:
        return None
    return ReplyKeyboardMarkup(
        [[KeyboardButton(label or _t(update, "open_wizard"), web_app=WebAppInfo(url))]],
        resize_keyboard=True,
    )


def _public_page_url(path: str) -> str:
    configured = (
        os.getenv("VPNW_PUBLIC_BASE_URL")
        or os.getenv("VPNW_MINIAPP_URL")
        or ""
    ).strip()
    if not configured:
        base = CANONICAL_API_BASE
    else:
        candidate = resolve_public_miniapp_url(configured)
        parsed = urlparse(candidate)
        base = f"{parsed.scheme}://{parsed.netloc}"
    return f"{base}{path}"


def _free_vpn_url() -> str:
    return _public_page_url("/connect/join.html")


def _portal_url() -> str:
    return _public_page_url("/portal/")


def _guide_url() -> str:
    return _public_page_url("/connect/guide.html")


def _entry_keyboard(update: Update) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(_t(update, "free_vpn"), url=_free_vpn_url())],
            [InlineKeyboardButton(
                _t(update, "own_server"), web_app=WebAppInfo(_miniapp_url())
            )],
        ]
    )


def _miniapp_url() -> str:
    configured = (os.getenv("VPNW_WIZARD_URL") or "").strip()
    parsed = urlparse(configured)
    if parsed.scheme == "https" and parsed.netloc:
        return configured
    return _public_page_url("/wizard/")

async def _send_miniapp_intro(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message:
        return
    await message.reply_text(
        _t(update, "start"),
        reply_markup=_entry_keyboard(update),
    )


async def _require_subscription(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not REQUIRED_CHANNEL:
        return True
    user = update.effective_user
    message = update.effective_message
    if not user:
        return False
    try:
        member = await context.bot.get_chat_member(REQUIRED_CHANNEL, user.id)
    except Exception:
        if message:
            await message.reply_text(
                _t(update, "subscribe_check_failed").format(channel=_channel_link()),
                reply_markup=ReplyKeyboardRemove(),
            )
        return False
    if not member or member.status in {"left", "kicked"}:
        if message:
            await message.reply_text(
                _t(update, "subscribe_required").format(channel=_channel_link()),
                reply_markup=ReplyKeyboardRemove(),
            )
        return False
    return True


def _parse_host_port(text: str) -> Tuple[str, int]:
    host = text.strip()
    port = 22
    if ":" in host:
        parts = host.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            host, port = parts[0], int(parts[1])
    return host, port


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await _send_miniapp_intro(update, context)
    context.user_data.clear()
    return ConversationHandler.END


async def host_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await _require_subscription(update, context):
        return ConversationHandler.END
    host, port = _parse_host_port(update.message.text)
    context.user_data["host"] = host
    context.user_data["port"] = port
    await update.message.reply_text(_t(update, "ask_user"))
    return STATE_USER


async def user_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await _require_subscription(update, context):
        return ConversationHandler.END
    context.user_data["user"] = update.message.text.strip()
    keyboard = ReplyKeyboardMarkup(
        [[_t(update, "auth_password"), _t(update, "auth_key")]],
        one_time_keyboard=True,
        resize_keyboard=True,
    )
    await update.message.reply_text(_t(update, "choose_auth"), reply_markup=keyboard)
    return STATE_AUTH


async def auth_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await _require_subscription(update, context):
        return ConversationHandler.END
    choice = update.message.text.strip().lower()
    if choice in {"password", "пароль"}:
        await update.message.reply_text(_t(update, "ask_password"), reply_markup=ReplyKeyboardRemove())
        return STATE_PASSWORD
    if choice in {"key", "ключ"}:
        await update.message.reply_text(_t(update, "ask_key"), reply_markup=ReplyKeyboardRemove())
        return STATE_KEY
    await update.message.reply_text(_t(update, "auth_retry"))
    return STATE_AUTH


def _write_temp_key(content: str) -> str:
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
    tmp.write(content)
    tmp.flush()
    tmp.close()
    os.chmod(tmp.name, 0o600)
    return tmp.name


def _provision(data: dict) -> tuple[str, list[dict]]:
    key_path = data.get("key_path")
    temp_key = None
    if data.get("key_content"):
        temp_key = _write_temp_key(data["key_content"])
        key_path = temp_key
    try:
        cfg = SSHConfig(
            host=data["host"],
            user=data["user"],
            port=data.get("port", 22),
            password=data.get("password"),
            key_path=key_path,
        )
        listen_port = data.get("listen_port") or DEFAULT_PORT
        with SSHRunner(cfg) as ssh:
            prov = WireGuardProvisioner(
                ssh,
                client_name="client1",
                auto_mtu=True,
                tune=True,
                listen_port=listen_port,
            )
            prov.provision()
            config = prov.export_client_config()
            checks = prov.post_check()
        return config, checks
    finally:
        if temp_key and Path(temp_key).exists():
            try:
                Path(temp_key).unlink()
            except OSError:
                pass


async def _run_provision(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(_t(update, "provisioning"), reply_markup=ReplyKeyboardRemove())
    data = context.user_data
    try:
        config, checks = await asyncio.to_thread(_provision, data)
    except Exception as exc:
        await update.message.reply_text(_t(update, "provision_failed").format(error=exc))
        return ConversationHandler.END

    ok = all(item.get("ok") for item in checks) if checks else True
    status = _t(update, "checks_ok") if ok else _t(update, "checks_fail")
    await update.message.reply_text(status)

    tmp_conf = tempfile.NamedTemporaryFile(delete=False, suffix=".conf", mode="w", encoding="utf-8")
    tmp_conf.write(config)
    tmp_conf.flush()
    tmp_conf.close()

    img = qrcode.make(config)
    tmp_qr = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    img.save(tmp_qr.name)
    tmp_qr.close()

    with open(tmp_conf.name, "rb") as conf_fp:
        await update.message.reply_document(document=conf_fp, filename="client1.conf")
    with open(tmp_qr.name, "rb") as qr_fp:
        await update.message.reply_photo(photo=qr_fp)

    Path(tmp_conf.name).unlink(missing_ok=True)
    Path(tmp_qr.name).unlink(missing_ok=True)
    return ConversationHandler.END


async def password_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await _require_subscription(update, context):
        return ConversationHandler.END
    context.user_data["password"] = update.message.text
    keyboard = ReplyKeyboardMarkup(
        [[str(DEFAULT_PORT), "33434", "27015", "443", _t(update, "port_default")]],
        one_time_keyboard=True,
        resize_keyboard=True,
    )
    await update.message.reply_text(_t(update, "ask_port"), reply_markup=keyboard)
    return STATE_PORT


async def key_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await _require_subscription(update, context):
        return ConversationHandler.END
    context.user_data["key_content"] = update.message.text
    keyboard = ReplyKeyboardMarkup(
        [[str(DEFAULT_PORT), "33434", "27015", "443", _t(update, "port_default")]],
        one_time_keyboard=True,
        resize_keyboard=True,
    )
    await update.message.reply_text(_t(update, "ask_port"), reply_markup=keyboard)
    return STATE_PORT


async def port_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await _require_subscription(update, context):
        return ConversationHandler.END
    text = update.message.text.strip().lower()
    default_labels = {
        _t(update, "port_default").lower(),
        "default",
        "по умолчанию",
        "по-умолчанию",
    }
    if text in {"", *default_labels}:
        context.user_data["listen_port"] = DEFAULT_PORT
    elif text.isdigit():
        port = int(text)
        if not 1 <= port <= 65535:
            await update.message.reply_text(_t(update, "port_invalid"))
            return STATE_PORT
        context.user_data["listen_port"] = port
    else:
        await update.message.reply_text(_t(update, "port_invalid"))
        return STATE_PORT
    return await _run_provision(update, context)


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await _require_subscription(update, context):
        return ConversationHandler.END
    await update.message.reply_text(_t(update, "canceled"), reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END


async def miniapp(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if message:
        label = "Открыть Fodder VPN" if _lang(update) == "ru" else "Open Fodder VPN"
        keyboard = _build_miniapp_keyboard(_portal_url(), update, label=label)
        await message.reply_text(
            "Откройте бесплатный каталог:" if _lang(update) == "ru" else "Open the free VPN catalog:",
            reply_markup=keyboard,
        )


async def wizard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if message:
        await message.reply_text(
            _t(update, "miniapp_open"),
            reply_markup=_build_miniapp_keyboard(_miniapp_url(), update),
        )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if message:
        keyboard = _entry_keyboard(update)
        rows = [list(row) for row in keyboard.inline_keyboard]
        rows.append(
            [InlineKeyboardButton(_t(update, "guide"), url=_guide_url())]
        )
        await message.reply_text(
            _t(update, "help"), reply_markup=InlineKeyboardMarkup(rows)
        )


async def fallback_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message:
        return
    await message.reply_text(_t(update, "bot_use_miniapp"), reply_markup=_entry_keyboard(update))


def main(*, in_thread: bool = False) -> None:
    token = os.getenv("VPNW_BOT_TOKEN")
    if not token:
        raise RuntimeError("VPNW_BOT_TOKEN is required.")

    app = ApplicationBuilder().token(token).build()
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            STATE_HOST: [MessageHandler(filters.TEXT & ~filters.COMMAND, host_step)],
            STATE_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, user_step)],
            STATE_AUTH: [MessageHandler(filters.TEXT & ~filters.COMMAND, auth_step)],
            STATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, password_step)],
            STATE_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, key_step)],
            STATE_PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, port_step)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    app.add_handler(conv)
    app.add_handler(CommandHandler("miniapp", miniapp))
    app.add_handler(CommandHandler("wizard", wizard))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, fallback_text))
    run_kwargs = {}
    if in_thread:
        # The combined service runs API in the main thread and the bot in a worker thread.
        # PTB should not try to register signal handlers there, and we must not close
        # the process-wide event loop on recoverable polling failures.
        run_kwargs["stop_signals"] = None
        run_kwargs["close_loop"] = False
    app.run_polling(**run_kwargs)


if __name__ == "__main__":
    main()
