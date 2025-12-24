from __future__ import annotations

import asyncio
import os
from pathlib import Path
import tempfile
from typing import Optional, Tuple

from telegram import KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove, Update, WebAppInfo
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


STATE_HOST, STATE_USER, STATE_AUTH, STATE_PASSWORD, STATE_KEY, STATE_PORT = range(6)
DEFAULT_PORT = 3478
REQUIRED_CHANNEL = os.getenv("VPNW_REQUIRED_CHANNEL", "@fodders_dev")

I18N = {
    "ru": {
        "start": (
            "Добро пожаловать в VPN Wizard.\n\n"
            "1) Отправьте IP или хост сервера (можно с :порт).\n"
            "2) Укажите SSH пользователя и пароль/ключ.\n"
            "3) Получите конфиг и QR.\n\n"
            "Команда /miniapp откроет веб-мастер."
        ),
        "help": (
            "Как пользоваться ботом:\n"
            "1) Отправьте IP/хост сервера.\n"
            "2) Укажите SSH пользователя и пароль/ключ.\n"
            "3) Выберите UDP порт (рекомендуем 3478).\n"
            "4) Получите конфиг и QR.\n\n"
            "Для веб-версии используйте /miniapp."
        ),
        "subscribe_required": "Подпишитесь на канал {channel} и нажмите /start, чтобы пользоваться ботом.",
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
        "miniapp_open": "Откройте мастер:",
        "miniapp_missing": "VPNW_MINIAPP_URL не настроен.",
    },
    "en": {
        "start": (
            "Welcome to VPN Wizard.\n\n"
            "1) Send your server IP or host (optionally with :port).\n"
            "2) Provide SSH user and password/key.\n"
            "3) Receive config and QR.\n\n"
            "Use /miniapp to open the web wizard."
        ),
        "help": (
            "How to use:\n"
            "1) Send your server IP/host.\n"
            "2) Provide SSH user and password/key.\n"
            "3) Pick UDP port (3478 recommended).\n"
            "4) Receive config and QR.\n\n"
            "Use /miniapp for the web UI."
        ),
        "subscribe_required": "Subscribe to {channel} and send /start to use the bot.",
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


async def _require_subscription(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not REQUIRED_CHANNEL:
        return True
    user = update.effective_user
    if not user:
        return False
    try:
        member = await context.bot.get_chat_member(REQUIRED_CHANNEL, user.id)
    except Exception:
        member = None
    if not member or member.status in {"left", "kicked"}:
        await update.message.reply_text(
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
    if not await _require_subscription(update, context):
        return ConversationHandler.END
    await update.message.reply_text(
        _t(update, "start"),
        reply_markup=ReplyKeyboardRemove(),
    )
    context.user_data.clear()
    return STATE_HOST


async def host_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    host, port = _parse_host_port(update.message.text)
    context.user_data["host"] = host
    context.user_data["port"] = port
    await update.message.reply_text(_t(update, "ask_user"))
    return STATE_USER


async def user_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["user"] = update.message.text.strip()
    keyboard = ReplyKeyboardMarkup(
        [[_t(update, "auth_password"), _t(update, "auth_key")]],
        one_time_keyboard=True,
        resize_keyboard=True,
    )
    await update.message.reply_text(_t(update, "choose_auth"), reply_markup=keyboard)
    return STATE_AUTH


async def auth_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
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
    context.user_data["password"] = update.message.text
    keyboard = ReplyKeyboardMarkup(
        [[str(DEFAULT_PORT), "33434", "27015", "443", _t(update, "port_default")]],
        one_time_keyboard=True,
        resize_keyboard=True,
    )
    await update.message.reply_text(_t(update, "ask_port"), reply_markup=keyboard)
    return STATE_PORT


async def key_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["key_content"] = update.message.text
    keyboard = ReplyKeyboardMarkup(
        [[str(DEFAULT_PORT), "33434", "27015", "443", _t(update, "port_default")]],
        one_time_keyboard=True,
        resize_keyboard=True,
    )
    await update.message.reply_text(_t(update, "ask_port"), reply_markup=keyboard)
    return STATE_PORT


async def port_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
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
    await update.message.reply_text(_t(update, "canceled"), reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END


async def miniapp(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_subscription(update, context):
        return
    url = os.getenv("VPNW_MINIAPP_URL")
    if not url:
        await update.message.reply_text(_t(update, "miniapp_missing"))
        return
    keyboard = ReplyKeyboardMarkup(
        [[KeyboardButton(_t(update, "open_wizard"), web_app=WebAppInfo(url))]],
        resize_keyboard=True,
    )
    await update.message.reply_text(_t(update, "miniapp_open"), reply_markup=keyboard)


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_subscription(update, context):
        return
    await update.message.reply_text(_t(update, "help"), reply_markup=ReplyKeyboardRemove())


def main() -> None:
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
    app.add_handler(CommandHandler("help", help_cmd))
    app.run_polling()


if __name__ == "__main__":
    main()
