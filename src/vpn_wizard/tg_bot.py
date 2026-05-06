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
from vpn_wizard.urls import CANONICAL_MINIAPP_URL, resolve_public_miniapp_url
from vpn_wizard.whitelist import WhitelistProvisioner
from vpn_wizard.yandex_cloud import YandexCloudError, provision_wl_gateway


STATE_HOST, STATE_USER, STATE_AUTH, STATE_PASSWORD, STATE_KEY, STATE_PORT = range(6)
DEFAULT_PORT = 3478
REQUIRED_CHANNEL = os.getenv("VPNW_REQUIRED_CHANNEL", "@fodders_dev")

I18N = {
    "ru": {
        "start": (
            "Привет! Это VPN Wizard.\n\n"
            "Бот работает через миниапп: там вся настройка и получение профилей.\n"
            "Нажмите кнопку ниже или используйте /miniapp.\n\n"
            "Где взять приложение AmneziaWG:\n"
            "Android: https://play.google.com/store/apps/details?id=org.amnezia.awg\n"
            "iOS: https://apps.apple.com/us/app/amneziawg/id6478942365\n"
            "Windows: https://github.com/amnezia-vpn/amneziawg-windows-client/releases\n"
            "Linux: https://github.com/amnezia-vpn/amneziawg-linux-kernel-module\n"
            "macOS: пока нет приложения\n\n"
            "Гайд по аренде сервера (HostKey):\n"
            "https://telegra.ph/Kak-arendovat-minimalnyj-server-VPS-na-HostKey-dlya-VPN-12-28\n\n"
            "После получения конфига откройте AmneziaWG и нажмите «+», чтобы добавить файл."
        ),
        "help": (
            "Для настройки используйте миниапп — бот не настраивает сервер напрямую.\n"
            "Нажмите /miniapp и следуйте шагам.\n\n"
            "Приложение AmneziaWG:\n"
            "Android: https://play.google.com/store/apps/details?id=org.amnezia.awg\n"
            "iOS: https://apps.apple.com/us/app/amneziawg/id6478942365\n"
            "Windows: https://github.com/amnezia-vpn/amneziawg-windows-client/releases\n"
            "Linux: https://github.com/amnezia-vpn/amneziawg-linux-kernel-module\n"
            "macOS: пока нет приложения\n\n"
            "Гайд по аренде сервера (HostKey):\n"
            "https://telegra.ph/Kak-arendovat-minimalnyj-server-VPS-na-HostKey-dlya-VPN-12-28\n\n"
            "После получения конфига откройте AmneziaWG и нажмите «+»."
        ),
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
        "miniapp_open": "Откройте мастер:",
        "miniapp_missing": "VPNW_MINIAPP_URL не настроен.",
    },
    "en": {
        "start": (
            "Hi! This is VPN Wizard.\n\n"
            "The bot works via the miniapp: all setup and profiles are there.\n"
            "Tap the button below or use /miniapp.\n\n"
            "Get AmneziaWG:\n"
            "Android: https://play.google.com/store/apps/details?id=org.amnezia.awg\n"
            "iOS: https://apps.apple.com/us/app/amneziawg/id6478942365\n"
            "Windows: https://github.com/amnezia-vpn/amneziawg-windows-client/releases\n"
            "Linux: https://github.com/amnezia-vpn/amneziawg-linux-kernel-module\n"
            "macOS: no official app yet\n\n"
            "VPS rental guide (HostKey):\n"
            "https://telegra.ph/Kak-arendovat-minimalnyj-server-VPS-na-HostKey-dlya-VPN-12-28\n\n"
            "After you get the config, open AmneziaWG and press “+” to add it."
        ),
        "help": (
            "Use the miniapp for setup — the bot no longer provisions directly.\n"
            "Open /miniapp and follow the steps.\n\n"
            "Get AmneziaWG:\n"
            "Android: https://play.google.com/store/apps/details?id=org.amnezia.awg\n"
            "iOS: https://apps.apple.com/us/app/amneziawg/id6478942365\n"
            "Windows: https://github.com/amnezia-vpn/amneziawg-windows-client/releases\n"
            "Linux: https://github.com/amnezia-vpn/amneziawg-linux-kernel-module\n"
            "macOS: no official app yet\n\n"
            "VPS rental guide (HostKey):\n"
            "https://telegra.ph/Kak-arendovat-minimalnyj-server-VPS-na-HostKey-dlya-VPN-12-28\n\n"
            "After you get the config, open AmneziaWG and press “+”."
        ),
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

def _build_miniapp_keyboard(url: Optional[str], update: Update) -> Optional[ReplyKeyboardMarkup]:
    if not url:
        return None
    return ReplyKeyboardMarkup(
        [[KeyboardButton(_t(update, "open_wizard"), web_app=WebAppInfo(url))]],
        resize_keyboard=True,
    )


def _miniapp_url() -> str:
    return resolve_public_miniapp_url(os.getenv("VPNW_MINIAPP_URL") or CANONICAL_MINIAPP_URL)

async def _send_miniapp_intro(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message:
        return
    url = _miniapp_url()
    keyboard = _build_miniapp_keyboard(url, update)
    await message.reply_text(
        _t(update, "start"),
        reply_markup=keyboard or ReplyKeyboardRemove(),
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
    if not await _require_subscription(update, context):
        return ConversationHandler.END
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
    if not await _require_subscription(update, context):
        return
    url = _miniapp_url()
    if not url:
        await update.message.reply_text(_t(update, "miniapp_missing"))
        return
    keyboard = _build_miniapp_keyboard(url, update)
    await update.message.reply_text(_t(update, "miniapp_open"), reply_markup=keyboard)


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_subscription(update, context):
        return
    keyboard = _build_miniapp_keyboard(_miniapp_url(), update)
    await update.message.reply_text(_t(update, "help"), reply_markup=keyboard or ReplyKeyboardRemove())


def _parse_owner_ids(raw: str) -> set[int]:
    ids: set[int] = set()
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            ids.add(int(chunk))
        except ValueError:
            continue
    return ids


def _is_owner(update: Update) -> bool:
    user = update.effective_user
    if not user:
        return False
    allowed = _parse_owner_ids(os.getenv("VPNW_OWNER_IDS", ""))
    if not allowed:
        return False
    return user.id in allowed


def _wl_ssh_config_from_env() -> Optional[SSHConfig]:
    host = (os.getenv("VPNW_WL_VPS_HOST") or "").strip()
    user = (os.getenv("VPNW_WL_VPS_USER") or "").strip() or "root"
    if not host:
        return None
    try:
        port = int((os.getenv("VPNW_WL_VPS_PORT") or "22").strip() or 22)
    except ValueError:
        port = 22
    password = os.getenv("VPNW_WL_VPS_PASSWORD") or None
    key_path = os.getenv("VPNW_WL_VPS_KEY_PATH") or None
    if not (password or key_path):
        return None
    return SSHConfig(host=host, user=user, port=port, password=password, key_path=key_path)


def _run_wl_provision(client_name: str) -> dict:
    """Blocking — meant to be called via asyncio.to_thread."""
    cfg = _wl_ssh_config_from_env()
    if cfg is None:
        raise RuntimeError(
            "VPNW_WL_VPS_HOST/USER/(PASSWORD|KEY_PATH) must be set in env to use /wl_add."
        )
    token = (os.getenv("YC_OAUTH_TOKEN") or "").strip()
    if not token:
        raise RuntimeError("YC_OAUTH_TOKEN missing in env.")
    folder_id = os.getenv("YC_FOLDER_ID") or None
    gateway_name = (os.getenv("VPNW_WL_GATEWAY_NAME") or "vpn-wl").strip() or "vpn-wl"
    try:
        listen_port = int((os.getenv("VPNW_WL_LISTEN_PORT") or "9443").strip() or 9443)
    except ValueError:
        listen_port = 9443
    stop_port80 = (os.getenv("VPNW_WL_STOP_PORT80_SERVICE") or "").strip() or None
    acme_mode = (os.getenv("VPNW_WL_ACME_MODE") or "auto").strip().lower() or "auto"

    progress_log: list[str] = []

    def log(msg: str) -> None:
        progress_log.append(msg)

    with SSHRunner(cfg) as ssh:
        wl = WhitelistProvisioner(
            ssh,
            progress=log,
            listen_port=listen_port,
            stop_port80_service=stop_port80,
            acme_mode=acme_mode,
        )
        inbound = wl.setup_inbound(client_name)
        gateway = provision_wl_gateway(
            oauth_token=token,
            backend_url=inbound["backend_url"],
            name=gateway_name,
            folder_id=folder_id,
            progress=log,
        )
    if not gateway.get("domain"):
        raise RuntimeError(f"Yandex API Gateway returned no domain (status={gateway.get('status')!r}).")
    link = WhitelistProvisioner.build_client_link(
        gateway_domain=gateway["domain"],
        client_uuid=inbound["client_uuid"],
        path=inbound["path"],
        client_name=inbound["client_name"],
    )
    return {
        "client_name": inbound["client_name"],
        "gateway_domain": gateway["domain"],
        "backend_url": inbound["backend_url"] + inbound["path"],
        "link": link,
        "log": progress_log,
    }


async def wl_add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message:
        return
    if not _is_owner(update):
        # Silently behave as a no-op for non-owners so the command doesn't leak to other users.
        return

    args = (context.args or [])
    name = (args[0] if args else "wl1").strip()
    if not name:
        await message.reply_text("Usage: /wl_add <client_name> (e.g. /wl_add mom)")
        return

    await message.reply_text(
        f"Provisioning WL profile for {name!r}... this can take ~30s on first run.",
        reply_markup=ReplyKeyboardRemove(),
    )
    try:
        result = await asyncio.to_thread(_run_wl_provision, name)
    except YandexCloudError as exc:
        await message.reply_text(f"Yandex Cloud error: {exc}")
        return
    except Exception as exc:
        await message.reply_text(f"WL provisioning failed: {exc}")
        return

    text = (
        f"WL profile ready for *{result['client_name']}*\n"
        f"Gateway: `{result['gateway_domain']}`\n"
        f"Backend: `{result['backend_url']}`\n\n"
        f"vless link:\n`{result['link']}`"
    )
    await message.reply_text(text, parse_mode="Markdown")

    img = qrcode.make(result["link"])
    tmp_qr = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    img.save(tmp_qr.name)
    tmp_qr.close()
    try:
        with open(tmp_qr.name, "rb") as fp:
            await message.reply_photo(photo=fp)
    finally:
        Path(tmp_qr.name).unlink(missing_ok=True)


async def wl_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message:
        return
    if not _is_owner(update):
        return
    cfg = _wl_ssh_config_from_env()
    has_token = bool((os.getenv("YC_OAUTH_TOKEN") or "").strip())
    lines = [
        "WL command — owner only",
        "",
        f"VPS configured: {'yes' if cfg else 'no (set VPNW_WL_VPS_HOST/USER/PASSWORD or KEY_PATH)'}",
        f"YC token set:   {'yes' if has_token else 'no (set YC_OAUTH_TOKEN)'}",
        "",
        "Usage:",
        "  /wl_add <name>   # generate or refresh a WL profile, returns vless:// + QR",
    ]
    await message.reply_text("\n".join(lines))


async def fallback_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_subscription(update, context):
        return
    message = update.effective_message
    if not message:
        return
    keyboard = _build_miniapp_keyboard(_miniapp_url(), update)
    await message.reply_text(_t(update, "bot_use_miniapp"), reply_markup=keyboard or ReplyKeyboardRemove())


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
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("wl", wl_cmd))
    app.add_handler(CommandHandler("wl_add", wl_add_cmd))
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
