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


STATE_HOST, STATE_USER, STATE_AUTH, STATE_PASSWORD, STATE_KEY = range(5)


def _parse_host_port(text: str) -> Tuple[str, int]:
    host = text.strip()
    port = 22
    if ":" in host:
        parts = host.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            host, port = parts[0], int(parts[1])
    return host, port


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(
        "Welcome to VPN Wizard.\nSend your server IP or host (optionally with :port).\n"
        "Tip: use /miniapp to open the web wizard.",
        reply_markup=ReplyKeyboardRemove(),
    )
    context.user_data.clear()
    return STATE_HOST


async def host_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    host, port = _parse_host_port(update.message.text)
    context.user_data["host"] = host
    context.user_data["port"] = port
    await update.message.reply_text("SSH user? (example: root)")
    return STATE_USER


async def user_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["user"] = update.message.text.strip()
    keyboard = ReplyKeyboardMarkup([["password", "key"]], one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("Choose auth method:", reply_markup=keyboard)
    return STATE_AUTH


async def auth_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    choice = update.message.text.strip().lower()
    if choice == "password":
        await update.message.reply_text("Send SSH password.", reply_markup=ReplyKeyboardRemove())
        return STATE_PASSWORD
    if choice == "key":
        await update.message.reply_text(
            "Send SSH private key content (paste as text).", reply_markup=ReplyKeyboardRemove()
        )
        return STATE_KEY
    await update.message.reply_text("Type 'password' or 'key'.")
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
        with SSHRunner(cfg) as ssh:
            prov = WireGuardProvisioner(ssh, client_name="client1", auto_mtu=True, tune=True)
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
    await update.message.reply_text("Provisioning... this can take a few minutes.")
    data = context.user_data
    try:
        config, checks = await asyncio.to_thread(_provision, data)
    except Exception as exc:
        await update.message.reply_text(f"Provision failed: {exc}")
        return ConversationHandler.END

    ok = all(item.get("ok") for item in checks) if checks else True
    status = "Checks: OK" if ok else "Checks: Issues"
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
    return await _run_provision(update, context)


async def key_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["key_content"] = update.message.text
    return await _run_provision(update, context)


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Canceled.", reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END


async def miniapp(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    url = os.getenv("VPNW_MINIAPP_URL")
    if not url:
        await update.message.reply_text("VPNW_MINIAPP_URL is not configured.")
        return
    keyboard = ReplyKeyboardMarkup(
        [[KeyboardButton("Open VPN Wizard", web_app=WebAppInfo(url))]],
        resize_keyboard=True,
    )
    await update.message.reply_text("Open the wizard:", reply_markup=keyboard)


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
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    app.add_handler(conv)
    app.add_handler(CommandHandler("miniapp", miniapp))
    app.run_polling()


if __name__ == "__main__":
    main()
