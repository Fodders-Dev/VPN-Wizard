"""Пополнение баланса звёздами — нативным счётом, а не ссылкой.

Что и почему изменено относительно оригинала Bedolaga
=====================================================

Оригинал создаёт ``create_invoice_link`` и вешает полученный ``t.me/$…`` на
URL-кнопку «⭐ Оплатить». Это законный метод API, но у него другой путь в
клиенте: счёт открывается как внешняя ссылка. И если звёзд на балансе не
хватает, комбинированный сценарий «докупи и заплати» на этом пути падает:

    Sorry, the payment form cannot be open.
    Sorry, but this payment method is not available for the selected product
    PROVIDER_ACCOUNT_INVALID

Проверено вживую на одном и том же аккаунте и в один и тот же момент:

    ссылка на URL-кнопке   -> PROVIDER_ACCOUNT_INVALID, форма не открывается
    нативный send_invoice  -> «Confirm Your Purchase» -> «34 Stars Needed»
                              с нормальным выбором пакетов

Документация Telegram описывает основным способом именно ``sendInvoice``:
«The user purchases Stars from Telegram (if necessary), then presses the pay
button». ``createInvoiceLink`` на странице про звёзды не упоминается вовсе.

Поэтому здесь счёт отправляется в чат нативно. Payload сохранён байт в байт
(``balance_{user_id}_{amount_kopeks}``) — на него завязана проверка в
``stars_payments.py``, и её ломать нельзя. Идентификаторы сообщений в state
тоже сохранены: по ним счёт потом удаляется.

Если нативная отправка почему-то не пройдёт, остаётся прежний путь со
ссылкой — хуже, чем было, не станет.
"""

import html

import structlog
from aiogram import types
from aiogram.fsm.context import FSMContext

from app.config import settings
from app.database.models import User
from app.external.telegram_stars import TelegramStarsService
from app.keyboards.topup_amounts import get_topup_amount_keyboard
from app.localization.texts import get_texts
from app.services.payment_service import PaymentService
from app.states import BalanceStates
from app.utils.decorators import error_handler


logger = structlog.get_logger(__name__)


def _restriction_keyboard(texts) -> types.InlineKeyboardMarkup:
    support_url = settings.get_support_contact_url()
    keyboard = []
    if support_url:
        keyboard.append([types.InlineKeyboardButton(text='🆘 Обжаловать', url=support_url)])
    keyboard.append([types.InlineKeyboardButton(text=texts.BACK, callback_data='menu_balance')])
    return types.InlineKeyboardMarkup(inline_keyboard=keyboard)


@error_handler
async def start_stars_payment(callback: types.CallbackQuery, db_user: User, state: FSMContext):
    texts = get_texts(db_user.language)

    if not settings.TELEGRAM_STARS_ENABLED:
        await callback.answer('❌ Пополнение через Stars временно недоступно', show_alert=True)
        return

    # Проверка ограничения на пополнение
    if getattr(db_user, 'restriction_topup', False):
        reason = html.escape(getattr(db_user, 'restriction_reason', None) or 'Действие ограничено администратором')
        await callback.message.edit_text(
            f'🚫 <b>Пополнение ограничено</b>\n\n{reason}\n\n'
            'Если вы считаете это ошибкой, вы можете обжаловать решение.',
            reply_markup=_restriction_keyboard(texts),
        )
        await callback.answer()
        return

    message_text = texts.TOP_UP_AMOUNT

    keyboard = await get_topup_amount_keyboard('stars', db_user.language, back_callback='back_to_menu')

    await callback.message.edit_text(message_text, reply_markup=keyboard)

    await state.update_data(
        stars_prompt_message_id=callback.message.message_id,
        stars_prompt_chat_id=callback.message.chat.id,
    )

    await state.set_state(BalanceStates.waiting_for_amount)
    await state.update_data(payment_method='stars')
    await callback.answer()


@error_handler
async def process_stars_payment_amount(message: types.Message, db_user: User, amount_kopeks: int, state: FSMContext):
    texts = get_texts(db_user.language)

    # Проверка ограничения на пополнение
    if getattr(db_user, 'restriction_topup', False):
        reason = html.escape(getattr(db_user, 'restriction_reason', None) or 'Действие ограничено администратором')
        await message.answer(
            f'🚫 <b>Пополнение ограничено</b>\n\n{reason}\n\n'
            'Если вы считаете это ошибкой, вы можете обжаловать решение.',
            reply_markup=_restriction_keyboard(texts),
            parse_mode='HTML',
        )
        await state.clear()
        return

    if not settings.TELEGRAM_STARS_ENABLED:
        await message.answer('⚠️ Оплата Stars временно недоступна')
        return

    try:
        amount_rubles = amount_kopeks / 100
        stars_amount = TelegramStarsService.calculate_stars_from_rubles(amount_rubles)
        stars_rate = settings.get_stars_rate()
        payload = f'balance_{db_user.id}_{amount_kopeks}'

        state_data = await state.get_data()
        prompt_message_id = state_data.get('stars_prompt_message_id')
        prompt_chat_id = state_data.get('stars_prompt_chat_id', message.chat.id)

        try:
            await message.delete()
        except Exception as delete_error:  # pragma: no cover - зависит от прав бота
            logger.warning('Не удалось удалить сообщение с суммой Stars', delete_error=delete_error)

        if prompt_message_id and prompt_message_id != message.message_id:
            try:
                await message.bot.delete_message(prompt_chat_id, prompt_message_id)
            except Exception as delete_error:  # pragma: no cover - диагностический лог
                logger.warning('Не удалось удалить сообщение с запросом суммы Stars', delete_error=delete_error)

        invoice_message = None
        try:
            invoice_message = await message.answer_invoice(
                title='Пополнение баланса',
                description=(
                    f'{texts.format_price(amount_kopeks)} на баланс. '
                    f'Курс: {stars_rate} ₽ за звезду.'
                ),
                payload=payload,
                provider_token='',
                currency='XTR',
                prices=[types.LabeledPrice(label='Пополнение', amount=stars_amount)],
            )
        except Exception as native_error:
            # Ссылка работает там, где звёзд уже достаточно, поэтому она остаётся
            # запасным путём, а не удаляется совсем.
            logger.warning('Нативный Stars invoice не отправился, откатываюсь на ссылку',
                           native_error=native_error)
            payment_service = PaymentService(message.bot)
            invoice_link = await payment_service.create_stars_invoice(
                amount_kopeks=amount_kopeks,
                description=f'Пополнение баланса на {texts.format_price(amount_kopeks)}',
                payload=payload,
            )
            keyboard = types.InlineKeyboardMarkup(
                inline_keyboard=[
                    [types.InlineKeyboardButton(text='⭐ Оплатить', url=invoice_link)],
                    [types.InlineKeyboardButton(text=texts.BACK, callback_data='balance_topup')],
                ]
            )
            invoice_message = await message.answer(
                f'⭐ <b>Оплата через Telegram Stars</b>\n\n'
                f'💰 Сумма: {texts.format_price(amount_kopeks)}\n'
                f'⭐ К оплате: {stars_amount} звезд\n'
                f'📊 Курс: {stars_rate}₽ за звезду\n\n'
                f'Нажмите кнопку ниже для оплаты:',
                reply_markup=keyboard,
                parse_mode='HTML',
            )

        await state.update_data(
            stars_invoice_message_id=invoice_message.message_id,
            stars_invoice_chat_id=invoice_message.chat.id,
        )

        await state.set_state(None)

    except Exception as e:
        logger.error('Ошибка создания Stars invoice', error=e)
        await message.answer('⚠️ Ошибка создания платежа')
