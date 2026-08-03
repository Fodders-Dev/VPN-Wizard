"""Пополнение баланса звёздами + выход из тупика, когда звёзд не хватает.

Единственное отличие от оригинала Bedolaga — вторая кнопка под счётом.

Зачем она
=========

Если у покупателя не хватает звёзд, Telegram предлагает докупить их прямо из
платёжной формы бота — и этот сценарий падает:

    Sorry, but this payment method is not available for the selected product
    PROVIDER_ACCOUNT_INVALID

Проверено на двух аккаунтах, на десктопе и на Android, и со ссылкой на
URL-кнопке, и с нативным sendInvoice — падает одинаково. Наш бот в этом шаге
не участвует: pre_checkout_query до него не доходит, менять в нём нечего.

При этом покупка звёзд САМА ПО СЕБЕ работает: через Настройки → Мои звёзды
пополнение открывается нормально и принимает карту или SberPay. Разница в
том, что там пополнение ни к какому боту не привязано.

Документированная ссылка ``tg://stars_topup?balance=<N>`` открывает ровно
такое непривязанное пополнение:

    «Used to ensure that the user has at least N Telegram Stars on their
     balance» — https://core.telegram.org/api/links#stars-topup-links

``balance`` — это ИТОГОВЫЙ желаемый баланс, а не недостающая часть, поэтому
передаём полную стоимость счёта. Если звёзд уже хватает, Telegram сам скажет
об этом вместо формы.

Бесшовно продолжить прерванную оплату бот не может: после пополнения человек
возвращается и жмёт «Оплатить» ещё раз. Это хуже, чем один клик, но лучше,
чем упереться в ошибку и уйти.
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

        payment_service = PaymentService(message.bot)
        invoice_link = await payment_service.create_stars_invoice(
            amount_kopeks=amount_kopeks,
            description=f'Пополнение баланса на {texts.format_price(amount_kopeks)}',
            payload=f'balance_{db_user.id}_{amount_kopeks}',
        )

        keyboard = types.InlineKeyboardMarkup(
            inline_keyboard=[
                [types.InlineKeyboardButton(text='⭐ Оплатить', url=invoice_link)],
                # Выход из тупика: непривязанное пополнение, которое работает.
                # balance — итоговый желаемый баланс, а не недостающая часть.
                [types.InlineKeyboardButton(
                    text=f'💫 Сначала пополнить звёзды ({stars_amount})',
                    url=f'tg://stars_topup?balance={stars_amount}',
                )],
                [types.InlineKeyboardButton(text=texts.BACK, callback_data='balance_topup')],
            ]
        )

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

        invoice_message = await message.answer(
            f'⭐ <b>Оплата через Telegram Stars</b>\n\n'
            f'💰 Сумма: {texts.format_price(amount_kopeks)}\n'
            f'⭐ К оплате: {stars_amount} звезд\n'
            f'📊 Курс: {stars_rate}₽ за звезду\n\n'
            f'Нажмите «Оплатить». Если звёзд не хватает — сначала пополните их '
            f'второй кнопкой, потом вернитесь и нажмите «Оплатить» ещё раз.',
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
