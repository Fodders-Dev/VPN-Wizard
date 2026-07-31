/* Fodder VPN — общий слой интерфейса «Звёздный атлас».
 *
 * Подключать сразу после <body>, без defer: скрипт кладёт SVG-спрайт первым
 * элементом страницы, поэтому все <use> ниже по документу резолвятся ещё на
 * разборе и иконки не мигают.
 *
 * Emoji не являются иконками интерфейса — здесь одна линейная семья на всё
 * приложение. Флаги остаются emoji, но только рядом со странами.
 */
(function () {
  'use strict';

  /* ------------------------------------------------------------ иконки */
  var ICONS = {
    shield: '<path d="M12 3l7 3v5.2c0 4.4-3 7.5-7 9.8-4-2.3-7-5.4-7-9.8V6z"/>',
    'shield-check':
      '<path d="M12 3l7 3v5.2c0 4.4-3 7.5-7 9.8-4-2.3-7-5.4-7-9.8V6z"/><path d="M9 11.8l2.2 2.2L15.4 10"/>',
    globe:
      '<circle cx="12" cy="12" r="9"/><path d="M3.2 9.5h17.6M3.2 14.5h17.6"/><path d="M12 3a14 14 0 010 18 14 14 0 010-18z"/>',
    phone:
      '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M10.5 18.6h3"/>',
    monitor:
      '<rect x="3" y="4" width="18" height="12.5" rx="2"/><path d="M8.5 20.5h7M12 16.5v4"/>',
    devices:
      '<rect x="2.5" y="5" width="12" height="10" rx="2"/><path d="M6 18.5h5"/><rect x="16" y="8.5" width="5.5" height="11" rx="1.6"/>',
    user:
      '<circle cx="12" cy="8" r="3.6"/><path d="M4.8 20.2c0-3.9 3.2-6.2 7.2-6.2s7.2 2.3 7.2 6.2"/>',
    download: '<path d="M12 3.5v11.5M7.6 10.6L12 15l4.4-4.4"/><path d="M4 19.5h16"/>',
    qr:
      '<rect x="3.5" y="3.5" width="6.5" height="6.5" rx="1.4"/><rect x="14" y="3.5" width="6.5" height="6.5" rx="1.4"/><rect x="3.5" y="14" width="6.5" height="6.5" rx="1.4"/><path d="M14 14h3M20.5 14v3M14 17.5v3M17.5 20.5h3"/>',
    trash: '<path d="M4 6.8h16M9.2 6.8V4.6h5.6v2.2M6.4 6.8l.9 13.2h9.4l.9-13.2"/>',
    pencil: '<path d="M4 20l.9-3.9L16.4 4.6a2.1 2.1 0 013 3L7.9 19.1z"/>',
    calendar:
      '<rect x="3.5" y="5" width="17" height="15.5" rx="2.2"/><path d="M3.5 10h17M8.4 3v4M15.6 3v4"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 6.8V12.4l3.4 2"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><path d="M12 7.6h.01"/>',
    alert: '<path d="M12 4.2l8.6 15.3H3.4z"/><path d="M12 10v4"/><path d="M12 16.8h.01"/>',
    check: '<path d="M5 12.6l4.4 4.4L19 7.4"/>',
    'check-circle': '<circle cx="12" cy="12" r="9"/><path d="M8.2 12.4l2.6 2.6 5-5.2"/>',
    'x-circle': '<circle cx="12" cy="12" r="9"/><path d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6"/>',
    close: '<path d="M6 6l12 12M18 6L6 18"/>',
    lock:
      '<rect x="4.6" y="10" width="14.8" height="10.4" rx="2.2"/><path d="M8.2 10V7.2a3.8 3.8 0 017.6 0V10"/>',
    chevron: '<path d="M9.5 5l7 7-7 7"/>',
    'arrow-left': '<path d="M19.5 12H5M11 5.6L4.6 12 11 18.4"/>',
    gift:
      '<rect x="3.2" y="8.2" width="17.6" height="4.2" rx="1.4"/><path d="M5 12.4v8.2h14v-8.2M12 8.2v12.4"/><path d="M12 8.2S9.8 3.4 7.8 4.6 9.4 8.2 12 8.2zm0 0s2.2-4.8 4.2-3.6S14.6 8.2 12 8.2z"/>',
    crown: '<path d="M3.6 8.4l4.2 3.8L12 5l4.2 7.2 4.2-3.8-1.7 11H5.3z"/>',
    star:
      '<path d="M12 3.6l2.6 5.4 5.9.9-4.3 4.1 1 5.9-5.2-2.8-5.2 2.8 1-5.9L3.5 9.9l5.9-.9z" fill="currentColor" stroke="none"/>',
    'star-line': '<path d="M12 3.6l2.6 5.4 5.9.9-4.3 4.1 1 5.9-5.2-2.8-5.2 2.8 1-5.9L3.5 9.9l5.9-.9z"/>',
    ticket:
      '<path d="M3.5 8.4V6.2h17v2.2a2.6 2.6 0 000 5.2v4.2h-17v-4.2a2.6 2.6 0 000-5.2z"/><path d="M13.6 6.2v11.6"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.5a2.5 2.5 0 114 2.2c-.9.6-1.6 1.1-1.6 2.1"/><path d="M12 17.2h.01"/>',
    copy:
      '<rect x="8.6" y="8.6" width="11.8" height="11.8" rx="2.2"/><path d="M15.4 5.6a2.2 2.2 0 00-2.2-2.2H5.8a2.2 2.2 0 00-2.2 2.2v7.4a2.2 2.2 0 002.2 2.2"/>',
    share:
      '<circle cx="18" cy="5.5" r="2.6"/><circle cx="6" cy="12" r="2.6"/><circle cx="18" cy="18.5" r="2.6"/><path d="M8.3 10.8l7.4-4M8.3 13.2l7.4 4"/>',
    refresh:
      '<path d="M20 12a8 8 0 11-2.6-5.9"/><path d="M20.4 4v4.4H16"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    'phone-plus':
      '<path d="M14.5 21.5H7a2.5 2.5 0 01-2.5-2.5V5A2.5 2.5 0 017 2.5h7A2.5 2.5 0 0116.5 5v3"/><path d="M19 12.5v7M15.5 16h7"/>',
    key:
      '<circle cx="8" cy="12" r="4.2"/><path d="M12.2 12H21M18.2 12v3.4M15.2 12v2.6"/>',
    server:
      '<rect x="3.5" y="4" width="17" height="6.4" rx="2"/><rect x="3.5" y="13.6" width="17" height="6.4" rx="2"/><path d="M7.4 7.2h.01M7.4 16.8h.01"/>',
    logout: '<path d="M14.5 4.5H6.8A2.3 2.3 0 004.5 6.8v10.4a2.3 2.3 0 002.3 2.3h7.7"/><path d="M18.5 12H9.6M15.6 8.6L19 12l-3.4 3.4"/>',
    wallet:
      '<rect x="3.5" y="6" width="17" height="13" rx="2.4"/><path d="M3.5 10.2h17"/><path d="M16.4 14.6h.01"/>',
  };

  function sprite() {
    var parts = [];
    for (var name in ICONS) {
      if (Object.prototype.hasOwnProperty.call(ICONS, name)) {
        parts.push(
          '<symbol id="i-' + name + '" viewBox="0 0 24 24">' + ICONS[name] + '</symbol>'
        );
      }
    }
    var host = document.createElement('div');
    host.setAttribute('aria-hidden', 'true');
    host.style.cssText = 'position:absolute;width:0;height:0;overflow:hidden';
    host.innerHTML =
      '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + parts.join('') + '</defs></svg>';
    document.body.insertBefore(host, document.body.firstChild);
  }

  /** Разметка иконки. Всегда aria-hidden — смысл несёт соседний текст. */
  function icon(name, cls) {
    return (
      '<svg class="i ' + (cls || '') + '" aria-hidden="true"><use href="#i-' + name + '"/></svg>'
    );
  }

  /* -------------------------------------------------------------- тема */
  /* CSS по умолчанию идёт за системной настройкой. Telegram знает лучше —
   * если он есть, его выбор закрепляется явным атрибутом. */
  function syncTheme(tg) {
    if (!tg) return;
    var apply = function () {
      var scheme = tg.colorScheme === 'light' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', scheme);
      var meta = document.querySelector('meta[name="color-scheme"]');
      if (meta) meta.content = scheme;
    };
    apply();
    if (tg.onEvent) tg.onEvent('themeChanged', apply);
  }

  /* ------------------------------------------------------------- тосты */
  var toastHost = null;
  function toast(message, kind) {
    if (!toastHost) {
      toastHost = document.createElement('div');
      toastHost.className = 'toast-host';
      toastHost.setAttribute('role', 'status');
      toastHost.setAttribute('aria-live', 'polite');
      document.body.appendChild(toastHost);
    }
    var node = document.createElement('div');
    node.className = 'toast' + (kind === 'bad' ? ' toast--bad' : '');
    node.innerHTML =
      icon(kind === 'bad' ? 'x-circle' : 'check-circle') +
      '<span class="toast__text"></span>' +
      '<button class="toast__close" type="button" aria-label="Закрыть">' +
      icon('close', 'i--sm') +
      '</button>';
    node.querySelector('.toast__text').textContent = message;
    var kill = function () {
      if (node.parentNode) node.parentNode.removeChild(node);
    };
    node.querySelector('.toast__close').addEventListener('click', kill);
    toastHost.appendChild(node);
    setTimeout(kill, kind === 'bad' ? 7000 : 4000);
    return kill;
  }

  /* ------------------------------------------- листы и диалоги */
  /* Safari ещё не знает closedby, поэтому клик по подложке ловим руками. */
  function enableLightDismiss(dialog) {
    if ('closedBy' in HTMLDialogElement.prototype) {
      dialog.setAttribute('closedby', 'any');
      return;
    }
    dialog.addEventListener('click', function (event) {
      if (event.target !== dialog) return;
      var rect = dialog.getBoundingClientRect();
      var inside =
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width;
      if (!inside) dialog.close();
    });
  }

  /**
   * Нижний лист. `build(close)` возвращает разметку содержимого.
   * Возвращает сам <dialog>, чтобы вызывающий мог навесить обработчики.
   */
  function sheet(title, build) {
    var dialog = document.createElement('dialog');
    dialog.className = 'sheet';
    dialog.setAttribute('aria-label', title);
    var close = function () {
      dialog.close();
    };
    dialog.innerHTML =
      '<div class="sheet__panel">' +
      '<div class="sheet__grip"></div>' +
      '<div class="sheet__head">' +
      '<h2 class="sheet__title"></h2>' +
      '<button class="head__action" type="button" data-close aria-label="Закрыть">' +
      icon('close') +
      '</button>' +
      '</div>' +
      '<div class="sheet__body"></div>' +
      '</div>';
    dialog.querySelector('.sheet__title').textContent = title;
    dialog.querySelector('.sheet__body').innerHTML = build(close);
    dialog.querySelector('[data-close]').addEventListener('click', close);
    dialog.addEventListener('close', function () {
      if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
    });
    enableLightDismiss(dialog);
    document.body.appendChild(dialog);
    dialog.showModal();
    return dialog;
  }

  /**
   * Подтверждение необратимого действия. Разрешается в true только по явному
   * нажатию — закрытие подложкой или Esc считается отказом.
   */
  function confirmDanger(options) {
    return new Promise(function (resolve) {
      var dialog = document.createElement('dialog');
      dialog.className = 'confirm';
      dialog.setAttribute('aria-label', options.title);
      dialog.innerHTML =
        '<div class="confirm__panel">' +
        '<svg class="confirm__icon" aria-hidden="true"><use href="#i-' +
        (options.icon || 'trash') +
        '"/></svg>' +
        '<h2 class="confirm__title"></h2>' +
        '<p class="confirm__body"></p>' +
        '<div class="confirm__actions">' +
        '<button class="btn btn--danger" type="button" data-yes><span class="btn__label"></span></button>' +
        '<button class="btn btn--secondary" type="button" data-no>Отмена</button>' +
        '</div>' +
        '</div>';
      dialog.querySelector('.confirm__title').textContent = options.title;
      dialog.querySelector('.confirm__body').textContent = options.body || '';
      dialog.querySelector('[data-yes] .btn__label').textContent =
        options.confirmLabel || 'Удалить';

      var settled = false;
      var finish = function (value) {
        if (settled) return;
        settled = true;
        resolve(value);
        dialog.close();
      };
      dialog.querySelector('[data-yes]').addEventListener('click', function () {
        finish(true);
      });
      dialog.querySelector('[data-no]').addEventListener('click', function () {
        finish(false);
      });
      dialog.addEventListener('close', function () {
        finish(false);
        if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
      });
      enableLightDismiss(dialog);
      document.body.appendChild(dialog);
      dialog.showModal();
      dialog.querySelector('[data-no]').focus();
    });
  }

  /* ------------------------------------------------------- мелкие руки */
  /** Кнопка в состоянии загрузки: подпись честно говорит, что происходит. */
  function busy(button, label) {
    var slot = button.querySelector('.btn__label');
    if (!slot) return function () {};
    if (button.dataset.idleLabel === undefined) {
      button.dataset.idleLabel = slot.textContent;
    }
    slot.textContent = label || 'Подождите…';
    button.classList.add('is-loading');
    button.setAttribute('aria-busy', 'true');
    return function () {
      slot.textContent = button.dataset.idleLabel;
      button.classList.remove('is-loading');
      button.removeAttribute('aria-busy');
    };
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[ch];
    });
  }

  /** «2 минуты назад» — человеческим языком, без выдуманной точности. */
  function ago(seconds) {
    if (!seconds) return null;
    var delta = Math.floor(Date.now() / 1000) - Number(seconds);
    if (delta < 0) delta = 0;
    if (delta < 90) return 'только что';
    var minutes = Math.round(delta / 60);
    if (minutes < 60) return minutes + ' ' + plural(minutes, 'минуту', 'минуты', 'минут') + ' назад';
    var hours = Math.round(delta / 3600);
    if (hours < 24) return hours + ' ' + plural(hours, 'час', 'часа', 'часов') + ' назад';
    var days = Math.round(delta / 86400);
    if (days < 32) return days + ' ' + plural(days, 'день', 'дня', 'дней') + ' назад';
    return 'давно';
  }

  function plural(count, one, few, many) {
    var mod100 = count % 100;
    if (mod100 > 10 && mod100 < 20) return many;
    var mod10 = count % 10;
    if (mod10 === 1) return one;
    if (mod10 >= 2 && mod10 <= 4) return few;
    return many;
  }

  function copyText(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(value);
    }
    return new Promise(function (resolve, reject) {
      try {
        var area = document.createElement('textarea');
        area.value = value;
        area.setAttribute('readonly', '');
        area.style.cssText = 'position:fixed;top:-1000px';
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        document.body.removeChild(area);
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  }

  sprite();

  window.Atlas = {
    icon: icon,
    toast: toast,
    sheet: sheet,
    confirmDanger: confirmDanger,
    busy: busy,
    escapeHtml: escapeHtml,
    ago: ago,
    plural: plural,
    copyText: copyText,
    syncTheme: syncTheme,
  };
})();
