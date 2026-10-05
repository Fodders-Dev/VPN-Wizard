/* File repair is local only: no upload, storage, analytics or profile logging. */
(function () {
  'use strict';
  var input = document.getElementById('repair-file');
  var button = document.getElementById('repair-download');
  var status = document.getElementById('repair-status');
  var selected = null, filename = '', lastDownloadName = '', revision = 0;
  input.addEventListener('change', async function () {
    var turn = ++revision, file = input.files && input.files[0];
    selected = null; button.disabled = true;
    if (!file) { status.textContent = 'Выберите скачанный файл профиля.'; return; }
    if (file.size > 65536 || !/\.conf(?:\.txt)?$/i.test(file.name)) {
      status.textContent = 'Нужен небольшой файл .conf или .conf.txt, не картинка и не установщик.'; return;
    }
    status.textContent = 'Проверяем файл на вашем устройстве…';
    try {
      var text = await file.text();
      if (turn !== revision) return;
      if (!/^\s*\[Interface\]\s*$/m.test(text) || !/^\s*\[Peer\]\s*$/m.test(text) || !/^\s*PrivateKey\s*=/m.test(text)) {
        status.textContent = 'Это не похоже на профиль AmneziaWG. Скачайте профиль заново со страницы серверов.'; return;
      }
      var region = /^FVPN-([a-z]{2,3})(?:[- .(]|$)/i.exec(file.name);
      filename = FodderProfileFile.name(region ? region[1].toLowerCase() : 'vpn');
      selected = file; button.disabled = false;
      status.textContent = 'Готово. Новая копия будет называться ' + filename + '. Содержимое не изменится.';
    } catch (_) { if (turn === revision) status.textContent = 'Не удалось прочитать файл. Выберите его ещё раз.'; }
  });
  button.addEventListener('click', function () {
    if (!selected) return;
    if (lastDownloadName === filename) filename = FodderProfileFile.name(filename.split('-')[1]);
    FodderProfileFile.save(selected, filename);
    lastDownloadName = filename;
    status.textContent = 'Копия скачана: ' + filename + '. В AmneziaWG выберите именно её через «Импорт из файла».';
  });
  function reveal(hash) {
    var section = document.getElementById(hash.replace(/^#/, ''));
    if (section && section.tagName === 'DETAILS') section.open = true;
  }
  document.querySelectorAll('.guide-device-nav a').forEach(function (a) {
    a.addEventListener('click', function () { reveal(a.hash); });
  });
  window.addEventListener('hashchange', function () { reveal(location.hash); });
  reveal(location.hash);
}());
