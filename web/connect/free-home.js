/* Public navigation must work before/without Telegram SDK, login or any API. */
(function () {
  "use strict";
  var tg = null;
  var hash = new URLSearchParams(location.hash.slice(1));
  var telegramLaunch = !!(window.TelegramWebviewProxy || hash.has("tgWebAppData") || window.parent !== window);
  var free = document.getElementById("public-vpn-link");
  var wizard = document.getElementById("wizard-link-main");
  // Keep signed Telegram launch context in the same-origin fragment only.
  // Our navigation never stores it or sends it as a query; the SDK manages its own session.
  if (hash.has("tgWebAppData")) {
    var launch = new URLSearchParams();
    ["tgWebAppData", "tgWebAppVersion", "tgWebAppPlatform", "tgWebAppThemeParams"].forEach(function (name) {
      if (hash.has(name)) launch.set(name, hash.get(name));
    });
    wizard.hash = launch.toString();
  }
  if (telegramLaunch) { free.target = "_blank"; free.rel = "noopener noreferrer"; }
  document.addEventListener("click", function (event) {
    var link = event.target.closest("a");
    if (!link || !tg) return;
    if (link === free && tg.openLink) {
      event.preventDefault(); tg.openLink(free.href);
    } else if (/^https:\/\/t\.me\//.test(link.href) && tg.openTelegramLink) {
      event.preventDefault(); tg.openTelegramLink(link.href);
    }
  });
  function ready() {
    tg = window.Telegram && window.Telegram.WebApp;
    if (!tg) return;
    try {
      tg.ready(); tg.expand();
      if (tg.setHeaderColor) tg.setHeaderColor("#101312");
      if (tg.setBackgroundColor) tg.setBackgroundColor("#101312");
      if (tg.BackButton) tg.BackButton.hide();
    } catch (_) { /* Both static entry links remain usable. */ }
  }
  if (telegramLaunch) {
    var sdk = document.createElement("script");
    sdk.src = "https://telegram.org/js/telegram-web-app.js";
    sdk.async = true; sdk.onload = ready; document.head.appendChild(sdk);
  } else { ready(); }
  FodderCatalog.support({});
  FodderCatalog.watch();
}());
