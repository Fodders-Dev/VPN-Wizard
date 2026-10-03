/* Shared public status/support UI. Credentials never enter this module. */
(function () {
  "use strict";

  var REFRESH_MS = 60000;
  var timer = null;
  var fetching = false;
  var lastRequestAt = 0;
  var visibilityObserver = null;
  var supportSection = null;
  var userPausedMotion = false;
  var sectionInView = true;
  var motionPreferenceObserved = false;
  var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)");

  function status(server) {
    var health = server.health || {};
    return {
      state: health.state || "unknown",
      label: health.label || "Статус не подтверждён",
      detail: health.detail || "",
      checked: health.checked_at,
      latency: health.latency && health.latency.ms
    };
  }

  function selectable(server) {
    var state = status(server).state;
    return server.enabled !== false && state !== "maintenance" && state !== "unavailable";
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function compactSupportLabel(node, text) {
    var label = node.querySelector(".support-cta-label");
    if (!label) {
      var heart = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      heart.setAttribute("class", "support-heart");
      heart.setAttribute("viewBox", "0 0 24 24");
      heart.setAttribute("aria-hidden", "true");
      heart.setAttribute("focusable", "false");
      var path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", "M12 20S3 14.5 3 8.5C3 3 9 2 12 6c3-4 9-3 9 2.5C21 14.5 12 20 12 20Z");
      heart.appendChild(path);
      label = el("span", "support-cta-label");
      node.replaceChildren(heart, label);
    }
    label.textContent = text;
  }

  function support(data) {
    var main = document.querySelector("main");
    if (!main) return;
    var minimal = main.classList.contains("vpn-minimal");

    var section = document.getElementById("project-support");
    if (!section) {
      section = el("section", "project-support");
      section.id = "project-support";
      if (minimal) section.classList.add("project-support--compact");
      section.setAttribute("aria-labelledby", "support-title");

      var art = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      art.setAttribute("class", "support-art");
      art.setAttribute("viewBox", "0 0 180 150");
      art.setAttribute("aria-hidden", "true");
      art.setAttribute("focusable", "false");
      art.innerHTML = '<circle class="support-art__orbit" cx="92" cy="74" r="43"/><circle class="support-art__orbit support-art__orbit--inner" cx="92" cy="74" r="28"/><path class="support-art__spark" d="M92 10v13M92 125v13M28 74h13M143 74h13M47 29l9 9M128 110l9 9M137 29l-9 9M56 110l-9 9"/><path class="support-art__heart" d="M92 101S53 79 53 56c0-18 23-24 39-4 16-20 39-14 39 4 0 23-39 45-39 45Z"/>';

      var content = el("div", "project-support__content");
      var kicker = el("p", "project-support__kicker", "НЕОБЯЗАТЕЛЬНО И ОТ СЕРДЦА");
      var title = el("h2", "", minimal ? "Помогите VPN оставаться бесплатным" : "Поддержать Fodder VPN");
      title.id = "support-title";
      var copy = el("p", "project-support__copy", minimal ? "Подпиской на канал или небольшим донатом ♥" : "Если проект вам полезен, можно помочь с расходами на серверы. Это полностью добровольно: скачивание профилей не зависит от пожертвования или подписки на канал.");
      var details = el("p", "support-details", "Реквизиты скоро появятся");
      details.id = "support-details";
      details.setAttribute("aria-live", "polite");

      var actions = el("div", "project-support__actions");
      var channel = el("a", "project-support__channel", minimal ? "Подписаться на канал ↗" : "Канал проекта");
      channel.href = "https://t.me/fodders_dev";
      channel.target = "_blank";
      channel.rel = "noopener noreferrer";
      var payment = el("a", "project-support__payment", minimal ? "Поддержать донатом ↗" : "Реквизиты для поддержки");
      if (minimal) compactSupportLabel(payment, "Поддержать донатом ↗");
      payment.id = "support-link";
      payment.target = "_blank";
      payment.rel = "noopener noreferrer";
      payment.hidden = true;
      actions.appendChild(channel);
      actions.appendChild(payment);

      var motion = el("button", "project-support__motion", "Остановить анимацию");
      motion.type = "button";
      motion.setAttribute("aria-pressed", "false");
      motion.setAttribute("aria-label", "Остановить декоративную анимацию");
      motion.addEventListener("click", function () {
        userPausedMotion = !userPausedMotion;
        syncSupportMotion();
      });

      content.appendChild(kicker);
      content.appendChild(title);
      content.appendChild(copy);
      if (minimal) {
        var disclosure = el("details", "support-disclosure");
        disclosure.id = "support-disclosure";
        disclosure.appendChild(el("summary", "", "Поддержать донатом"));
        var panel = el("div", "support-payment-panel");
        panel.appendChild(details);
        var copyButton = el("button", "support-copy", "Скопировать номер карты");
        copyButton.id = "support-copy";
        copyButton.type = "button";
        copyButton.hidden = true;
        var copyStatus = el("p", "support-copy-status");
        copyStatus.id = "support-copy-status";
        copyStatus.setAttribute("role", "status");
        copyButton.addEventListener("click", async function () {
          copyStatus.textContent = "";
          try {
            await navigator.clipboard.writeText(copyButton.dataset.card);
            copyStatus.textContent = "Номер карты скопирован";
          } catch (error) {
            copyStatus.textContent = "Выделите номер карты выше и скопируйте вручную.";
          }
        });
        panel.appendChild(copyButton);
        panel.appendChild(copyStatus);
        disclosure.appendChild(panel);
        actions.appendChild(disclosure);
      } else content.appendChild(details);
      content.appendChild(actions);
      if (minimal) {
        var purpose = el("details", "support-purpose");
        purpose.appendChild(el("summary", "", "На что идут деньги?"));
        purpose.appendChild(el("p", "", "На содержание сайта, оплату VPN-серверов, мониторинг и стабильную работу. Поддержка добровольная: все профили доступны и без доната или подписки."));
        content.appendChild(purpose);
      }
      if (!minimal) {
        content.appendChild(motion);
        section.appendChild(art);
      }
      section.appendChild(content);
      (document.getElementById("support-slot") || main).appendChild(section);
      supportSection = section;

      if ("IntersectionObserver" in window) {
        visibilityObserver = new IntersectionObserver(function (entries) {
          sectionInView = !!(entries[0] && entries[0].isIntersecting);
          syncSupportMotion();
        }, { threshold: 0.01 });
        visibilityObserver.observe(section);
      }
    } else {
      supportSection = section;
    }

    data = data || {};
    var detailsNode = document.getElementById("support-details");
    var detailsText = typeof data.details === "string" ? data.details.trim() : "";
    detailsNode.textContent = detailsText || (minimal ? "Реквизиты пока не добавлены. Поддержать проект можно подпиской на канал." : "Реквизиты скоро появятся");
    var copyButton = document.getElementById("support-copy");
    if (copyButton) {
      var card = detailsText.match(/\b(?:\d[ -]?){15}\d\b/);
      copyButton.hidden = !card;
      copyButton.dataset.card = card ? card[0].replace(/\D/g, "") : "";
    }

    var paymentLink = document.getElementById("support-link");
    var url = typeof data.url === "string" ? data.url.trim() : "";
    if (/^https:\/\//i.test(url)) {
      paymentLink.href = url;
      paymentLink.hidden = false;
    } else {
      paymentLink.hidden = true;
      paymentLink.removeAttribute("href");
    }
    var donationDetails = document.getElementById("support-disclosure");
    if (donationDetails) {
      donationDetails.hidden = !paymentLink.hidden && !detailsText;
      compactSupportLabel(donationDetails.querySelector("summary"), paymentLink.hidden ? "Поддержать донатом" : "Реквизиты");
    }
    syncSupportMotion();
  }

  function syncSupportMotion() {
    if (!supportSection) return;
    var button = supportSection.querySelector(".project-support__motion");
    if (!button) return; // Compact CTA motion is finite, interaction-only, and controlled by CSS.
    var prefersReduced = !!(reducedMotion && reducedMotion.matches);
    var paused = userPausedMotion || document.hidden || !sectionInView || prefersReduced;
    button.hidden = prefersReduced;
    supportSection.classList.toggle("motion-paused", paused);
    button.textContent = supportSection.classList.contains("project-support--compact") ? (userPausedMotion ? "▶" : "Ⅱ") : (userPausedMotion ? "Включить анимацию" : "Остановить анимацию");
    button.setAttribute("aria-pressed", String(userPausedMotion));
    button.setAttribute("aria-label", userPausedMotion ? "Включить декоративную анимацию" : "Остановить декоративную анимацию");
  }

  function emit(name, detail) {
    document.dispatchEvent(new CustomEvent(name, { detail: detail }));
  }

  function stateClass(node, state) {
    Array.from(node.classList).forEach(function (name) {
      if (name.indexOf("server-health--") === 0) node.classList.remove(name);
    });
    node.classList.add("server-health");
    if (state) node.classList.add("server-health--" + state);
  }

  function updateCatalog(data) {
    support(data.support || {});
    (data.servers || []).forEach(function (server) {
      var health = status(server);
      document.querySelectorAll("[data-health-id]").forEach(function (node) {
        if (node.dataset.healthId !== server.id) return;
        stateClass(node, health.state);
        node.textContent = health.label + (health.checked ? " · проверено " + new Date(health.checked * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }) : "");
      });
      document.querySelectorAll("[data-health-detail]").forEach(function (node) {
        if (node.dataset.healthDetail === server.id) node.textContent = health.detail;
      });
      document.querySelectorAll("[data-health-latency]").forEach(function (node) {
        if (node.dataset.healthLatency !== server.id) return;
        if (typeof health.latency === "number") node.textContent = Math.round(health.latency) + " мс · от NL-монитора";
        else node.textContent = "Нет сравнимого замера";
      });
      document.querySelectorAll("button[data-catalog-id]").forEach(function (node) {
        if (node.dataset.catalogId === server.id) node.disabled = !selectable(server);
      });
    });
    emit("fodder:catalog", data);
  }

  function refresh() {
    if (fetching || document.hidden) return;
    fetching = true;
    lastRequestAt = Date.now();
    fetch("/api/awg/servers?include_unavailable=true", { cache: "no-store", credentials: "omit" })
      .then(function (response) {
        if (!response.ok) throw new Error("status");
        return response.json();
      })
      .then(updateCatalog)
      .catch(function (error) {
        document.querySelectorAll("[data-health-id]").forEach(function (node) {
          stateClass(node, "");
          node.textContent = "Не удалось обновить статус";
        });
        emit("fodder:catalog-error", error);
      })
      .then(function () {
        fetching = false;
        scheduleRefresh();
      });
  }

  function scheduleRefresh() {
    if (timer) window.clearTimeout(timer);
    timer = null;
    if (document.hidden) return;
    var delay = Math.max(0, REFRESH_MS - (Date.now() - lastRequestAt));
    timer = window.setTimeout(function () {
      timer = null;
      refresh();
    }, delay || REFRESH_MS);
  }

  function onVisibilityChange() {
    syncSupportMotion();
    if (document.hidden) {
      if (timer) window.clearTimeout(timer);
      timer = null;
      return;
    }
    scheduleRefresh();
  }

  function watch() {
    document.removeEventListener("visibilitychange", onVisibilityChange);
    document.addEventListener("visibilitychange", onVisibilityChange);
    if (reducedMotion && reducedMotion.addEventListener && !motionPreferenceObserved) {
      reducedMotion.addEventListener("change", syncSupportMotion);
      motionPreferenceObserved = true;
    }
    if (!lastRequestAt) refresh();
    else scheduleRefresh();
  }

  window.FodderCatalog = { status: status, selectable: selectable, support: support, watch: watch };
})();
