const form = document.getElementById("provision-form");
const statusEl = document.getElementById("status");
const progressCard = document.getElementById("progress-card");
const resultCard = document.getElementById("result-card");
const downloadLink = document.getElementById("download-link");
const qrImage = document.getElementById("qr-image");
const qrDownload = document.getElementById("qr-download");
const provisionBtn = document.getElementById("provision-btn");
const progressLog = document.getElementById("progress-log");
const progressFill = document.getElementById("progress-fill");
const spinner = document.querySelector(".spinner");
const toggleLogBtn = document.getElementById("toggle-log-btn");
const simpleToggle = document.getElementById("simple-toggle");
const advancedFields = document.querySelectorAll(".advanced");
const addClientBtn = document.getElementById("add-client-btn");
const checkServerBtn = document.getElementById("check-server-btn");
const serversCard = document.getElementById("servers-card");
const serverStatusEl = document.getElementById("server-status");
const serverMetaEl = document.getElementById("server-meta");
const reconfigureToggle = document.getElementById("reconfigure-toggle");
const reconfigureCheckbox = document.getElementById("reconfigure-checkbox");
const serversListEl = document.getElementById("servers-list");
const serversEmptyEl = document.getElementById("servers-empty");
const clientsCard = document.getElementById("clients-card");
const clientsListEl = document.getElementById("clients-list");
const clientsEmptyEl = document.getElementById("clients-empty");
const langButtons = document.querySelectorAll(".lang-btn");
const tourBtn = document.getElementById("tour-btn");
const faqBtn = document.getElementById("faq-btn");
const faqModal = document.getElementById("faq-modal");
const tourModal = document.getElementById("tour-modal");
const faqContent = document.getElementById("faq-content");
const tourStepTitle = document.getElementById("tour-step-title");
const tourStepBody = document.getElementById("tour-step-body");
const tourPrevBtn = document.getElementById("tour-prev");
const tourNextBtn = document.getElementById("tour-next");
const profileOnlyFields = document.querySelectorAll(".profile-only");
const modalCloseEls = document.querySelectorAll("[data-modal-close]");

const I18N = {
  ru: {
    app_title: "VPN Wizard",
    app_subtitle: "Простая настройка AmneziaWG VPN на вашем сервере",
    step1_title: "Шаг 1. Доступ к серверу",
    server_host_label: "IP или хост сервера",
    server_host_placeholder: "1.2.3.4",
    ssh_user_label: "SSH пользователь",
    ssh_user_placeholder: "root",
    ssh_password_label: "SSH пароль",
    ssh_password_placeholder: "если ключ - можно пусто",
    client_name_label: "Имя профиля",
    client_name_placeholder: "grandma-phone",
    profile_name_hint: "Нужно, чтобы разные устройства не перезаписывали конфиги. Можно оставить пустым.",
    ssh_key_label: "SSH ключ (необязательно)",
    ssh_key_placeholder: "вставьте приватный ключ",
    udp_port_label: "UDP порт сервера",
    tour_btn: "Обучение",
    faq_btn: "FAQ",
    check_server_btn: "Проверить сервер",
    server_status_idle: "Сервер не проверен",
    reconfigure_label: "Показать настройку сервера",
    simple_mode_label: "Простой режим",
    simple_mode_hint: "Скрыть расширенные поля",
    provision_btn: "Настроить сервер и получить первый профиль",
    add_client_btn: "Добавить профиль",
    step2_title: "Шаг 2. Прогресс",
    status_waiting: "Ожидание...",
    step3_title: "Шаг 3. Скачать",
    download_btn: "Скачать конфиг",
    download_qr_btn: "Скачать QR",
    servers_title: "Мои серверы",
    servers_empty: "Пока нет сохранённых серверов.",
    servers_use_btn: "Использовать",
    onboarding_title: "Быстрый старт",
    onboarding_step1: "1) Введите IP/хост, SSH пользователя и пароль или ключ.",
    onboarding_step2: "2) Нажмите \"Проверить сервер\" - если VPN уже есть, появятся профили.",
    onboarding_step3: "3) Если нет - нажмите \"Настроить сервер\" и скачайте конфиг и QR.",
    onboarding_step4: "4) При блокировках попробуйте другой UDP порт или префикс tyumen-.",
    clients_title: "Профили",
    clients_empty: "Профили не найдены.",
    clients_loading: "Загружаем профили...",
    client_ip: "IP",
    client_handshake: "Рукопожатие",
    client_transfer: "Трафик",
    client_interface: "Интерфейс",
    client_download: "Конфиг",
    client_qr: "QR",
    client_qr_hide: "Скрыть QR",
    client_qr_download: "Скачать QR",
    client_remove: "Удалить",
    client_rotate: "Перевыпустить",
    client_busy_remove: "Удаляем профиль...",
    client_busy_rotate: "Перевыпускаем ключи...",
    client_busy_export: "Готовим конфиг...",
    client_busy_qr: "Готовим QR...",
    toggle_log_btn: "Показать лог",
    toggle_log_hide: "Скрыть лог",
    status_creating_job: "Создаём задачу...",
    status_provisioning: "Настраиваем сервер... это может занять пару минут.",
    status_adding_client: "Добавляем профиль...",
    status_ready: "Готово.",
    status_client_ready: "Профиль готов",
    status_client_removed: "Профиль удален",
    status_client_rotated: "Профиль перевыпущен",
    status_failed: "Ошибка",
    status_checking: "Проверяем сервер...",
    status_loading_clients: "Загружаем профили...",
    status_server_configured: "Сервер уже настроен",
    status_server_needs_setup: "Сервер не настроен",
    status_server_error: "Не удалось проверить сервер",
    server_use_hint: "Введите пароль или ключ и нажмите \"Проверить сервер\".",
    download_ready: "Скачайте конфиг и отсканируйте QR.",
    check_ok: "ok",
    check_fail: "fail",
    progress_idle: "Ожидание",
    job_queued: "В очереди",
    job_running: "В работе",
    job_done: "Готово",
    job_error: "Ошибка",
    meta_protocol: "Протокол",
    meta_port: "Порт",
    meta_clients: "Профилей",
    meta_tyumen: "Tyumen порт",
    protocol_amneziawg: "AmneziaWG",
    protocol_wireguard: "WireGuard",
    alert_fill_host_user: "Заполните поля Host и User.",
    alert_check_first: "Сначала нажмите \"Проверить сервер\".",
    alert_remove_client: "Удалить профиль",
    alert_remove_confirm: "Точно удалить профиль?",
    alert_rotate_confirm: "Перевыпустить ключи для профиля?",
    alert_export_failed: "Не удалось получить конфиг",
    tour_title: "Обучение",
    tour_prev: "Назад",
    tour_next: "Далее",
    tour_done: "Готово",
    tour_step1_title: "IP или хост",
    tour_step1_body: "IP-адрес или домен берите из панели хостинга (например 212.69.84.167).",
    tour_step2_title: "SSH пользователь",
    tour_step2_body: "Обычно это root, если вы не меняли пользователя при покупке сервера.",
    tour_step3_title: "Пароль или ключ",
    tour_step3_body: "Пароль приходит от хостинга. Если вход по ключу — оставьте поле пустым и вставьте ключ в расширенных полях.",
    tour_step4_title: "Проверка сервера",
    tour_step4_body: "Нажмите, чтобы проверить сервер и увидеть готовые профили.",
    faq_title: "FAQ",
    faq_what_is_title: "Что это за бот?",
    faq_what_is_body: "VPN Wizard подключается к вашему серверу по SSH и автоматически настраивает быстрый VPN. В результате вы получаете готовые конфиги и QR.",
    faq_safe_title: "Это безопасно?",
    faq_safe_body: "Бот использует ваши SSH-данные только для настройки. Мы не храним пароли, всё выполняется на вашем сервере.",
    faq_ports_title: "Что делать, если VPN не работает?",
    faq_ports_body: "Попробуйте другой UDP порт в расширенных настройках (например 3478 или 33434).",
    faq_tyumen_title: "Как добавить профиль?",
    faq_tyumen_body: "Введите имя профиля и нажмите \"Добавить профиль\". Порт можно выбрать в расширенных полях.",
  },
  en: {
    app_title: "VPN Wizard",
    app_subtitle: "Simple setup for your own AmneziaWG VPN",
    step1_title: "Step 1: Server access",
    server_host_label: "Server IP or host",
    server_host_placeholder: "1.2.3.4",
    ssh_user_label: "SSH user",
    ssh_user_placeholder: "root",
    ssh_password_label: "SSH password",
    ssh_password_placeholder: "optional if key",
    client_name_label: "Profile name",
    client_name_placeholder: "grandma-phone",
    profile_name_hint: "Helps avoid overwriting configs between devices. You can leave it empty.",
    ssh_key_label: "SSH key (optional)",
    ssh_key_placeholder: "paste private key",
    udp_port_label: "Server UDP port",
    tour_btn: "Tour",
    faq_btn: "FAQ",
    check_server_btn: "Check server",
    server_status_idle: "Server not checked",
    reconfigure_label: "Show server setup",
    simple_mode_label: "Simple mode",
    simple_mode_hint: "Hide advanced fields",
    provision_btn: "Configure server and get the first profile",
    add_client_btn: "Add profile",
    step2_title: "Step 2: Progress",
    status_waiting: "Waiting...",
    step3_title: "Step 3: Download",
    download_btn: "Download config",
    download_qr_btn: "Download QR",
    servers_title: "My servers",
    servers_empty: "No saved servers yet.",
    servers_use_btn: "Use",
    onboarding_title: "Quick start",
    onboarding_step1: "1) Enter host, SSH user, and password or key.",
    onboarding_step2: "2) Click \"Check server\" - if VPN exists you will see profiles.",
    onboarding_step3: "3) Otherwise click \"Configure server\" and download config + QR.",
    onboarding_step4: "4) If blocked, try another UDP port or the tyumen- prefix.",
    clients_title: "Profiles",
    clients_empty: "No profiles yet.",
    clients_loading: "Loading profiles...",
    client_ip: "IP",
    client_handshake: "Handshake",
    client_transfer: "Traffic",
    client_interface: "Interface",
    client_download: "Config",
    client_qr: "QR",
    client_qr_hide: "Hide QR",
    client_qr_download: "Download QR",
    client_remove: "Remove",
    client_rotate: "Rotate",
    client_busy_remove: "Removing profile...",
    client_busy_rotate: "Rotating keys...",
    client_busy_export: "Preparing config...",
    client_busy_qr: "Preparing QR...",
    toggle_log_btn: "Show log",
    toggle_log_hide: "Hide log",
    status_creating_job: "Creating job...",
    status_provisioning: "Provisioning... this can take a few minutes.",
    status_adding_client: "Adding profile...",
    status_ready: "Ready.",
    status_client_ready: "Profile ready",
    status_client_removed: "Profile removed",
    status_client_rotated: "Profile rotated",
    status_failed: "Failed",
    status_checking: "Checking server...",
    status_loading_clients: "Loading profiles...",
    status_server_configured: "Server already configured",
    status_server_needs_setup: "Server is not configured",
    status_server_error: "Failed to check server",
    server_use_hint: "Enter password or key and click \"Check server\".",
    download_ready: "Ready. Download your config and scan the QR.",
    check_ok: "ok",
    check_fail: "fail",
    progress_idle: "Waiting",
    job_queued: "Queued",
    job_running: "Running",
    job_done: "Done",
    job_error: "Error",
    meta_protocol: "Protocol",
    meta_port: "Port",
    meta_clients: "Profiles",
    meta_tyumen: "Tyumen port",
    protocol_amneziawg: "AmneziaWG",
    protocol_wireguard: "WireGuard",
    alert_fill_host_user: "Please fill in Host and User fields first.",
    alert_check_first: "Please click \"Check server\" first.",
    alert_remove_client: "Remove profile",
    alert_remove_confirm: "Delete this profile?",
    alert_rotate_confirm: "Rotate keys for this profile?",
    alert_export_failed: "Failed to export config",
    tour_title: "Tour",
    tour_prev: "Back",
    tour_next: "Next",
    tour_done: "Done",
    tour_step1_title: "Server host",
    tour_step1_body: "Use the IP or domain from your hosting panel (for example 212.69.84.167).",
    tour_step2_title: "SSH user",
    tour_step2_body: "Usually root unless you changed it when buying the server.",
    tour_step3_title: "Password or key",
    tour_step3_body: "Password comes from the hoster. If you use an SSH key, keep it empty and paste the key in advanced fields.",
    tour_step4_title: "Server check",
    tour_step4_body: "Click to check the server and load profiles.",
    faq_title: "FAQ",
    faq_what_is_title: "What is this bot?",
    faq_what_is_body: "VPN Wizard connects to your server over SSH and configures a fast VPN. You get ready configs and QR.",
    faq_safe_title: "Is it safe?",
    faq_safe_body: "The bot uses your SSH credentials only for setup. We do not store passwords.",
    faq_ports_title: "VPN not working?",
    faq_ports_body: "Try another UDP port in advanced settings (for example 3478 or 33434).",
    faq_tyumen_title: "How to add a profile?",
    faq_tyumen_body: "Enter a profile name and click \"Add profile\". You can change the UDP port in advanced fields.",
  },
};

const LANG_KEY = "vpnw_lang";
const TOUR_STEPS = [
  { titleKey: "tour_step1_title", bodyKey: "tour_step1_body", target: 'input[name="host"]' },
  { titleKey: "tour_step2_title", bodyKey: "tour_step2_body", target: 'input[name="user"]' },
  { titleKey: "tour_step3_title", bodyKey: "tour_step3_body", target: 'input[name="password"]' },
  { titleKey: "tour_step4_title", bodyKey: "tour_step4_body", target: "#check-server-btn" },
];

function isLightColor(hex) {
  if (!hex || !hex.startsWith("#") || hex.length !== 7) {
    return false;
  }
  const r = Number.parseInt(hex.slice(1, 3), 16);
  const g = Number.parseInt(hex.slice(3, 5), 16);
  const b = Number.parseInt(hex.slice(5, 7), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance > 0.7;
}

function resolveLang(tgApp) {
  const url = new URL(window.location.href);
  const param = url.searchParams.get("lang");
  if (param) {
    return param.toLowerCase().startsWith("en") ? "en" : "ru";
  }
  const stored = localStorage.getItem(LANG_KEY);
  if (stored === "en" || stored === "ru") {
    return stored;
  }
  const tgLang = tgApp?.initDataUnsafe?.user?.language_code || "";
  if (tgLang && !tgLang.toLowerCase().startsWith("ru")) {
    return "en";
  }
  return "ru";
}

let currentLang = resolveLang(window.Telegram && window.Telegram.WebApp);
let pollTimer = null;
let serverConfigured = false;

const STATE = {
  clients: [],
  logVisible: false,
  lastAuth: null,
  checked: false,
  clientBusy: {},
  qrByClient: {},
  qrOpen: null,
  clientsLoading: false,
  downloads: {
    configUrl: null,
    qrUrl: null,
  },
  tourIndex: 0,
};

function t(key) {
  return I18N[currentLang]?.[key] || I18N.ru[key] || key;
}

function setLogVisible(visible) {
  STATE.logVisible = visible;
  if (progressLog) {
    progressLog.classList.toggle("hidden", !visible);
  }
  if (toggleLogBtn) {
    toggleLogBtn.textContent = visible ? t("toggle_log_hide") : t("toggle_log_btn");
  }
}

function applyI18n() {
  document.documentElement.lang = currentLang;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    el.textContent = t(key);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    el.setAttribute("placeholder", t(key));
  });
  langButtons.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.lang === currentLang);
  });
  document.title = t("app_title");
  renderServers();
  renderClients();
  renderFaq();
  updateTourStep();
  setLogVisible(STATE.logVisible);
  updateStageVisibility();
}
const tg = window.Telegram && window.Telegram.WebApp;
if (tg) {
  tg.expand();
  const theme = tg.themeParams || {};
  const root = document.documentElement.style;
  const secondary = theme.secondary_bg_color;
  const bg = theme.bg_color;
  const textIsLight = isLightColor(theme.text_color || "");
  if (bg) {
    root.setProperty("--bg-top", bg);
    root.setProperty("--bg-bottom", bg);
  }
  if (secondary) {
    root.setProperty("--card-bg", secondary);
    root.setProperty("--input-bg", secondary);
    root.setProperty("--surface-bg", secondary);
    root.setProperty("--surface-border", "rgba(148, 163, 184, 0.2)");
  }
  if (theme.text_color) {
    root.setProperty("--ink", theme.text_color);
    root.setProperty("--input-text", theme.text_color);
  }
  if (theme.hint_color) {
    root.setProperty("--muted", theme.hint_color);
    root.setProperty("--border", theme.hint_color);
  }
  if (theme.button_color) {
    root.setProperty("--accent", theme.button_color);
    root.setProperty("--accent-dark", theme.button_color);
  }
  if (theme.button_text_color) {
    root.setProperty("--button-text", theme.button_text_color);
  }
  if (secondary) {
    root.setProperty("--hero-bg", secondary);
    root.setProperty("--hero-text", theme.text_color || "#f8fafc");
  }
  if (!secondary && theme.button_color) {
    root.setProperty("--hero-bg", theme.button_color);
    root.setProperty("--hero-text", theme.button_text_color || "#f8fafc");
  }
  if (bg && !secondary) {
    const hex = bg.startsWith("#") ? bg.slice(1) : bg;
    if (hex.length === 6) {
      const r = parseInt(hex.slice(0, 2), 16);
      const g = parseInt(hex.slice(2, 4), 16);
      const b = parseInt(hex.slice(4, 6), 16);
      const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
      if (luminance < 0.4) {
        root.setProperty("--card-bg", "#1f2937");
        root.setProperty("--input-bg", "#111827");
        root.setProperty("--border", "#334155");
        root.setProperty("--muted", "#94a3b8");
        root.setProperty("--hero-bg", "#0f172a");
        root.setProperty("--hero-text", "#e2e8f0");
        root.setProperty("--button-text", "#f8fafc");
        root.setProperty("--surface-bg", "rgba(15, 23, 42, 0.6)");
        root.setProperty("--surface-border", "rgba(148, 163, 184, 0.35)");
      }
    }
  }
  if (textIsLight) {
    root.setProperty("--card-bg", secondary || "#1f2937");
    root.setProperty("--input-bg", secondary || "#111827");
    root.setProperty("--border", "#334155");
    root.setProperty("--muted", "#94a3b8");
    root.setProperty("--surface-bg", "rgba(15, 23, 42, 0.6)");
    root.setProperty("--surface-border", "rgba(148, 163, 184, 0.35)");
  }
}

applyI18n();
setProgressState("idle");
setLogVisible(false);
if (downloadLink) {
  downloadLink.addEventListener("click", handleDownloadClick);
}
if (qrDownload) {
  qrDownload.addEventListener("click", handleDownloadClick);
}
langButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    currentLang = btn.dataset.lang === "en" ? "en" : "ru";
    localStorage.setItem(LANG_KEY, currentLang);
    applyI18n();
  });
});

modalCloseEls.forEach((el) => {
  el.addEventListener("click", () => {
    const modal = el.closest(".modal");
    closeModal(modal);
    if (modal === tourModal) {
      clearTourHighlight();
    }
  });
});

if (faqBtn) {
  faqBtn.addEventListener("click", () => {
    renderFaq();
    openModal(faqModal);
  });
}

if (tourBtn) {
  tourBtn.addEventListener("click", () => {
    STATE.tourIndex = 0;
    openModal(tourModal);
    updateTourStep();
  });
}

if (tourPrevBtn) {
  tourPrevBtn.addEventListener("click", () => {
    if (STATE.tourIndex > 0) {
      STATE.tourIndex -= 1;
      updateTourStep();
    }
  });
}

if (tourNextBtn) {
  tourNextBtn.addEventListener("click", () => {
    if (STATE.tourIndex >= TOUR_STEPS.length - 1) {
      closeModal(tourModal);
      clearTourHighlight();
      return;
    }
    STATE.tourIndex += 1;
    updateTourStep();
  });
}

function setStatus(text) {
  statusEl.textContent = text;
}

function setProgress(lines) {
  progressLog.textContent = lines.join("\n");
}

function setProgressState(state) {
  if (!progressFill) {
    return;
  }
  const map = {
    idle: 8,
    queued: 20,
    running: 65,
    done: 100,
    error: 100,
  };
  progressFill.style.width = `${map[state] ?? 8}%`;
  progressFill.classList.toggle("error", state === "error");
  if (spinner) {
    spinner.classList.toggle("hidden", state !== "running");
  }
}

function scrollToCard(el) {
  if (!el) {
    return;
  }
  el.scrollIntoView({ behavior: "smooth", block: "start" });
}

function handleDownloadClick(event) {
  if (!tg?.openLink) {
    return;
  }
  const url = event.currentTarget?.dataset?.url;
  if (!url) {
    return;
  }
  event.preventDefault();
  tg.openLink(url);
}

function buildConfigUrl(config) {
  if (tg?.openLink) {
    return `data:text/plain;charset=utf-8,${encodeURIComponent(config)}`;
  }
  const blob = new Blob([config], { type: "text/plain" });
  return URL.createObjectURL(blob);
}

function buildQrUrl(qrBase64) {
  return `data:image/png;base64,${qrBase64}`;
}

function setDownload(config, qrBase64, name, options = {}) {
  const safeName = name || "client1";
  const { showResult = true, scroll = true } = options;

  if (STATE.downloads.configUrl?.startsWith("blob:")) {
    URL.revokeObjectURL(STATE.downloads.configUrl);
  }
  const configUrl = buildConfigUrl(config);
  STATE.downloads.configUrl = configUrl;
  downloadLink.download = `${safeName}.conf`;
  downloadLink.href = configUrl;
  downloadLink.dataset.url = configUrl;

  if (qrBase64) {
    const qrData = buildQrUrl(qrBase64);
    STATE.downloads.qrUrl = qrData;
    qrImage.src = qrData;
    if (qrDownload) {
      qrDownload.href = qrData;
      qrDownload.download = `${safeName}.png`;
      qrDownload.dataset.url = qrData;
      qrDownload.classList.remove("hidden");
    }
  } else if (qrDownload) {
    qrImage.removeAttribute("src");
    qrDownload.classList.add("hidden");
  }

  if (showResult && resultCard) {
    resultCard.classList.remove("hidden");
    if (scroll) {
      scrollToCard(resultCard);
    }
  }
}

function setProgressVisible(visible) {
  if (!progressCard) {
    return;
  }
  progressCard.classList.toggle("hidden", !visible);
}

function updateStageVisibility() {
  const checked = STATE.checked;
  const configured = serverConfigured;

  if (serversCard) {
    const hasServers = loadServers().length > 0;
    serversCard.classList.toggle("hidden", !checked && !hasServers);
  }
  if (clientsCard) {
    clientsCard.classList.toggle("hidden", !checked || !configured);
  }
  if (addClientBtn) {
    addClientBtn.classList.toggle("hidden", !checked || !configured);
  }
  if (provisionBtn) {
    provisionBtn.classList.toggle("hidden", !checked || configured);
  }
  profileOnlyFields.forEach((field) => {
    field.classList.toggle("hidden", !checked);
  });
  if (reconfigureToggle) {
    reconfigureToggle.classList.add("hidden");
  }
  if (!checked) {
    if (resultCard) {
      resultCard.classList.add("hidden");
    }
    setProgressVisible(false);
  }
}

function setServerMeta(status) {
  if (!serverMetaEl) {
    return;
  }
  const parts = [];
  if (status.protocol) {
    const protocolLabel = t(`protocol_${status.protocol}`) || status.protocol;
    parts.push(`${t("meta_protocol")}: ${protocolLabel}`);
  }
  if (status.listen_port) {
    parts.push(`${t("meta_port")}: ${status.listen_port}`);
  }
  if (status.clients_count !== undefined) {
    parts.push(`${t("meta_clients")}: ${status.clients_count}`);
  }
  if (status.tyumen_port) {
    parts.push(`${t("meta_tyumen")}: ${status.tyumen_port}`);
  }
  serverMetaEl.textContent = parts.join(" · ");
}

function openModal(modal) {
  if (!modal) {
    return;
  }
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function closeModal(modal) {
  if (!modal) {
    return;
  }
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

function renderFaq() {
  if (!faqContent) {
    return;
  }
  const items = [
    { titleKey: "faq_what_is_title", bodyKey: "faq_what_is_body" },
    { titleKey: "faq_safe_title", bodyKey: "faq_safe_body" },
    { titleKey: "faq_ports_title", bodyKey: "faq_ports_body" },
    { titleKey: "faq_tyumen_title", bodyKey: "faq_tyumen_body" },
  ];
  faqContent.innerHTML = "";
  items.forEach((item) => {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = t(item.titleKey);
    const body = document.createElement("p");
    body.textContent = t(item.bodyKey);
    details.appendChild(summary);
    details.appendChild(body);
    faqContent.appendChild(details);
  });
}

function clearTourHighlight() {
  document.querySelectorAll(".tour-highlight").forEach((el) => {
    el.classList.remove("tour-highlight");
  });
}

function highlightTourTarget(selector) {
  clearTourHighlight();
  if (!selector) {
    return;
  }
  const target = document.querySelector(selector);
  if (!target) {
    return;
  }
  target.classList.add("tour-highlight");
  target.scrollIntoView({ behavior: "smooth", block: "center" });
}

function updateTourStep() {
  if (!tourModal || tourModal.classList.contains("hidden")) {
    return;
  }
  const step = TOUR_STEPS[STATE.tourIndex] || TOUR_STEPS[0];
  if (!step) {
    return;
  }
  if (tourStepTitle) {
    tourStepTitle.textContent = t(step.titleKey);
  }
  if (tourStepBody) {
    tourStepBody.textContent = t(step.bodyKey);
  }
  if (tourPrevBtn) {
    tourPrevBtn.disabled = STATE.tourIndex === 0;
  }
  if (tourNextBtn) {
    tourNextBtn.textContent =
      STATE.tourIndex === TOUR_STEPS.length - 1 ? t("tour_done") : t("tour_next");
  }
  highlightTourTarget(step.target);
}

function resolveApiBase() {
  const url = new URL(window.location.href);
  const param = url.searchParams.get("api");
  if (param) {
    localStorage.setItem("vpnw_api_base", param);
  }
  const stored = localStorage.getItem("vpnw_api_base");
  if (stored) {
    return stored;
  }
  if (window.API_BASE) {
    return window.API_BASE;
  }
  if (window.location.host.endsWith("vercel.app")) {
    return "https://vpn-wizard-production.up.railway.app";
  }
  return "";
}

const API_BASE = resolveApiBase();
const SERVERS_KEY = "vpnw_servers";
const LEGACY_KEYS = ["vpnw_creds", "vpnw_salt", "vpnw_iv"];

function cleanupLegacySecrets() {
  LEGACY_KEYS.forEach((key) => localStorage.removeItem(key));
}

cleanupLegacySecrets();

function getFormData() {
  const data = Object.fromEntries(new FormData(form).entries());
  const keyContent = simpleToggle.checked ? null : data.key_content;
  const listenPort = Number.parseInt(data.listen_port, 10);
  return {
    host: (data.host || "").trim(),
    user: (data.user || "").trim(),
    password: data.password || null,
    key_content: keyContent || null,
    client_name: (data.client_name || "").trim(),
    listen_port: Number.isFinite(listenPort) ? listenPort : null,
  };
}

function loadServers() {
  if (!serversListEl || !serversEmptyEl) {
    return [];
  }
  try {
    const raw = localStorage.getItem(SERVERS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    console.error(err);
    return [];
  }
}

function saveServers(list) {
  if (!serversListEl || !serversEmptyEl) {
    return;
  }
  localStorage.setItem(SERVERS_KEY, JSON.stringify(list));
}

function renderServers() {
  if (!serversListEl || !serversEmptyEl) {
    return;
  }
  const servers = loadServers();
  serversListEl.innerHTML = "";
  serversEmptyEl.classList.toggle("hidden", servers.length > 0);
  servers.forEach((server) => {
    const row = document.createElement("div");
    row.className = "server-row";
    const info = document.createElement("div");
    info.className = "server-info";
    const title = document.createElement("div");
    title.className = "server-title";
    title.textContent = server.host;
    const meta = document.createElement("div");
    meta.className = "server-meta";
    const parts = [];
    if (server.user) {
      parts.push(`SSH: ${server.user}`);
    }
    if (server.listen_port) {
      parts.push(`${t("meta_port")}: ${server.listen_port}`);
    }
    if (server.clients_count !== undefined) {
      parts.push(`${t("meta_clients")}: ${server.clients_count}`);
    }
    meta.textContent = parts.join(" · ");
    info.appendChild(title);
    info.appendChild(meta);
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "secondary";
    useBtn.textContent = t("servers_use_btn");
    useBtn.addEventListener("click", () => {
      form.elements.host.value = server.host || "";
      form.elements.user.value = server.user || "";
      if (form.elements.listen_port && server.listen_port) {
        form.elements.listen_port.value = server.listen_port;
      }
      if (form.elements.password) {
        form.elements.password.value = "";
      }
      if (form.elements.key_content) {
        form.elements.key_content.value = "";
      }
      serverConfigured = false;
      STATE.checked = false;
      updateStageVisibility();
      if (serverStatusEl) {
        serverStatusEl.textContent = t("server_use_hint");
      }
      scrollToCard(form.closest(".card"));
    });
    row.appendChild(info);
    row.appendChild(useBtn);
    serversListEl.appendChild(row);
  });
}

function upsertServer(entry) {
  if (!serversListEl || !serversEmptyEl || !entry?.host) {
    return;
  }
  const servers = loadServers();
  const idx = servers.findIndex((item) => item.host === entry.host);
  if (idx >= 0) {
    servers[idx] = { ...servers[idx], ...entry };
  } else {
    servers.unshift(entry);
  }
  saveServers(servers.slice(0, 8));
  renderServers();
}

async function fetchJson(url, options) {
  const response = await fetch(`${API_BASE}${url}`, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Request failed");
  }
  return payload;
}

function buildSshPayload(data) {
  return {
    host: data.host,
    user: data.user,
    password: data.password || null,
    key_content: data.key_content || null,
  };
}

async function fetchServerStatus(data) {
  return fetchJson("/api/server/status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ssh: buildSshPayload(data),
    }),
  });
}
async function fetchClients(data) {
  const result = await fetchJson("/api/clients/list", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ssh: buildSshPayload(data),
    }),
  });
  if (!result.ok) {
    throw new Error(result.error || "Request failed");
  }
  return result.clients || [];
}

async function exportClient(data, clientName) {
  if (!data?.host || !data?.user) {
    throw new Error(t("alert_fill_host_user"));
  }
  const result = await fetchJson("/api/clients/export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ssh: buildSshPayload(data),
      client_name: clientName,
    }),
  });
  if (!result.ok) {
    throw new Error(result.error || t("alert_export_failed"));
  }
  return result;
}

async function removeClient(data, clientName) {
  if (!data?.host || !data?.user) {
    throw new Error(t("alert_fill_host_user"));
  }
  const result = await fetchJson("/api/clients/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ssh: buildSshPayload(data),
      client_name: clientName,
    }),
  });
  if (!result.ok) {
    throw new Error(result.error || t("status_failed"));
  }
  return result;
}

async function rotateClient(data, clientName) {
  if (!data?.host || !data?.user) {
    throw new Error(t("alert_fill_host_user"));
  }
  const result = await fetchJson("/api/clients/rotate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ssh: buildSshPayload(data),
      client_name: clientName,
      listen_port: data.listen_port || undefined,
    }),
  });
  if (!result.ok) {
    throw new Error(result.error || t("status_failed"));
  }
  return result;
}

function setSimpleMode(enabled) {
  advancedFields.forEach((field) => {
    field.classList.toggle("hidden", enabled);
  });
}

setSimpleMode(true);
simpleToggle.addEventListener("change", () => {
  setSimpleMode(simpleToggle.checked);
});

if (reconfigureCheckbox) {
  reconfigureCheckbox.addEventListener("change", updateStageVisibility);
}
updateStageVisibility();

["host", "user"].forEach((name) => {
  const field = form.elements[name];
  if (!field) {
    return;
  }
  field.addEventListener("input", () => {
    serverConfigured = false;
    STATE.checked = false;
    updateStageVisibility();
    if (serverStatusEl) {
      serverStatusEl.textContent = t("server_status_idle");
    }
    if (serverMetaEl) {
      serverMetaEl.textContent = "";
    }
    renderClients([]);
  });
});

function formatTransfer(rx, tx) {
  if (!rx && !tx) {
    return "0 / 0";
  }
  const left = rx || "0";
  const right = tx || "0";
  return `${left} / ${right}`;
}

function setClientBusy(name, action) {
  if (!name) {
    return;
  }
  STATE.clientBusy[name] = action;
  renderClients();
}

function clearClientBusy(name) {
  if (!name) {
    return;
  }
  delete STATE.clientBusy[name];
  renderClients();
}

function renderClients(list = STATE.clients) {
  if (!clientsCard || !clientsListEl || !clientsEmptyEl) {
    return;
  }
  const showCard = serverConfigured || (list && list.length > 0);
  clientsCard.classList.toggle("hidden", !showCard);
  if (!showCard) {
    return;
  }
  clientsListEl.innerHTML = "";
  const hasClients = list && list.length > 0;
  if (!hasClients) {
    clientsEmptyEl.classList.remove("hidden");
    clientsEmptyEl.innerHTML = STATE.clientsLoading
      ? `<span class="inline-spinner" aria-hidden="true"></span>${t("clients_loading")}`
      : t("clients_empty");
    return;
  }
  clientsEmptyEl.classList.add("hidden");
  list.forEach((client) => {
    const row = document.createElement("div");
    row.className = "client-row";
    const busyAction = STATE.clientBusy[client.name];
    const isBusy = Boolean(busyAction);
    const clientLabel = client.name || "profile";

    const header = document.createElement("div");
    header.className = "client-header";
    const nameEl = document.createElement("div");
    nameEl.textContent = clientLabel;
    const ifaceEl = document.createElement("div");
    ifaceEl.className = "client-meta";
    ifaceEl.textContent = client.interface
      ? `${t("client_interface")}: ${client.interface}`
      : "";
    header.appendChild(nameEl);
    header.appendChild(ifaceEl);

    const meta = document.createElement("div");
    meta.className = "client-meta";
    const handshake = client.latest_handshake || "-";
    const transfer = formatTransfer(client.transfer_rx, client.transfer_tx);
    const parts = [
      `${t("client_ip")}: ${client.ip || "-"}`,
      `${t("client_handshake")}: ${handshake}`,
      `${t("client_transfer")}: ${transfer}`,
    ];
    meta.textContent = parts.join(" · ");

    const actions = document.createElement("div");
    actions.className = "client-actions";

    const configBtn = document.createElement("button");
    configBtn.type = "button";
    configBtn.className = "secondary";
    configBtn.textContent = t("client_download");
    configBtn.disabled = isBusy;
    configBtn.addEventListener("click", async () => {
      try {
        setClientBusy(client.name, "export");
        setStatus(t("client_busy_export"));
        const result = await exportClient(STATE.lastAuth, client.name);
        setDownload(result.config, result.qr_png_base64, result.client_name);
        setStatus(`${t("status_client_ready")}: ${result.client_name}`);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${err}`);
      } finally {
        clearClientBusy(client.name);
      }
    });

    const qrBtn = document.createElement("button");
    qrBtn.type = "button";
    qrBtn.className = "secondary";
    qrBtn.textContent = STATE.qrOpen === client.name ? t("client_qr_hide") : t("client_qr");
    qrBtn.disabled = isBusy;
    qrBtn.addEventListener("click", async () => {
      try {
        if (STATE.qrOpen === client.name) {
          STATE.qrOpen = null;
          renderClients();
          return;
        }
        if (STATE.qrByClient[client.name]) {
          STATE.qrOpen = client.name;
          renderClients();
          return;
        }
        setClientBusy(client.name, "qr");
        setStatus(t("client_busy_qr"));
        const result = await exportClient(STATE.lastAuth, client.name);
        if (result.qr_png_base64) {
          STATE.qrByClient[client.name] = {
            qr: result.qr_png_base64,
            fileName: result.client_name || client.name || "profile",
          };
          STATE.qrOpen = client.name;
          renderClients();
        }
        setStatus(`${t("status_client_ready")}: ${result.client_name}`);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${err}`);
      } finally {
        clearClientBusy(client.name);
      }
    });

    const rotateBtn = document.createElement("button");
    rotateBtn.type = "button";
    rotateBtn.className = "secondary";
    rotateBtn.textContent = t("client_rotate");
    rotateBtn.disabled = isBusy;
    rotateBtn.addEventListener("click", async () => {
      if (!confirm(t("alert_rotate_confirm"))) {
        return;
      }
      try {
        setClientBusy(client.name, "rotate");
        setStatus(t("client_busy_rotate"));
        const result = await rotateClient(STATE.lastAuth, client.name);
        setDownload(result.config, result.qr_png_base64, result.client_name);
        setStatus(`${t("status_client_rotated")}: ${result.client_name}`);
        await refreshClients(STATE.lastAuth);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${err}`);
      } finally {
        clearClientBusy(client.name);
      }
    });

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "secondary";
    removeBtn.textContent = t("client_remove");
    removeBtn.disabled = isBusy;
    removeBtn.addEventListener("click", async () => {
      if (!confirm(t("alert_remove_confirm"))) {
        return;
      }
      try {
        setClientBusy(client.name, "remove");
        setStatus(t("client_busy_remove"));
        await removeClient(STATE.lastAuth, client.name);
        setStatus(t("status_client_removed"));
        if (STATE.qrOpen === client.name) {
          STATE.qrOpen = null;
        }
        delete STATE.qrByClient[client.name];
        await refreshClients(STATE.lastAuth);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${err}`);
      } finally {
        clearClientBusy(client.name);
      }
    });

    actions.appendChild(configBtn);
    actions.appendChild(qrBtn);
    actions.appendChild(rotateBtn);
    actions.appendChild(removeBtn);

    row.appendChild(header);
    row.appendChild(meta);
    row.appendChild(actions);
    if (busyAction) {
      const status = document.createElement("div");
      status.className = "client-status";
      status.textContent = t(`client_busy_${busyAction}`);
      row.appendChild(status);
    }
    if (STATE.qrOpen === client.name && STATE.qrByClient[client.name]?.qr) {
      const qrWrap = document.createElement("div");
      qrWrap.className = "client-qr";
      const img = document.createElement("img");
      img.alt = "QR";
      img.src = buildQrUrl(STATE.qrByClient[client.name].qr);
      const qrLink = document.createElement("a");
      qrLink.className = "secondary";
      qrLink.textContent = t("client_qr_download");
      const qrData = buildQrUrl(STATE.qrByClient[client.name].qr);
      const qrName = STATE.qrByClient[client.name].fileName || clientLabel;
      qrLink.href = qrData;
      qrLink.download = `${qrName}.png`;
      qrLink.dataset.url = qrData;
      qrLink.addEventListener("click", handleDownloadClick);
      qrWrap.appendChild(img);
      qrWrap.appendChild(qrLink);
      row.appendChild(qrWrap);
    }
    clientsListEl.appendChild(row);
  });
}

async function refreshClients(data) {
  if (!data?.host || !data?.user) {
    return;
  }
  STATE.clientsLoading = true;
  setStatus(t("status_loading_clients"));
  renderClients();
  if (serverStatusEl && serverConfigured) {
    serverStatusEl.textContent = `${t("status_server_configured")} · ${t("status_loading_clients")}`;
  }
  try {
    const clients = await fetchClients(data);
    STATE.clients = clients;
    STATE.clientsLoading = false;
    const names = new Set(clients.map((client) => client.name));
    Object.keys(STATE.qrByClient).forEach((name) => {
      if (!names.has(name)) {
        delete STATE.qrByClient[name];
      }
    });
    if (STATE.qrOpen && !names.has(STATE.qrOpen)) {
      STATE.qrOpen = null;
    }
    renderClients();
    upsertServer({
      host: data.host,
      user: data.user,
      listen_port: data.listen_port || undefined,
      clients_count: clients.length,
    });
  } catch (err) {
    setStatus(`${t("status_failed")}: ${err}`);
    STATE.clientsLoading = false;
    renderClients();
  }
}

async function pollJob(jobId, clientName, authData) {
  const status = await fetchJson(`/api/jobs/${jobId}`);
  const lines = status.progress || [];
  setProgress(lines);
  const last = lines.length ? lines[lines.length - 1] : status.status;
  const statusLabel = t(`job_${status.status}`) || status.status;
  setStatus(`${statusLabel}: ${last}`);
  setProgressState(status.status);

  if (status.status === "error") {
    setStatus(`${t("status_failed")}: ${status.error || "unknown error"}`);
    setProgressState("error");
    clearInterval(pollTimer);
    pollTimer = null;
    if (provisionBtn) {
      provisionBtn.disabled = false;
    }
    return;
  }

  if (status.status === "done") {
    clearInterval(pollTimer);
    pollTimer = null;
    const result = await fetchJson(`/api/jobs/${jobId}/result`);
    setDownload(result.config, result.qr_png_base64, clientName || "client1");
    const checks = result.checks || [];
    if (checks.length) {
      const checkText = checks
        .map((item) => `${item.name}: ${item.ok ? t("check_ok") : t("check_fail")}`)
        .join(" | ");
      setStatus(`${t("status_ready")} ${checkText}`);
    } else {
      setStatus(t("download_ready"));
    }
    if (provisionBtn) {
      provisionBtn.disabled = false;
    }
    serverConfigured = true;
    updateStageVisibility();
    if (authData) {
      await refreshClients(authData);
    }
  }
}

if (toggleLogBtn) {
  toggleLogBtn.addEventListener("click", () => {
    setLogVisible(!STATE.logVisible);
  });
}

async function runServerCheck(data) {
  if (!data.host || !data.user) {
    alert(t("alert_fill_host_user"));
    return;
  }
  if (checkServerBtn) {
    checkServerBtn.disabled = true;
  }
  if (serverStatusEl) {
    serverStatusEl.textContent = t("status_checking");
  }
  if (serverMetaEl) {
    serverMetaEl.textContent = "";
  }
  setProgressVisible(false);
  if (resultCard) {
    resultCard.classList.add("hidden");
  }

  try {
    const result = await fetchServerStatus(data);
    if (!result.ok) {
      if (serverStatusEl) {
        serverStatusEl.textContent = `${t("status_server_error")}: ${result.error || "unknown error"}`;
      }
      serverConfigured = false;
      STATE.checked = false;
      STATE.clientsLoading = false;
      updateStageVisibility();
      renderClients([]);
      return;
    }
    STATE.checked = true;
    serverConfigured = Boolean(result.configured);
    if (!serverConfigured) {
      STATE.clientsLoading = false;
    }
    if (serverStatusEl) {
      serverStatusEl.textContent = serverConfigured
        ? t("status_server_configured")
        : t("status_server_needs_setup");
    }
    if (result.listen_port && form.elements.listen_port) {
      form.elements.listen_port.value = result.listen_port;
    }
    setServerMeta(result);
    updateStageVisibility();
    upsertServer({
      host: data.host,
      user: data.user,
      listen_port: result.listen_port || data.listen_port || undefined,
      clients_count: result.clients_count,
    });
    if (serverConfigured) {
      await refreshClients(data);
    } else {
      renderClients([]);
    }
  } catch (err) {
    if (serverStatusEl) {
      serverStatusEl.textContent = `${t("status_server_error")}: ${err}`;
    }
    serverConfigured = false;
    STATE.checked = false;
    STATE.clientsLoading = false;
    updateStageVisibility();
    renderClients([]);
  } finally {
    if (checkServerBtn) {
      checkServerBtn.disabled = false;
    }
  }
}

async function runProvision() {
  const data = getFormData();
  STATE.lastAuth = data;
  if (!data.host || !data.user) {
    alert(t("alert_fill_host_user"));
    return;
  }
  if (!STATE.checked) {
    alert(t("alert_check_first"));
    return;
  }
  STATE.checked = true;
  updateStageVisibility();
  if (provisionBtn) {
    provisionBtn.disabled = true;
  }
  setProgressVisible(true);
  scrollToCard(progressCard);
  setStatus(t("status_creating_job"));
  setProgress([]);
  setProgressState("queued");
  setLogVisible(false);
  if (resultCard) {
    resultCard.classList.add("hidden");
  }

  const payload = {
    ssh: buildSshPayload(data),
    options: {
      client_name: data.client_name || undefined,
      auto_mtu: true,
      tune: true,
      check: true,
    },
  };
  if (data.listen_port) {
    payload.options.listen_port = data.listen_port;
  }

  const currentClientName = data.client_name || "client1";

  try {
    const result = await fetchJson("/api/provision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus(t("status_provisioning"));
    setProgressState("running");
    upsertServer({
      host: data.host,
      user: data.user,
      listen_port: data.listen_port || undefined,
    });
    if (pollTimer) {
      clearInterval(pollTimer);
    }
    pollTimer = setInterval(() => {
      pollJob(result.job_id, currentClientName, data).catch((err) => {
        setStatus(`${t("status_failed")}: ${err}`);
        setProgressState("error");
        clearInterval(pollTimer);
        pollTimer = null;
        if (provisionBtn) {
          provisionBtn.disabled = false;
        }
      });
    }, 2000);
    await pollJob(result.job_id, currentClientName, data);
  } catch (err) {
    setStatus(`${t("status_failed")}: ${err}`);
    setProgressState("error");
    if (provisionBtn) {
      provisionBtn.disabled = false;
    }
  } finally {
    if (!pollTimer && provisionBtn) {
      provisionBtn.disabled = false;
    }
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = getFormData();
  STATE.lastAuth = data;
  await runServerCheck(data);
});

if (provisionBtn) {
  provisionBtn.addEventListener("click", async () => {
    await runProvision();
  });
}

addClientBtn.addEventListener("click", async () => {
  const data = getFormData();
  STATE.lastAuth = data;
  if (!data.host || !data.user) {
    alert(t("alert_fill_host_user"));
    return;
  }
  if (!STATE.checked) {
    alert(t("alert_check_first"));
    return;
  }
  STATE.checked = true;
  updateStageVisibility();
  addClientBtn.disabled = true;
  setProgressVisible(true);
  scrollToCard(progressCard);
  setStatus(t("status_adding_client"));
  setProgress([]);
  setProgressState("running");
  setLogVisible(false);
  if (resultCard) {
    resultCard.classList.add("hidden");
  }
  try {
    const result = await fetchJson("/api/clients/add", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ssh: buildSshPayload(data),
        client_name: data.client_name || null,
        listen_port: data.listen_port || undefined,
      }),
    });
    if (!result.ok) {
      setStatus(`${t("status_failed")}: ${result.error || "unknown error"}`);
      setProgressState("error");
      return;
    }
    setDownload(result.config, result.qr_png_base64, result.client_name);
    setStatus(`${t("status_client_ready")}: ${result.client_name}`);
    setProgressState("done");
    upsertServer({ host: data.host, user: data.user, listen_port: data.listen_port || undefined });
    serverConfigured = true;
    updateStageVisibility();
    await refreshClients(data);
  } catch (err) {
    setStatus(`${t("status_failed")}: ${err}`);
    setProgressState("error");
  } finally {
    addClientBtn.disabled = false;
  }
});
