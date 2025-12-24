const form = document.getElementById("provision-form");
const statusEl = document.getElementById("status");
const progressCard = document.getElementById("progress-card");
const resultCard = document.getElementById("result-card");
const downloadLink = document.getElementById("download-link");
const qrImage = document.getElementById("qr-image");
const qrDownload = document.getElementById("qr-download");
const button = document.getElementById("provision-btn");
const progressLog = document.getElementById("progress-log");
const progressFill = document.getElementById("progress-fill");
const spinner = document.querySelector(".spinner");
const toggleLogBtn = document.getElementById("toggle-log-btn");
const simpleToggle = document.getElementById("simple-toggle");
const advancedFields = document.querySelectorAll(".advanced");
const addClientBtn = document.getElementById("add-client-btn");
const checkServerBtn = document.getElementById("check-server-btn");
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
    client_name_label: "Имя клиента (необязательно)",
    client_name_placeholder: "grandma-phone",
    ssh_key_label: "SSH ключ (необязательно)",
    ssh_key_placeholder: "вставьте приватный ключ",
    udp_port_label: "UDP порт сервера",
    check_server_btn: "Проверить сервер",
    server_status_idle: "Сервер не проверен",
    reconfigure_label: "Показать настройку сервера",
    simple_mode_label: "Простой режим",
    simple_mode_hint: "Скрыть расширенные поля",
    provision_btn: "Настроить сервер",
    add_client_btn: "Добавить клиента",
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
    onboarding_step2: "2) Нажмите \"Проверить сервер\" - если VPN уже есть, появятся клиенты.",
    onboarding_step3: "3) Если нет - нажмите \"Настроить сервер\" и скачайте конфиг и QR.",
    onboarding_step4: "4) При блокировках попробуйте другой UDP порт или префикс tyumen-.",
    clients_title: "Клиенты",
    clients_empty: "Клиенты не найдены.",
    client_ip: "IP",
    client_handshake: "Рукопожатие",
    client_transfer: "Трафик",
    client_interface: "Интерфейс",
    client_download: "Конфиг",
    client_qr: "QR",
    client_remove: "Удалить",
    client_rotate: "Перевыпустить",
    toggle_log_btn: "Показать лог",
    toggle_log_hide: "Скрыть лог",
    status_creating_job: "Создаём задачу...",
    status_provisioning: "Настраиваем сервер... это может занять пару минут.",
    status_adding_client: "Добавляем клиента...",
    status_ready: "Готово.",
    status_client_ready: "Клиент готов",
    status_client_removed: "Клиент удален",
    status_client_rotated: "Клиент перевыпущен",
    status_failed: "Ошибка",
    status_checking: "Проверяем сервер...",
    status_loading_clients: "Загружаем клиентов...",
    status_server_configured: "Сервер уже настроен",
    status_server_needs_setup: "Сервер не настроен",
    status_server_error: "Не удалось проверить сервер",
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
    meta_clients: "Клиентов",
    meta_tyumen: "Tyumen порт",
    protocol_amneziawg: "AmneziaWG",
    protocol_wireguard: "WireGuard",
    alert_fill_host_user: "Заполните поля Host и User.",
    alert_remove_client: "Удалить клиента",
    alert_remove_confirm: "Точно удалить клиента?",
    alert_rotate_confirm: "Перевыпустить ключи для клиента?",
    alert_export_failed: "Не удалось получить конфиг",
    faq_title: "FAQ",
    faq_what_is_title: "Что это за бот?",
    faq_what_is_body: "VPN Wizard подключается к вашему серверу по SSH и автоматически настраивает быстрый VPN. В результате вы получаете готовые конфиги и QR.",
    faq_safe_title: "Это безопасно?",
    faq_safe_body: "Бот использует ваши SSH-данные только для настройки. Мы не храним пароли, всё выполняется на вашем сервере.",
    faq_ports_title: "Что делать, если VPN не работает?",
    faq_ports_body: "Попробуйте другой UDP порт в расширенных настройках (например 3478 или 33434).",
    faq_tyumen_title: "Как добавить клиента?",
    faq_tyumen_body: "Введите имя клиента и нажмите \"Добавить клиента\". Для обхода блокировок используйте префикс tyumen-.",
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
    client_name_label: "Client name (optional)",
    client_name_placeholder: "grandma-phone",
    ssh_key_label: "SSH key (optional)",
    ssh_key_placeholder: "paste private key",
    udp_port_label: "Server UDP port",
    check_server_btn: "Check server",
    server_status_idle: "Server not checked",
    reconfigure_label: "Show server setup",
    simple_mode_label: "Simple mode",
    simple_mode_hint: "Hide advanced fields",
    provision_btn: "Configure server",
    add_client_btn: "Add new client",
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
    onboarding_step2: "2) Click \"Check server\" - if VPN exists you will see clients.",
    onboarding_step3: "3) Otherwise click “Configure server” and download config + QR.",
    onboarding_step4: "4) If blocked, try another UDP port or the tyumen- prefix.",
    clients_title: "Clients",
    clients_empty: "No clients yet.",
    client_ip: "IP",
    client_handshake: "Handshake",
    client_transfer: "Traffic",
    client_interface: "Interface",
    client_download: "Config",
    client_qr: "QR",
    client_remove: "Remove",
    client_rotate: "Rotate",
    toggle_log_btn: "Show log",
    toggle_log_hide: "Hide log",
    status_creating_job: "Creating job...",
    status_provisioning: "Provisioning... this can take a few minutes.",
    status_adding_client: "Adding client...",
    status_ready: "Ready.",
    status_client_ready: "Client ready",
    status_client_removed: "Client removed",
    status_client_rotated: "Client rotated",
    status_failed: "Failed",
    status_checking: "Checking server...",
    status_loading_clients: "Loading clients...",
    status_server_configured: "Server already configured",
    status_server_needs_setup: "Server is not configured",
    status_server_error: "Failed to check server",
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
    meta_clients: "Clients",
    meta_tyumen: "Tyumen port",
    protocol_amneziawg: "AmneziaWG",
    protocol_wireguard: "WireGuard",
    alert_fill_host_user: "Please fill in Host and User fields first.",
    alert_remove_client: "Remove client",
    alert_remove_confirm: "Delete this client?",
    alert_rotate_confirm: "Rotate keys for this client?",
    alert_export_failed: "Failed to export config",
    faq_title: "FAQ",
    faq_what_is_title: "What is this bot?",
    faq_what_is_body: "VPN Wizard connects to your server over SSH and configures a fast VPN. You get ready configs and QR.",
    faq_safe_title: "Is it safe?",
    faq_safe_body: "The bot uses your SSH credentials only for setup. We do not store passwords.",
    faq_ports_title: "VPN not working?",
    faq_ports_body: "Try another UDP port in advanced settings (for example 3478 or 33434).",
    faq_tyumen_title: "How to add a client?",
    faq_tyumen_body: "Enter a client name and click \"Add client\". For bypass, use the tyumen- prefix.",
  },
};

const LANG_KEY = "vpnw_lang";

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
  setLogVisible(STATE.logVisible);
}
const tg = window.Telegram && window.Telegram.WebApp;
if (tg) {
  tg.expand();
  const theme = tg.themeParams || {};
  const root = document.documentElement.style;
  const secondary = theme.secondary_bg_color;
  const bg = theme.bg_color;
  if (bg) {
    root.setProperty("--bg-top", bg);
    root.setProperty("--bg-bottom", bg);
  }
  if (secondary) {
    root.setProperty("--card-bg", secondary);
    root.setProperty("--input-bg", secondary);
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
      }
    }
  }
}

applyI18n();
setProgressState("idle");
setLogVisible(false);
langButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    currentLang = btn.dataset.lang === "en" ? "en" : "ru";
    localStorage.setItem(LANG_KEY, currentLang);
    applyI18n();
  });
});

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

function setDownload(config, qrBase64, name) {
  const safeName = name || "client1";
  const blob = new Blob([config], { type: "text/plain" });
  downloadLink.download = `${safeName}.conf`;
  downloadLink.href = URL.createObjectURL(blob);
  if (qrBase64) {
    const qrData = `data:image/png;base64,${qrBase64}`;
    qrImage.src = qrData;
    if (qrDownload) {
      qrDownload.href = qrData;
      qrDownload.download = `${safeName}.png`;
      qrDownload.classList.remove("hidden");
    }
  } else if (qrDownload) {
    qrDownload.classList.add("hidden");
  }
  resultCard.style.display = "block";
}

function setConfigureVisibility() {
  if (!button) {
    return;
  }
  const allow = !serverConfigured || (reconfigureCheckbox && reconfigureCheckbox.checked);
  button.style.display = allow ? "inline-flex" : "none";
  if (reconfigureToggle) {
    reconfigureToggle.classList.toggle("hidden", !serverConfigured);
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
      setStatus(t("status_waiting"));
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
  reconfigureCheckbox.addEventListener("change", setConfigureVisibility);
}
setConfigureVisibility();

["host", "user"].forEach((name) => {
  const field = form.elements[name];
  if (!field) {
    return;
  }
  field.addEventListener("input", () => {
    serverConfigured = false;
    setConfigureVisibility();
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
  clientsEmptyEl.classList.toggle("hidden", hasClients);
  if (!hasClients) {
    return;
  }
  list.forEach((client) => {
    const row = document.createElement("div");
    row.className = "client-row";

    const header = document.createElement("div");
    header.className = "client-header";
    const nameEl = document.createElement("div");
    nameEl.textContent = client.name || "client";
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
    configBtn.addEventListener("click", async () => {
      try {
        const result = await exportClient(STATE.lastAuth, client.name);
        setDownload(result.config, result.qr_png_base64, result.client_name);
        setStatus(`${t("status_client_ready")}: ${result.client_name}`);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${err}`);
      }
    });

    const qrBtn = document.createElement("button");
    qrBtn.type = "button";
    qrBtn.className = "secondary";
    qrBtn.textContent = t("client_qr");
    qrBtn.addEventListener("click", async () => {
      try {
        const result = await exportClient(STATE.lastAuth, client.name);
        setDownload(result.config, result.qr_png_base64, result.client_name);
        setStatus(`${t("status_client_ready")}: ${result.client_name}`);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${err}`);
      }
    });

    const rotateBtn = document.createElement("button");
    rotateBtn.type = "button";
    rotateBtn.className = "secondary";
    rotateBtn.textContent = t("client_rotate");
    rotateBtn.addEventListener("click", async () => {
      if (!confirm(t("alert_rotate_confirm"))) {
        return;
      }
      try {
        const result = await rotateClient(STATE.lastAuth, client.name);
        setDownload(result.config, result.qr_png_base64, result.client_name);
        setStatus(`${t("status_client_rotated")}: ${result.client_name}`);
        await refreshClients(STATE.lastAuth);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${err}`);
      }
    });

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "secondary";
    removeBtn.textContent = t("client_remove");
    removeBtn.addEventListener("click", async () => {
      if (!confirm(t("alert_remove_confirm"))) {
        return;
      }
      try {
        await removeClient(STATE.lastAuth, client.name);
        setStatus(t("status_client_removed"));
        await refreshClients(STATE.lastAuth);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${err}`);
      }
    });

    actions.appendChild(configBtn);
    actions.appendChild(qrBtn);
    actions.appendChild(rotateBtn);
    actions.appendChild(removeBtn);

    row.appendChild(header);
    row.appendChild(meta);
    row.appendChild(actions);
    clientsListEl.appendChild(row);
  });
}

async function refreshClients(data) {
  if (!data?.host || !data?.user) {
    return;
  }
  setStatus(t("status_loading_clients"));
  try {
    const clients = await fetchClients(data);
    STATE.clients = clients;
    renderClients();
    upsertServer({
      host: data.host,
      user: data.user,
      listen_port: data.listen_port || undefined,
      clients_count: clients.length,
    });
  } catch (err) {
    setStatus(`${t("status_failed")}: ${err}`);
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
    button.disabled = false;
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
    button.disabled = false;
    serverConfigured = true;
    setConfigureVisibility();
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  resultCard.style.display = "none";
  setStatus(t("status_creating_job"));
  setProgress([]);
  setProgressState("queued");
  setLogVisible(false);

  const data = getFormData();
  STATE.lastAuth = data;

  if (reconfigureCheckbox && !reconfigureCheckbox.checked) {
    try {
      const status = await fetchServerStatus(data);
      if (status.ok && status.configured) {
        serverConfigured = true;
        if (serverStatusEl) {
          serverStatusEl.textContent = t("status_server_configured");
        }
        setServerMeta(status);
        setConfigureVisibility();
        setStatus(t("status_server_configured"));
        button.disabled = false;
        await refreshClients(data);
        return;
      }
    } catch (err) {
      console.error(err);
    }
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
        button.disabled = false;
      });
    }, 2000);
    await pollJob(result.job_id, currentClientName, data);
  } catch (err) {
    setStatus(`${t("status_failed")}: ${err}`);
    setProgressState("error");
    button.disabled = false;
  } finally {
    if (!pollTimer) {
      button.disabled = false;
    }
  }
});

addClientBtn.addEventListener("click", async () => {
  const data = getFormData();
  STATE.lastAuth = data;
  setStatus(t("status_adding_client"));
  setProgress([]);
  setProgressState("running");
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
    upsertServer({ host: data.host, user: data.user, listen_port: data.listen_port || undefined });
    serverConfigured = true;
    setConfigureVisibility();
    await refreshClients(data);
  } catch (err) {
    setStatus(`${t("status_failed")}: ${err}`);
    setProgressState("error");
  }
});

if (checkServerBtn) {
  checkServerBtn.addEventListener("click", async () => {
    const data = getFormData();
    STATE.lastAuth = data;
    if (!data.host || !data.user) {
      alert(t("alert_fill_host_user"));
      return;
    }
    if (serverStatusEl) {
      serverStatusEl.textContent = t("status_checking");
    }
    if (serverMetaEl) {
      serverMetaEl.textContent = "";
    }
    try {
      const result = await fetchServerStatus(data);
      if (!result.ok) {
        if (serverStatusEl) {
          serverStatusEl.textContent = `${t("status_server_error")}: ${result.error || "unknown error"}`;
        }
        serverConfigured = false;
        setConfigureVisibility();
        renderClients([]);
        return;
      }
      serverConfigured = Boolean(result.configured);
      if (serverStatusEl) {
        serverStatusEl.textContent = serverConfigured
          ? t("status_server_configured")
          : t("status_server_needs_setup");
      }
      if (result.listen_port && form.elements.listen_port) {
        form.elements.listen_port.value = result.listen_port;
      }
      setServerMeta(result);
      setConfigureVisibility();
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
      setConfigureVisibility();
      renderClients([]);
    }
  });
}
