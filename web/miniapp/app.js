const form = document.getElementById("provision-form");
const statusEl = document.getElementById("status");
const progressCard = document.getElementById("progress-card");
const resultCard = document.getElementById("result-card");
const downloadLink = document.getElementById("download-link");
const qrImage = document.getElementById("qr-image");
const button = document.getElementById("provision-btn");
const progressLog = document.getElementById("progress-log");
const rollbackBtn = document.getElementById("rollback-btn");
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
    ssh_password_placeholder: "если ключ — можно пусто",
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
    rollback_btn: "Откатить последний конфиг",
    debug_btn: "Показать Debug Info",
    servers_title: "Мои серверы",
    servers_empty: "Пока нет сохранённых серверов.",
    servers_use_btn: "Использовать",
    status_creating_job: "Создаём задачу...",
    status_provisioning: "Настраиваем сервер... это может занять несколько минут.",
    status_adding_client: "Добавляем клиента...",
    status_ready: "Готово.",
    status_client_ready: "Клиент готов",
    status_failed: "Ошибка",
    status_checking: "Проверяем сервер...",
    status_server_configured: "Сервер уже настроен",
    status_server_needs_setup: "Сервер не настроен",
    status_server_error: "Не удалось проверить сервер",
    status_logs_fetch: "Получаем логи...",
    download_ready: "Скачайте конфиг и отсканируйте QR.",
    check_ok: "ok",
    check_fail: "fail",
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
    alert_logs_copied: "Логи скопированы в буфер. Вставьте их в чат поддержки.",
    alert_logs_failed: "Не удалось получить логи",
    alert_debug_failed: "Не удалось запросить диагностику",
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
    rollback_btn: "Rollback last config",
    debug_btn: "Show Debug Info",
    servers_title: "My servers",
    servers_empty: "No saved servers yet.",
    servers_use_btn: "Use",
    status_creating_job: "Creating job...",
    status_provisioning: "Provisioning... this can take a few minutes.",
    status_adding_client: "Adding client...",
    status_ready: "Ready.",
    status_client_ready: "Client ready",
    status_failed: "Failed",
    status_checking: "Checking server...",
    status_server_configured: "Server already configured",
    status_server_needs_setup: "Server is not configured",
    status_server_error: "Failed to check server",
    status_logs_fetch: "Fetching logs...",
    download_ready: "Ready. Download your config and scan the QR.",
    check_ok: "ok",
    check_fail: "fail",
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
    alert_logs_copied: "Logs copied to clipboard. Paste them in the support chat.",
    alert_logs_failed: "Failed to get logs",
    alert_debug_failed: "Debug request failed",
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

function t(key) {
  return I18N[currentLang]?.[key] || I18N.ru[key] || key;
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

let pollTimer = null;
let serverConfigured = false;

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

async function fetchServerStatus(data) {
  return fetchJson("/api/server/status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ssh: {
        host: data.host,
        user: data.user,
        password: data.password || null,
        key_content: data.key_content || null,
      },
    }),
  });
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
  });
});

async function pollJob(jobId, clientName) {
  const status = await fetchJson(`/api/jobs/${jobId}`);
  const lines = status.progress || [];
  setProgress(lines);
  const last = lines.length ? lines[lines.length - 1] : status.status;
  const statusLabel = t(`job_${status.status}`) || status.status;
  setStatus(`${statusLabel}: ${last}`);

  if (status.status === "error") {
    setStatus(`${t("status_failed")}: ${status.error || "unknown error"}`);
    clearInterval(pollTimer);
    pollTimer = null;
    button.disabled = false;
    return;
  }

  if (status.status === "done") {
    clearInterval(pollTimer);
    pollTimer = null;
    const result = await fetchJson(`/api/jobs/${jobId}/result`);
    const blob = new Blob([result.config], { type: "text/plain" });
    const name = clientName || "client1";
    downloadLink.download = `${name}.conf`;
    downloadLink.href = URL.createObjectURL(blob);
    qrImage.src = `data:image/png;base64,${result.qr_png_base64}`;
    const checks = result.checks || [];
    if (checks.length) {
      const checkText = checks
        .map((item) => `${item.name}: ${item.ok ? t("check_ok") : t("check_fail")}`)
        .join(" | ");
      setStatus(`${t("status_ready")} ${checkText}`);
    } else {
      setStatus(t("download_ready"));
    }
    resultCard.style.display = "block";
    button.disabled = false;
    serverConfigured = true;
    setConfigureVisibility();
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  resultCard.style.display = "none";
  setStatus(t("status_creating_job"));
  setProgress([]);

  const data = getFormData();
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
        return;
      }
    } catch (err) {
      console.error(err);
    }
  }
  const payload = {
    ssh: {
      host: data.host,
      user: data.user,
      password: data.password || null,
      key_content: data.key_content || null,
    },
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
    upsertServer({
      host: data.host,
      user: data.user,
      listen_port: data.listen_port || undefined,
    });
    if (pollTimer) {
      clearInterval(pollTimer);
    }
    pollTimer = setInterval(() => {
      pollJob(result.job_id, currentClientName).catch((err) => {
        setStatus(`${t("status_failed")}: ${err}`);
        clearInterval(pollTimer);
        pollTimer = null;
        button.disabled = false;
      });
    }, 2000);
    await pollJob(result.job_id, currentClientName);
  } catch (err) {
    setStatus(`${t("status_failed")}: ${err}`);
    button.disabled = false;
  } finally {
    if (!pollTimer) {
      button.disabled = false;
    }
  }
});

addClientBtn.addEventListener("click", async () => {
  const data = getFormData();
  setStatus(t("status_adding_client"));
  setProgress([]);
  try {
    const result = await fetchJson("/api/clients/add", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ssh: {
          host: data.host,
          user: data.user,
          password: data.password || null,
          key_content: data.key_content || null,
        },
        client_name: data.client_name || null,
        listen_port: data.listen_port || undefined,
      }),
    });
    if (!result.ok) {
      setStatus(`${t("status_failed")}: ${result.error || "unknown error"}`);
      return;
    }
    const blob = new Blob([result.config], { type: "text/plain" });
    downloadLink.download = `${result.client_name}.conf`;
    downloadLink.href = URL.createObjectURL(blob);
    qrImage.src = `data:image/png;base64,${result.qr_png_base64}`;
    resultCard.style.display = "block";
    setStatus(`${t("status_client_ready")}: ${result.client_name}`);
    upsertServer({ host: data.host, user: data.user, listen_port: data.listen_port || undefined });
    serverConfigured = true;
    setConfigureVisibility();
  } catch (err) {
    setStatus(`${t("status_failed")}: ${err}`);
  }
});

if (checkServerBtn) {
  checkServerBtn.addEventListener("click", async () => {
    const data = getFormData();
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
    } catch (err) {
      if (serverStatusEl) {
        serverStatusEl.textContent = `${t("status_server_error")}: ${err}`;
      }
      serverConfigured = false;
      setConfigureVisibility();
    }
  });
}

const debugBtn = document.getElementById("debug-btn");
if (debugBtn) {
  debugBtn.addEventListener("click", async () => {
    const data = getFormData();

    // Simple verification
    if (!data.host || !data.user) {
      alert(t("alert_fill_host_user"));
      return;
    }

    const originalText = debugBtn.innerText;
    debugBtn.innerText = t("status_logs_fetch");
    debugBtn.disabled = true;

    try {
      const resp = await fetchJson("/api/logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ssh: {
            host: data.host,
            user: data.user,
            password: data.password || null,
            key_content: data.key_content || null,
          }
        }),
      });

      if (resp.ok && resp.logs) {
        try {
          await navigator.clipboard.writeText(resp.logs);
          alert(t("alert_logs_copied"));
        } catch (err) {
          console.error("Clipboard failed", err);
          const userCopy = confirm(t("alert_logs_copied"));
          if (userCopy) {
            prompt("Copy these logs:", resp.logs);
          }
        }
      } else {
        alert(`${t("alert_logs_failed")}: ${resp.error}`);
      }

    } catch (err) {
      alert(`${t("alert_debug_failed")}: ${err}`);
    } finally {
      debugBtn.innerText = originalText;
      debugBtn.disabled = false;
    }
  });
}
