const CANONICAL_API_BASE = "https://vpn-wizard-production.up.railway.app";
const CANONICAL_MINIAPP_URL = `${CANONICAL_API_BASE}/miniapp/`;
const API_OVERRIDE_KEY = "vpnw_api_base";
const LANG_KEY = "vpnw_lang";
const SETTINGS_KEY = "vpnw_settings_v3";
const PAGE_KEY = "vpnw_page_v3";
const tg = window.Telegram?.WebApp || null;
const PROXY_MODES = new Set(["shadowtls_ss", "vless_reality"]);

const refs = {
  authCard: document.getElementById("auth-card"),
  versionPill: document.getElementById("version-pill"),
  topbarBadge: document.getElementById("topbar-badge"),
  topbarCopy: document.getElementById("topbar-copy"),
  diagnosticsPanel: document.getElementById("diagnostics-panel"),
  diagnosticsTitle: document.getElementById("diagnostics-title"),
  diagnosticsBody: document.getElementById("diagnostics-body"),
  diagnosticsMeta: document.getElementById("diagnostics-meta"),
  diagnosticsRetryBtn: document.getElementById("diagnostics-retry-btn"),
  diagnosticsResetBtn: document.getElementById("diagnostics-reset-btn"),
  diagnosticsOpenBtn: document.getElementById("diagnostics-open-btn"),
  diagnosticsCloseBtn: document.getElementById("diagnostics-close-btn"),
  authTitle: document.getElementById("auth-title"),
  authCopy: document.getElementById("auth-copy"),
  authStatePill: document.getElementById("auth-state-pill"),
  miniappLoginBtn: document.getElementById("miniapp-login-btn"),
  telegramWidgetSlot: document.getElementById("telegram-widget-slot"),
  logoutBtn: document.getElementById("logout-btn"),
  logoutSettingsBtn: document.getElementById("logout-settings-btn"),
  connectForm: document.getElementById("connect-form"),
  host: document.getElementById("host-input"),
  user: document.getElementById("user-input"),
  password: document.getElementById("password-input"),
  key: document.getElementById("key-input"),
  passwordField: document.getElementById("password-field"),
  keyField: document.getElementById("key-field"),
  authMethodInputs: Array.from(document.querySelectorAll('input[name="auth_method"]')),
  methodPills: Array.from(document.querySelectorAll(".method-pill")).filter((node) => node.querySelector('input[name="auth_method"]')),
  modeInputs: Array.from(document.querySelectorAll('input[name="connection_mode"]')),
  modeCards: Array.from(document.querySelectorAll(".mode-card")),
  rememberServerToggle: document.getElementById("remember-server-toggle"),
  rememberServerHint: document.getElementById("remember-server-hint"),
  connectBtn: document.getElementById("connect-btn"),
  setupBtn: document.getElementById("setup-btn"),
  openProfilesBtn: document.getElementById("open-profiles-btn"),
  connectStatusChip: document.getElementById("connect-status-chip"),
  connectStatusTitle: document.getElementById("connect-status-title"),
  connectStatusBody: document.getElementById("connect-status-body"),
  profileName: document.getElementById("profile-name-input"),
  addProfileBtn: document.getElementById("add-profile-btn"),
  profilesRefreshBtn: document.getElementById("profiles-refresh-btn"),
  currentServerTitle: document.getElementById("current-server-title"),
  serverPicker: document.getElementById("server-picker"),
  profilesMeta: document.getElementById("profiles-meta"),
  profilesEmptyCard: document.getElementById("profiles-empty-card"),
  goConnectBtn: document.getElementById("go-connect-btn"),
  addProfileRow: document.getElementById("add-profile-row"),
  clientsList: document.getElementById("clients-list"),
  savedServersList: document.getElementById("saved-servers-list"),
  sshPort: document.getElementById("ssh-port-input"),
  listenPort: document.getElementById("listen-port-input"),
  proxySni: document.getElementById("proxy-sni-input"),
  langButtons: Array.from(document.querySelectorAll("[data-lang]")),
  pinEnabledToggle: document.getElementById("pin-enabled-toggle"),
  pinInput: document.getElementById("pin-input"),
  savePinBtn: document.getElementById("save-pin-btn"),
  pinUnlockRow: document.getElementById("pin-unlock-row"),
  pinUnlockInput: document.getElementById("pin-unlock-input"),
  unlockPinBtn: document.getElementById("unlock-pin-btn"),
  pinNote: document.getElementById("pin-note"),
  helpButtons: Array.from(document.querySelectorAll(".help-btn")),
  helpPopover: document.getElementById("help-popover"),
  pageNodes: Array.from(document.querySelectorAll(".page")),
  navButtons: Array.from(document.querySelectorAll(".nav-btn")),
  confirmModal: document.getElementById("confirm-modal"),
  confirmTitle: document.getElementById("confirm-title"),
  confirmBody: document.getElementById("confirm-body"),
  confirmCancelBtn: document.getElementById("confirm-cancel-btn"),
  confirmContinueBtn: document.getElementById("confirm-continue-btn"),
};

const COPY = {
  ru: {
    topbarCopy: "Сервер, профили и все действия на одном экране.",
    guestBadge: "Гость",
    accountBadge: "Telegram",
    diagnosticsTitle: "Миниапп не может дотянуться до API",
    diagnosticsBody: "Это проблема связи между интерфейсом и сервисом, а не ошибка SSH на вашем сервере.",
    diagnosticsResetDone: "Сохранённый API-адрес сброшен. Railway снова активен.",
    authTitleGuest: "Войти через Telegram",
    authCopyGuest: "Войдите через Telegram, чтобы выбирать свои серверы без повторного ввода IP и пароля.",
    authTitleReady: "Аккаунт подключен",
    authCopyReady: "Сохранённые серверы уже под рукой. Можно просто выбрать нужный.",
    authStateGuest: "Не подключен",
    authStateReady: "Готово",
    authStateLocked: "Нужен PIN",
    loginTg: "Войти через Telegram",
    logout: "Выйти",
    connectIdleChip: "Ожидание",
    connectBusyChip: "Подключаемся",
    connectReadyChip: "Готово",
    connectErrorChip: "Ошибка",
    connectIdleTitle: "Подключите сервер и продолжайте без лишних шагов.",
    connectIdleBody: "После проверки вы сразу увидите настройку сервера или список профилей.",
    connectBusyTitle: "Подключаемся к серверу",
    connectBusyBody: "Проверяем SSH и текущее состояние сервиса.",
    connectReadyConfigured: "Сервер готов. Переходим к профилям.",
    connectReadyUnconfigured: "Сервер доступен. Осталась одна кнопка настройки.",
    connectTransportError: "Интерфейс не может достучаться до API. Сначала восстановите связь, потом повторите попытку.",
    connectAuthError: "Не удалось войти по SSH. Проверьте пользователя, пароль или ключ.",
    connectPortError: "SSH порт не найден. Если он не 22, укажите его в настройках.",
    connectSessionError: "Сессия истекла. Подключитесь заново.",
    connectServerError: "Сервер вернул ошибку. Попробуйте ещё раз или проверьте параметры.",
    serverNotSaved: "Telegram-вход не выполнен, поэтому сервер не сохранён.",
    serverSaved: "Сервер сохранён в аккаунте.",
    invalidFields: "Нужны адрес сервера и SSH пользователь.",
    invalidPassword: "Введите пароль или переключитесь на ключ.",
    invalidKey: "Вставьте приватный SSH ключ.",
    profilesNoServer: "Сначала подключите сервер",
    profilesMetaNone: "Нет активного сервера",
    profilesMetaLoading: "Загружаем профили...",
    profilesMetaReady: "Профилей: {count}",
    profilesMetaPending: "Сервер ещё не настроен",
    profilesEmptyTitle: "Серверов пока нет",
    profilesEmptyCopy: "Подключитесь вручную или войдите через Telegram, чтобы выбрать сохранённый сервер.",
    goConnect: "Добавить сервер",
    settingsLogout: "Выйти",
    pinNoteDisabled: "PIN выключен. После Telegram-входа серверы открываются сразу.",
    pinNoteLocked: "PIN включён. Разблокируйте серверы ниже, чтобы выбрать их без лишнего ввода.",
    pinNoteReady: "PIN включён. Серверы разблокированы для текущей сессии.",
    savedServersEmpty: "После Telegram-входа здесь появятся ваши серверы.",
    browserLoginUnavailable: "Для браузерного входа нужен `VPNW_BOT_USERNAME` на сервере.",
    authFailed: "Не удалось войти через Telegram.",
    wrongPin: "PIN не подошёл.",
    clientNone: "Пока профилей нет.",
    clientOpen: "Открыть",
    clientHide: "Скрыть",
    clientCopy: "Скопировать",
    clientDownload: "Скачать",
    clientRotate: "Перевыпустить",
    clientRemove: "Удалить",
    savedServerUse: "Открыть",
    savedServerDelete: "Удалить",
    savedServerSaved: "Сохранён",
    confirmRemoveTitle: "Удалить профиль?",
    confirmRemoveBody: "Профиль исчезнет с сервера. Потом придётся создать новый.",
    confirmRotateTitle: "Перевыпустить профиль?",
    confirmRotateBody: "Старый конфиг перестанет работать. На устройстве нужно будет импортировать новый.",
    confirmContinue: "Продолжить",
    confirmCancel: "Отмена",
    setupBusy: "Настраиваем сервер. Это может занять пару минут.",
    profileBusy: "Создаём профиль...",
    copyDone: "Скопировано.",
    copyFailed: "Не удалось скопировать.",
    help_host: "Вставьте IP, домен или IP:порт. Если SSH не на 22, можно указать порт в настройках.",
    help_user: "Обычно это `root`. Если провайдер дал другого SSH пользователя, введите его.",
    help_password: "Нужен именно SSH пароль от сервера. Для авторизации ключом переключитесь выше.",
    help_key: "Вставьте приватный SSH ключ полностью. Он не сохраняется без галочки “Запомнить сервер”.",
    help_ssh_port: "Нужен только если SSH у вас не на 22. Иначе оставьте пустым.",
    help_listen_port: "Порт VPN или прокси. Если не знаете, оставьте пустым.",
    help_proxy_sni: "Нужен только для proxy-режимов и нестандартных сценариев.",
  },
  en: {
    topbarCopy: "Server, profiles, and useful actions on a single screen.",
    guestBadge: "Guest",
    accountBadge: "Telegram",
    diagnosticsTitle: "The miniapp cannot reach the API",
    diagnosticsBody: "This is an app-to-service transport issue, not an SSH issue on your server.",
    diagnosticsResetDone: "Stored API target was cleared. Railway is active again.",
    authTitleGuest: "Sign in with Telegram",
    authCopyGuest: "Use Telegram sign-in to pick your servers without entering IP and password again.",
    authTitleReady: "Account connected",
    authCopyReady: "Saved servers are ready. Pick the one you need.",
    authStateGuest: "Signed out",
    authStateReady: "Ready",
    authStateLocked: "PIN required",
    loginTg: "Sign in with Telegram",
    logout: "Log out",
    connectIdleChip: "Idle",
    connectBusyChip: "Connecting",
    connectReadyChip: "Ready",
    connectErrorChip: "Error",
    connectIdleTitle: "Connect your server and keep every next action nearby.",
    connectIdleBody: "After the check you immediately get either setup or the profile list.",
    connectBusyTitle: "Connecting to the server",
    connectBusyBody: "Checking SSH and current service state.",
    connectReadyConfigured: "The server is ready. Opening profiles.",
    connectReadyUnconfigured: "The server is reachable. One setup button is left.",
    connectTransportError: "The app cannot reach the API yet. Fix connectivity and retry.",
    connectAuthError: "SSH login failed. Check the user, password, or key.",
    connectPortError: "No SSH port was found. If it is not 22, set it in Settings.",
    connectSessionError: "Session expired. Connect again.",
    connectServerError: "The server returned an error. Try again or verify settings.",
    serverNotSaved: "Telegram sign-in is missing, so the server was not saved.",
    serverSaved: "The server was saved to your account.",
    invalidFields: "Server address and SSH user are required.",
    invalidPassword: "Enter the SSH password or switch to key auth.",
    invalidKey: "Paste the private SSH key.",
    profilesNoServer: "Connect a server first",
    profilesMetaNone: "No active server",
    profilesMetaLoading: "Loading profiles...",
    profilesMetaReady: "Profiles: {count}",
    profilesMetaPending: "The server is not set up yet",
    profilesEmptyTitle: "No saved servers yet",
    profilesEmptyCopy: "Connect manually or sign in with Telegram to select a saved server.",
    goConnect: "Add server",
    settingsLogout: "Log out",
    pinNoteDisabled: "PIN is off. Saved servers open right after Telegram sign-in.",
    pinNoteLocked: "PIN is on. Unlock saved servers below before using them.",
    pinNoteReady: "PIN is on. Saved servers are unlocked for this session.",
    savedServersEmpty: "Your saved servers will appear here after Telegram sign-in.",
    browserLoginUnavailable: "Browser Telegram sign-in requires `VPNW_BOT_USERNAME` on the server.",
    authFailed: "Telegram sign-in failed.",
    wrongPin: "Wrong PIN.",
    clientNone: "No profiles yet.",
    clientOpen: "Open",
    clientHide: "Hide",
    clientCopy: "Copy",
    clientDownload: "Download",
    clientRotate: "Rotate",
    clientRemove: "Delete",
    savedServerUse: "Open",
    savedServerDelete: "Delete",
    savedServerSaved: "Saved",
    confirmRemoveTitle: "Delete profile?",
    confirmRemoveBody: "This profile will disappear from the server. You will have to create a new one later.",
    confirmRotateTitle: "Rotate profile?",
    confirmRotateBody: "The old config will stop working. Import a new one on devices.",
    confirmContinue: "Continue",
    confirmCancel: "Cancel",
    setupBusy: "Setting up the server. This may take a few minutes.",
    profileBusy: "Creating a profile...",
    copyDone: "Copied.",
    copyFailed: "Could not copy.",
    help_host: "Paste the IP, domain, or IP:port. If SSH is not on 22, you can set the port in Settings.",
    help_user: "Usually this is `root`. If your provider gave another SSH user, use that one.",
    help_password: "This must be the SSH password for the server. Switch above if you log in with a key.",
    help_key: "Paste the full private SSH key. It is only stored when you explicitly save the server.",
    help_ssh_port: "Only needed if SSH is not on 22. Otherwise leave empty.",
    help_listen_port: "VPN or proxy port. Leave empty if you are not sure.",
    help_proxy_sni: "Only needed for proxy modes and uncommon setups.",
  },
};

const STATE = {
  lang: localStorage.getItem(LANG_KEY) || "ru",
  page: localStorage.getItem(PAGE_KEY) || "connect",
  apiBase: CANONICAL_API_BASE,
  rejectedApiParam: false,
  authConfig: null,
  account: { authenticated: false, user: null, pin_enabled: false, pin_required: false },
  savedServers: [],
  activeSavedServerId: null,
  activeTarget: null,
  connectionChecked: false,
  serverConfigured: false,
  serverInfo: null,
  clients: [],
  clientsLoading: false,
  clientResults: {},
  retryAction: null,
  helpTimer: null,
  confirmResolver: null,
  settings: loadSettings(),
};

function loadSettings() {
  try {
    const parsed = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    return { ssh_port: parsed.ssh_port || "", listen_port: parsed.listen_port || "", proxy_sni: parsed.proxy_sni || "" };
  } catch {
    return { ssh_port: "", listen_port: "", proxy_sni: "" };
  }
}

function saveSettings() {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(STATE.settings));
}

function t(key) {
  return COPY[STATE.lang]?.[key] || COPY.ru[key] || key;
}

function interpolate(key, values = {}) {
  return Object.entries(values).reduce((acc, [name, value]) => acc.replace(`{${name}}`, String(value)), t(key));
}

function normalizeApiBaseCandidate(candidate) {
  const raw = String(candidate || "").trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (!["http:", "https:"].includes(url.protocol) || !url.host) return null;
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

function resolveApiBaseFrom(source = {}) {
  const normalizedParam = normalizeApiBaseCandidate(source.searchParamApi ?? null);
  const normalizedStored = normalizeApiBaseCandidate(source.storedApi ?? null);
  const normalizedRuntime = normalizeApiBaseCandidate(source.runtimeApi ?? window.API_BASE ?? null);
  const normalizedOrigin = normalizeApiBaseCandidate(source.origin ?? window.location.origin);
  return {
    value: normalizedParam || normalizedStored || normalizedRuntime || normalizedOrigin || CANONICAL_API_BASE,
    rejectedParam: Boolean(source.searchParamApi && !normalizedParam),
  };
}

function bootstrapApiBase() {
  const params = new URLSearchParams(window.location.search);
  const resolved = resolveApiBaseFrom({
    searchParamApi: params.get("api"),
    storedApi: localStorage.getItem(API_OVERRIDE_KEY),
    runtimeApi: window.API_BASE,
    origin: window.location.origin,
  });
  STATE.apiBase = resolved.value;
  STATE.rejectedApiParam = resolved.rejectedParam;
  if (resolved.rejectedParam) {
    localStorage.removeItem(API_OVERRIDE_KEY);
  } else if (params.get("api")) {
    localStorage.setItem(API_OVERRIDE_KEY, resolved.value);
  }
}

function isSameOriginApi() {
  try {
    return new URL(STATE.apiBase).origin === window.location.origin;
  } catch {
    return false;
  }
}

async function fetchJson(path, init = {}) {
  const response = await fetch(`${STATE.apiBase}${path}`, {
    ...init,
    headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...(init.headers || {}) },
    credentials: isSameOriginApi() ? "same-origin" : "omit",
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error(payload?.detail || payload?.error || response.statusText || "Request failed");
    error.kind = "http";
    error.status = response.status;
    throw error;
  }
  return payload;
}

function openExternal(url) {
  if (!url) return;
  if (tg?.openLink) {
    tg.openLink(url);
    return;
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

function parsePort(value) {
  if (!value) return null;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

function selectedMode() {
  return refs.modeInputs.find((input) => input.checked)?.value || "amneziawg";
}

function authMethod() {
  return refs.authMethodInputs.find((input) => input.checked)?.value || "password";
}

function isProxyMode() {
  return PROXY_MODES.has(selectedMode());
}

function setRetryAction(action, payload = null) {
  STATE.retryAction = { action, payload };
}

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function makeQrDataUrl(base64Value) {
  return base64Value ? `data:image/png;base64,${base64Value}` : null;
}

function makeDownloadUrl(downloadId) {
  return downloadId ? `${STATE.apiBase}/api/download/${downloadId}/config` : null;
}

function classifyError(error) {
  const message = String(error?.message || error || "");
  if (error?.kind === "http" && error.status === 401) return { type: "session", text: t("connectSessionError") };
  if (error?.kind === "http" && error.status === 403 && /pin/i.test(message)) return { type: "session", text: t("pinNoteLocked") };
  if (error?.kind === "http" && error.status >= 500) return { type: "server", text: t("connectServerError") };
  if (/failed to fetch|networkerror|load failed|cors/i.test(message)) return { type: "api", text: t("connectTransportError") };
  if (/session expired/i.test(message)) return { type: "session", text: t("connectSessionError") };
  if (/pin unlock required/i.test(message)) return { type: "session", text: t("pinNoteLocked") };
  if (/permission denied|authentication failed|private key|password/i.test(message)) return { type: "auth", text: t("connectAuthError") };
  if (/ssh port|reachable ssh port|banner/i.test(message)) return { type: "port", text: t("connectPortError") };
  return { type: "server", text: message || t("connectServerError") };
}

function connectErrorBody(info, error) {
  if (info.type === "api") return t("diagnosticsBody");
  const detail = String(error?.message || error || "").trim();
  if (detail && detail !== info.text) return detail;
  return t("connectIdleBody");
}

function setDiagnostics({ title, body, extra } = {}) {
  if (!title) {
    refs.diagnosticsPanel.classList.add("hidden");
    refs.diagnosticsTitle.textContent = "";
    refs.diagnosticsBody.textContent = "";
    refs.diagnosticsMeta.textContent = "";
    refs.diagnosticsMeta.classList.add("hidden");
    return;
  }
  refs.diagnosticsPanel.classList.remove("hidden");
  refs.diagnosticsTitle.textContent = title;
  refs.diagnosticsBody.textContent = body || "";
  refs.diagnosticsMeta.textContent = extra || "";
  refs.diagnosticsMeta.classList.toggle("hidden", !extra);
}

function showTransportDiagnostics(extra = "") {
  setDiagnostics({ title: t("diagnosticsTitle"), body: t("diagnosticsBody"), extra });
}

function toast(message) {
  showHelp({ x: window.innerWidth / 2, y: 86, width: 0, height: 0 }, message);
}

function showHelp(anchorRect, text) {
  clearTimeout(STATE.helpTimer);
  refs.helpPopover.textContent = text;
  refs.helpPopover.classList.remove("hidden");
  const width = refs.helpPopover.offsetWidth || 240;
  const x = Math.max(12, Math.min(window.innerWidth - width - 12, anchorRect.x + anchorRect.width / 2 - width / 2));
  const y = Math.min(window.innerHeight - 140, anchorRect.y + anchorRect.height + 10);
  refs.helpPopover.style.left = `${x}px`;
  refs.helpPopover.style.top = `${y}px`;
  STATE.helpTimer = setTimeout(() => refs.helpPopover.classList.add("hidden"), 3200);
}

function hideHelp() {
  refs.helpPopover.classList.add("hidden");
  clearTimeout(STATE.helpTimer);
}

function updateViewportState() {
  const height = window.innerHeight || 0;
  const width = window.innerWidth || 0;
  document.body.classList.toggle("compact-height", height <= 820);
  document.body.classList.toggle("ultra-compact-height", height <= 720);
  document.body.classList.toggle("compact-width", width <= 420);
}

function renderMethodSwitch() {
  const current = authMethod();
  refs.methodPills.forEach((pill) => {
    const input = pill.querySelector('input[name="auth_method"]');
    pill.classList.toggle("active", input?.value === current);
  });
  refs.passwordField.classList.toggle("hidden", current !== "password");
  refs.keyField.classList.toggle("hidden", current !== "key");
}

function renderModeCards() {
  const current = selectedMode();
  refs.modeCards.forEach((card) => {
    const input = card.querySelector('input[name="connection_mode"]');
    card.classList.toggle("active", input?.value === current);
  });
}

function setPage(page) {
  STATE.page = page;
  localStorage.setItem(PAGE_KEY, page);
  refs.pageNodes.forEach((node) => node.classList.toggle("active", node.dataset.page === page));
  refs.navButtons.forEach((node) => node.classList.toggle("active", node.dataset.pageTarget === page));
}

function renderConnectStatus(kind, title, body) {
  refs.connectStatusChip.textContent =
    kind === "busy" ? t("connectBusyChip") :
    kind === "success" ? t("connectReadyChip") :
    kind === "error" ? t("connectErrorChip") :
    t("connectIdleChip");
  refs.connectStatusTitle.textContent = title;
  refs.connectStatusBody.textContent = body;
}

function renderAuth() {
  const account = STATE.account;
  refs.authTitle.textContent = account.authenticated ? t("authTitleReady") : t("authTitleGuest");
  refs.authCopy.textContent = account.authenticated ? t("authCopyReady") : t("authCopyGuest");
  refs.authStatePill.textContent = account.pin_required ? t("authStateLocked") : account.authenticated ? t("authStateReady") : t("authStateGuest");
  refs.topbarBadge.textContent = account.authenticated ? (account.user?.first_name || account.user?.username || t("accountBadge")) : t("guestBadge");
  refs.rememberServerToggle.disabled = !account.authenticated;
  if (!account.authenticated) refs.rememberServerToggle.checked = false;
  refs.rememberServerHint.textContent = account.authenticated ? t("serverSaved") : t("serverNotSaved");
  refs.miniappLoginBtn.classList.toggle("hidden", account.authenticated || !tg?.initData);
  refs.logoutBtn.classList.toggle("hidden", !account.authenticated);
  refs.logoutSettingsBtn.classList.toggle("hidden", !account.authenticated);
  refs.pinEnabledToggle.checked = Boolean(account.pin_enabled);
  refs.pinUnlockRow.classList.toggle("hidden", !account.pin_required);
  refs.pinNote.textContent = account.pin_required ? t("pinNoteLocked") : account.pin_enabled ? t("pinNoteReady") : t("pinNoteDisabled");
  refs.authCard.classList.toggle("is-condensed", Boolean(account.authenticated && !account.pin_required));
}

function activeServerLabel() {
  const activeSaved = STATE.savedServers.find((item) => item.id === STATE.activeSavedServerId);
  if (activeSaved) return activeSaved.label || `${activeSaved.ssh_user}@${activeSaved.host}`;
  if (STATE.activeTarget?.manualSnapshot) return `${STATE.activeTarget.manualSnapshot.user}@${STATE.activeTarget.manualSnapshot.host}`;
  return t("profilesNoServer");
}

function renderServerPicker() {
  refs.serverPicker.innerHTML = "";
  STATE.savedServers.forEach((server) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "server-chip";
    button.dataset.serverId = server.id;
    button.classList.toggle("active", server.id === STATE.activeSavedServerId);
    button.textContent = server.label || `${server.ssh_user}@${server.host}`;
    refs.serverPicker.appendChild(button);
  });
}

function renderSavedServers() {
  refs.savedServersList.innerHTML = "";
  if (!STATE.account.authenticated) {
    refs.savedServersList.innerHTML = `<div class="empty-card"><div class="empty-copy">${t("authCopyGuest")}</div></div>`;
    return;
  }
  if (!STATE.savedServers.length) {
    refs.savedServersList.innerHTML = `<div class="empty-card"><div class="empty-copy">${t("savedServersEmpty")}</div></div>`;
    return;
  }
  STATE.savedServers.forEach((server) => {
    const card = document.createElement("article");
    card.className = "saved-server-card";
    card.innerHTML = `
      <div class="saved-server-top">
        <div>
          <div class="saved-server-name">${escapeHtml(server.label || `${server.ssh_user}@${server.host}`)}</div>
          <div class="saved-server-meta">
            <span class="meta-pill">${escapeHtml(server.ssh_user)}@${escapeHtml(server.host)}:${server.ssh_port}</span>
            ${server.mode ? `<span class="meta-pill">${escapeHtml(server.mode)}</span>` : ""}
            <span class="meta-pill">${t("savedServerSaved")}</span>
          </div>
        </div>
        <div class="saved-server-actions">
          <button type="button" class="tiny-btn" data-saved-open="${server.id}">${t("savedServerUse")}</button>
          <button type="button" class="tiny-btn danger" data-saved-delete="${server.id}">${t("savedServerDelete")}</button>
        </div>
      </div>
    `;
    refs.savedServersList.appendChild(card);
  });
}

function renderClients() {
  refs.clientsList.innerHTML = "";
  if (!STATE.activeTarget) {
    refs.clientsList.innerHTML = `<div class="empty-card"><div class="empty-title">${t("profilesEmptyTitle")}</div><div class="empty-copy">${t("profilesEmptyCopy")}</div></div>`;
    return;
  }
  if (STATE.clientsLoading) {
    refs.clientsList.innerHTML = `<div class="empty-card"><div class="empty-copy">${t("profilesMetaLoading")}</div></div>`;
    return;
  }
  if (!STATE.serverConfigured) {
    refs.clientsList.innerHTML = `<div class="empty-card"><div class="empty-title">${t("connectReadyUnconfigured")}</div><div class="empty-copy">${t("connectIdleBody")}</div></div>`;
    return;
  }
  if (!STATE.clients.length) {
    refs.clientsList.innerHTML = `<div class="empty-card"><div class="empty-copy">${t("clientNone")}</div></div>`;
    return;
  }
  STATE.clients.forEach((client) => {
    const result = STATE.clientResults[client.name];
    const meta = [];
    if (client.interface) meta.push(`<span class="meta-pill">${escapeHtml(client.interface)}</span>`);
    if (client.ip) meta.push(`<span class="meta-pill">${escapeHtml(client.ip)}</span>`);
    if (client.last_handshake) meta.push(`<span class="meta-pill">${escapeHtml(client.last_handshake)}</span>`);
    if (client.transfer) meta.push(`<span class="meta-pill">${escapeHtml(client.transfer)}</span>`);
    const inline = result ? `
      <div class="client-inline">
        <div class="result-layout">
          ${result.qrUrl ? `<img class="inline-qr" src="${result.qrUrl}" alt="QR" />` : '<div class="meta-pill">QR</div>'}
          <div class="inline-actions">
            ${result.downloadUrl ? `<button type="button" class="tiny-btn" data-download="${result.downloadUrl}">${t("clientDownload")}</button>` : ""}
            <button type="button" class="tiny-btn" data-copy-client="${client.name}">${t("clientCopy")}</button>
          </div>
        </div>
        <textarea class="result-text" readonly>${result.primaryText || result.autoText || ""}</textarea>
      </div>
    ` : "";
    const rotate = isProxyMode() ? "" : `<button type="button" class="tiny-btn" data-client-rotate="${client.name}">${t("clientRotate")}</button>`;
    const card = document.createElement("article");
    card.className = "client-card";
    card.innerHTML = `
      <div class="client-top">
        <div>
          <div class="client-name">${escapeHtml(client.name)}</div>
          <div class="client-meta">${meta.join("")}</div>
        </div>
        <div class="client-actions">
          <button type="button" class="tiny-btn" data-client-open="${client.name}">${result ? t("clientHide") : t("clientOpen")}</button>
          ${rotate}
          <button type="button" class="tiny-btn danger" data-client-remove="${client.name}">${t("clientRemove")}</button>
        </div>
      </div>
      ${inline}
    `;
    refs.clientsList.appendChild(card);
  });
}

function renderProfilesHeader() {
  refs.currentServerTitle.textContent = activeServerLabel();
  refs.profilesEmptyCard.classList.toggle("hidden", Boolean(STATE.activeTarget || STATE.savedServers.length));
  refs.addProfileRow.classList.toggle("hidden", !STATE.activeTarget || !STATE.serverConfigured);
  refs.profilesMeta.textContent = !STATE.activeTarget
    ? t("profilesMetaNone")
    : STATE.clientsLoading
      ? t("profilesMetaLoading")
      : !STATE.serverConfigured
        ? t("profilesMetaPending")
        : interpolate("profilesMetaReady", { count: STATE.clients.length });
  renderServerPicker();
}

function renderAll() {
  refs.topbarCopy.textContent = t("topbarCopy");
  document.getElementById("connect-title").textContent = STATE.lang === "ru" ? "Подключение к серверу" : "Connect your server";
  document.getElementById("host-label").textContent = STATE.lang === "ru" ? "IP или домен" : "IP or domain";
  document.getElementById("user-label").textContent = STATE.lang === "ru" ? "SSH пользователь" : "SSH user";
  document.getElementById("password-label").textContent = STATE.lang === "ru" ? "SSH пароль" : "SSH password";
  document.getElementById("key-label").textContent = STATE.lang === "ru" ? "SSH ключ" : "SSH key";
  document.getElementById("remember-server-label").textContent = STATE.lang === "ru" ? "Запомнить сервер в аккаунте" : "Save this server in my account";
  document.getElementById("auth-method-password-label").textContent = STATE.lang === "ru" ? "Пароль" : "Password";
  document.getElementById("auth-method-key-label").textContent = STATE.lang === "ru" ? "Ключ" : "Key";
  document.getElementById("mode-vpn-title").textContent = STATE.lang === "ru" ? "VPN" : "VPN";
  document.getElementById("mode-vpn-copy").textContent = STATE.lang === "ru" ? "Для всего устройства и семьи." : "Whole-device access for home and family.";
  document.getElementById("mode-shadowtls-title").textContent = STATE.lang === "ru" ? "Антиблок" : "Anti-block";
  document.getElementById("mode-shadowtls-copy").textContent = STATE.lang === "ru" ? "Быстрый импорт в Hiddify." : "Fast Hiddify import.";
  document.getElementById("mode-vless-title").textContent = STATE.lang === "ru" ? "Legacy proxy" : "Legacy proxy";
  document.getElementById("mode-vless-copy").textContent = STATE.lang === "ru" ? "Для тяжёлых сетей и TCP 443." : "For tougher networks and TCP 443.";
  document.getElementById("profiles-eyebrow").textContent = STATE.lang === "ru" ? "Текущий сервер" : "Current server";
  document.getElementById("clients-title").textContent = STATE.lang === "ru" ? "Все под рукой" : "Everything nearby";
  document.getElementById("settings-eyebrow").textContent = STATE.lang === "ru" ? "Настройки" : "Settings";
  document.getElementById("settings-title").textContent = STATE.lang === "ru" ? "Язык, PIN и порты" : "Language, PIN, and ports";
  document.getElementById("lang-label").textContent = STATE.lang === "ru" ? "Язык" : "Language";
  document.getElementById("advanced-label").textContent = STATE.lang === "ru" ? "Расширенные параметры" : "Advanced parameters";
  document.getElementById("ssh-port-label").textContent = STATE.lang === "ru" ? "SSH порт" : "SSH port";
  document.getElementById("listen-port-label").textContent = STATE.lang === "ru" ? "Порт сервиса" : "Service port";
  document.getElementById("proxy-sni-label").textContent = STATE.lang === "ru" ? "SNI домен" : "SNI domain";
  document.getElementById("pin-label").textContent = STATE.lang === "ru" ? "Дополнительный PIN" : "Extra PIN";
  document.getElementById("pin-enabled-copy").textContent = STATE.lang === "ru" ? "Запрашивать PIN перед доступом к сохранённым серверам" : "Require a PIN before opening saved servers";
  document.getElementById("saved-servers-eyebrow").textContent = STATE.lang === "ru" ? "Сохранённые серверы" : "Saved servers";
  document.getElementById("saved-servers-title").textContent = STATE.lang === "ru" ? "Выбор в один тап" : "One-tap picker";
  document.getElementById("nav-connect-label").textContent = STATE.lang === "ru" ? "Подключение" : "Connect";
  document.getElementById("nav-profiles-label").textContent = STATE.lang === "ru" ? "Профили" : "Profiles";
  document.getElementById("nav-settings-label").textContent = STATE.lang === "ru" ? "Настройки" : "Settings";
  refs.diagnosticsRetryBtn.textContent = STATE.lang === "ru" ? "Повторить" : "Retry";
  refs.diagnosticsResetBtn.textContent = STATE.lang === "ru" ? "Сбросить API" : "Reset API";
  refs.diagnosticsOpenBtn.textContent = STATE.lang === "ru" ? "Открыть Railway" : "Open Railway";
  refs.miniappLoginBtn.textContent = t("loginTg");
  refs.logoutBtn.textContent = t("logout");
  refs.logoutSettingsBtn.textContent = t("settingsLogout");
  refs.goConnectBtn.textContent = t("goConnect");
  refs.profilesRefreshBtn.textContent = STATE.lang === "ru" ? "Обновить" : "Refresh";
  refs.addProfileBtn.textContent = STATE.lang === "ru" ? "Добавить" : "Add";
  refs.profileName.placeholder = STATE.lang === "ru" ? "grandma-phone" : "grandma-phone";
  refs.connectBtn.textContent = STATE.lang === "ru" ? "Подключиться" : "Connect";
  refs.setupBtn.textContent = STATE.lang === "ru" ? "Настроить сервер" : "Set up server";
  refs.openProfilesBtn.textContent = STATE.lang === "ru" ? "Открыть профили" : "Open profiles";
  refs.savePinBtn.textContent = STATE.lang === "ru" ? "Сохранить PIN" : "Save PIN";
  refs.unlockPinBtn.textContent = STATE.lang === "ru" ? "Открыть серверы" : "Unlock servers";
  refs.confirmCancelBtn.textContent = t("confirmCancel");
  refs.confirmContinueBtn.textContent = t("confirmContinue");
  renderMethodSwitch();
  renderModeCards();
  renderAuth();
  renderSavedServers();
  renderProfilesHeader();
  renderClients();
  refs.setupBtn.classList.toggle("hidden", !STATE.connectionChecked || STATE.serverConfigured);
  refs.openProfilesBtn.classList.toggle("hidden", !STATE.connectionChecked || !STATE.serverConfigured);
  refs.langButtons.forEach((button) => button.classList.toggle("active", button.dataset.lang === STATE.lang));
  refs.sshPort.value = STATE.settings.ssh_port || "";
  refs.listenPort.value = STATE.settings.listen_port || "";
  refs.proxySni.value = STATE.settings.proxy_sni || "";
  refs.navButtons.forEach((node) => node.classList.toggle("active", node.dataset.pageTarget === STATE.page));
  refs.pageNodes.forEach((node) => node.classList.toggle("active", node.dataset.page === STATE.page));
}

function setupTelegramChrome() {
  if (!tg) return;
  try {
    tg.ready();
    tg.expand();
    tg.setHeaderColor?.("#eef4ff");
    tg.setBackgroundColor?.("#eef4ff");
  } catch {
    // Ignore Telegram shell issues.
  }
}

function buildSshPayloadFromForm() {
  const host = refs.host.value.trim();
  const user = refs.user.value.trim();
  if (!host || !user) throw new Error(t("invalidFields"));
  if (authMethod() === "password" && !refs.password.value) throw new Error(t("invalidPassword"));
  if (authMethod() === "key" && !refs.key.value.trim()) throw new Error(t("invalidKey"));
  return {
    host,
    user,
    port: parsePort(STATE.settings.ssh_port) || 22,
    password: authMethod() === "password" ? refs.password.value : null,
    key_content: authMethod() === "key" ? refs.key.value.trim() : null,
  };
}

async function loginTransientSession(ssh) {
  const result = await fetchJson("/api/sessions/login", {
    method: "POST",
    body: JSON.stringify({ ssh }),
  });
  if (!result.ok || !result.session_id) throw new Error(result.error || "Session login failed");
  return result.session_id;
}

function activePayloadBase() {
  if (STATE.activeTarget?.kind === "saved") return { saved_server_id: STATE.activeTarget.serverId, protocol: selectedMode() };
  if (STATE.activeTarget?.kind === "manual" && STATE.activeTarget.sessionId) return { session_id: STATE.activeTarget.sessionId, protocol: selectedMode() };
  throw new Error(t("profilesEmptyCopy"));
}

async function maybeSaveServer(ssh) {
  if (!refs.rememberServerToggle.checked) return;
  if (!STATE.account.authenticated) {
    toast(t("serverNotSaved"));
    return;
  }
  const result = await fetchJson("/api/account/servers", {
    method: "POST",
    body: JSON.stringify({
      ssh,
      label: `${ssh.user}@${ssh.host}`,
      protocol: selectedMode(),
      listen_port: parsePort(STATE.settings.listen_port) || undefined,
      proxy_sni: STATE.settings.proxy_sni || undefined,
    }),
  });
  if (!result.ok || !result.server) throw new Error(result.error || "Could not save server");
  await loadSavedServers();
  STATE.activeSavedServerId = result.server.id;
  STATE.activeTarget = { kind: "saved", serverId: result.server.id };
  toast(t("serverSaved"));
}

async function connectManual() {
  renderConnectStatus("busy", t("connectBusyTitle"), t("connectBusyBody"));
  setRetryAction("connect-manual");
  setDiagnostics();
  renderAll();
  try {
    const ssh = buildSshPayloadFromForm();
    const sessionId = await loginTransientSession(ssh);
    const status = await fetchJson("/api/server/status", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionId, protocol: selectedMode() }),
    });
    if (!status.ok) throw new Error(status.error || "Status failed");
    STATE.connectionChecked = true;
    STATE.serverConfigured = Boolean(status.configured);
    STATE.serverInfo = status;
    STATE.activeTarget = { kind: "manual", sessionId, manualSnapshot: { host: ssh.host, user: ssh.user } };
    await maybeSaveServer(ssh);
    if (STATE.serverConfigured) {
      renderConnectStatus("success", t("connectReadyConfigured"), t("connectIdleBody"));
      await refreshClients();
      setPage("profiles");
    } else {
      STATE.clients = [];
      renderConnectStatus("success", t("connectReadyUnconfigured"), t("connectIdleBody"));
      setPage("connect");
    }
  } catch (error) {
    const info = classifyError(error);
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    renderConnectStatus("error", info.text, connectErrorBody(info, error));
  } finally {
    renderAll();
  }
}

async function activateSavedServer(serverId) {
  const server = STATE.savedServers.find((item) => item.id === serverId);
  if (!server) return;
  if (server.mode) {
    const input = refs.modeInputs.find((node) => node.value === server.mode);
    if (input) input.checked = true;
  }
  STATE.activeSavedServerId = serverId;
  renderConnectStatus("busy", t("connectBusyTitle"), t("connectBusyBody"));
  setRetryAction("connect-saved", { serverId });
  setDiagnostics();
  renderAll();
  try {
    const status = await fetchJson("/api/server/status", {
      method: "POST",
      body: JSON.stringify({ saved_server_id: serverId, protocol: selectedMode() }),
    });
    if (!status.ok) throw new Error(status.error || "Status failed");
    STATE.connectionChecked = true;
    STATE.serverConfigured = Boolean(status.configured);
    STATE.serverInfo = status;
    STATE.activeTarget = { kind: "saved", serverId };
    if (STATE.serverConfigured) {
      renderConnectStatus("success", t("connectReadyConfigured"), t("connectIdleBody"));
      await refreshClients();
      setPage("profiles");
    } else {
      STATE.clients = [];
      renderConnectStatus("success", t("connectReadyUnconfigured"), t("connectIdleBody"));
      setPage("connect");
    }
  } catch (error) {
    const info = classifyError(error);
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    renderConnectStatus("error", info.text, connectErrorBody(info, error));
    if (info.type === "session") setPage("settings");
  } finally {
    renderAll();
  }
}

async function refreshClients() {
  if (!STATE.activeTarget || !STATE.serverConfigured) {
    STATE.clients = [];
    renderAll();
    return;
  }
  STATE.clientsLoading = true;
  renderAll();
  try {
    const result = await fetchJson("/api/clients/list", {
      method: "POST",
      body: JSON.stringify(activePayloadBase()),
    });
    if (!result.ok) throw new Error(result.error || "Client list failed");
    STATE.clients = Array.isArray(result.clients) ? result.clients : [];
    setRetryAction("refresh-clients");
  } catch (error) {
    const info = classifyError(error);
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    toast(info.text);
  } finally {
    STATE.clientsLoading = false;
    renderAll();
  }
}

async function pollJob(jobId, fallbackName) {
  while (true) {
    const job = await fetchJson(`/api/jobs/${jobId}`);
    if (job.status === "error") throw new Error(job.error || "Job failed");
    if (job.status === "done") {
      const result = await fetchJson(`/api/jobs/${jobId}/result`);
      const name = result.client_name || fallbackName || "client1";
      STATE.clientResults[name] = {
        primaryText: result.config || "",
        autoText: result.auto_config || "",
        qrUrl: makeQrDataUrl(result.qr_png_base64),
        downloadUrl: makeDownloadUrl(result.download_id || result.auto_download_id),
      };
      return;
    }
    renderConnectStatus("busy", t("setupBusy"), (job.progress || []).slice(-1)[0] || t("connectBusyBody"));
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}

async function setupServer() {
  if (!STATE.activeTarget) return;
  renderConnectStatus("busy", t("setupBusy"), t("connectBusyBody"));
  setRetryAction("setup-server");
  renderAll();
  try {
    const clientName = refs.profileName.value.trim() || "client1";
    const result = await fetchJson("/api/provision", {
      method: "POST",
      body: JSON.stringify({
        ...activePayloadBase(),
        options: {
          client_name: clientName,
          protocol: selectedMode(),
          listen_port: parsePort(STATE.settings.listen_port) || undefined,
          proxy_sni: STATE.settings.proxy_sni || undefined,
          check: false,
          auto_mtu: true,
          tune: true,
        },
      }),
    });
    await pollJob(result.job_id, clientName);
    STATE.serverConfigured = true;
    await refreshClients();
    renderConnectStatus("success", t("connectReadyConfigured"), t("connectIdleBody"));
    setPage("profiles");
  } catch (error) {
    const info = classifyError(error);
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    renderConnectStatus("error", info.text, connectErrorBody(info, error));
  } finally {
    renderAll();
  }
}

async function addProfile() {
  if (!STATE.activeTarget || !STATE.serverConfigured) return;
  refs.addProfileBtn.disabled = true;
  setRetryAction("add-profile");
  try {
    const clientName = refs.profileName.value.trim() || `client-${STATE.clients.length + 1}`;
    const result = await fetchJson("/api/clients/add", {
      method: "POST",
      body: JSON.stringify({
        ...activePayloadBase(),
        client_name: clientName,
        listen_port: parsePort(STATE.settings.listen_port) || undefined,
      }),
    });
    if (!result.ok) throw new Error(result.error || "Could not add profile");
    STATE.clientResults[result.client_name || clientName] = {
      primaryText: result.config || "",
      autoText: result.auto_config || "",
      qrUrl: makeQrDataUrl(result.qr_png_base64),
      downloadUrl: makeDownloadUrl(result.download_id || result.auto_download_id),
    };
    refs.profileName.value = "";
    await refreshClients();
  } catch (error) {
    const info = classifyError(error);
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    toast(info.text);
  } finally {
    refs.addProfileBtn.disabled = false;
    renderAll();
  }
}

async function toggleClientInline(clientName) {
  if (STATE.clientResults[clientName]) {
    delete STATE.clientResults[clientName];
    renderAll();
    return;
  }
  try {
    const result = await fetchJson("/api/clients/export", {
      method: "POST",
      body: JSON.stringify({
        ...activePayloadBase(),
        client_name: clientName,
        listen_port: parsePort(STATE.settings.listen_port) || undefined,
      }),
    });
    if (!result.ok) throw new Error(result.error || "Export failed");
    STATE.clientResults[clientName] = {
      primaryText: result.config || "",
      autoText: result.auto_config || "",
      qrUrl: makeQrDataUrl(result.qr_png_base64),
      downloadUrl: makeDownloadUrl(result.download_id || result.auto_download_id),
    };
  } catch (error) {
    const info = classifyError(error);
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    toast(info.text);
  } finally {
    renderAll();
  }
}

function askConfirm(title, body) {
  refs.confirmTitle.textContent = title;
  refs.confirmBody.textContent = body;
  refs.confirmModal.classList.remove("hidden");
  return new Promise((resolve) => {
    STATE.confirmResolver = resolve;
  });
}

function closeConfirm(answer) {
  refs.confirmModal.classList.add("hidden");
  const resolver = STATE.confirmResolver;
  STATE.confirmResolver = null;
  if (resolver) resolver(Boolean(answer));
}

async function rotateClient(clientName) {
  if (!await askConfirm(t("confirmRotateTitle"), t("confirmRotateBody"))) return;
  try {
    const result = await fetchJson("/api/clients/rotate", {
      method: "POST",
      body: JSON.stringify({
        ...activePayloadBase(),
        client_name: clientName,
        listen_port: parsePort(STATE.settings.listen_port) || undefined,
      }),
    });
    if (!result.ok) throw new Error(result.error || "Rotate failed");
    STATE.clientResults[clientName] = {
      primaryText: result.config || "",
      autoText: result.auto_config || "",
      qrUrl: makeQrDataUrl(result.qr_png_base64),
      downloadUrl: makeDownloadUrl(result.download_id || result.auto_download_id),
    };
    await refreshClients();
  } catch (error) {
    const info = classifyError(error);
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    toast(info.text);
  } finally {
    renderAll();
  }
}

async function removeClient(clientName) {
  if (!await askConfirm(t("confirmRemoveTitle"), t("confirmRemoveBody"))) return;
  try {
    const result = await fetchJson("/api/clients/remove", {
      method: "POST",
      body: JSON.stringify({
        ...activePayloadBase(),
        client_name: clientName,
        listen_port: parsePort(STATE.settings.listen_port) || undefined,
      }),
    });
    if (!result.ok) throw new Error(result.error || "Delete failed");
    delete STATE.clientResults[clientName];
    await refreshClients();
  } catch (error) {
    const info = classifyError(error);
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    toast(info.text);
  } finally {
    renderAll();
  }
}

async function loadSavedServers() {
  if (!STATE.account.authenticated) {
    STATE.savedServers = [];
    renderAll();
    return;
  }
  try {
    const result = await fetchJson("/api/account/servers");
    STATE.savedServers = result.servers || [];
  } catch (error) {
    toast(classifyError(error).text);
  } finally {
    renderAll();
  }
}

async function deleteSavedServer(serverId) {
  try {
    const result = await fetchJson(`/api/account/servers/${serverId}`, { method: "DELETE" });
    if (!result.ok) throw new Error(result.error || "Delete failed");
    STATE.savedServers = STATE.savedServers.filter((item) => item.id !== serverId);
    if (STATE.activeSavedServerId === serverId) {
      STATE.activeSavedServerId = null;
      STATE.activeTarget = null;
      STATE.connectionChecked = false;
      STATE.serverConfigured = false;
      STATE.clients = [];
    }
  } catch (error) {
    toast(classifyError(error).text);
  } finally {
    renderAll();
  }
}

async function refreshAuthState() {
  try {
    const me = await fetchJson("/api/auth/me");
    STATE.account = {
      authenticated: Boolean(me.authenticated),
      user: me.user || null,
      pin_enabled: Boolean(me.pin_enabled),
      pin_required: Boolean(me.pin_required),
    };
    if (!STATE.account.authenticated) STATE.savedServers = [];
  } catch {
    STATE.account = { authenticated: false, user: null, pin_enabled: false, pin_required: false };
    STATE.savedServers = [];
  } finally {
    renderAll();
  }
}

async function loginViaMiniApp() {
  if (!tg?.initData) {
    toast(t("authFailed"));
    return;
  }
  try {
    const result = await fetchJson("/api/auth/telegram/miniapp", {
      method: "POST",
      body: JSON.stringify({ init_data: tg.initData }),
    });
    if (!result.ok || !result.authenticated) throw new Error(result.error || t("authFailed"));
    await refreshAuthState();
    await loadSavedServers();
    maybeAutoActivateSavedServer();
  } catch (error) {
    toast(error.message || t("authFailed"));
  }
}

async function loginViaBrowserPayload(user) {
  try {
    const result = await fetchJson("/api/auth/telegram/web", {
      method: "POST",
      body: JSON.stringify(user),
    });
    if (!result.ok || !result.authenticated) throw new Error(result.error || t("authFailed"));
    await refreshAuthState();
    await loadSavedServers();
    maybeAutoActivateSavedServer();
  } catch (error) {
    toast(error.message || t("authFailed"));
  }
}

window.onTelegramAuth = (user) => {
  loginViaBrowserPayload(user);
};

function renderTelegramWidget() {
  refs.telegramWidgetSlot.innerHTML = "";
  if (STATE.account.authenticated || tg?.initData) return;
  if (!STATE.authConfig?.browser_login_enabled || !STATE.authConfig?.telegram_bot_username) {
    refs.telegramWidgetSlot.innerHTML = `<div class="inline-note">${t("browserLoginUnavailable")}</div>`;
    return;
  }
  const script = document.createElement("script");
  script.async = true;
  script.src = "https://telegram.org/js/telegram-widget.js?22";
  script.setAttribute("data-telegram-login", STATE.authConfig.telegram_bot_username);
  script.setAttribute("data-size", "large");
  script.setAttribute("data-radius", "18");
  script.setAttribute("data-request-access", "write");
  script.setAttribute("data-userpic", "false");
  script.setAttribute("data-onauth", "onTelegramAuth(user)");
  refs.telegramWidgetSlot.appendChild(script);
}

async function fetchAuthConfig() {
  try {
    STATE.authConfig = await fetchJson("/api/auth/config");
  } catch {
    STATE.authConfig = null;
  } finally {
    renderTelegramWidget();
    renderAll();
  }
}

async function logout() {
  try {
    await fetchJson("/api/auth/logout", { method: "POST" });
  } catch {
    // Ignore.
  } finally {
    STATE.account = { authenticated: false, user: null, pin_enabled: false, pin_required: false };
    STATE.savedServers = [];
    if (STATE.activeTarget?.kind === "saved") {
      STATE.activeSavedServerId = null;
      STATE.activeTarget = null;
      STATE.connectionChecked = false;
      STATE.serverConfigured = false;
      STATE.clients = [];
    }
    renderTelegramWidget();
    renderAll();
  }
}

async function configurePin() {
  try {
    const result = await fetchJson("/api/account/pin", {
      method: "POST",
      body: JSON.stringify({ enabled: refs.pinEnabledToggle.checked, pin: refs.pinInput.value.trim() || undefined }),
    });
    if (!result.ok) throw new Error(result.error || "PIN update failed");
    refs.pinInput.value = "";
    await refreshAuthState();
  } catch (error) {
    toast(error.message || t("wrongPin"));
  }
}

async function unlockPin() {
  try {
    const result = await fetchJson("/api/account/pin/unlock", {
      method: "POST",
      body: JSON.stringify({ pin: refs.pinUnlockInput.value.trim() }),
    });
    if (!result.ok) throw new Error(result.error || t("wrongPin"));
    refs.pinUnlockInput.value = "";
    await refreshAuthState();
    maybeAutoActivateSavedServer();
  } catch (error) {
    toast(error.message || t("wrongPin"));
  }
}

function maybeAutoActivateSavedServer() {
  if (!STATE.account.authenticated || STATE.account.pin_required || STATE.activeTarget || !STATE.savedServers.length) {
    renderAll();
    return;
  }
  activateSavedServer(STATE.savedServers[0].id).catch((error) => console.warn(error));
}

async function refreshVersion() {
  try {
    const version = await fetchJson("/api/version");
    const ui = window.location.host.endsWith("railway.app") ? "railway" : "miniapp";
    const sha = String(version.commit_sha || "").trim();
    refs.versionPill.textContent = `ui ${ui} · api ${version.version}${sha ? `+${sha.slice(0, 8)}` : ""}`;
    refs.versionPill.classList.remove("hidden");
  } catch {
    refs.versionPill.classList.add("hidden");
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(t("copyDone"));
  } catch {
    toast(t("copyFailed"));
  }
}

async function retryLastAction() {
  if (!STATE.retryAction) return;
  const { action, payload } = STATE.retryAction;
  if (action === "connect-manual") return connectManual();
  if (action === "connect-saved") return activateSavedServer(payload?.serverId || STATE.activeSavedServerId);
  if (action === "setup-server") return setupServer();
  if (action === "add-profile") return addProfile();
  if (action === "refresh-clients") return refreshClients();
}

function bindEvents() {
  window.addEventListener("resize", () => {
    updateViewportState();
    renderAll();
  });
  refs.connectForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await connectManual();
  });
  refs.modeInputs.forEach((input) => input.addEventListener("change", () => { renderModeCards(); renderAll(); }));
  refs.authMethodInputs.forEach((input) => input.addEventListener("change", renderMethodSwitch));
  refs.navButtons.forEach((button) => button.addEventListener("click", () => setPage(button.dataset.pageTarget)));
  refs.diagnosticsRetryBtn.addEventListener("click", async () => { setDiagnostics(); await retryLastAction(); });
  refs.diagnosticsResetBtn.addEventListener("click", () => {
    localStorage.removeItem(API_OVERRIDE_KEY);
    bootstrapApiBase();
    setDiagnostics({ title: t("diagnosticsTitle"), body: t("diagnosticsResetDone"), extra: STATE.apiBase });
  });
  refs.diagnosticsOpenBtn.addEventListener("click", () => openExternal(CANONICAL_MINIAPP_URL));
  refs.diagnosticsCloseBtn.addEventListener("click", () => setDiagnostics());
  refs.miniappLoginBtn.addEventListener("click", async () => loginViaMiniApp());
  refs.logoutBtn.addEventListener("click", async () => logout());
  refs.logoutSettingsBtn.addEventListener("click", async () => logout());
  refs.setupBtn.addEventListener("click", async () => setupServer());
  refs.openProfilesBtn.addEventListener("click", () => setPage("profiles"));
  refs.profilesRefreshBtn.addEventListener("click", async () => refreshClients());
  refs.goConnectBtn.addEventListener("click", () => setPage("connect"));
  refs.addProfileBtn.addEventListener("click", async () => addProfile());
  refs.savePinBtn.addEventListener("click", async () => configurePin());
  refs.unlockPinBtn.addEventListener("click", async () => unlockPin());
  refs.langButtons.forEach((button) => button.addEventListener("click", () => {
    STATE.lang = button.dataset.lang || "ru";
    localStorage.setItem(LANG_KEY, STATE.lang);
    renderTelegramWidget();
    renderAll();
  }));
  refs.sshPort.addEventListener("input", () => { STATE.settings.ssh_port = refs.sshPort.value.trim(); saveSettings(); });
  refs.listenPort.addEventListener("input", () => { STATE.settings.listen_port = refs.listenPort.value.trim(); saveSettings(); });
  refs.proxySni.addEventListener("input", () => { STATE.settings.proxy_sni = refs.proxySni.value.trim(); saveSettings(); });
  refs.helpButtons.forEach((button) => button.addEventListener("click", (event) => {
    event.stopPropagation();
    showHelp(button.getBoundingClientRect(), t(`help_${button.dataset.help}`));
  }));
  document.addEventListener("click", () => hideHelp());
  document.querySelectorAll("[data-modal-close]").forEach((node) => node.addEventListener("click", () => closeConfirm(false)));
  refs.confirmCancelBtn.addEventListener("click", () => closeConfirm(false));
  refs.confirmContinueBtn.addEventListener("click", () => closeConfirm(true));
  refs.serverPicker.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-server-id]");
    if (button) await activateSavedServer(button.dataset.serverId);
  });
  refs.savedServersList.addEventListener("click", async (event) => {
    const openBtn = event.target.closest("[data-saved-open]");
    if (openBtn) return activateSavedServer(openBtn.dataset.savedOpen);
    const deleteBtn = event.target.closest("[data-saved-delete]");
    if (deleteBtn) await deleteSavedServer(deleteBtn.dataset.savedDelete);
  });
  refs.clientsList.addEventListener("click", async (event) => {
    const openBtn = event.target.closest("[data-client-open]");
    if (openBtn) return toggleClientInline(openBtn.dataset.clientOpen);
    const rotateBtn = event.target.closest("[data-client-rotate]");
    if (rotateBtn) return rotateClient(rotateBtn.dataset.clientRotate);
    const removeBtn = event.target.closest("[data-client-remove]");
    if (removeBtn) return removeClient(removeBtn.dataset.clientRemove);
    const copyBtn = event.target.closest("[data-copy-client]");
    if (copyBtn) return copyText((STATE.clientResults[copyBtn.dataset.copyClient]?.primaryText || STATE.clientResults[copyBtn.dataset.copyClient]?.autoText || ""));
    const downloadBtn = event.target.closest("[data-download]");
    if (downloadBtn) openExternal(downloadBtn.dataset.download);
  });
}

async function bootstrap() {
  bootstrapApiBase();
  setupTelegramChrome();
  updateViewportState();
  bindEvents();
  renderConnectStatus("idle", t("connectIdleTitle"), t("connectIdleBody"));
  renderAll();
  if (STATE.rejectedApiParam) showTransportDiagnostics(STATE.apiBase);
  await Promise.all([refreshVersion(), fetchAuthConfig(), refreshAuthState()]);
  if (tg?.initData && !STATE.account.authenticated && STATE.authConfig?.miniapp_login_enabled) {
    await loginViaMiniApp();
  }
  if (STATE.account.authenticated) {
    await loadSavedServers();
    maybeAutoActivateSavedServer();
  }
}

window.__VPNW_TEST__ = {
  normalizeApiBaseCandidate,
  resolveApiBaseFrom,
  CANONICAL_API_BASE,
  CANONICAL_MINIAPP_URL,
};

bootstrap().catch((error) => {
  console.warn(error);
  showTransportDiagnostics(String(error?.message || ""));
});
