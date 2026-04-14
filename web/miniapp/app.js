const CANONICAL_API_BASE = "https://vpn-wizard-production.up.railway.app";
const CANONICAL_MINIAPP_URL = `${CANONICAL_API_BASE}/miniapp/`;
const API_OVERRIDE_KEY = "vpnw_api_base";
const LANG_KEY = "vpnw_lang";
const SETTINGS_KEY = "vpnw_settings_v3";
const PAGE_KEY = "vpnw_page_v3";
const CLIENT_SORT_KEY = "vpnw_client_sort_v1";
const tg = window.Telegram?.WebApp || null;
const PROXY_MODES = new Set(["xray", "vless_reality", "shadowtls_ss"]);
const DEBUG_LOG_LIMIT = 60;
const PROVISION_STEP_ESTIMATE = {
  amneziawg: 8,
  wireguard: 8,
  xray: 7,
  vless_reality: 7,
  shadowtls_ss: 7,
};

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
  relayCard: document.getElementById("relay-card"),
  relayEnabledToggle: document.getElementById("relay-enabled-toggle"),
  relayFields: document.getElementById("relay-fields"),
  relayHost: document.getElementById("relay-host-input"),
  relayUser: document.getElementById("relay-user-input"),
  relayPassword: document.getElementById("relay-password-input"),
  relayKey: document.getElementById("relay-key-input"),
  relayPasswordField: document.getElementById("relay-password-field"),
  relayKeyField: document.getElementById("relay-key-field"),
  relayAuthMethodInputs: Array.from(document.querySelectorAll('input[name="relay_auth_method"]')),
  relayMethodPills: Array.from(document.querySelectorAll(".method-pill")).filter((node) => node.querySelector('input[name="relay_auth_method"]')),
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
  connectProgressPanel: document.getElementById("connect-progress-panel"),
  connectProgressLabel: document.getElementById("connect-progress-label"),
  connectProgressElapsed: document.getElementById("connect-progress-elapsed"),
  connectProgressBar: document.getElementById("connect-progress-bar"),
  connectProgressLog: document.getElementById("connect-progress-log"),
  connectChecklist: document.getElementById("connect-checklist"),
  profileName: document.getElementById("profile-name-input"),
  addProfileBtn: document.getElementById("add-profile-btn"),
  profilesRefreshBtn: document.getElementById("profiles-refresh-btn"),
  currentServerTitle: document.getElementById("current-server-title"),
  serverPicker: document.getElementById("server-picker"),
  serverAliasToggleBtn: document.getElementById("server-alias-toggle-btn"),
  serverAliasRow: document.getElementById("server-alias-row"),
  serverAliasInput: document.getElementById("server-alias-input"),
  serverAliasSaveBtn: document.getElementById("server-alias-save-btn"),
  serverAliasHint: document.getElementById("server-alias-hint"),
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
  debugLog: document.getElementById("debug-log"),
  debugCopyBtn: document.getElementById("debug-copy-btn"),
  debugClearBtn: document.getElementById("debug-clear-btn"),
  helpButtons: Array.from(document.querySelectorAll(".help-btn")),
  helpPopover: document.getElementById("help-popover"),
  pageNodes: Array.from(document.querySelectorAll(".page")),
  navButtons: Array.from(document.querySelectorAll(".nav-btn")),
  clientSortButtons: Array.from(document.querySelectorAll("[data-client-sort]")),
  confirmModal: document.getElementById("confirm-modal"),
  confirmTitle: document.getElementById("confirm-title"),
  confirmBody: document.getElementById("confirm-body"),
  confirmCancelBtn: document.getElementById("confirm-cancel-btn"),
  confirmContinueBtn: document.getElementById("confirm-continue-btn"),
};

const COPY = {
  ru: {
    topbarCopy: "Конструктор сервера: выберите протокол, поднимите сервис и выдайте профили.",
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
    connectLoginRequired: "Сначала войдите через Telegram.",
    connectIdleTitle: "Подключите сервер и продолжайте без лишних шагов.",
    connectIdleBody: "После проверки вы сразу увидите настройку сервера или список профилей.",
    connectBusyTitle: "Подключаемся к серверу",
    connectBusyBody: "Проверяем SSH и текущее состояние сервиса.",
    connectReadyConfigured: "Сервер готов. Можно открывать профили.",
    connectReadyConfiguredBody: "Сервис уже поднят. Проверьте список профилей или создайте новый.",
    connectReadyUnconfigured: "Сервер доступен. Следующий шаг: настройка.",
    connectReadyUnconfiguredBody: "Нажмите «Настроить сервер». Мы покажем живой прогресс и последние шаги установки.",
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
    clientDownloadQr: "Скачать QR",
    clientRotate: "Перевыпустить",
    clientRemove: "Удалить",
    clientReady: "Профиль готов",
    sortUpdated: "Новые",
    sortCreated: "Создан",
    sortAlpha: "A-Z",
    savedServerUse: "Открыть",
    savedServerDelete: "Удалить",
    savedServerSaved: "Сохранён",
    serverAliasToggle: "Имя",
    serverAliasToggleHide: "Скрыть имя",
    serverAliasPlaceholder: "Имя сервера",
    serverAliasSave: "Сохранить имя",
    serverAliasHint: "Можно дать серверу понятное имя, а IP останется рядом.",
    serverAliasSaved: "Имя сервера сохранено.",
    profilePlaceholder: "Add profile...",
    confirmRemoveTitle: "Удалить профиль?",
    confirmRemoveBody: "Профиль исчезнет с сервера. Потом придётся создать новый.",
    confirmRotateTitle: "Перевыпустить профиль?",
    confirmRotateBody: "Старый конфиг перестанет работать. На устройстве нужно будет импортировать новый.",
    confirmContinue: "Продолжить",
    confirmCancel: "Отмена",
    setupBusy: "Настраиваем сервер. Это может занять пару минут.",
    setupBusyBody: "Ниже видно, сколько шагов уже прошло и на чём сейчас установка.",
    setupProgressCounter: "Шаг {count} из ~{total}",
    setupProgressUnknown: "Запускаем установку",
    setupElapsed: "Прошло {time}",
    roadmapConnectTitle: "Проверить доступ к серверу",
    roadmapConnectPending: "Введите IP, SSH-пользователя и пароль или ключ.",
    roadmapConnectDone: "Доступ подтверждён для {target}.",
    roadmapSetupTitle: "Установить VPN и открыть нужные порты",
    roadmapSetupPending: "После проверки появится кнопка настройки.",
    roadmapSetupReady: "Сервер пустой или сервис ещё не поднят. Нажмите «Настроить сервер».",
    roadmapSetupBusy: "Настройка идёт. Ниже показываем последние шаги сервера.",
    roadmapSetupDone: "Сервис поднят. Можно переходить к профилям.",
    roadmapProfilesTitle: "Выдать и сохранить профили",
    roadmapProfilesPending: "После настройки здесь появится выдача профилей.",
    roadmapProfilesReady: "Откройте профили и создайте первый конфиг.",
    roadmapProfilesDone: "Профили готовы. Их можно открывать, перевыпускать и удалять.",
    connectRecheck: "Проверить снова",
    connectRefresh: "Обновить состояние",
    goSetup: "Вернуться к настройке",
    clientsSetupTitle: "Сервер подключён, но ещё не настроен",
    clientsSetupCopy: "Вернитесь на вкладку подключения и запустите настройку. После этого здесь появятся профили.",
    clientsFirstProfileTitle: "Сервер готов, профилей пока нет",
    clientsFirstProfileCopy: "Введите имя выше и нажмите «Добавить», чтобы выпустить первый профиль.",
    profileBusy: "Создаём профиль...",
    copyDone: "Скопировано.",
    copyFailed: "Не удалось скопировать.",
    help_host: "Вставьте IP, домен или IP:порт. Если SSH не на 22, можно указать порт в настройках.",
    help_user: "Обычно это `root`. Если провайдер дал другого SSH пользователя, введите его.",
    help_password: "Нужен именно SSH пароль от сервера. Для авторизации ключом переключитесь выше.",
    help_key: "Вставьте приватный SSH ключ полностью. Он не сохраняется без галочки “Запомнить сервер”.",
    help_relay_host: "IP или домен relay-сервера. Обычно это отдельный VPS в Yandex Cloud или другой разрешённой сети.",
    help_relay_user: "SSH пользователь relay-сервера. Обычно это `root`.",
    help_relay_password: "SSH пароль от relay-сервера.",
    help_relay_key: "Приватный SSH ключ relay-сервера.",
    help_ssh_port: "Нужен только если SSH у вас не на 22. Иначе оставьте пустым.",
    help_listen_port: "Порт VPN или прокси. Если не знаете, оставьте пустым.",
    help_proxy_sni: "Нужен только для XRay и нестандартных сценариев.",
    debugEmpty: "Debug log is empty.",
    debugLabel: "Debug",
    debugCopy: "Последние шаги miniapp и API без секретов.",
    debugCopyBtn: "Скопировать",
    debugClearBtn: "Очистить",
  },
  en: {
    topbarCopy: "Server builder: choose a protocol, provision the stack, and issue profiles.",
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
    connectLoginRequired: "Sign in with Telegram first.",
    connectIdleTitle: "Connect your server and keep every next action nearby.",
    connectIdleBody: "After the check you immediately get either setup or the profile list.",
    connectBusyTitle: "Connecting to the server",
    connectBusyBody: "Checking SSH and current service state.",
    connectReadyConfigured: "The server is ready. Profiles are next.",
    connectReadyConfiguredBody: "The service is already up. Open profiles or create a new one.",
    connectReadyUnconfigured: "The server is reachable. Setup is the next step.",
    connectReadyUnconfiguredBody: "Tap “Set up server”. We will show live progress and recent install steps.",
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
    clientDownloadQr: "Download QR",
    clientRotate: "Rotate",
    clientRemove: "Delete",
    clientReady: "Profile ready",
    sortUpdated: "Updated",
    sortCreated: "Created",
    sortAlpha: "A-Z",
    savedServerUse: "Open",
    savedServerDelete: "Delete",
    savedServerSaved: "Saved",
    serverAliasToggle: "Name",
    serverAliasToggleHide: "Hide name",
    serverAliasPlaceholder: "Server name",
    serverAliasSave: "Save name",
    serverAliasHint: "Give the server a clear name while keeping the IP nearby.",
    serverAliasSaved: "Server name saved.",
    profilePlaceholder: "Add profile...",
    confirmRemoveTitle: "Delete profile?",
    confirmRemoveBody: "This profile will disappear from the server. You will have to create a new one later.",
    confirmRotateTitle: "Rotate profile?",
    confirmRotateBody: "The old config will stop working. Import a new one on devices.",
    confirmContinue: "Continue",
    confirmCancel: "Cancel",
    setupBusy: "Setting up the server. This may take a few minutes.",
    setupBusyBody: "You can see completed steps and the current stage below.",
    setupProgressCounter: "Step {count} of ~{total}",
    setupProgressUnknown: "Starting setup",
    setupElapsed: "Elapsed {time}",
    roadmapConnectTitle: "Check server access",
    roadmapConnectPending: "Enter the IP, SSH user, and password or key.",
    roadmapConnectDone: "Access confirmed for {target}.",
    roadmapSetupTitle: "Install VPN and open the required ports",
    roadmapSetupPending: "The setup action appears after the connection check.",
    roadmapSetupReady: "The server is empty or the service is not installed yet. Tap “Set up server”.",
    roadmapSetupBusy: "Setup is running. Recent server steps are shown below.",
    roadmapSetupDone: "The service is up. You can move to profiles.",
    roadmapProfilesTitle: "Issue and reuse profiles",
    roadmapProfilesPending: "Profile delivery appears after setup finishes.",
    roadmapProfilesReady: "Open profiles and create the first config.",
    roadmapProfilesDone: "Profiles are ready. You can open, rotate, and delete them.",
    connectRecheck: "Check again",
    connectRefresh: "Refresh state",
    goSetup: "Back to setup",
    clientsSetupTitle: "The server is connected but not configured yet",
    clientsSetupCopy: "Go back to the Connect tab and start setup. Profiles will appear here after that.",
    clientsFirstProfileTitle: "The server is ready but there are no profiles yet",
    clientsFirstProfileCopy: "Enter a name above and tap “Add” to issue the first profile.",
    profileBusy: "Creating a profile...",
    copyDone: "Copied.",
    copyFailed: "Could not copy.",
    help_host: "Paste the IP, domain, or IP:port. If SSH is not on 22, you can set the port in Settings.",
    help_user: "Usually this is `root`. If your provider gave another SSH user, use that one.",
    help_password: "This must be the SSH password for the server. Switch above if you log in with a key.",
    help_key: "Paste the full private SSH key. It is only stored when you explicitly save the server.",
    help_relay_host: "IP or domain of the relay server. Usually this is a separate VPS in Yandex Cloud or another allowed network.",
    help_relay_user: "SSH user for the relay server. Usually `root`.",
    help_relay_password: "SSH password for the relay server.",
    help_relay_key: "Private SSH key for the relay server.",
    help_ssh_port: "Only needed if SSH is not on 22. Otherwise leave empty.",
    help_listen_port: "VPN or proxy port. Leave empty if you are not sure.",
    help_proxy_sni: "Only needed for XRay and uncommon setups.",
    debugEmpty: "Debug log is empty.",
    debugLabel: "Debug",
    debugCopy: "Recent miniapp and API steps without secrets.",
    debugCopyBtn: "Copy",
    debugClearBtn: "Clear",
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
  connectStatus: { kind: "idle", title: "", body: "" },
  provision: { active: false, jobId: null, progress: [], startedAt: 0, finishedAt: 0 },
  clients: [],
  clientsLoading: false,
  clientSort: localStorage.getItem(CLIENT_SORT_KEY) || "updated",
  clientResults: {},
  retryAction: null,
  helpTimer: null,
  confirmResolver: null,
  debugLog: [],
  pendingClientFocus: null,
  settings: loadSettings(),
  serverAliasDraft: { serverId: null, value: "" },
  serverAliasOpen: false,
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
  const method = String(init.method || "GET").toUpperCase();
  logDebug("api.start", { method, path, body: sanitizeDebugValue(init.body) });
  try {
    const response = await fetch(`${STATE.apiBase}${path}`, {
      ...init,
      headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...(init.headers || {}) },
      credentials: isSameOriginApi() ? "same-origin" : "omit",
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      logDebug("api.http_error", { method, path, status: response.status, payload: sanitizeDebugValue(payload) });
      const error = new Error(payload?.detail || payload?.error || response.statusText || "Request failed");
      error.kind = "http";
      error.status = response.status;
      throw error;
    }
    logDebug("api.ok", { method, path, payload: sanitizeDebugValue(payload) });
    return payload;
  } catch (error) {
    logDebug("api.fail", { method, path, error: String(error?.message || error || "") });
    throw error;
  }
}

function sanitizeDebugValue(value) {
  if (value == null || value === "") return null;
  let parsed = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      parsed = value;
    }
  }
  return redactSecrets(parsed);
}

function redactSecrets(value) {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value && typeof value === "object") {
    const output = {};
    Object.entries(value).forEach(([key, val]) => {
      const normalized = key.toLowerCase();
      if (["password", "key_content", "key", "init_data", "pin", "session_id"].includes(normalized)) {
        output[key] = "***";
      } else {
        output[key] = redactSecrets(val);
      }
    });
    return output;
  }
  if (typeof value === "string" && value.length > 220) return `${value.slice(0, 220)}...`;
  return value;
}

function logDebug(event, details = null) {
  const stamp = new Date().toISOString().slice(11, 19);
  const line = details ? `[${stamp}] ${event} ${JSON.stringify(details)}` : `[${stamp}] ${event}`;
  STATE.debugLog = [...STATE.debugLog.slice(-(DEBUG_LOG_LIMIT - 1)), line];
  renderDebugLog();
}

function renderDebugLog() {
  if (!refs.debugLog) return;
  refs.debugLog.textContent = STATE.debugLog.length ? STATE.debugLog.join("\n") : t("debugEmpty");
}

function openExternal(url) {
  if (!url) return;
  if (tg?.openLink) {
    tg.openLink(url);
    return;
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

function currentMiniappUrl() {
  const configured = String(STATE.authConfig?.canonical_miniapp_url || "").trim();
  if (configured) return configured;
  try {
    return new URL("/miniapp/", window.location.origin).toString();
  } catch {
    return CANONICAL_MINIAPP_URL;
  }
}

function parsePort(value) {
  if (!value) return null;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

function selectedMode() {
  return normalizeMode(refs.modeInputs.find((input) => input.checked)?.value);
}

function normalizeMode(mode) {
  const value = String(mode || "").trim();
  if (!value) return "amneziawg";
  if (value === "vless_reality") return "xray";
  return value;
}

function modeDisplayLabel(mode) {
  const value = normalizeMode(mode);
  if (value === "amneziawg") return "AmneziaWG";
  if (value === "xray") return "XRay";
  if (value === "wireguard") return "WireGuard";
  return value;
}

function authMethod() {
  return refs.authMethodInputs.find((input) => input.checked)?.value || "password";
}

function relayAuthMethod() {
  return refs.relayAuthMethodInputs.find((input) => input.checked)?.value || "password";
}

function relayEnabled() {
  return selectedMode() === "xray" && Boolean(refs.relayEnabledToggle.checked);
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

function makeQrDownloadUrl(downloadId) {
  return downloadId ? `${STATE.apiBase}/api/download/${downloadId}/qr` : null;
}

function applyClientResult(name, result) {
  const downloadId = result.download_id || result.auto_download_id || null;
  STATE.clientResults[name] = {
    primaryText: result.config || "",
    autoText: result.auto_config || "",
    qrUrl: makeQrDataUrl(result.qr_png_base64),
    downloadUrl: makeDownloadUrl(downloadId),
    qrDownloadUrl: makeQrDownloadUrl(downloadId),
  };
  STATE.pendingClientFocus = name;
}

function focusClientResultIfNeeded() {
  const clientName = STATE.pendingClientFocus;
  if (!clientName) return;
  const card = Array.from(refs.clientsList.querySelectorAll("[data-client-card]")).find((node) => node.dataset.clientCard === clientName);
  if (!card) return;
  STATE.pendingClientFocus = null;
  card.classList.add("result-emphasis");
  card.scrollIntoView({ block: "nearest", behavior: "smooth" });
  setTimeout(() => card.classList.remove("result-emphasis"), 1800);
}

function classifyError(error) {
  const message = String(error?.message || error || "");
  if (error?.kind === "http" && error.status === 401 && /telegram login required/i.test(message)) {
    return { type: "session", text: t("connectLoginRequired") };
  }
  if (error?.kind === "http" && error.status === 401) return { type: "session", text: t("connectSessionError") };
  if (error?.kind === "http" && error.status === 403 && /pin/i.test(message)) return { type: "session", text: t("pinNoteLocked") };
  if (error?.kind === "http" && error.status >= 500) return { type: "server", text: t("connectServerError") };
  if (/failed to fetch|networkerror|load failed|cors/i.test(message)) return { type: "api", text: t("connectTransportError") };
  if (/telegram login required/i.test(message)) return { type: "session", text: t("connectLoginRequired") };
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
  document.body.classList.toggle("compact-height", height <= 860);
  document.body.classList.toggle("ultra-compact-height", height <= 760);
  document.body.classList.toggle("micro-compact-height", height <= 700);
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

function renderRelayMethodSwitch() {
  const current = relayAuthMethod();
  refs.relayMethodPills.forEach((pill) => {
    const input = pill.querySelector('input[name="relay_auth_method"]');
    pill.classList.toggle("active", input?.value === current);
  });
  refs.relayPasswordField.classList.toggle("hidden", current !== "password");
  refs.relayKeyField.classList.toggle("hidden", current !== "key");
}

function renderModeCards() {
  const current = selectedMode();
  refs.modeCards.forEach((card) => {
    const input = card.querySelector('input[name="connection_mode"]');
    card.classList.toggle("active", input?.value === current);
  });
}

function renderRelaySection() {
  const visible = selectedMode() === "xray";
  const expanded = visible && refs.relayEnabledToggle.checked;
  refs.relayCard.classList.toggle("hidden", !visible);
  refs.relayFields.classList.toggle("hidden", !expanded);
  if (!visible) refs.relayEnabledToggle.checked = false;
  renderRelayMethodSwitch();
}

function setPage(page) {
  STATE.page = page;
  localStorage.setItem(PAGE_KEY, page);
  refs.pageNodes.forEach((node) => node.classList.toggle("active", node.dataset.page === page));
  refs.navButtons.forEach((node) => node.classList.toggle("active", node.dataset.pageTarget === page));
}

function expectedProvisionSteps() {
  return PROVISION_STEP_ESTIMATE[selectedMode()] || 7;
}

function formatElapsed(ms) {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function setActionButtonStyle(button, variant) {
  button.classList.remove("primary-btn", "mini-btn", "subtle");
  if (variant === "primary") {
    button.classList.add("primary-btn");
    return;
  }
  button.classList.add("mini-btn");
  if (variant === "subtle") button.classList.add("subtle");
}

function renderConnectStatus(kind, title, body) {
  STATE.connectStatus = { kind, title, body };
  refs.connectStatusChip.textContent =
    kind === "busy" ? t("connectBusyChip") :
    kind === "success" ? t("connectReadyChip") :
    kind === "error" ? t("connectErrorChip") :
    t("connectIdleChip");
  refs.connectStatusTitle.textContent = title;
  refs.connectStatusBody.textContent = body;
}

function renderConnectChecklist() {
  const target = activeServerLabel();
  const steps = [
    {
      title: t("roadmapConnectTitle"),
      copy: STATE.connectionChecked && STATE.activeTarget
        ? interpolate("roadmapConnectDone", { target })
        : t("roadmapConnectPending"),
      state: STATE.connectionChecked && STATE.activeTarget ? "done" : "current",
    },
    {
      title: t("roadmapSetupTitle"),
      copy: STATE.serverConfigured
        ? t("roadmapSetupDone")
        : STATE.provision.active
          ? t("roadmapSetupBusy")
          : STATE.connectionChecked
            ? t("roadmapSetupReady")
            : t("roadmapSetupPending"),
      state: STATE.serverConfigured ? "done" : STATE.provision.active || STATE.connectionChecked ? "current" : "pending",
    },
    {
      title: t("roadmapProfilesTitle"),
      copy: STATE.serverConfigured
        ? (STATE.clients.length ? t("roadmapProfilesDone") : t("roadmapProfilesReady"))
        : t("roadmapProfilesPending"),
      state: !STATE.serverConfigured ? "pending" : STATE.clients.length ? "done" : "current",
    },
  ];

  refs.connectChecklist.innerHTML = steps.map((step, index) => `
    <div class="status-step is-${step.state}">
      <div class="status-step-badge">${step.state === "done" ? "✓" : index + 1}</div>
      <div>
        <div class="status-step-title">${escapeHtml(step.title)}</div>
        <div class="status-step-copy">${escapeHtml(step.copy)}</div>
      </div>
    </div>
  `).join("");
}

function renderConnectProgress() {
  const progress = STATE.provision.progress || [];
  const active = STATE.provision.active || progress.length > 0;
  refs.connectProgressPanel.classList.toggle("hidden", !active);
  if (!active) {
    refs.connectProgressLabel.textContent = "";
    refs.connectProgressElapsed.textContent = "";
    refs.connectProgressBar.style.width = "0%";
    refs.connectProgressLog.innerHTML = "";
    return;
  }

  const expected = expectedProvisionSteps();
  const completed = progress.length;
  const ratio = STATE.provision.active
    ? Math.min(92, Math.max(14, Math.round((completed / Math.max(expected, 1)) * 100)))
    : 100;
  const recent = (progress.length ? progress : [t("setupBusyBody")]).slice(-3);

  refs.connectProgressLabel.textContent = completed
    ? interpolate("setupProgressCounter", { count: completed, total: expected })
    : t("setupProgressUnknown");
  refs.connectProgressElapsed.textContent = interpolate("setupElapsed", {
    time: formatElapsed((STATE.provision.finishedAt || Date.now()) - (STATE.provision.startedAt || Date.now())),
  });
  refs.connectProgressBar.style.width = `${ratio}%`;
  refs.connectProgressLog.innerHTML = recent.map((line, index) => `
    <div class="status-log-line ${index === recent.length - 1 ? "current" : ""}">${escapeHtml(line)}</div>
  `).join("");
}

function resetProvisionState() {
  STATE.provision = { active: false, jobId: null, progress: [], startedAt: 0, finishedAt: 0 };
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

function serverIdentity(server) {
  return `${server.ssh_user}@${server.host}`;
}

function hasCustomServerLabel(server) {
  const label = String(server?.label || "").trim();
  return Boolean(label) && label !== serverIdentity(server);
}

function serverDisplayName(server) {
  return hasCustomServerLabel(server) ? String(server.label).trim() : serverIdentity(server);
}

function activeSavedServer() {
  return STATE.savedServers.find((item) => item.id === STATE.activeSavedServerId) || null;
}

function activeServerLabel() {
  const activeSaved = activeSavedServer();
  if (activeSaved) {
    const identity = serverIdentity(activeSaved);
    return hasCustomServerLabel(activeSaved) ? `${serverDisplayName(activeSaved)} · ${identity}` : identity;
  }
  if (STATE.activeTarget?.manualSnapshot) return `${STATE.activeTarget.manualSnapshot.user}@${STATE.activeTarget.manualSnapshot.host}`;
  return t("profilesNoServer");
}

function sortClients(clients) {
  const list = [...clients];
  if (STATE.clientSort === "alpha") {
    list.sort((a, b) => String(a.name || "").localeCompare(String(b.name || ""), STATE.lang === "ru" ? "ru" : "en", { sensitivity: "base" }));
    return list;
  }
  if (STATE.clientSort === "created") {
    list.sort((a, b) => (Number(b.created_at || 0) - Number(a.created_at || 0)) || String(a.name || "").localeCompare(String(b.name || ""), "en", { sensitivity: "base" }));
    return list;
  }
  list.sort((a, b) => (Number(b.updated_at || b.created_at || 0) - Number(a.updated_at || a.created_at || 0)) || String(a.name || "").localeCompare(String(b.name || ""), "en", { sensitivity: "base" }));
  return list;
}

function upsertClientLocal(nextClient) {
  const existingIndex = STATE.clients.findIndex((item) => item.name === nextClient.name);
  if (existingIndex >= 0) {
    STATE.clients[existingIndex] = { ...STATE.clients[existingIndex], ...nextClient };
    return;
  }
  STATE.clients = [...STATE.clients, nextClient];
}

function renderServerPicker() {
  refs.serverPicker.innerHTML = "";
  STATE.savedServers.forEach((server) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "server-chip";
    button.dataset.serverId = server.id;
    button.classList.toggle("active", server.id === STATE.activeSavedServerId);
    const identity = serverIdentity(server);
    const displayName = serverDisplayName(server);
    button.title = hasCustomServerLabel(server) ? `${displayName} (${identity})` : identity;
    button.innerHTML = hasCustomServerLabel(server)
      ? `<span class="server-chip-name">${escapeHtml(displayName)}</span><span class="server-chip-meta">${escapeHtml(identity)}</span>`
      : `<span class="server-chip-name">${escapeHtml(identity)}</span>`;
    refs.serverPicker.appendChild(button);
  });
}

function renderServerAliasEditor() {
  const server = activeSavedServer();
  const available = Boolean(server && STATE.account.authenticated);
  refs.serverAliasToggleBtn.classList.toggle("hidden", !available);
  refs.serverAliasToggleBtn.textContent = STATE.serverAliasOpen ? t("serverAliasToggleHide") : t("serverAliasToggle");
  const shouldShow = available && STATE.serverAliasOpen;
  refs.serverAliasRow.classList.toggle("hidden", !shouldShow);
  refs.serverAliasHint.classList.toggle("hidden", !shouldShow);
  if (!available) {
    refs.serverAliasInput.value = "";
    STATE.serverAliasDraft = { serverId: null, value: "" };
    STATE.serverAliasOpen = false;
    return;
  }
  const customLabel = hasCustomServerLabel(server) ? String(server.label).trim() : "";
  if (STATE.serverAliasDraft.serverId !== server.id) {
    STATE.serverAliasDraft = { serverId: server.id, value: customLabel };
  }
  refs.serverAliasInput.value = STATE.serverAliasDraft.value;
  refs.serverAliasInput.placeholder = t("serverAliasPlaceholder");
  refs.serverAliasSaveBtn.textContent = t("serverAliasSave");
  refs.serverAliasHint.textContent = t("serverAliasHint");
}

function enableHorizontalWheelScroll(node) {
  if (!node) return;
  node.addEventListener("wheel", (event) => {
    if (node.scrollWidth <= node.clientWidth + 4) return;
    const delta = Math.abs(event.deltaX) > Math.abs(event.deltaY) ? event.deltaX : event.deltaY;
    if (!delta) return;
    node.scrollLeft += delta;
    event.preventDefault();
  }, { passive: false });
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
            ${server.mode ? `<span class="meta-pill">${escapeHtml(modeDisplayLabel(server.mode))}</span>` : ""}
            ${server.relay_enabled ? `<span class="meta-pill">relay</span>` : ""}
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
    refs.clientsList.innerHTML = `
      <div class="empty-card">
        <div class="empty-title">${t("clientsSetupTitle")}</div>
        <div class="empty-copy">${t("clientsSetupCopy")}</div>
        <div class="empty-actions">
          <button type="button" class="mini-btn" data-open-setup="true">${t("goSetup")}</button>
        </div>
      </div>
    `;
    return;
  }
  if (!STATE.clients.length) {
    refs.clientsList.innerHTML = `
      <div class="empty-card">
        <div class="empty-title">${t("clientsFirstProfileTitle")}</div>
        <div class="empty-copy">${t("clientsFirstProfileCopy")}</div>
      </div>
    `;
    return;
  }
  sortClients(STATE.clients).forEach((client) => {
    const result = STATE.clientResults[client.name];
    const meta = [];
    if (client.interface) meta.push(`<span class="meta-pill">${escapeHtml(client.interface)}</span>`);
    if (client.ip) meta.push(`<span class="meta-pill">${escapeHtml(client.ip)}</span>`);
    if (client.last_handshake) meta.push(`<span class="meta-pill">${escapeHtml(client.last_handshake)}</span>`);
    if (client.transfer) meta.push(`<span class="meta-pill">${escapeHtml(client.transfer)}</span>`);
    const inline = result ? `
      <div class="client-inline">
        <div class="inline-result-head">
          <div class="inline-result-title">${t("clientReady")}</div>
        </div>
        <div class="result-layout">
          ${result.qrUrl ? `<img class="inline-qr" src="${result.qrUrl}" alt="QR" />` : '<div class="meta-pill">QR</div>'}
          <div class="inline-actions">
            ${result.downloadUrl ? `<button type="button" class="tiny-btn" data-download="${result.downloadUrl}">${t("clientDownload")}</button>` : ""}
            ${result.qrDownloadUrl ? `<button type="button" class="tiny-btn" data-download-qr="${result.qrDownloadUrl}">${t("clientDownloadQr")}</button>` : ""}
            <button type="button" class="tiny-btn" data-copy-client="${client.name}">${t("clientCopy")}</button>
          </div>
        </div>
        <textarea class="result-text" readonly>${result.primaryText || result.autoText || ""}</textarea>
      </div>
    ` : "";
    const rotate = isProxyMode() ? "" : `<button type="button" class="tiny-btn" data-client-rotate="${client.name}">${t("clientRotate")}</button>`;
    const card = document.createElement("article");
    card.className = "client-card";
    card.dataset.clientCard = client.name;
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
  renderServerAliasEditor();
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
  document.getElementById("mode-vpn-title").textContent = "AmneziaWG";
  document.getElementById("mode-vpn-copy").textContent = STATE.lang === "ru" ? "Основной выбор для устройств, семьи и всего трафика." : "Primary choice for devices, family, and full-tunnel access.";
  document.getElementById("mode-xray-title").textContent = "XRay";
  document.getElementById("mode-xray-copy").textContent = STATE.lang === "ru" ? "VLESS XHTTP REALITY для сложных сетей и запасного канала." : "VLESS XHTTP REALITY for tougher networks and fallback access.";
  document.getElementById("relay-enabled-label").textContent = STATE.lang === "ru" ? "Использовать relay для белых списков" : "Use a relay for whitelist networks";
  document.getElementById("relay-enabled-hint").textContent = STATE.lang === "ru" ? "Второй VPS принимает вход и пересылает его на XRay." : "A second VPS accepts the entry traffic and forwards it to XRay.";
  document.getElementById("relay-note").textContent = STATE.lang === "ru" ? "Подходит для отдельного VPS в Yandex Cloud или другой разрешённой сети." : "Useful for a separate VPS in Yandex Cloud or another allowed network.";
  document.getElementById("relay-host-label").textContent = STATE.lang === "ru" ? "Relay IP или домен" : "Relay IP or domain";
  document.getElementById("relay-user-label").textContent = STATE.lang === "ru" ? "Relay SSH пользователь" : "Relay SSH user";
  document.getElementById("relay-auth-password-label").textContent = STATE.lang === "ru" ? "Пароль" : "Password";
  document.getElementById("relay-auth-key-label").textContent = STATE.lang === "ru" ? "Ключ" : "Key";
  document.getElementById("relay-password-label").textContent = STATE.lang === "ru" ? "Relay SSH пароль" : "Relay SSH password";
  document.getElementById("relay-key-label").textContent = STATE.lang === "ru" ? "Relay SSH ключ" : "Relay SSH key";
  refs.relayHost.placeholder = STATE.lang === "ru" ? "203.0.113.10" : "203.0.113.10";
  refs.relayUser.placeholder = "root";
  refs.relayPassword.placeholder = STATE.lang === "ru" ? "Пароль от relay-сервера" : "Relay server password";
  refs.relayKey.placeholder = STATE.lang === "ru" ? "Вставьте приватный ключ relay" : "Paste the relay private key";
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
  refs.clientSortButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.clientSort === STATE.clientSort);
    button.textContent =
      button.dataset.clientSort === "alpha" ? t("sortAlpha") :
      button.dataset.clientSort === "created" ? t("sortCreated") :
      t("sortUpdated");
  });
  document.getElementById("debug-label").textContent = t("debugLabel");
  document.getElementById("debug-copy").textContent = t("debugCopy");
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
  refs.profileName.placeholder = t("profilePlaceholder");
  refs.connectBtn.textContent = !STATE.connectionChecked
    ? (STATE.lang === "ru" ? "Подключиться" : "Connect")
    : (STATE.serverConfigured ? t("connectRefresh") : t("connectRecheck"));
  refs.setupBtn.textContent = STATE.lang === "ru" ? "Настроить сервер" : "Set up server";
  refs.openProfilesBtn.textContent = STATE.lang === "ru" ? "Открыть профили" : "Open profiles";
  refs.savePinBtn.textContent = STATE.lang === "ru" ? "Сохранить PIN" : "Save PIN";
  refs.unlockPinBtn.textContent = STATE.lang === "ru" ? "Открыть серверы" : "Unlock servers";
  refs.debugCopyBtn.textContent = t("debugCopyBtn");
  refs.debugClearBtn.textContent = t("debugClearBtn");
  refs.confirmCancelBtn.textContent = t("confirmCancel");
  refs.confirmContinueBtn.textContent = t("confirmContinue");
  renderMethodSwitch();
  renderModeCards();
  renderRelaySection();
  renderAuth();
  renderSavedServers();
  renderProfilesHeader();
  renderClients();
  const shouldShowSetup = STATE.connectionChecked && !STATE.serverConfigured;
  const shouldShowProfiles = STATE.connectionChecked && STATE.serverConfigured;
  refs.setupBtn.classList.toggle("hidden", !shouldShowSetup);
  refs.openProfilesBtn.classList.toggle("hidden", !shouldShowProfiles);
  refs.connectBtn.disabled = STATE.provision.active;
  refs.setupBtn.disabled = STATE.provision.active;
  refs.openProfilesBtn.disabled = false;
  setActionButtonStyle(refs.connectBtn, STATE.connectionChecked ? "subtle" : "primary");
  setActionButtonStyle(refs.setupBtn, shouldShowSetup ? "primary" : "subtle");
  setActionButtonStyle(refs.openProfilesBtn, shouldShowProfiles ? "primary" : "subtle");
  refs.langButtons.forEach((button) => button.classList.toggle("active", button.dataset.lang === STATE.lang));
  refs.sshPort.value = STATE.settings.ssh_port || "";
  refs.listenPort.value = STATE.settings.listen_port || "";
  refs.proxySni.value = STATE.settings.proxy_sni || "";
  refs.navButtons.forEach((node) => node.classList.toggle("active", node.dataset.pageTarget === STATE.page));
  refs.pageNodes.forEach((node) => node.classList.toggle("active", node.dataset.page === STATE.page));
  renderConnectChecklist();
  renderConnectProgress();
  renderDebugLog();
  focusClientResultIfNeeded();
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

function buildRelayPayloadFromForm() {
  if (!relayEnabled()) return null;
  const host = refs.relayHost.value.trim();
  const user = refs.relayUser.value.trim();
  if (!host || !user) throw new Error(STATE.lang === "ru" ? "Для relay нужен адрес и SSH пользователь." : "Relay host and SSH user are required.");
  if (relayAuthMethod() === "password" && !refs.relayPassword.value) {
    throw new Error(STATE.lang === "ru" ? "Введите пароль relay-сервера или переключитесь на ключ." : "Enter the relay password or switch to key auth.");
  }
  if (relayAuthMethod() === "key" && !refs.relayKey.value.trim()) {
    throw new Error(STATE.lang === "ru" ? "Вставьте приватный SSH ключ relay-сервера." : "Paste the relay private SSH key.");
  }
  return {
    ssh: {
      host,
      user,
      port: 22,
      password: relayAuthMethod() === "password" ? refs.relayPassword.value : null,
      key_content: relayAuthMethod() === "key" ? refs.relayKey.value.trim() : null,
    },
    public_host: host,
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
  if (STATE.activeTarget?.kind === "manual" && STATE.activeTarget.sessionId) {
    return {
      session_id: STATE.activeTarget.sessionId,
      protocol: selectedMode(),
      relay: relayEnabled() ? (buildRelayPayloadFromForm() || STATE.activeTarget.relay || undefined) : undefined,
    };
  }
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
      relay: buildRelayPayloadFromForm() || undefined,
    }),
  });
  if (!result.ok || !result.server) throw new Error(result.error || "Could not save server");
  await loadSavedServers();
  STATE.activeSavedServerId = result.server.id;
  STATE.activeTarget = { kind: "saved", serverId: result.server.id };
  toast(t("serverSaved"));
}

async function connectManual() {
  logDebug("connect.manual.start", { host: refs.host.value.trim(), user: refs.user.value.trim(), mode: selectedMode() });
  resetProvisionState();
  renderConnectStatus("busy", t("connectBusyTitle"), t("connectBusyBody"));
  setRetryAction("connect-manual");
  setDiagnostics();
  renderAll();
  try {
    const ssh = buildSshPayloadFromForm();
    const relay = buildRelayPayloadFromForm();
    const sessionId = await loginTransientSession(ssh);
    logDebug("connect.manual.session_ok", { sessionId });
    const status = await fetchJson("/api/server/status", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionId, protocol: selectedMode() }),
    });
    if (!status.ok) throw new Error(status.error || "Status failed");
    STATE.connectionChecked = true;
    STATE.serverConfigured = Boolean(status.configured);
    STATE.serverInfo = status;
    STATE.activeTarget = { kind: "manual", sessionId, manualSnapshot: { host: ssh.host, user: ssh.user }, relay };
    await maybeSaveServer(ssh);
    if (STATE.serverConfigured) {
      renderConnectStatus("success", t("connectReadyConfigured"), t("connectReadyConfiguredBody"));
      await refreshClients();
      setPage("profiles");
    } else {
      STATE.clients = [];
      renderConnectStatus("success", t("connectReadyUnconfigured"), t("connectReadyUnconfiguredBody"));
      setPage("connect");
    }
  } catch (error) {
    const info = classifyError(error);
    logDebug("connect.manual.fail", { type: info.type, error: String(error?.message || error || "") });
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    renderConnectStatus("error", info.text, connectErrorBody(info, error));
  } finally {
    renderAll();
  }
}

async function activateSavedServer(serverId) {
  const server = STATE.savedServers.find((item) => item.id === serverId);
  if (!server) return;
  const previousSavedServerId = STATE.activeSavedServerId;
  const previousTarget = STATE.activeTarget;
  const previousConnectionChecked = STATE.connectionChecked;
  const previousServerConfigured = STATE.serverConfigured;
  const previousServerInfo = STATE.serverInfo;
  const previousClients = [...STATE.clients];
  resetProvisionState();
  if (server.mode) {
    const input = refs.modeInputs.find((node) => node.value === normalizeMode(server.mode));
    if (input) input.checked = true;
  }
  STATE.activeSavedServerId = serverId;
  STATE.serverAliasOpen = false;
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
      renderConnectStatus("success", t("connectReadyConfigured"), t("connectReadyConfiguredBody"));
      await refreshClients();
      setPage("profiles");
    } else {
      STATE.clients = [];
      renderConnectStatus("success", t("connectReadyUnconfigured"), t("connectReadyUnconfiguredBody"));
      setPage("connect");
    }
  } catch (error) {
    const info = classifyError(error);
    STATE.activeSavedServerId = previousSavedServerId;
    STATE.activeTarget = previousTarget;
    STATE.connectionChecked = previousConnectionChecked;
    STATE.serverConfigured = previousServerConfigured;
    STATE.serverInfo = previousServerInfo;
    STATE.clients = previousClients;
    if (info.type === "api") showTransportDiagnostics(STATE.apiBase);
    renderConnectStatus("error", info.text, connectErrorBody(info, error));
    if (info.type === "session") setPage("settings");
  } finally {
    renderAll();
  }
}

async function refreshClients(options = {}) {
  const silent = Boolean(options.silent);
  if (!STATE.activeTarget || !STATE.serverConfigured) {
    STATE.clients = [];
    renderAll();
    return;
  }
  STATE.clientsLoading = !silent;
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
    STATE.provision.jobId = jobId;
    STATE.provision.progress = Array.isArray(job.progress) ? job.progress : [];
    if (job.status === "error") {
      STATE.provision.active = false;
      STATE.provision.finishedAt = Date.now();
      throw new Error(job.error || "Job failed");
    }
    if (job.status === "done") {
      STATE.provision.active = false;
      STATE.provision.finishedAt = Date.now();
      const result = await fetchJson(`/api/jobs/${jobId}/result`);
      const name = result.client_name || fallbackName || "client1";
      applyClientResult(name, result);
      return;
    }
    renderConnectStatus("busy", t("setupBusy"), t("setupBusyBody"));
    renderAll();
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}

async function setupServer() {
  if (!STATE.activeTarget) return;
  STATE.provision = { active: true, jobId: null, progress: [], startedAt: Date.now(), finishedAt: 0 };
  renderConnectStatus("busy", t("setupBusy"), t("setupBusyBody"));
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
    renderConnectStatus("success", t("connectReadyConfigured"), t("connectReadyConfiguredBody"));
    setPage("profiles");
  } catch (error) {
    STATE.provision.active = false;
    STATE.provision.finishedAt = Date.now();
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
    applyClientResult(result.client_name || clientName, result);
    upsertClientLocal({
      name: result.client_name || clientName,
      ip: result.client_ip || "",
      interface: result.interface || (selectedMode() === "amneziawg" ? "awg0" : selectedMode()),
      created_at: Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
    });
    refs.profileName.value = "";
    setPage("profiles");
    renderAll();
    refreshClients({ silent: true }).catch((error) => console.warn(error));
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
    applyClientResult(clientName, result);
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
    applyClientResult(clientName, result);
    upsertClientLocal({
      name: clientName,
      ip: result.client_ip || STATE.clients.find((item) => item.name === clientName)?.ip || "",
      interface: result.interface || STATE.clients.find((item) => item.name === clientName)?.interface || "awg0",
      created_at: STATE.clients.find((item) => item.name === clientName)?.created_at || Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
    });
    renderAll();
    refreshClients({ silent: true }).catch((error) => console.warn(error));
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
      resetProvisionState();
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
      resetProvisionState();
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

async function saveServerAlias() {
  const server = activeSavedServer();
  if (!server) return;
  refs.serverAliasSaveBtn.disabled = true;
  try {
    const result = await fetchJson(`/api/account/servers/${server.id}`, {
      method: "PATCH",
      body: JSON.stringify({ label: STATE.serverAliasDraft.value.trim() || undefined }),
    });
    if (!result.ok || !result.server) throw new Error(result.error || "Could not save server name");
    STATE.savedServers = STATE.savedServers.map((item) => item.id === server.id ? result.server : item);
    STATE.serverAliasDraft = {
      serverId: result.server.id,
      value: hasCustomServerLabel(result.server) ? String(result.server.label).trim() : "",
    };
    STATE.serverAliasOpen = false;
    toast(t("serverAliasSaved"));
  } catch (error) {
    toast(classifyError(error).text);
  } finally {
    refs.serverAliasSaveBtn.disabled = false;
    renderAll();
  }
}

function scheduleFocusIntoView(target) {
  const container = target?.closest(".field, .settings-block, .toggle-row, .pin-row, .action-row, .add-profile-row, .server-alias-row");
  if (!container) return;
  const behavior = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ? "auto" : "smooth";
  window.setTimeout(() => {
    container.scrollIntoView({ block: "center", inline: "nearest", behavior });
  }, 180);
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
  refs.modeInputs.forEach((input) => input.addEventListener("change", () => { renderModeCards(); renderRelaySection(); renderAll(); }));
  refs.authMethodInputs.forEach((input) => input.addEventListener("change", renderMethodSwitch));
  refs.relayAuthMethodInputs.forEach((input) => input.addEventListener("change", renderRelayMethodSwitch));
  refs.relayEnabledToggle.addEventListener("change", () => { renderRelaySection(); renderAll(); });
  refs.navButtons.forEach((button) => button.addEventListener("click", () => setPage(button.dataset.pageTarget)));
  refs.diagnosticsRetryBtn.addEventListener("click", async () => { setDiagnostics(); await retryLastAction(); });
  refs.diagnosticsResetBtn.addEventListener("click", () => {
    localStorage.removeItem(API_OVERRIDE_KEY);
    bootstrapApiBase();
    setDiagnostics({ title: t("diagnosticsTitle"), body: t("diagnosticsResetDone"), extra: STATE.apiBase });
  });
  refs.diagnosticsOpenBtn.addEventListener("click", () => openExternal(currentMiniappUrl()));
  refs.diagnosticsCloseBtn.addEventListener("click", () => setDiagnostics());
  refs.miniappLoginBtn.addEventListener("click", async () => loginViaMiniApp());
  refs.logoutBtn.addEventListener("click", async () => logout());
  refs.logoutSettingsBtn.addEventListener("click", async () => logout());
  refs.setupBtn.addEventListener("click", async () => setupServer());
  refs.openProfilesBtn.addEventListener("click", () => setPage("profiles"));
  refs.profilesRefreshBtn.addEventListener("click", async () => refreshClients());
  refs.goConnectBtn.addEventListener("click", () => setPage("connect"));
  refs.addProfileBtn.addEventListener("click", async () => addProfile());
  refs.serverAliasToggleBtn.addEventListener("click", () => {
    STATE.serverAliasOpen = !STATE.serverAliasOpen;
    renderAll();
    if (STATE.serverAliasOpen) scheduleFocusIntoView(refs.serverAliasInput);
  });
  refs.serverAliasInput.addEventListener("input", () => {
    STATE.serverAliasDraft = {
      serverId: STATE.activeSavedServerId,
      value: refs.serverAliasInput.value,
    };
  });
  refs.serverAliasSaveBtn.addEventListener("click", async () => saveServerAlias());
  refs.serverAliasInput.addEventListener("keydown", async (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      await saveServerAlias();
    }
  });
  refs.savePinBtn.addEventListener("click", async () => configurePin());
  refs.unlockPinBtn.addEventListener("click", async () => unlockPin());
  refs.debugCopyBtn.addEventListener("click", async () => copyText(STATE.debugLog.join("\n") || t("debugEmpty")));
  refs.debugClearBtn.addEventListener("click", () => {
    STATE.debugLog = [];
    renderDebugLog();
  });
  refs.langButtons.forEach((button) => button.addEventListener("click", () => {
    STATE.lang = button.dataset.lang || "ru";
    localStorage.setItem(LANG_KEY, STATE.lang);
    renderTelegramWidget();
    renderAll();
  }));
  refs.clientSortButtons.forEach((button) => button.addEventListener("click", () => {
    STATE.clientSort = button.dataset.clientSort || "updated";
    localStorage.setItem(CLIENT_SORT_KEY, STATE.clientSort);
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
  enableHorizontalWheelScroll(refs.serverPicker);
  refs.savedServersList.addEventListener("click", async (event) => {
    const openBtn = event.target.closest("[data-saved-open]");
    if (openBtn) return activateSavedServer(openBtn.dataset.savedOpen);
    const deleteBtn = event.target.closest("[data-saved-delete]");
    if (deleteBtn) await deleteSavedServer(deleteBtn.dataset.savedDelete);
  });
  refs.clientsList.addEventListener("click", async (event) => {
    const setupBtn = event.target.closest("[data-open-setup]");
    if (setupBtn) {
      setPage("connect");
      return;
    }
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
    const downloadQrBtn = event.target.closest("[data-download-qr]");
    if (downloadQrBtn) openExternal(downloadQrBtn.dataset.downloadQr);
  });
  document.addEventListener("focusin", (event) => {
    if (event.target.matches("input, textarea")) scheduleFocusIntoView(event.target);
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
  getDebugLog: () => STATE.debugLog.slice(),
};

bootstrap().catch((error) => {
  console.warn(error);
  showTransportDiagnostics(String(error?.message || ""));
});
