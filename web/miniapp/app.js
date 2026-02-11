const form = document.getElementById("provision-form");
const statusEl = document.getElementById("status");
const progressCard = document.getElementById("progress-card");
const resultCard = document.getElementById("result-card");
const downloadLink = document.getElementById("download-link");
const copyConfigBtn = document.getElementById("copy-config-btn");
const configCopy = document.getElementById("config-copy");
const configText = document.getElementById("config-text");
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
const nextStepEl = document.getElementById("next-step");
const reconfigureToggle = document.getElementById("reconfigure-toggle");
const reconfigureCheckbox = document.getElementById("reconfigure-checkbox");
const serversListEl = document.getElementById("servers-list");
const serversEmptyEl = document.getElementById("servers-empty");
const clientsCard = document.getElementById("clients-card");
const clientsListEl = document.getElementById("clients-list");
const clientsEmptyEl = document.getElementById("clients-empty");
const langButtons = document.querySelectorAll(".lang-btn");
const safeToggle = document.getElementById("safe-toggle");
const safeRow = document.querySelector(".safe-row");
const externalLinks = document.querySelectorAll(".external-link");
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
const rememberLoginToggle = document.getElementById("remember-login-toggle");
const installGuard = document.getElementById("install-guard");
const installConfirmToggle = document.getElementById("install-confirm-toggle");
const installModal = document.getElementById("install-modal");
const installSummary = document.getElementById("install-summary");
const installCancelBtn = document.getElementById("install-cancel");
const installContinueBtn = document.getElementById("install-continue");
const stageUncheckedOnlyEls = document.querySelectorAll(".stage-unchecked-only");
const stageBeforeConfigEls = document.querySelectorAll(".stage-before-config");

const I18N = {
  ru: {
    app_title: "VPN Wizard",
    app_subtitle: "Простая настройка AmneziaWG VPN на вашем сервере",
    step1_title: "Шаг 1. Доступ к серверу",
    server_host_label: "IP или хост сервера",
    server_host_placeholder: "1.2.3.4",
    ssh_user_label: "SSH пользователь",
    ssh_user_placeholder: "root",
    ssh_port_label: "SSH порт (вручную)",
    ssh_port_placeholder: "авто",
    ssh_port_hint: "По умолчанию порт SSH ищется автоматически.",
    ssh_password_label: "SSH пароль",
    ssh_password_placeholder: "если ключ - можно пусто",
    remember_login_label: "Запомнить вход на этом устройстве",
    remember_login_hint: "Сессия хранится на этом устройстве и обновляется после входа.",
    remember_login_saved: "Вход сохранен",
    client_name_label: "Имя профиля",
    client_name_placeholder: "grandma-phone",
    profile_name_hint: "Нужно, чтобы разные устройства не перезаписывали конфиги. Можно оставить пустым.",
    ssh_key_label: "SSH ключ (необязательно)",
    ssh_key_placeholder: "вставьте приватный ключ",
    udp_port_label: "UDP порт сервера",
    tour_btn: "Обучение",
    faq_btn: "FAQ",
    safe_mode_label: "Предпросмотр изменений перед установкой",
    safe_mode_hint: "Нужен только при установке, если на сервере есть другие сервисы.",
    install_confirm_label: "Я понимаю, что установка изменит сетевые настройки сервера.",
    install_confirm_hint: "Рекомендуем сначала сделать предпросмотр изменений.",
    check_server_btn: "Проверить сервер",
    check_safe_hint: "Проверить сервер - безопасно: ничего не устанавливается. Установка - отдельной кнопкой.",
    server_status_idle: "Сервер не проверен",
    next_step_initial: "Сначала заполните доступ к серверу и нажмите \"Проверить сервер\".",
    next_step_after_check_empty: "Сервер пустой. Сначала сделайте предпросмотр, затем установку.",
    next_step_novice_preview_first: "Режим новичка: сначала включите предпросмотр изменений, затем установку.",
    next_step_after_check_configured: "Сервер уже настроен. Можно сразу управлять профилями.",
    next_step_preview_ready: "Предпросмотр включен: нажатие кнопки покажет план, но ничего не установит.",
    next_step_confirm_install: "Перед установкой подтвердите чекбокс ниже и нажмите кнопку установки.",
    reconfigure_label: "Показать настройку сервера",
    simple_mode_label: "Режим новичка (рекомендуется)",
    simple_mode_hint: "Пошаговый безопасный сценарий. Отключайте только если уверены в действиях.",
    provision_btn: "Настроить сервер и получить первый профиль",
    add_client_btn: "Добавить профиль",
    step2_title: "Шаг 2. Прогресс",
    status_waiting: "Ожидание...",
    step3_title: "Шаг 3. Скачать",
    download_btn: "Скачать конфиг",
    download_qr_btn: "Скачать QR",
    copy_btn: "Скопировать конфиг",
    copy_done: "Конфиг скопирован.",
    copy_failed: "Не удалось скопировать конфиг.",
    copy_empty: "Сначала получите конфиг.",
    copy_title: "Конфиг для ручного копирования",
    copy_hint: "Можно выделить и скопировать вручную.",
    step3_hint: "Откройте AmneziaWG и нажмите \"+\", чтобы добавить файл конфигурации.",
    apps_title: "Скачать приложение AmneziaWG",
    apps_android: "Android (Google Play)",
    apps_ios: "iOS (App Store)",
    apps_windows: "Windows",
    apps_linux: "Linux",
    apps_macos_missing: "macOS: приложения пока нет",
    servers_title: "Мои серверы",
    servers_empty: "Пока нет сохранённых серверов.",
    servers_use_btn: "Использовать",
    servers_forget_login_btn: "Забыть вход",
    servers_remove_btn: "Удалить",
    onboarding_title: "Быстрый старт",
    onboarding_step1: "1) Введите IP/хост, SSH пользователя и пароль или ключ (SSH порт найдется автоматически).",
    onboarding_step2: "2) Нажмите \"Проверить сервер\" - если VPN уже есть, появятся профили.",
    onboarding_step3: "3) Если нет - нажмите \"Настроить сервер\" и скачайте конфиг и QR.",
    onboarding_step4: "4) При блокировках попробуйте другой UDP порт (например 3478 или 33434).",
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
    status_detecting_ssh_port: "Ищем SSH порт автоматически...",
    status_ssh_port_detected: "Найден SSH порт",
    status_loading_clients: "Загружаем профили...",
    status_server_configured: "Сервер уже настроен",
    status_server_needs_setup: "Сервер не настроен",
    status_server_error: "Не удалось проверить сервер",
    status_auto_connect: "Восстанавливаем вход и проверяем сервер...",
    status_relogin_required: "Сессия истекла. Введите пароль или ключ снова.",
    status_session_saved: "Вход сохранён на этом устройстве.",
    status_session_cleared: "Сохраненный вход удален.",
    status_install_requires_confirm: "Подтвердите чекбокс перед установкой, чтобы избежать случайных изменений.",
    status_install_cancelled: "Установка отменена.",
    status_novice_preview_required: "Режим новичка: сначала сделайте предпросмотр изменений, чтобы ничего не сломать.",
    status_precheck: "Проверяем сервер и план изменений... ничего не устанавливаем.",
    status_precheck_done: "Предпросмотр готов. Чтобы установить VPN, отключите предпросмотр.",
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
    meta_ssh_port: "SSH",
    meta_port: "Порт",
    meta_clients: "Профилей",
    meta_tyumen: "Доп. порт",
    protocol_amneziawg: "AmneziaWG",
    protocol_wireguard: "WireGuard",
    alert_fill_host_user: "Заполните поля Host и User.",
    alert_check_first: "Сначала нажмите \"Проверить сервер\".",
    alert_remove_client: "Удалить профиль",
    alert_remove_confirm: "Точно удалить профиль?",
    alert_rotate_confirm: "Перевыпустить ключи для профиля?",
    alert_export_failed: "Не удалось получить конфиг",
    error_ssh_port_autodetect: "Не удалось автоопределить SSH порт. Укажите его вручную в расширенных настройках.",
    error_port_22_hint: "SSH на порту 22 недоступен. Проверьте SSH порт (например 2222).",
    error_auth_hint: "Ошибка SSH авторизации. Проверьте логин, пароль/ключ и SSH порт.",
    install_modal_title: "Подтвердить установку",
    install_modal_body: "Будут изменены сетевые настройки и установлен VPN на вашем сервере.",
    install_modal_cancel: "Отмена",
    install_modal_continue: "Продолжить установку",
    install_summary_host: "Сервер",
    install_summary_ssh: "SSH",
    install_summary_udp: "UDP порт VPN",
    install_summary_note: "Если на сервере есть другие сервисы, сначала включите предпросмотр изменений.",
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
    tour_step4_body:
      "Проверка ничего не устанавливает: она лишь определяет, пустой сервер или уже настроен. После проверки появятся нужные кнопки.",
    faq_title: "FAQ",
    faq_what_is_title: "Что это за бот?",
    faq_what_is_body: "VPN Wizard подключается к вашему серверу по SSH и автоматически настраивает быстрый VPN. В результате вы получаете готовые конфиги и QR.",
    faq_safe_title: "Это безопасно?",
    faq_safe_body: "Бот использует ваши SSH-данные только для настройки. Мы не храним пароли, всё выполняется на вашем сервере.",
    faq_ports_title: "Что делать, если VPN не работает?",
    faq_ports_body: "Попробуйте другой UDP порт в расширенных настройках (например 3478 или 33434).",
    faq_tyumen_title: "Как добавить профиль?",
    faq_tyumen_body: "Введите имя профиля и нажмите \"Добавить профиль\". Порт можно выбрать в расширенных полях.",
    faq_changes_title: "Что именно мы делаем на сервере?",
    faq_changes_body:
      "1) Подключаемся по SSH и проверяем ОС, sudo и свободный порт.\n2) Ставим WireGuard/AmneziaWG и зависимости.\n3) Создаём ключи и конфиги в /etc/amnezia/amneziawg или /etc/wireguard.\n4) Включаем IP forwarding и добавляем NAT (iptables).\n5) Поднимаем сервис awg-quick@ или wg-quick@ и делаем бэкапы конфигов.\n6) Генерируем ваш профиль и QR.\n\nЕсли у вас на сервере есть свои сервисы или строгий firewall — используйте безопасный режим и внимательно прочитайте пункты выше.",
    faq_servers_title: "Как запоминаются серверы?",
    faq_servers_body:
      "Список серверов хранится локально на устройстве. Пароли и ключи не сохраняются: вместо них можно включить \"Запомнить вход\", тогда используется временная защищенная сессия.",
    server_advice:
      "Если сервер пустой - можно смело настраивать. Если нет - прочитайте FAQ и включите расширенные настройки.",
    server_rent_link: "Как арендовать сервер: пошаговый гайд",
  },
  en: {
    app_title: "VPN Wizard",
    app_subtitle: "Simple setup for your own AmneziaWG VPN",
    step1_title: "Step 1: Server access",
    server_host_label: "Server IP or host",
    server_host_placeholder: "1.2.3.4",
    ssh_user_label: "SSH user",
    ssh_user_placeholder: "root",
    ssh_port_label: "SSH port (manual)",
    ssh_port_placeholder: "auto",
    ssh_port_hint: "By default the SSH port is discovered automatically.",
    ssh_password_label: "SSH password",
    ssh_password_placeholder: "optional if key",
    remember_login_label: "Remember login on this device",
    remember_login_hint: "A secure session is stored on this device and refreshed after login.",
    remember_login_saved: "Login remembered",
    client_name_label: "Profile name",
    client_name_placeholder: "grandma-phone",
    profile_name_hint: "Helps avoid overwriting configs between devices. You can leave it empty.",
    ssh_key_label: "SSH key (optional)",
    ssh_key_placeholder: "paste private key",
    udp_port_label: "Server UDP port",
    tour_btn: "Tour",
    faq_btn: "FAQ",
    safe_mode_label: "Preview changes before setup",
    safe_mode_hint: "Only for setup when the server hosts other services.",
    install_confirm_label: "I understand that setup will change server network settings.",
    install_confirm_hint: "We recommend running change preview first.",
    check_server_btn: "Check server",
    check_safe_hint: "Checking the server is safe: nothing is installed. Setup uses a separate button.",
    server_status_idle: "Server not checked",
    next_step_initial: "Fill server access fields first, then click \"Check server\".",
    next_step_after_check_empty: "Server is empty. Run preview first, then install.",
    next_step_novice_preview_first: "Novice mode: run change preview first, then install.",
    next_step_after_check_configured: "Server is already configured. You can manage profiles now.",
    next_step_preview_ready: "Preview is enabled: button click will show a plan and install nothing.",
    next_step_confirm_install: "Before install, check the confirmation box below and click setup.",
    reconfigure_label: "Show server setup",
    simple_mode_label: "Novice mode (recommended)",
    simple_mode_hint: "Safe step-by-step flow. Disable only if you understand the risks.",
    provision_btn: "Configure server and get the first profile",
    add_client_btn: "Add profile",
    step2_title: "Step 2: Progress",
    status_waiting: "Waiting...",
    step3_title: "Step 3: Download",
    download_btn: "Download config",
    download_qr_btn: "Download QR",
    copy_btn: "Copy config",
    copy_done: "Config copied.",
    copy_failed: "Failed to copy config.",
    copy_empty: "Generate a config first.",
    copy_title: "Config for manual copy",
    copy_hint: "Select and copy manually if needed.",
    step3_hint: "Open AmneziaWG and press \"+\" to add the configuration file.",
    apps_title: "Get AmneziaWG",
    apps_android: "Android (Google Play)",
    apps_ios: "iOS (App Store)",
    apps_windows: "Windows",
    apps_linux: "Linux",
    apps_macos_missing: "macOS: no official app yet",
    servers_title: "My servers",
    servers_empty: "No saved servers yet.",
    servers_use_btn: "Use",
    servers_forget_login_btn: "Forget login",
    servers_remove_btn: "Delete",
    onboarding_title: "Quick start",
    onboarding_step1: "1) Enter host, SSH user, and password or key (SSH port is auto-detected).",
    onboarding_step2: "2) Click \"Check server\" - if VPN exists you will see profiles.",
    onboarding_step3: "3) Otherwise click \"Configure server\" and download config + QR.",
    onboarding_step4: "4) If blocked, try another UDP port (for example 3478 or 33434).",
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
    status_detecting_ssh_port: "Detecting SSH port automatically...",
    status_ssh_port_detected: "SSH port detected",
    status_loading_clients: "Loading profiles...",
    status_server_configured: "Server already configured",
    status_server_needs_setup: "Server is not configured",
    status_server_error: "Failed to check server",
    status_auto_connect: "Restoring login and checking the server...",
    status_relogin_required: "Session expired. Enter password or key again.",
    status_session_saved: "Login saved on this device.",
    status_session_cleared: "Saved login cleared.",
    status_install_requires_confirm: "Check the confirmation box before install to avoid accidental changes.",
    status_install_cancelled: "Install canceled.",
    status_novice_preview_required: "Novice mode: run change preview first to avoid breaking your server.",
    status_precheck: "Checking server and change plan... nothing is installed.",
    status_precheck_done: "Preview ready. Disable preview to install the VPN.",
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
    meta_ssh_port: "SSH",
    meta_port: "Port",
    meta_clients: "Profiles",
    meta_tyumen: "Alt port",
    protocol_amneziawg: "AmneziaWG",
    protocol_wireguard: "WireGuard",
    alert_fill_host_user: "Please fill in Host and User fields first.",
    alert_check_first: "Please click \"Check server\" first.",
    alert_remove_client: "Remove profile",
    alert_remove_confirm: "Delete this profile?",
    alert_rotate_confirm: "Rotate keys for this profile?",
    alert_export_failed: "Failed to export config",
    error_ssh_port_autodetect: "Could not auto-detect SSH port. Set it manually in advanced settings.",
    error_port_22_hint: "Cannot reach SSH on port 22. Check the SSH port (for example 2222).",
    error_auth_hint: "SSH auth failed. Check user, password/key, and SSH port.",
    install_modal_title: "Confirm installation",
    install_modal_body: "Server network settings will be changed and VPN will be installed.",
    install_modal_cancel: "Cancel",
    install_modal_continue: "Continue install",
    install_summary_host: "Server",
    install_summary_ssh: "SSH",
    install_summary_udp: "VPN UDP port",
    install_summary_note: "If the server hosts other services, run preview changes first.",
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
    tour_step4_body:
      "The check does not install anything. It only detects if the server is empty or already configured, then shows the next buttons.",
    faq_title: "FAQ",
    faq_what_is_title: "What is this bot?",
    faq_what_is_body: "VPN Wizard connects to your server over SSH and configures a fast VPN. You get ready configs and QR.",
    faq_safe_title: "Is it safe?",
    faq_safe_body: "The bot uses your SSH credentials only for setup. We do not store passwords.",
    faq_ports_title: "VPN not working?",
    faq_ports_body: "Try another UDP port in advanced settings (for example 3478 or 33434).",
    faq_tyumen_title: "How to add a profile?",
    faq_tyumen_body: "Enter a profile name and click \"Add profile\". You can change the UDP port in advanced fields.",
    faq_changes_title: "What exactly do we change on the server?",
    faq_changes_body:
      "1) Connect over SSH and check OS, sudo, and free port.\n2) Install WireGuard/AmneziaWG and dependencies.\n3) Create keys/configs under /etc/amnezia/amneziawg or /etc/wireguard.\n4) Enable IP forwarding and add NAT (iptables).\n5) Start awg-quick@ or wg-quick@ and create config backups.\n6) Generate your profile and QR.\n\nIf your server hosts other services or strict firewall rules, use safe mode and review the steps above.",
    faq_servers_title: "How are servers saved?",
    faq_servers_body:
      "Servers are stored locally on your device. Passwords and keys are not stored: with \"Remember login\" the app uses a temporary secure session token instead.",
    server_advice:
      "Empty server? You can install safely. If not, read the FAQ and enable advanced settings.",
    server_rent_link: "How to rent a VPS: step-by-step guide",
  },
};

const LANG_KEY = "vpnw_lang";
const SERVERS_KEY = "vpnw_servers";
const ACTIVE_SERVER_KEY = "vpnw_active_server";
const LEGACY_KEYS = ["vpnw_creds", "vpnw_salt", "vpnw_iv"];
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
  activeServerKey: null,
  activeSessionId: null,
  checked: false,
  safeTouched: false,
  installConfirmResolver: null,
  previewDoneByServer: {},
  clientBusy: {},
  qrByClient: {},
  qrOpen: null,
  clientsLoading: false,
  downloads: {
    configUrl: null,
    qrUrl: null,
    configText: null,
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
if (copyConfigBtn) {
  copyConfigBtn.addEventListener("click", async () => {
    const config = STATE.downloads.configText;
    if (!config) {
      setStatus(t("copy_empty"));
      return;
    }
    try {
      const ok = await copyToClipboard(config);
      if (!ok && configText) {
        configText.focus();
        configText.select();
      }
      setStatus(ok ? t("copy_done") : t("copy_failed"));
    } catch (err) {
      if (configText) {
        configText.focus();
        configText.select();
      }
      setStatus(t("copy_failed"));
    }
  });
}
if (configText) {
  configText.addEventListener("focus", () => {
    configText.select();
  });
}
externalLinks.forEach((link) => {
  link.addEventListener("click", handleDownloadClick);
});
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
    if (modal === installModal && STATE.installConfirmResolver) {
      resolveInstallConfirmation(false);
      return;
    }
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

function triggerDownload(url, filename) {
  const link = document.createElement("a");
  link.href = url;
  if (filename) {
    link.download = filename;
  }
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
}

function handleDownloadClick(event) {
  const url = event.currentTarget?.dataset?.url;
  if (!url) {
    return;
  }
  if (url.startsWith("data:") || url.startsWith("blob:")) {
    if (tg?.openLink) {
      event.preventDefault();
      triggerDownload(url, event.currentTarget?.download);
    }
    return;
  }
  if (tg?.openLink) {
    event.preventDefault();
    tg.openLink(url);
  }
}

function buildConfigUrl(config) {
  const blob = new Blob([config], { type: "text/plain" });
  return URL.createObjectURL(blob);
}

function buildQrUrl(qrBase64) {
  return `data:image/png;base64,${qrBase64}`;
}

function buildDownloadUrl(downloadId, kind) {
  if (!downloadId) {
    return null;
  }
  return `${API_BASE}/api/download/${downloadId}/${kind}`;
}

async function copyToClipboard(text) {
  if (!text) {
    return false;
  }
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return true;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  const ok = document.execCommand("copy");
  textarea.remove();
  return ok;
}

function setDownload(config, qrBase64, name, options = {}) {
  const safeName = name || "client1";
  const { showResult = true, scroll = true, downloadId = null } = options;

  if (STATE.downloads.configUrl?.startsWith("blob:")) {
    URL.revokeObjectURL(STATE.downloads.configUrl);
  }
  const remoteConfigUrl = buildDownloadUrl(downloadId, "config");
  const configUrl = config ? remoteConfigUrl || buildConfigUrl(config) : null;
  STATE.downloads.configUrl = configUrl;
  STATE.downloads.configText = config || null;
  if (configUrl && downloadLink) {
    downloadLink.download = `${safeName}.conf`;
    downloadLink.href = configUrl;
    downloadLink.dataset.url = configUrl;
    downloadLink.classList.remove("hidden");
  } else if (downloadLink) {
    downloadLink.classList.add("hidden");
  }
  if (copyConfigBtn) {
    copyConfigBtn.classList.toggle("hidden", !config);
  }
  if (configCopy) {
    configCopy.classList.toggle("hidden", !config);
  }
  if (configText) {
    configText.value = config || "";
  }

  if (qrBase64) {
    const remoteQrUrl = buildDownloadUrl(downloadId, "qr");
    const qrDisplay = buildQrUrl(qrBase64);
    const qrData = remoteQrUrl || qrDisplay;
    STATE.downloads.qrUrl = qrData;
    qrImage.src = qrDisplay;
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

  stageUncheckedOnlyEls.forEach((el) => {
    el.classList.toggle("hidden", checked);
  });
  stageBeforeConfigEls.forEach((el) => {
    el.classList.toggle("hidden", configured);
  });

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
    STATE.downloads.configText = null;
    if (copyConfigBtn) {
      copyConfigBtn.classList.add("hidden");
    }
    if (configCopy) {
      configCopy.classList.add("hidden");
    }
    setProgressVisible(false);
  }
  setSafeVisibility();
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
    { titleKey: "faq_changes_title", bodyKey: "faq_changes_body" },
    { titleKey: "faq_servers_title", bodyKey: "faq_servers_body" },
  ];
  faqContent.innerHTML = "";
  items.forEach((item) => {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = t(item.titleKey);
    const body = document.createElement("p");
    body.className = "faq-body";
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
  const stored = normalizeApiBase(localStorage.getItem("vpnw_api_base"));
  if (stored) {
    const isRailway = stored.includes("railway.app");
    const isHttp = stored.startsWith("https://") || stored.startsWith("http://");
    if (window.location.host.endsWith("vercel.app") && !isRailway) {
      // Avoid stale override pointing to the miniapp host.
      localStorage.removeItem("vpnw_api_base");
    } else if (isHttp) {
      return stored;
    }
  }
  if (window.API_BASE) {
    return window.API_BASE;
  }
  if (window.location.host.endsWith("railway.app")) {
    return window.location.origin;
  }
  if (window.location.host.endsWith("vercel.app")) {
    return "https://vpn-wizard-production.up.railway.app";
  }
  return "";
}

function normalizeApiBase(value) {
  return value ? value.replace(/\/+$/, "") : "";
}

const API_BASE = normalizeApiBase(resolveApiBase());

function cleanupLegacySecrets() {
  LEGACY_KEYS.forEach((key) => localStorage.removeItem(key));
}

cleanupLegacySecrets();

function normalizeSshPort(value, fallback = 22) {
  const port = Number.parseInt(value, 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return fallback;
  }
  return port;
}

function parseOptionalSshPort(value) {
  const port = Number.parseInt(value, 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return null;
  }
  return port;
}

function normalizeListenPort(value) {
  const port = Number.parseInt(value, 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return null;
  }
  return port;
}

function splitHostAndPort(rawHost, rawPort) {
  let host = (rawHost || "").trim();
  let port = parseOptionalSshPort(rawPort);
  if (!host) {
    return { host: "", port };
  }
  if (host.startsWith("[")) {
    const closing = host.indexOf("]");
    if (closing > 0) {
      const ipv6 = host.slice(1, closing).trim();
      const tail = host.slice(closing + 1).trim();
      if (tail.startsWith(":")) {
        return {
          host: ipv6,
          port: parseOptionalSshPort(tail.slice(1)) ?? port,
        };
      }
      return { host: ipv6, port };
    }
  }
  if (host.includes(":") && host.indexOf(":") === host.lastIndexOf(":")) {
    const [left, right] = host.split(":");
    if (left && /^[0-9]+$/.test(right || "")) {
      return {
        host: left.trim(),
        port: parseOptionalSshPort(right) ?? port,
      };
    }
  }
  return { host, port };
}

function makeServerKey(host, user, sshPort) {
  return `${(host || "").trim().toLowerCase()}|${(user || "").trim().toLowerCase()}|${normalizeSshPort(
    sshPort,
    22,
  )}`;
}

function getServerRuntimeKey(data = null) {
  if (data?.host && data?.user) {
    return makeServerKey(data.host, data.user, data.ssh_port || 22);
  }
  const host = form?.elements?.host?.value || "";
  const user = form?.elements?.user?.value || "";
  const sshPort = form?.elements?.ssh_port?.value || 22;
  if (!host || !user) {
    return null;
  }
  return makeServerKey(host, user, sshPort);
}

function setActiveServerKey(key) {
  STATE.activeServerKey = key || null;
  if (key) {
    localStorage.setItem(ACTIVE_SERVER_KEY, key);
  } else {
    localStorage.removeItem(ACTIVE_SERVER_KEY);
  }
}

function getFormData() {
  const data = Object.fromEntries(new FormData(form).entries());
  const keyContent = simpleToggle.checked ? null : data.key_content;
  const parsedHost = splitHostAndPort(data.host, data.ssh_port);
  const listenPort = normalizeListenPort(data.listen_port);
  return {
    host: parsedHost.host,
    user: (data.user || "").trim(),
    ssh_port: parsedHost.port,
    password: data.password || null,
    key_content: keyContent || null,
    client_name: (data.client_name || "").trim(),
    listen_port: listenPort,
    safe_mode: Boolean(safeToggle?.checked) && !simpleToggle.checked,
    remember_login: Boolean(rememberLoginToggle?.checked),
    session_id: STATE.activeSessionId || null,
  };
}

function loadServers() {
  if (!serversListEl || !serversEmptyEl) {
    return [];
  }
  try {
    const raw = localStorage.getItem(SERVERS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .filter((item) => item && item.host)
      .map((item) => ({
        host: String(item.host || "").trim(),
        user: String(item.user || "").trim(),
        ssh_port: parseOptionalSshPort(item.ssh_port),
        listen_port: normalizeListenPort(item.listen_port),
        clients_count:
          typeof item.clients_count === "number" && item.clients_count >= 0
            ? item.clients_count
            : undefined,
        session_id: item.session_id ? String(item.session_id) : null,
      }));
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
    if (server.ssh_port) {
      parts.push(`${t("meta_ssh_port")}: ${server.ssh_port}`);
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
    if (server.session_id) {
      const badge = document.createElement("div");
      badge.className = "server-badge";
      badge.textContent = t("remember_login_saved");
      info.appendChild(badge);
    }
    const actions = document.createElement("div");
    actions.className = "server-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "secondary";
    useBtn.textContent = t("servers_use_btn");
    useBtn.addEventListener("click", async () => {
      applyServerToForm(server);
      serverConfigured = false;
      STATE.checked = false;
      updateStageVisibility();
      if (serverStatusEl) {
        serverStatusEl.textContent = server.session_id ? t("status_auto_connect") : t("server_use_hint");
      }
      if (server.session_id) {
        await runServerCheck(getFormData());
      }
      scrollToCard(form.closest(".card"));
    });
    actions.appendChild(useBtn);
    if (server.session_id) {
      const forgetBtn = document.createElement("button");
      forgetBtn.type = "button";
      forgetBtn.className = "secondary";
      forgetBtn.textContent = t("servers_forget_login_btn");
      forgetBtn.addEventListener("click", async () => {
        await forgetServerSession(server, { notify: true });
      });
      actions.appendChild(forgetBtn);
    }
    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "secondary";
    removeBtn.textContent = t("servers_remove_btn");
    removeBtn.addEventListener("click", () => {
      removeServer(server);
    });
    actions.appendChild(removeBtn);
    row.appendChild(info);
    row.appendChild(actions);
    serversListEl.appendChild(row);
  });
}

function upsertServer(entry) {
  if (!serversListEl || !serversEmptyEl || !entry?.host) {
    return;
  }
  const normalized = {
    host: String(entry.host || "").trim(),
    user: String(entry.user || "").trim(),
    ssh_port: parseOptionalSshPort(entry.ssh_port),
    listen_port: normalizeListenPort(entry.listen_port),
    clients_count:
      typeof entry.clients_count === "number" && entry.clients_count >= 0
        ? entry.clients_count
        : undefined,
    session_id: entry.session_id || undefined,
  };
  if (!normalized.host) {
    return;
  }
  const servers = loadServers();
  const key = makeServerKey(normalized.host, normalized.user, normalized.ssh_port);
  const idx = servers.findIndex(
    (item) => makeServerKey(item.host, item.user, item.ssh_port || 22) === key,
  );
  if (idx >= 0) {
    servers[idx] = { ...servers[idx], ...normalized };
    if (entry.session_id === null) {
      delete servers[idx].session_id;
    }
    servers.unshift(servers.splice(idx, 1)[0]);
  } else {
    servers.unshift(normalized);
  }
  saveServers(servers.slice(0, 8));
  if (!STATE.activeServerKey) {
    setActiveServerKey(key);
  }
  renderServers();
}

function applyServerToForm(server) {
  form.elements.host.value = server.host || "";
  form.elements.user.value = server.user || "";
  if (form.elements.ssh_port) {
    const port = parseOptionalSshPort(server.ssh_port);
    form.elements.ssh_port.value = port ? String(port) : "";
  }
  if (form.elements.listen_port && server.listen_port) {
    form.elements.listen_port.value = server.listen_port;
  }
  if (form.elements.password) {
    form.elements.password.value = "";
  }
  if (form.elements.key_content) {
    form.elements.key_content.value = "";
  }
  const key = makeServerKey(server.host, server.user, server.ssh_port || 22);
  setActiveServerKey(key);
  STATE.activeSessionId = server.session_id || null;
  if (rememberLoginToggle) {
    rememberLoginToggle.checked = Boolean(server.session_id);
  }
}

function removeServer(server) {
  const key = makeServerKey(server.host, server.user, server.ssh_port || 22);
  const list = loadServers().filter(
    (item) => makeServerKey(item.host, item.user, item.ssh_port || 22) !== key,
  );
  saveServers(list);
  if (STATE.activeServerKey === key) {
    STATE.activeSessionId = null;
    setActiveServerKey(null);
    if (rememberLoginToggle) {
      rememberLoginToggle.checked = false;
    }
  }
  renderServers();
}

async function revokeSession(sessionId) {
  if (!sessionId) {
    return;
  }
  try {
    await fetchJson("/api/sessions/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId }),
    });
  } catch (err) {
    console.warn(err);
  }
}

async function forgetServerSession(server, options = {}) {
  const { notify = false } = options;
  const key = makeServerKey(server.host, server.user, server.ssh_port || 22);
  const list = loadServers();
  const idx = list.findIndex(
    (item) => makeServerKey(item.host, item.user, item.ssh_port || 22) === key,
  );
  if (idx < 0) {
    return;
  }
  const previousSession = list[idx].session_id || null;
  delete list[idx].session_id;
  saveServers(list);
  if (STATE.activeServerKey === key) {
    STATE.activeSessionId = null;
    if (rememberLoginToggle) {
      rememberLoginToggle.checked = false;
    }
  }
  renderServers();
  if (notify) {
    setStatus(t("status_session_cleared"));
  }
  await revokeSession(previousSession);
}

function getServerByKey(key) {
  if (!key) {
    return null;
  }
  return (
    loadServers().find(
      (item) => makeServerKey(item.host, item.user, item.ssh_port || 22) === key,
    ) || null
  );
}

async function restoreActiveServer() {
  const storedKey = localStorage.getItem(ACTIVE_SERVER_KEY);
  let server = getServerByKey(storedKey);
  if (!server) {
    const servers = loadServers();
    server = servers.length ? servers[0] : null;
  }
  if (!server) {
    return;
  }
  applyServerToForm(server);
  if (server.session_id) {
    setStatus(t("status_auto_connect"));
    await runServerCheck(getFormData());
  }
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
    port: data.ssh_port || 22,
    password: data.password || null,
    key_content: data.key_content || null,
  };
}

function hasAuthSecrets(data) {
  return Boolean(data?.password || data?.key_content);
}

function buildAuthPayload(data) {
  const payload = {};
  if (data?.session_id) {
    payload.session_id = data.session_id;
  }
  if (hasAuthSecrets(data) || !data?.session_id) {
    payload.ssh = buildSshPayload(data);
  }
  return payload;
}

async function loginSession(data) {
  if (!data?.remember_login || !hasAuthSecrets(data)) {
    return null;
  }
  const result = await fetchJson("/api/sessions/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ssh: buildSshPayload(data) }),
  });
  if (!result.ok) {
    throw new Error(result.error || t("status_failed"));
  }
  return result.session_id || null;
}

async function discoverSshPort(data) {
  if (!data?.host) {
    throw new Error(t("error_ssh_port_autodetect"));
  }
  const result = await fetchJson("/api/ssh/discover-port", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      host: data.host,
      port: data.ssh_port || undefined,
    }),
  });
  if (!result.ok || !result.port) {
    throw new Error(result.error || t("error_ssh_port_autodetect"));
  }
  return {
    host: (result.host || data.host || "").trim(),
    port: normalizeSshPort(result.port, 22),
  };
}

async function ensureSshPort(data) {
  if (!data?.host) {
    throw new Error(t("error_ssh_port_autodetect"));
  }
  if (data.ssh_port) {
    return data.ssh_port;
  }
  if (serverStatusEl) {
    serverStatusEl.textContent = t("status_detecting_ssh_port");
  }
  const found = await discoverSshPort(data);
  data.host = found.host;
  data.ssh_port = found.port;
  if (form?.elements?.host) {
    form.elements.host.value = found.host;
  }
  if (form?.elements?.ssh_port) {
    form.elements.ssh_port.value = found.port;
  }
  if (serverStatusEl) {
    serverStatusEl.textContent = `${t("status_ssh_port_detected")}: ${found.port}`;
  }
  return found.port;
}

function humanizeError(error, data = null) {
  const message = `${error || ""}`.trim();
  if (!message) {
    return t("status_failed");
  }
  if (/session expired/i.test(message)) {
    return t("status_relogin_required");
  }
  if (/unable to connect to port 22/i.test(message)) {
    return `${message}. ${t("error_port_22_hint")}`;
  }
  if (/authentication failed/i.test(message)) {
    return `${message}. ${t("error_auth_hint")}`;
  }
  if (data?.ssh_port === 22 && /unable to connect to port/i.test(message)) {
    return `${message}. ${t("error_port_22_hint")}`;
  }
  return message;
}

async function fetchServerStatus(data) {
  return fetchJson("/api/server/status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(buildAuthPayload(data)),
  });
}

async function fetchServerPrecheck(data) {
  const payload = buildAuthPayload(data);
  payload.options = {
    listen_port: data.listen_port || undefined,
    protocol: "amneziawg",
  };
  return fetchJson("/api/server/precheck", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function fetchClients(data) {
  const payload = buildAuthPayload(data);
  const result = await fetchJson("/api/clients/list", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
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
      ...buildAuthPayload(data),
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
      ...buildAuthPayload(data),
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
      ...buildAuthPayload(data),
      client_name: clientName,
      listen_port: data.listen_port || undefined,
    }),
  });
  if (!result.ok) {
    throw new Error(result.error || t("status_failed"));
  }
  return result;
}

function setSafeVisibility() {
  if (!safeRow || !safeToggle) {
    return;
  }
  const shouldShow = STATE.checked && !serverConfigured;
  safeRow.classList.toggle("hidden", !shouldShow);
  if (shouldShow && !STATE.safeTouched) {
    safeToggle.checked = true;
  }
  if (!shouldShow) {
    safeToggle.checked = false;
    STATE.safeTouched = false;
  }
  updateInstallGuard();
  updateNextStepMessage();
}

function updateInstallGuard() {
  if (!installGuard || !installConfirmToggle || !safeToggle) {
    return;
  }
  const requiresConfirm = STATE.checked && !serverConfigured && !safeToggle.checked;
  installGuard.classList.toggle("hidden", !requiresConfirm);
  if (!requiresConfirm) {
    installConfirmToggle.checked = false;
  }
}

function updateNextStepMessage() {
  if (!nextStepEl) {
    return;
  }
  const serverKey = getServerRuntimeKey();
  const previewDone = Boolean(serverKey && STATE.previewDoneByServer[serverKey]);
  const noviceMode = Boolean(simpleToggle?.checked);
  if (!STATE.checked) {
    nextStepEl.textContent = t("next_step_initial");
    return;
  }
  if (serverConfigured) {
    nextStepEl.textContent = t("next_step_after_check_configured");
    return;
  }
  if (noviceMode && !previewDone) {
    nextStepEl.textContent = t("next_step_novice_preview_first");
    return;
  }
  if (safeToggle?.checked) {
    nextStepEl.textContent = t("next_step_preview_ready");
    return;
  }
  if (installConfirmToggle?.checked) {
    nextStepEl.textContent = t("next_step_after_check_empty");
    return;
  }
  nextStepEl.textContent = t("next_step_confirm_install");
}

function setInstallSummary(data) {
  if (!installSummary) {
    return;
  }
  const udp = data.listen_port || form.elements.listen_port?.value || "-";
  const lines = [
    `${t("install_summary_host")}: ${data.host || "-"}`,
    `${t("install_summary_ssh")}: ${data.user || "-"}@${data.host || "-"}:${data.ssh_port || 22}`,
    `${t("install_summary_udp")}: ${udp}`,
    "",
    t("install_summary_note"),
  ];
  installSummary.textContent = lines.join("\n");
}

function requestInstallConfirmation(data) {
  if (!installModal || !installContinueBtn || !installCancelBtn) {
    return Promise.resolve(true);
  }
  setInstallSummary(data);
  openModal(installModal);
  return new Promise((resolve) => {
    STATE.installConfirmResolver = resolve;
  });
}

function resolveInstallConfirmation(confirmed) {
  if (!STATE.installConfirmResolver) {
    return;
  }
  const resolver = STATE.installConfirmResolver;
  STATE.installConfirmResolver = null;
  resolver(Boolean(confirmed));
  closeModal(installModal);
}

function setSimpleMode(enabled) {
  advancedFields.forEach((field) => {
    field.classList.toggle("hidden", enabled);
  });
  if (enabled) {
    STATE.safeTouched = false;
    if (safeToggle) {
      safeToggle.checked = true;
    }
  }
  setSafeVisibility();
  updateNextStepMessage();
}

setSimpleMode(simpleToggle?.checked ?? true);
simpleToggle.addEventListener("change", () => {
  setSimpleMode(simpleToggle.checked);
});

if (safeToggle) {
  safeToggle.addEventListener("change", () => {
    STATE.safeTouched = true;
    updateInstallGuard();
    updateNextStepMessage();
  });
}

if (installConfirmToggle) {
  installConfirmToggle.addEventListener("change", () => {
    updateNextStepMessage();
  });
}

if (installCancelBtn) {
  installCancelBtn.addEventListener("click", () => {
    resolveInstallConfirmation(false);
  });
}

if (installContinueBtn) {
  installContinueBtn.addEventListener("click", () => {
    resolveInstallConfirmation(true);
  });
}

if (reconfigureCheckbox) {
  reconfigureCheckbox.addEventListener("change", updateStageVisibility);
}
updateStageVisibility();

["host", "user", "ssh_port"].forEach((name) => {
  const field = form.elements[name];
  if (!field) {
    return;
  }
  field.addEventListener("input", () => {
    STATE.activeSessionId = null;
    setActiveServerKey(null);
    STATE.safeTouched = false;
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

if (rememberLoginToggle) {
  rememberLoginToggle.addEventListener("change", async () => {
    if (!rememberLoginToggle.checked && STATE.activeSessionId) {
      const list = loadServers();
      const active = list.find(
        (item) =>
          makeServerKey(item.host, item.user, item.ssh_port || 22) ===
          makeServerKey(form.elements.host.value, form.elements.user.value, form.elements.ssh_port?.value || 22),
      );
      if (active?.session_id) {
        await forgetServerSession(active, { notify: true });
      } else {
        STATE.activeSessionId = null;
      }
    }
  });
}

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
        setDownload(result.config, result.qr_png_base64, result.client_name, {
          downloadId: result.download_id,
        });
        setStatus(`${t("status_client_ready")}: ${result.client_name}`);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${humanizeError(err, STATE.lastAuth)}`);
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
            downloadId: result.download_id,
          };
          STATE.qrOpen = client.name;
          renderClients();
        }
        setStatus(`${t("status_client_ready")}: ${result.client_name}`);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${humanizeError(err, STATE.lastAuth)}`);
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
        setDownload(result.config, result.qr_png_base64, result.client_name, {
          downloadId: result.download_id,
        });
        setStatus(`${t("status_client_rotated")}: ${result.client_name}`);
        await refreshClients(STATE.lastAuth);
      } catch (err) {
        setStatus(`${t("status_failed")}: ${humanizeError(err, STATE.lastAuth)}`);
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
        setStatus(`${t("status_failed")}: ${humanizeError(err, STATE.lastAuth)}`);
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
      const qrData =
        buildDownloadUrl(STATE.qrByClient[client.name].downloadId, "qr") ||
        buildQrUrl(STATE.qrByClient[client.name].qr);
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
      ssh_port: data.ssh_port || undefined,
      listen_port: data.listen_port || undefined,
      clients_count: clients.length,
      session_id: data.session_id || undefined,
    });
  } catch (err) {
    setStatus(`${t("status_failed")}: ${humanizeError(err, data)}`);
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
    setDownload(result.config, result.qr_png_base64, clientName || "client1", {
      downloadId: result.download_id,
    });
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
  const authData = { ...data };
  if (checkServerBtn) {
    checkServerBtn.disabled = true;
  }
  if (serverStatusEl) {
    serverStatusEl.textContent = authData.ssh_port ? t("status_checking") : t("status_detecting_ssh_port");
  }
  if (serverMetaEl) {
    serverMetaEl.textContent = "";
  }
  setProgressVisible(false);
  if (resultCard) {
    resultCard.classList.add("hidden");
  }

  try {
    await ensureSshPort(authData);
    setActiveServerKey(makeServerKey(authData.host, authData.user, authData.ssh_port || 22));
    if (serverStatusEl) {
      serverStatusEl.textContent = t("status_checking");
    }

    if (authData.remember_login && hasAuthSecrets(authData)) {
      const sessionId = await loginSession(authData);
      if (sessionId) {
        authData.session_id = sessionId;
        STATE.activeSessionId = sessionId;
        setStatus(t("status_session_saved"));
      }
    }
    if (!authData.remember_login && authData.session_id) {
      const previousSession = authData.session_id;
      authData.session_id = null;
      STATE.activeSessionId = null;
      await revokeSession(previousSession);
    }
    const result = await fetchServerStatus(authData);
    if (!result.ok) {
      if (serverStatusEl) {
        serverStatusEl.textContent = `${t("status_server_error")}: ${humanizeError(
          result.error || "unknown error",
          authData,
        )}`;
      }
      serverConfigured = false;
      STATE.checked = false;
      STATE.clientsLoading = false;
      updateStageVisibility();
      renderClients([]);
      return;
    }
    STATE.lastAuth = authData;
    STATE.checked = true;
    serverConfigured = Boolean(result.configured);
    const checkedServerKey = getServerRuntimeKey(authData);
    if (checkedServerKey) {
      STATE.previewDoneByServer[checkedServerKey] = serverConfigured;
    }
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
      host: authData.host,
      user: authData.user,
      ssh_port: authData.ssh_port || undefined,
      listen_port: result.listen_port || authData.listen_port || undefined,
      clients_count: result.clients_count,
      session_id: authData.remember_login ? authData.session_id || undefined : null,
    });
    if (serverConfigured) {
      await refreshClients(authData);
    } else {
      renderClients([]);
    }
  } catch (err) {
    const pretty = humanizeError(err, authData);
    if (/session expired/i.test(`${err || ""}`)) {
      STATE.activeSessionId = null;
      if (rememberLoginToggle) {
        rememberLoginToggle.checked = false;
      }
      upsertServer({
        host: authData.host,
        user: authData.user,
        ssh_port: authData.ssh_port || undefined,
        listen_port: authData.listen_port || undefined,
        session_id: null,
      });
    }
    if (serverStatusEl) {
      serverStatusEl.textContent = `${t("status_server_error")}: ${pretty}`;
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
  setActiveServerKey(makeServerKey(data.host, data.user, data.ssh_port || 22));
  if (data.remember_login && hasAuthSecrets(data)) {
    try {
      const sessionId = await loginSession(data);
      if (sessionId) {
        data.session_id = sessionId;
        STATE.activeSessionId = sessionId;
      }
    } catch (err) {
      setStatus(`${t("status_failed")}: ${humanizeError(err, data)}`);
      return;
    }
  }
  if (!data.remember_login) {
    if (data.session_id) {
      await revokeSession(data.session_id);
    }
    data.session_id = null;
    STATE.activeSessionId = null;
  }
  STATE.lastAuth = data;
  if (!data.host || !data.user) {
    alert(t("alert_fill_host_user"));
    return;
  }
  if (!STATE.checked) {
    alert(t("alert_check_first"));
    return;
  }
  const currentServerKey = getServerRuntimeKey(data);
  const previewDone = Boolean(currentServerKey && STATE.previewDoneByServer[currentServerKey]);
  const noviceMode = Boolean(simpleToggle?.checked);
  if (noviceMode && !data.safe_mode && !serverConfigured && !previewDone) {
    if (safeToggle) {
      safeToggle.checked = true;
    }
    STATE.safeTouched = true;
    updateInstallGuard();
    updateNextStepMessage();
    setStatus(t("status_novice_preview_required"));
    scrollToCard(safeRow || form.closest(".card"));
    return;
  }
  if (!data.safe_mode) {
    if (installConfirmToggle && !installConfirmToggle.checked) {
      setStatus(t("status_install_requires_confirm"));
      scrollToCard(installGuard || form.closest(".card"));
      return;
    }
    const confirmed = await requestInstallConfirmation(data);
    if (!confirmed) {
      setStatus(t("status_install_cancelled"));
      return;
    }
  }
  if (data.safe_mode) {
    if (provisionBtn) {
      provisionBtn.disabled = true;
    }
    setProgressVisible(true);
    scrollToCard(progressCard);
    setStatus(t("status_precheck"));
    setProgressState("running");
    setLogVisible(true);
    setProgress([]);
    if (resultCard) {
      resultCard.classList.add("hidden");
    }
    try {
      const result = await fetchServerPrecheck(data);
      if (!result.ok) {
        setStatus(`${t("status_failed")}: ${result.error || "unknown error"}`);
        setProgressState("error");
        return;
      }
      const checks = result.checks || [];
      const lines = checks.map((item) => {
        const status = item.ok ? t("check_ok") : t("check_fail");
        const details = item.details ? ` (${item.details})` : "";
        return `precheck ${item.name}: ${status}${details}`;
      });
      setProgress(lines);
      const previewKey = getServerRuntimeKey(data);
      if (previewKey) {
        STATE.previewDoneByServer[previewKey] = true;
      }
      setStatus(t("status_precheck_done"));
      setProgressState("done");
      updateNextStepMessage();
    } catch (err) {
      setStatus(`${t("status_failed")}: ${humanizeError(err, data)}`);
      setProgressState("error");
    } finally {
      if (provisionBtn) {
        provisionBtn.disabled = false;
      }
    }
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
    ...buildAuthPayload(data),
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
      ssh_port: data.ssh_port || undefined,
      listen_port: data.listen_port || undefined,
      session_id: data.remember_login ? data.session_id || undefined : null,
    });
    if (pollTimer) {
      clearInterval(pollTimer);
    }
    pollTimer = setInterval(() => {
      pollJob(result.job_id, currentClientName, data).catch((err) => {
        setStatus(`${t("status_failed")}: ${humanizeError(err, data)}`);
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
    setStatus(`${t("status_failed")}: ${humanizeError(err, data)}`);
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
  setActiveServerKey(makeServerKey(data.host, data.user, data.ssh_port || 22));
  if (data.remember_login && hasAuthSecrets(data)) {
    try {
      const sessionId = await loginSession(data);
      if (sessionId) {
        data.session_id = sessionId;
        STATE.activeSessionId = sessionId;
      }
    } catch (err) {
      setStatus(`${t("status_failed")}: ${humanizeError(err, data)}`);
      return;
    }
  }
  if (!data.remember_login) {
    if (data.session_id) {
      await revokeSession(data.session_id);
    }
    data.session_id = null;
    STATE.activeSessionId = null;
  }
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
        ...buildAuthPayload(data),
        client_name: data.client_name || null,
        listen_port: data.listen_port || undefined,
      }),
    });
    if (!result.ok) {
      setStatus(`${t("status_failed")}: ${result.error || "unknown error"}`);
      setProgressState("error");
      return;
    }
    setDownload(result.config, result.qr_png_base64, result.client_name, {
      downloadId: result.download_id,
    });
    setStatus(`${t("status_client_ready")}: ${result.client_name}`);
    setProgressState("done");
    upsertServer({
      host: data.host,
      user: data.user,
      ssh_port: data.ssh_port || undefined,
      listen_port: data.listen_port || undefined,
      session_id: data.remember_login ? data.session_id || undefined : null,
    });
    serverConfigured = true;
    updateStageVisibility();
    await refreshClients(data);
  } catch (err) {
    setStatus(`${t("status_failed")}: ${humanizeError(err, data)}`);
    setProgressState("error");
  } finally {
    addClientBtn.disabled = false;
  }
});

restoreActiveServer().catch((err) => {
  console.warn(err);
});
