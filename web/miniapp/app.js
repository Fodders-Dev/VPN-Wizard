const form = document.getElementById("provision-form");
const statusEl = document.getElementById("status");
const progressCard = document.getElementById("progress-card");
const resultCard = document.getElementById("result-card");
const downloadLink = document.getElementById("download-link");
const downloadAutoLink = document.getElementById("download-auto-link");
const copyAutoUrlBtn = document.getElementById("copy-auto-url-btn");
const copyConfigBtn = document.getElementById("copy-config-btn");
const configCopy = document.getElementById("config-copy");
const configText = document.getElementById("config-text");
const qrImage = document.getElementById("qr-image");
const qrDownload = document.getElementById("qr-download");
const altLinksCard = document.getElementById("alt-links");
const altLinksList = document.getElementById("alt-links-list");
const provisionBtn = document.getElementById("provision-btn");
const progressLog = document.getElementById("progress-log");
const progressFill = document.getElementById("progress-fill");
const spinner = document.querySelector(".spinner");
const toggleLogBtn = document.getElementById("toggle-log-btn");
const simpleToggle = document.getElementById("simple-toggle");
const advancedToggleBtn = document.getElementById("advanced-toggle-btn");
const advancedFields = document.querySelectorAll(".advanced");
const addClientBtn = document.getElementById("add-client-btn");
const checkServerBtn = document.getElementById("check-server-btn");
const profilesIntroCard = document.getElementById("profiles-intro-card");
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
const appsTitleEl = document.querySelector(".app-links-title");
const appAndroidEl = document.querySelector('[data-i18n="apps_android"]');
const appIosEl = document.querySelector('[data-i18n="apps_ios"]');
const appWindowsEl = document.querySelector('[data-i18n="apps_windows"]');
const appLinuxEl = document.querySelector('[data-i18n="apps_linux"]');
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
const connectionModeSelect = document.getElementById("connection-mode");
const tabButtons = document.querySelectorAll(".tab-btn");
const tabPanels = document.querySelectorAll("[data-tab-panel]");
const connectionCard = document.getElementById("connection-card");
const wizardShell = document.getElementById("wizard-shell");
const wizardHintEl = document.getElementById("wizard-hint");
const wizardStepButtons = document.querySelectorAll(".wizard-step-btn");
const wizardPrevBtn = document.getElementById("wizard-prev-btn");
const wizardNextBtn = document.getElementById("wizard-next-btn");

const PROXY_APP_URLS = {
  android: "https://github.com/hiddify/hiddify-app/releases",
  ios: "https://hiddify.com/app/",
  windows: "https://github.com/hiddify/hiddify-app/releases",
  linux: "https://github.com/hiddify/hiddify-app/releases",
};

const VPN_APP_URLS = {
  android: appAndroidEl?.getAttribute("href") || "https://play.google.com/store/apps/details?id=org.amnezia.awg",
  ios: appIosEl?.getAttribute("href") || "https://apps.apple.com/us/app/amneziawg/id6478942365",
  windows:
    appWindowsEl?.getAttribute("href") ||
    "https://github.com/amnezia-vpn/amneziawg-windows-client/releases",
  linux:
    appLinuxEl?.getAttribute("href") ||
    "https://github.com/amnezia-vpn/amneziawg-linux-kernel-module",
};

const I18N = {
  ru: {
    app_title: "VPN Wizard",
    app_subtitle: "Простая настройка VPN и антиблок-прокси на вашем сервере",
    tab_connect: "Подключение",
    tab_profiles: "Профили",
    tab_cabinet: "Личный кабинет",
    tab_help: "Помощь",
    wizard_step_connect: "1. Подключение",
    wizard_step_setup: "2. Настройка",
    wizard_step_result: "3. Профиль",
    wizard_prev_btn: "Назад",
    wizard_action_next: "Далее",
    wizard_action_connect: "Подключиться",
    wizard_action_setup: "Настроить сервер",
    wizard_action_to_profile: "К профилю",
    wizard_action_to_cabinet: "В кабинет",
    wizard_hint_step1: "Введите доступ к серверу и нажмите \"Подключиться\".",
    wizard_hint_need_connect: "Сначала подключитесь к серверу на шаге 1.",
    wizard_hint_step2_setup: "Сервер проверен. Если он пустой, нажмите \"Настроить сервер\".",
    wizard_hint_step2_ready: "Сервер уже настроен. Перейдите к шагу 3 и добавьте профиль.",
    wizard_hint_step3_empty: "Задайте имя профиля и нажмите \"Добавить профиль\".",
    wizard_hint_step3_ready: "Профиль готов: скачайте файл/ссылку и QR.",
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
    connection_mode_label: "Режим подключения",
    connection_mode_hint: "VPN быстрее для всего устройства. Прокси лучше при жестких блокировках.",
    connection_mode_switch_hint: "Режим можно менять в любой момент: после смены нажмите \"Подключиться\".",
    mode_vpn: "VPN (AmneziaWG)",
    mode_proxy: "Антиблок прокси (VLESS Reality)",
    remember_login_label: "Запомнить вход на этом устройстве",
    remember_login_hint: "Сессия хранится на этом устройстве и обновляется после входа.",
    remember_login_saved: "Вход сохранен",
    advanced_toggle_btn_show: "Показать расширенные настройки",
    advanced_toggle_btn_hide: "Скрыть расширенные настройки",
    advanced_toggle_hint:
      "Если нужно изменить SSH порт, ключ или порт сервера - откройте расширенные настройки.",
    client_name_label: "Имя профиля",
    client_name_placeholder: "grandma-phone",
    profile_name_hint: "Нужно, чтобы разные устройства не перезаписывали конфиги. Можно оставить пустым.",
    ssh_key_label: "SSH ключ (необязательно)",
    ssh_key_placeholder: "вставьте приватный ключ",
    udp_port_label: "Порт сервера",
    listen_port_placeholder: "авто",
    listen_port_hint: "Для прокси оставьте пустым: порт подберется автоматически.",
    proxy_sni_label: "SNI домен для прокси (опционально)",
    proxy_sni_placeholder: "авто",
    proxy_sni_hint: "Пусто = авто-подбор оптимального SNI. Заполняйте только если знаете нужный домен.",
    tour_btn: "Обучение",
    faq_btn: "FAQ",
    safe_mode_label: "Предпросмотр изменений перед установкой",
    safe_mode_hint: "Нужен только при установке, если на сервере есть другие сервисы.",
    install_confirm_label: "Я понимаю, что установка изменит сетевые настройки сервера.",
    install_confirm_hint: "Рекомендуем сначала сделать предпросмотр изменений.",
    check_server_btn: "Подключиться",
    check_safe_hint: "Подключение безопасно: ничего не устанавливается. Установка - отдельной кнопкой.",
    server_status_idle: "Сервер не подключен",
    next_step_initial: "Сначала заполните доступ к серверу и нажмите \"Подключиться\".",
    next_step_after_check_empty: "Сервер пустой. Сначала сделайте предпросмотр, затем установку.",
    next_step_novice_preview_first: "Режим новичка: сначала включите предпросмотр изменений, затем установку.",
    next_step_after_check_configured: "Сервер уже настроен. Можно сразу управлять профилями.",
    next_step_preview_ready: "Предпросмотр включен: нажатие кнопки покажет план, но ничего не установит.",
    next_step_confirm_install: "Перед установкой подтвердите чекбокс ниже и нажмите кнопку установки.",
    reconfigure_label: "Изменить порт / перенастроить сервер",
    simple_mode_label: "Режим новичка (рекомендуется)",
    simple_mode_hint: "Пошаговый безопасный сценарий. Отключайте только если уверены в действиях.",
    provision_btn: "Настроить сервер и получить первый профиль",
    provision_btn_proxy: "Настроить прокси и получить первую ссылку",
    add_client_btn: "Добавить профиль",
    add_client_btn_proxy: "Добавить прокси-профиль",
    step2_title: "Шаг 2. Прогресс",
    status_waiting: "Ожидание...",
    step3_title: "Шаг 3. Скачать",
    step3_title_proxy: "Шаг 3. Ссылка и QR",
    download_btn: "Скачать конфиг",
    download_btn_proxy: "Скачать ссылку",
    download_btn_auto: "Скачать авто-конфиг",
    copy_auto_url_btn: "Скопировать ссылку авто-подписки",
    download_qr_btn: "Скачать QR",
    copy_btn: "Скопировать конфиг",
    copy_done: "Конфиг скопирован.",
    copy_failed: "Не удалось скопировать конфиг.",
    copy_empty: "Сначала получите конфиг.",
    copy_title: "Конфиг для ручного копирования",
    copy_title_proxy: "Ссылка для ручного копирования",
    copy_hint: "Можно выделить и скопировать вручную.",
    alt_links_title: "Если не работает: альтернативные ссылки",
    alt_links_hint:
      "Импортируйте одну из ссылок в клиент прокси и проверьте. Иногда помогает смена SNI/FP из-за блокировок.",
    step3_hint: "Откройте AmneziaWG и нажмите \"+\", чтобы добавить файл конфигурации.",
    step3_hint_proxy: "Откройте клиент прокси (Hiddify/sing-box), импортируйте ссылку или QR и подключитесь.",
    apps_title: "Скачать приложение AmneziaWG",
    apps_title_proxy: "Рекомендуемые клиенты прокси",
    apps_android: "Android (Google Play)",
    apps_ios: "iOS (App Store)",
    apps_windows: "Windows",
    apps_linux: "Linux",
    apps_proxy_android: "Android (Hiddify / v2rayNG)",
    apps_proxy_ios: "iOS (Hiddify / Shadowrocket)",
    apps_proxy_windows: "Windows (Hiddify / Nekoray)",
    apps_proxy_linux: "Linux (Nekoray / sing-box)",
    apps_macos_missing: "macOS: приложения пока нет",
    servers_title: "Личный кабинет: серверы",
    servers_empty: "Пока нет сохранённых серверов.",
    servers_use_btn: "Использовать",
    servers_forget_login_btn: "Забыть вход",
    servers_remove_btn: "Удалить",
    onboarding_title: "Быстрый старт",
    onboarding_step1: "1) Введите IP/хост, SSH пользователя и пароль или ключ (SSH порт найдется автоматически).",
    onboarding_step2: "2) Нажмите \"Подключиться\" - если VPN уже есть, появятся профили.",
    onboarding_step3:
      "3) В режиме прокси порт и SNI подберутся автоматически (ручной ввод есть в расширенных настройках).",
    onboarding_step4: "4) Если нет - нажмите \"Настроить сервер\" и скачайте конфиг/ссылку и QR.",
    profiles_intro_title: "Управление профилями",
    profiles_intro_body: "Сначала подключитесь к серверу. После этого здесь появятся профили, QR и ссылки/конфиги.",
    clients_title: "Профили",
    clients_empty: "Профили не найдены.",
    clients_loading: "Загружаем профили...",
    client_ip: "IP",
    client_handshake: "Рукопожатие",
    client_transfer: "Трафик",
    client_interface: "Интерфейс",
    client_download: "Конфиг",
    client_download_proxy: "Ссылка",
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
    status_provisioning_proxy: "Настраиваем антиблок-прокси... это может занять пару минут.",
    status_adding_client: "Добавляем профиль...",
    status_adding_client_proxy: "Добавляем прокси-профиль...",
    status_ready: "Готово.",
    status_client_ready: "Профиль готов",
    status_client_removed: "Профиль удален",
    status_client_rotated: "Профиль перевыпущен",
    status_failed: "Ошибка",
    status_checking: "Подключаемся к серверу...",
    status_detecting_ssh_port: "Ищем SSH порт автоматически...",
    status_ssh_port_detected: "Найден SSH порт",
    status_loading_clients: "Загружаем профили...",
    status_server_configured: "Сервер уже настроен",
    status_server_configured_proxy: "Прокси уже настроен",
    status_server_needs_setup: "Сервер не настроен",
    status_server_needs_setup_proxy: "Прокси не настроен",
    status_server_error: "Не удалось подключиться к серверу",
    status_auto_connect: "Восстанавливаем вход и подключаемся к серверу...",
    status_relogin_required: "Сессия истекла. Введите пароль или ключ снова.",
    status_session_saved: "Вход сохранён на этом устройстве.",
    status_session_cleared: "Сохраненный вход удален.",
    status_install_requires_confirm: "Подтвердите чекбокс перед установкой, чтобы избежать случайных изменений.",
    status_install_cancelled: "Установка отменена.",
    status_job_tracker_lost:
      "Связь с задачей потеряна (возможен перезапуск сервиса). Пытаемся восстановить по состоянию сервера...",
    status_job_tracker_recovered: "Задача восстановлена по текущему состоянию сервера.",
    status_job_tracker_timeout:
      "Не удалось восстановить задачу. Нажмите \"Подключиться\" снова и продолжите с текущего состояния сервера.",
    status_novice_preview_required: "Режим новичка: сначала сделайте предпросмотр изменений, чтобы ничего не сломать.",
    status_precheck: "Проверяем сервер и план изменений... ничего не устанавливаем.",
    status_precheck_done: "Предпросмотр готов. Чтобы установить VPN, отключите предпросмотр.",
    server_use_hint: "Введите пароль или ключ и нажмите \"Подключиться\".",
    download_ready: "Скачайте конфиг и отсканируйте QR.",
    download_ready_proxy: "Скопируйте ссылку или отсканируйте QR в клиенте прокси.",
    check_ok: "ok",
    check_fail: "fail",
    auto_value: "авто",
    progress_idle: "Ожидание",
    job_queued: "В очереди",
    job_running: "В работе",
    job_done: "Готово",
    job_error: "Ошибка",
    meta_protocol: "Протокол",
    meta_ssh_port: "SSH",
    meta_port: "Порт",
    meta_sni: "SNI",
    meta_clients: "Профилей",
    meta_tyumen: "Доп. порт",
    protocol_amneziawg: "AmneziaWG",
    protocol_wireguard: "WireGuard",
    protocol_vless_reality: "VLESS Reality",
    alert_fill_host_user: "Заполните поля Host и User.",
    alert_check_first: "Сначала нажмите \"Подключиться\".",
    alert_remove_client: "Удалить профиль",
    alert_remove_confirm: "Точно удалить профиль?",
    alert_rotate_confirm: "Перевыпустить ключи для профиля?",
    alert_export_failed: "Не удалось получить конфиг",
    error_ssh_port_autodetect: "Не удалось автоопределить SSH порт. Укажите его вручную в расширенных настройках.",
    error_port_22_hint: "SSH на порту 22 недоступен. Проверьте SSH порт (например 2222).",
    error_banner_hint:
      "На указанном порту отвечает не SSH. Проверьте SSH порт или очистите поле SSH порт для автоопределения.",
    error_auth_hint: "Ошибка SSH авторизации. Проверьте логин, пароль/ключ и SSH порт.",
    install_modal_title: "Подтвердить установку",
    install_modal_body: "Будут изменены сетевые настройки и установлен VPN на вашем сервере.",
    install_modal_cancel: "Отмена",
    install_modal_continue: "Продолжить установку",
    install_summary_host: "Сервер",
    install_summary_ssh: "SSH",
    install_summary_udp: "Порт",
    install_summary_proxy_port: "TCP порт прокси",
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
    tour_step4_title: "Подключение к серверу",
    tour_step4_body:
      "Подключение ничего не устанавливает: оно лишь определяет, пустой сервер или уже настроен. После подключения появятся нужные кнопки.",
    profile_name_callout: "Перед добавлением профиля укажите имя (например: grandma-phone).",
    faq_title: "FAQ",
    faq_what_is_title: "Что это за бот?",
    faq_what_is_body: "VPN Wizard подключается к вашему серверу по SSH и автоматически настраивает быстрый VPN. В результате вы получаете готовые конфиги и QR.",
    faq_safe_title: "Это безопасно?",
    faq_safe_body: "Бот использует ваши SSH-данные только для настройки. Мы не храним пароли, всё выполняется на вашем сервере.",
    faq_ports_title: "Что делать, если VPN не работает?",
    faq_ports_body: "Попробуйте другой UDP порт в расширенных настройках (например 3478 или 33434).",
    faq_tyumen_title: "Как добавить профиль?",
    faq_tyumen_body: "Введите имя профиля и нажмите \"Добавить профиль\". Порт можно выбрать в расширенных полях.",
    faq_proxy_slow_title: "Прокси подключен, но сайты медленные или не грузятся",
    faq_proxy_slow_body:
      "Чаще всего это DNS/маршрутизация в клиенте прокси (особенно в РФ).\n\nПроверьте:\n1) Включен ли DNS Routing.\n2) Remote DNS = DoH (https://dns.google/dns-query или https://unfiltered.adguard-dns.com/dns-query).\n3) На Windows попробуйте режим VPN (экспериментальный/TUN) и включите Strict Routing.\n4) Отключите другие VPN/прокси и оставьте активным только один профиль.\n5) Если стало хуже после смены порта/SNI — включите авто и перенастройте прокси.",
    faq_changes_title: "Что именно мы делаем на сервере?",
    faq_changes_body:
      "1) Подключаемся по SSH и проверяем ОС, sudo и свободный порт.\n2) Ставим WireGuard/AmneziaWG и зависимости.\n3) Создаём ключи и конфиги в /etc/amnezia/amneziawg или /etc/wireguard.\n4) Включаем IP forwarding и добавляем NAT (iptables).\n5) Поднимаем сервис awg-quick@ или wg-quick@ и делаем бэкапы конфигов.\n6) Генерируем ваш профиль и QR.\n\nЕсли у вас на сервере есть свои сервисы или строгий firewall — используйте безопасный режим и внимательно прочитайте пункты выше.",
    faq_servers_title: "Как запоминаются серверы?",
    faq_servers_body:
      "Список серверов хранится локально на устройстве. Пароли и ключи не сохраняются: вместо них можно включить \"Запомнить вход\", тогда используется временная защищенная сессия.",
    server_advice:
      "Если сервер пустой - можно смело настраивать. Если нет - прочитайте FAQ и включите расширенные настройки.",
    server_rent_link: "Как арендовать сервер: пошаговый гайд",
    help_title: "Как пользоваться",
    help_vpn_title: "Режим VPN (AmneziaWG)",
    help_vpn_body:
      "1) Подключитесь к серверу.\n2) Нажмите \"Настроить сервер\".\n3) Скачайте конфиг и импортируйте в AmneziaWG.",
    help_proxy_title: "Режим антиблок-прокси (VLESS Reality)",
    help_proxy_body:
      "1) Подключитесь к серверу и настройте прокси (порт/SNI можно оставить пустыми - авто).\n2) Получите ссылку и QR.\n3) Импортируйте в Hiddify/sing-box и подключитесь.\n4) Для РФ (особенно Windows): чаще стабильнее режим VPN (экспериментальный/TUN) + Strict Routing = ON + DNS Routing = ON. Если ломаются приложения — переключитесь на System Proxy.\n5) DNS: используйте DoH (например https://dns.google/dns-query или https://unfiltered.adguard-dns.com/dns-query). Избегайте udp://1.1.1.1.\n6) Не держите одновременно активным другой VPN/прокси и несколько профилей.",
    help_install_title: "Что установить на устройство",
    help_install_body:
      "VPN: AmneziaWG.\nПрокси: Hiddify (рекомендуется) или v2rayNG/sing-box.",
  },
  en: {
    app_title: "VPN Wizard",
    app_subtitle: "Simple setup for VPN and anti-censorship proxy on your server",
    tab_connect: "Connect",
    tab_profiles: "Profiles",
    tab_cabinet: "Cabinet",
    tab_help: "Help",
    wizard_step_connect: "1. Connect",
    wizard_step_setup: "2. Setup",
    wizard_step_result: "3. Profile",
    wizard_prev_btn: "Back",
    wizard_action_next: "Next",
    wizard_action_connect: "Connect",
    wizard_action_setup: "Configure server",
    wizard_action_to_profile: "To profile",
    wizard_action_to_cabinet: "Cabinet",
    wizard_hint_step1: "Enter server access and click \"Connect\".",
    wizard_hint_need_connect: "Connect to the server first on step 1.",
    wizard_hint_step2_setup: "Server is checked. If it is empty, click \"Configure server\".",
    wizard_hint_step2_ready: "Server is already configured. Go to step 3 and add a profile.",
    wizard_hint_step3_empty: "Set a profile name and click \"Add profile\".",
    wizard_hint_step3_ready: "Profile is ready: download file/link and QR.",
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
    connection_mode_label: "Connection mode",
    connection_mode_hint: "VPN is faster for full-device traffic. Proxy works better under strict blocking.",
    connection_mode_switch_hint: "You can switch modes anytime: after changing it, click \"Connect\" again.",
    mode_vpn: "VPN (AmneziaWG)",
    mode_proxy: "Anti-block proxy (VLESS Reality)",
    remember_login_label: "Remember login on this device",
    remember_login_hint: "A secure session is stored on this device and refreshed after login.",
    remember_login_saved: "Login remembered",
    advanced_toggle_btn_show: "Show advanced settings",
    advanced_toggle_btn_hide: "Hide advanced settings",
    advanced_toggle_hint:
      "Need to change SSH port, key, or server port? Open advanced settings.",
    client_name_label: "Profile name",
    client_name_placeholder: "grandma-phone",
    profile_name_hint: "Helps avoid overwriting configs between devices. You can leave it empty.",
    ssh_key_label: "SSH key (optional)",
    ssh_key_placeholder: "paste private key",
    udp_port_label: "Server port",
    listen_port_placeholder: "auto",
    listen_port_hint: "For proxy, leave empty to auto-select a suitable port.",
    proxy_sni_label: "Proxy SNI domain (optional)",
    proxy_sni_placeholder: "auto",
    proxy_sni_hint: "Leave empty for automatic SNI selection. Fill only if you know a specific domain.",
    tour_btn: "Tour",
    faq_btn: "FAQ",
    safe_mode_label: "Preview changes before setup",
    safe_mode_hint: "Only for setup when the server hosts other services.",
    install_confirm_label: "I understand that setup will change server network settings.",
    install_confirm_hint: "We recommend running change preview first.",
    check_server_btn: "Connect",
    check_safe_hint: "Connection is safe: nothing is installed. Setup uses a separate button.",
    server_status_idle: "Server not connected",
    next_step_initial: "Fill server access fields first, then click \"Connect\".",
    next_step_after_check_empty: "Server is empty. Run preview first, then install.",
    next_step_novice_preview_first: "Novice mode: run change preview first, then install.",
    next_step_after_check_configured: "Server is already configured. You can manage profiles now.",
    next_step_preview_ready: "Preview is enabled: button click will show a plan and install nothing.",
    next_step_confirm_install: "Before install, check the confirmation box below and click setup.",
    reconfigure_label: "Change port / reconfigure server",
    simple_mode_label: "Novice mode (recommended)",
    simple_mode_hint: "Safe step-by-step flow. Disable only if you understand the risks.",
    provision_btn: "Configure server and get the first profile",
    provision_btn_proxy: "Configure proxy and get the first link",
    add_client_btn: "Add profile",
    add_client_btn_proxy: "Add proxy profile",
    step2_title: "Step 2: Progress",
    status_waiting: "Waiting...",
    step3_title: "Step 3: Download",
    step3_title_proxy: "Step 3: Link and QR",
    download_btn: "Download config",
    download_btn_proxy: "Download link",
    download_btn_auto: "Download auto config",
    copy_auto_url_btn: "Copy auto profile URL",
    download_qr_btn: "Download QR",
    copy_btn: "Copy config",
    copy_done: "Config copied.",
    copy_failed: "Failed to copy config.",
    copy_empty: "Generate a config first.",
    copy_title: "Config for manual copy",
    copy_title_proxy: "Link for manual copy",
    copy_hint: "Select and copy manually if needed.",
    alt_links_title: "If it doesn't work: alternative links",
    alt_links_hint:
      "Import one of the links into your proxy client and try again. Sometimes switching SNI/FP helps under blocking.",
    step3_hint: "Open AmneziaWG and press \"+\" to add the configuration file.",
    step3_hint_proxy: "Open your proxy client (Hiddify/sing-box), import the link or scan QR, then connect.",
    apps_title: "Get AmneziaWG",
    apps_title_proxy: "Recommended proxy clients",
    apps_android: "Android (Google Play)",
    apps_ios: "iOS (App Store)",
    apps_windows: "Windows",
    apps_linux: "Linux",
    apps_proxy_android: "Android (Hiddify / v2rayNG)",
    apps_proxy_ios: "iOS (Hiddify / Shadowrocket)",
    apps_proxy_windows: "Windows (Hiddify / Nekoray)",
    apps_proxy_linux: "Linux (Nekoray / sing-box)",
    apps_macos_missing: "macOS: no official app yet",
    servers_title: "Cabinet: servers",
    servers_empty: "No saved servers yet.",
    servers_use_btn: "Use",
    servers_forget_login_btn: "Forget login",
    servers_remove_btn: "Delete",
    onboarding_title: "Quick start",
    onboarding_step1: "1) Enter host, SSH user, and password or key (SSH port is auto-detected).",
    onboarding_step2: "2) Click \"Connect\" - if VPN exists you will see profiles.",
    onboarding_step3:
      "3) In proxy mode, port and SNI are auto-selected (manual override is in advanced settings).",
    onboarding_step4: "4) Otherwise click \"Configure server\" and download config/link + QR.",
    profiles_intro_title: "Profile management",
    profiles_intro_body: "Connect to a server first. Profiles, QR and links/configs will appear here.",
    clients_title: "Profiles",
    clients_empty: "No profiles yet.",
    clients_loading: "Loading profiles...",
    client_ip: "IP",
    client_handshake: "Handshake",
    client_transfer: "Traffic",
    client_interface: "Interface",
    client_download: "Config",
    client_download_proxy: "Link",
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
    status_provisioning_proxy: "Setting up anti-block proxy... this can take a few minutes.",
    status_adding_client: "Adding profile...",
    status_adding_client_proxy: "Adding proxy profile...",
    status_ready: "Ready.",
    status_client_ready: "Profile ready",
    status_client_removed: "Profile removed",
    status_client_rotated: "Profile rotated",
    status_failed: "Failed",
    status_checking: "Connecting to server...",
    status_detecting_ssh_port: "Detecting SSH port automatically...",
    status_ssh_port_detected: "SSH port detected",
    status_loading_clients: "Loading profiles...",
    status_server_configured: "Server already configured",
    status_server_configured_proxy: "Proxy is already configured",
    status_server_needs_setup: "Server is not configured",
    status_server_needs_setup_proxy: "Proxy is not configured",
    status_server_error: "Failed to connect to server",
    status_auto_connect: "Restoring login and connecting to server...",
    status_relogin_required: "Session expired. Enter password or key again.",
    status_session_saved: "Login saved on this device.",
    status_session_cleared: "Saved login cleared.",
    status_install_requires_confirm: "Check the confirmation box before install to avoid accidental changes.",
    status_install_cancelled: "Install canceled.",
    status_job_tracker_lost:
      "Lost job tracker state (service restart is possible). Trying to recover from current server state...",
    status_job_tracker_recovered: "Recovered job state from current server.",
    status_job_tracker_timeout:
      "Could not recover job state. Click \"Connect\" again and continue from current server state.",
    status_novice_preview_required: "Novice mode: run change preview first to avoid breaking your server.",
    status_precheck: "Checking server and change plan... nothing is installed.",
    status_precheck_done: "Preview ready. Disable preview to install the VPN.",
    server_use_hint: "Enter password or key and click \"Connect\".",
    download_ready: "Ready. Download your config and scan the QR.",
    download_ready_proxy: "Ready. Copy the link or scan the QR in your proxy client.",
    check_ok: "ok",
    check_fail: "fail",
    auto_value: "auto",
    progress_idle: "Waiting",
    job_queued: "Queued",
    job_running: "Running",
    job_done: "Done",
    job_error: "Error",
    meta_protocol: "Protocol",
    meta_ssh_port: "SSH",
    meta_port: "Port",
    meta_sni: "SNI",
    meta_clients: "Profiles",
    meta_tyumen: "Alt port",
    protocol_amneziawg: "AmneziaWG",
    protocol_wireguard: "WireGuard",
    protocol_vless_reality: "VLESS Reality",
    alert_fill_host_user: "Please fill in Host and User fields first.",
    alert_check_first: "Please click \"Connect\" first.",
    alert_remove_client: "Remove profile",
    alert_remove_confirm: "Delete this profile?",
    alert_rotate_confirm: "Rotate keys for this profile?",
    alert_export_failed: "Failed to export config",
    error_ssh_port_autodetect: "Could not auto-detect SSH port. Set it manually in advanced settings.",
    error_port_22_hint: "Cannot reach SSH on port 22. Check the SSH port (for example 2222).",
    error_banner_hint:
      "The selected port is not speaking SSH. Check SSH port or clear SSH port field to use auto-discovery.",
    error_auth_hint: "SSH auth failed. Check user, password/key, and SSH port.",
    install_modal_title: "Confirm installation",
    install_modal_body: "Server network settings will be changed and VPN will be installed.",
    install_modal_cancel: "Cancel",
    install_modal_continue: "Continue install",
    install_summary_host: "Server",
    install_summary_ssh: "SSH",
    install_summary_udp: "Port",
    install_summary_proxy_port: "Proxy TCP port",
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
    tour_step4_title: "Server connection",
    tour_step4_body:
      "Connecting does not install anything. It only detects if the server is empty or already configured, then shows the next buttons.",
    profile_name_callout: "Set profile name before adding it (for example: grandma-phone).",
    faq_title: "FAQ",
    faq_what_is_title: "What is this bot?",
    faq_what_is_body: "VPN Wizard connects to your server over SSH and configures a fast VPN. You get ready configs and QR.",
    faq_safe_title: "Is it safe?",
    faq_safe_body: "The bot uses your SSH credentials only for setup. We do not store passwords.",
    faq_ports_title: "VPN not working?",
    faq_ports_body: "Try another UDP port in advanced settings (for example 3478 or 33434).",
    faq_tyumen_title: "How to add a profile?",
    faq_tyumen_body: "Enter a profile name and click \"Add profile\". You can change the UDP port in advanced fields.",
    faq_proxy_slow_title: "Proxy connected but sites are slow or not loading",
    faq_proxy_slow_body:
      "This is usually client-side DNS/routing (common on RU networks).\n\nCheck:\n1) DNS Routing is enabled.\n2) Remote DNS is DoH (https://dns.google/dns-query or https://unfiltered.adguard-dns.com/dns-query).\n3) On Windows, try VPN (experimental/TUN) and enable Strict Routing.\n4) Disable other VPN/proxy apps and keep only one active profile.\n5) If it got worse after changing port/SNI, reset them to auto and reconfigure.",
    faq_changes_title: "What exactly do we change on the server?",
    faq_changes_body:
      "1) Connect over SSH and check OS, sudo, and free port.\n2) Install WireGuard/AmneziaWG and dependencies.\n3) Create keys/configs under /etc/amnezia/amneziawg or /etc/wireguard.\n4) Enable IP forwarding and add NAT (iptables).\n5) Start awg-quick@ or wg-quick@ and create config backups.\n6) Generate your profile and QR.\n\nIf your server hosts other services or strict firewall rules, use safe mode and review the steps above.",
    faq_servers_title: "How are servers saved?",
    faq_servers_body:
      "Servers are stored locally on your device. Passwords and keys are not stored: with \"Remember login\" the app uses a temporary secure session token instead.",
    server_advice:
      "Empty server? You can install safely. If not, read the FAQ and enable advanced settings.",
    server_rent_link: "How to rent a VPS: step-by-step guide",
    help_title: "How to use",
    help_vpn_title: "VPN mode (AmneziaWG)",
    help_vpn_body:
      "1) Connect to your server.\n2) Click \"Configure server\".\n3) Download config and import it into AmneziaWG.",
    help_proxy_title: "Anti-block proxy mode (VLESS Reality)",
    help_proxy_body:
      "1) Connect and configure proxy (leave port/SNI empty for auto mode).\n2) Get link and QR.\n3) Import into Hiddify/sing-box and connect.\n4) For RU networks (especially Windows): VPN (experimental/TUN) is often more stable with Strict Routing = ON and DNS Routing = ON. If apps break, switch to System Proxy.\n5) DNS: use DoH (for example https://dns.google/dns-query or https://unfiltered.adguard-dns.com/dns-query). Avoid udp://1.1.1.1.\n6) Do not keep another VPN/proxy or multiple profiles active at the same time.",
    help_install_title: "What to install on device",
    help_install_body:
      "VPN: AmneziaWG.\nProxy: Hiddify (recommended) or v2rayNG/sing-box.",
  },
};

const LANG_KEY = "vpnw_lang";
const SERVERS_KEY = "vpnw_servers";
const ACTIVE_SERVER_KEY = "vpnw_active_server";
const ACTIVE_TAB_KEY = "vpnw_active_tab";
const SIMPLE_MODE_KEY = "vpnw_simple_mode";
const LEGACY_KEYS = ["vpnw_creds", "vpnw_salt", "vpnw_iv"];
const WIZARD_MIN_STEP = 1;
const WIZARD_MAX_STEP = 3;
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
  missingJobPolls: {},
  downloads: {
    configUrl: null,
    qrUrl: null,
    configText: null,
  },
  tourIndex: 0,
  activeTab: localStorage.getItem(ACTIVE_TAB_KEY) || "connect",
  wizardStep: WIZARD_MIN_STEP,
};

function t(key) {
  return I18N[currentLang]?.[key] || I18N.ru[key] || key;
}

function isReconfigureMode() {
  return Boolean(reconfigureCheckbox?.checked && STATE.checked && serverConfigured);
}

function isUiConfigured() {
  return serverConfigured && !isReconfigureMode();
}

function getMaxWizardStep() {
  if (!STATE.checked) {
    return WIZARD_MIN_STEP;
  }
  if (!isUiConfigured()) {
    return 2;
  }
  return WIZARD_MAX_STEP;
}

function hasReadyProfileDownload() {
  return Boolean(
    STATE.downloads.configText ||
      (downloadLink && !downloadLink.classList.contains("hidden")) ||
      (resultCard && !resultCard.classList.contains("hidden")),
  );
}

function clampWizardStep() {
  const maxStep = getMaxWizardStep();
  if (STATE.wizardStep < WIZARD_MIN_STEP) {
    STATE.wizardStep = WIZARD_MIN_STEP;
  }
  if (STATE.wizardStep > maxStep) {
    STATE.wizardStep = maxStep;
  }
}

function updateWizardVisibility() {
  if (!wizardShell) {
    return;
  }
  const visibleTab = STATE.activeTab === "connect" || STATE.activeTab === "profiles";
  const noviceMode = Boolean(simpleToggle?.checked);
  wizardShell.classList.toggle("hidden", !visibleTab || !noviceMode);
}

function updateWizardUi() {
  if (!wizardShell) {
    return;
  }
  clampWizardStep();
  const maxStep = getMaxWizardStep();
  wizardStepButtons.forEach((btn) => {
    const step = Number.parseInt(btn.dataset.wizardStep || "", 10);
    const isActive = step === STATE.wizardStep;
    const isDone = step < STATE.wizardStep && step <= maxStep;
    const isLocked = step > maxStep;
    btn.classList.toggle("active", isActive);
    btn.classList.toggle("done", isDone);
    btn.classList.toggle("locked", isLocked);
    btn.disabled = isLocked;
  });
  if (wizardPrevBtn) {
    wizardPrevBtn.disabled = STATE.wizardStep <= WIZARD_MIN_STEP;
  }
  if (wizardNextBtn) {
    if (STATE.wizardStep <= 1) {
      wizardNextBtn.textContent = STATE.checked ? t("wizard_action_next") : t("wizard_action_connect");
    } else if (STATE.wizardStep === 2) {
      wizardNextBtn.textContent = isUiConfigured() ? t("wizard_action_to_profile") : t("wizard_action_setup");
    } else {
      wizardNextBtn.textContent = t("wizard_action_to_cabinet");
    }
  }
  if (wizardHintEl) {
    if (STATE.wizardStep === 1) {
      wizardHintEl.textContent = t("wizard_hint_step1");
    } else if (STATE.wizardStep === 2) {
      wizardHintEl.textContent = STATE.checked
        ? isUiConfigured()
          ? t("wizard_hint_step2_ready")
          : t("wizard_hint_step2_setup")
        : t("wizard_hint_need_connect");
    } else {
      wizardHintEl.textContent = hasReadyProfileDownload()
        ? t("wizard_hint_step3_ready")
        : t("wizard_hint_step3_empty");
    }
  }
  updateWizardVisibility();
}

function getStepAnchor(step) {
  if (step <= 1) {
    return connectionCard || form?.closest(".card") || null;
  }
  if (step === 2) {
    if (progressCard && !progressCard.classList.contains("hidden")) {
      return progressCard;
    }
    if (provisionBtn && !provisionBtn.classList.contains("hidden")) {
      return provisionBtn;
    }
    return profilesIntroCard || connectionCard || null;
  }
  if (resultCard && !resultCard.classList.contains("hidden")) {
    return resultCard;
  }
  if (clientsCard && !clientsCard.classList.contains("hidden")) {
    return clientsCard;
  }
  if (addClientBtn && !addClientBtn.classList.contains("hidden")) {
    return addClientBtn;
  }
  return profilesIntroCard || connectionCard || null;
}

function setWizardStep(step, options = {}) {
  const { syncTab = true, scroll = false } = options;
  const numericStep = Number.parseInt(`${step}`, 10);
  const targetStep = Number.isFinite(numericStep) ? numericStep : WIZARD_MIN_STEP;
  const boundedStep = Math.max(WIZARD_MIN_STEP, Math.min(WIZARD_MAX_STEP, targetStep));
  const maxStep = getMaxWizardStep();
  STATE.wizardStep = Math.min(boundedStep, maxStep);

  if (syncTab) {
    if (STATE.wizardStep <= 1) {
      setActiveTab("connect");
    } else {
      setActiveTab("profiles");
    }
  }
  updateWizardUi();
  if (scroll) {
    scrollToCard(getStepAnchor(STATE.wizardStep));
  }
}

function setActiveTab(tab, options = {}) {
  const target = ["connect", "profiles", "cabinet", "help"].includes(tab) ? tab : "connect";
  STATE.activeTab = target;
  if (!options.silent) {
    localStorage.setItem(ACTIVE_TAB_KEY, target);
  }
  tabButtons.forEach((btn) => {
    const active = btn.dataset.tab === target;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  tabPanels.forEach((panel) => {
    panel.classList.toggle("tab-panel-hidden", panel.dataset.tabPanel !== target);
  });
  updateWizardVisibility();
  updateWizardUi();
}

function revealProfilesTab() {
  if (STATE.activeTab !== "profiles") {
    setActiveTab("profiles");
  }
  if (STATE.wizardStep < 2) {
    STATE.wizardStep = 2;
    updateWizardUi();
  }
}

function getConnectionMode(data = null) {
  const mode = (data?.connection_mode || connectionModeSelect?.value || "amneziawg").toString();
  return mode === "vless_reality" ? "vless_reality" : "amneziawg";
}

function isProxyMode(data = null) {
  return getConnectionMode(data) === "vless_reality";
}

function updateModeUi(data = null) {
  const proxyMode = isProxyMode(data);
  if (provisionBtn) {
    provisionBtn.textContent = proxyMode ? t("provision_btn_proxy") : t("provision_btn");
  }
  if (addClientBtn) {
    addClientBtn.textContent = proxyMode ? t("add_client_btn_proxy") : t("add_client_btn");
  }
  if (downloadLink) {
    downloadLink.textContent = proxyMode ? t("download_btn_proxy") : t("download_btn");
  }
  if (downloadAutoLink) {
    downloadAutoLink.textContent = t("download_btn_auto");
  }
  const step3Title = document.querySelector("#result-card h2");
  if (step3Title) {
    step3Title.textContent = proxyMode ? t("step3_title_proxy") : t("step3_title");
  }
  const copyTitle = document.querySelector(".config-title");
  if (copyTitle) {
    copyTitle.textContent = proxyMode ? t("copy_title_proxy") : t("copy_title");
  }
  const step3Hint = document.querySelector(".step3-hint");
  if (step3Hint) {
    step3Hint.textContent = proxyMode ? t("step3_hint_proxy") : t("step3_hint");
  }
  if (appsTitleEl) {
    appsTitleEl.textContent = proxyMode ? t("apps_title_proxy") : t("apps_title");
  }
  if (appAndroidEl) {
    appAndroidEl.textContent = proxyMode ? t("apps_proxy_android") : t("apps_android");
    const href = proxyMode ? PROXY_APP_URLS.android : VPN_APP_URLS.android;
    appAndroidEl.href = href;
    appAndroidEl.dataset.url = href;
  }
  if (appIosEl) {
    appIosEl.textContent = proxyMode ? t("apps_proxy_ios") : t("apps_ios");
    const href = proxyMode ? PROXY_APP_URLS.ios : VPN_APP_URLS.ios;
    appIosEl.href = href;
    appIosEl.dataset.url = href;
  }
  if (appWindowsEl) {
    appWindowsEl.textContent = proxyMode ? t("apps_proxy_windows") : t("apps_windows");
    const href = proxyMode ? PROXY_APP_URLS.windows : VPN_APP_URLS.windows;
    appWindowsEl.href = href;
    appWindowsEl.dataset.url = href;
  }
  if (appLinuxEl) {
    appLinuxEl.textContent = proxyMode ? t("apps_proxy_linux") : t("apps_linux");
    const href = proxyMode ? PROXY_APP_URLS.linux : VPN_APP_URLS.linux;
    appLinuxEl.href = href;
    appLinuxEl.dataset.url = href;
  }
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
  updateModeUi();
  renderServers();
  renderClients();
  renderFaq();
  updateTourStep();
  setLogVisible(STATE.logVisible);
  updateAdvancedToggleUi();
  updateStageVisibility();
  setActiveTab(STATE.activeTab, { silent: true });
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

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    setActiveTab(btn.dataset.tab || "connect");
    if (btn.dataset.tab === "connect") {
      setWizardStep(1, { syncTab: false });
    } else if (btn.dataset.tab === "profiles") {
      const nextStep = getMaxWizardStep() >= 2 ? (isUiConfigured() ? 3 : 2) : 1;
      setWizardStep(nextStep, { syncTab: false });
    }
  });
});

wizardStepButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetStep = Number.parseInt(btn.dataset.wizardStep || "", 10);
    if (!Number.isFinite(targetStep)) {
      return;
    }
    setWizardStep(targetStep, { syncTab: true, scroll: true });
  });
});

if (wizardPrevBtn) {
  wizardPrevBtn.addEventListener("click", () => {
    setWizardStep(STATE.wizardStep - 1, { syncTab: true, scroll: true });
  });
}

if (wizardNextBtn) {
  wizardNextBtn.addEventListener("click", async () => {
    if (STATE.wizardStep <= 1) {
      if (!STATE.checked) {
        if (form.requestSubmit) {
          form.requestSubmit();
        } else {
          checkServerBtn?.click();
        }
        return;
      }
      setWizardStep(2, { syncTab: true, scroll: true });
      return;
    }
    if (STATE.wizardStep === 2) {
      if (!STATE.checked) {
        setWizardStep(1, { syncTab: true, scroll: true });
        return;
      }
      if (!isUiConfigured()) {
        await runProvision();
        return;
      }
      setWizardStep(3, { syncTab: true, scroll: true });
      return;
    }
    setActiveTab("cabinet");
  });
}

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
  const { showResult = true, scroll = true, downloadId = null, autoDownloadId = null, alternatives = null } = options;
  const ext = isProxyMode(STATE.lastAuth) ? "txt" : "conf";

  if (STATE.downloads.configUrl?.startsWith("blob:")) {
    URL.revokeObjectURL(STATE.downloads.configUrl);
  }
  const remoteConfigUrl = buildDownloadUrl(downloadId, "config");
  const configUrl = config ? remoteConfigUrl || buildConfigUrl(config) : null;
  STATE.downloads.configUrl = configUrl;
  STATE.downloads.configText = config || null;
  if (configUrl && downloadLink) {
    downloadLink.download = `${safeName}.${ext}`;
    downloadLink.href = configUrl;
    downloadLink.dataset.url = configUrl;
    downloadLink.classList.remove("hidden");
  } else if (downloadLink) {
    downloadLink.classList.add("hidden");
  }

  // Auto config (sing-box JSON) for proxy mode
  if (downloadAutoLink) {
    const proxyMode = isProxyMode(STATE.lastAuth);
    const autoUrl = buildDownloadUrl(autoDownloadId, "config");
    downloadAutoLink.textContent = t("download_btn_auto");
    downloadAutoLink.classList.toggle("hidden", !(proxyMode && autoUrl));
    if (proxyMode && autoUrl) {
      downloadAutoLink.download = `${safeName}-auto.json`;
      downloadAutoLink.href = autoUrl;
      downloadAutoLink.dataset.url = autoUrl;
    }
    if (copyAutoUrlBtn) {
      copyAutoUrlBtn.textContent = t("copy_auto_url_btn");
      copyAutoUrlBtn.classList.toggle("hidden", !(proxyMode && autoUrl));
      copyAutoUrlBtn.onclick = async () => {
        const ok = await copyToClipboard(autoUrl || "");
        setStatus(ok ? t("copy_done") : t("copy_failed"));
      };
    }
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

  // Alternative links: proxy-only helper for RU networks (DPI issues).
  if (altLinksCard && altLinksList) {
    const proxyMode = isProxyMode(STATE.lastAuth);
    const list = Array.isArray(alternatives) ? alternatives : [];
    altLinksList.innerHTML = "";
    altLinksCard.classList.toggle("hidden", !(proxyMode && list.length));
    if (proxyMode && list.length) {
      list.slice(0, 6).forEach((item, idx) => {
        const row = document.createElement("div");
        row.className = "alt-link-row";

        const meta = document.createElement("div");
        meta.className = "alt-link-meta";
        const sni = String(item?.sni || "").trim();
        const fp = String(item?.fp || "").trim();
        meta.textContent = `${idx + 1}. SNI: ${sni || "-"} · FP: ${fp || "-"}`;

        const actions = document.createElement("div");
        actions.className = "alt-link-actions";

        const copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "secondary";
        copyBtn.textContent = currentLang === "ru" ? "Скопировать" : "Copy";
        const link = String(item?.link || "");
        copyBtn.addEventListener("click", async () => {
          const ok = await copyToClipboard(link);
          setStatus(ok ? t("copy_done") : t("copy_failed"));
        });

        actions.appendChild(copyBtn);
        row.appendChild(meta);
        row.appendChild(actions);
        altLinksList.appendChild(row);
      });
    }
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
    updateModeUi(STATE.lastAuth);
    revealProfilesTab();
    STATE.wizardStep = 3;
    updateWizardUi();
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
  const configured = isUiConfigured();
  const reconfiguring = isReconfigureMode();

  if (profilesIntroCard) {
    profilesIntroCard.classList.remove("hidden");
  }

  stageUncheckedOnlyEls.forEach((el) => {
    el.classList.toggle("hidden", checked);
  });
  stageBeforeConfigEls.forEach((el) => {
    el.classList.toggle("hidden", configured);
  });

  if (serversCard) {
    serversCard.classList.remove("hidden");
  }
  if (clientsCard) {
    clientsCard.classList.toggle("hidden", !checked || !serverConfigured);
  }
  if (addClientBtn) {
    addClientBtn.classList.toggle("hidden", !checked || !serverConfigured || reconfiguring);
  }
  if (provisionBtn) {
    provisionBtn.classList.toggle("hidden", !checked || configured);
  }
  profileOnlyFields.forEach((field) => {
    field.classList.toggle("hidden", !checked || reconfiguring);
  });
  if (reconfigureToggle) {
    reconfigureToggle.classList.toggle("hidden", !(checked && serverConfigured));
  }
  if ((!checked || !serverConfigured) && reconfigureCheckbox?.checked) {
    reconfigureCheckbox.checked = false;
  }
  if (!checked) {
    STATE.wizardStep = 1;
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
  if (checked && !configured && STATE.wizardStep < 2) {
    STATE.wizardStep = 2;
  }
  if (checked && !configured && STATE.wizardStep > 2) {
    STATE.wizardStep = 2;
  }
  if (configured && STATE.wizardStep < 2) {
    STATE.wizardStep = 2;
  }
  updateModeUi(STATE.lastAuth || getFormData());
  setSafeVisibility();
  updateWizardUi();
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
  if (status.proxy_sni) {
    parts.push(`${t("meta_sni")}: ${status.proxy_sni}`);
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
    { titleKey: "faq_proxy_slow_title", bodyKey: "faq_proxy_slow_body" },
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

function makeServerKey(host, user, sshPort, mode = "amneziawg") {
  const normalizedMode = mode === "vless_reality" ? "vless_reality" : "amneziawg";
  return `${(host || "").trim().toLowerCase()}|${(user || "").trim().toLowerCase()}|${normalizeSshPort(
    sshPort,
    22,
  )}|${normalizedMode}`;
}

function getServerRuntimeKey(data = null) {
  if (data?.host && data?.user) {
    return makeServerKey(data.host, data.user, data.ssh_port || 22, getConnectionMode(data));
  }
  const host = form?.elements?.host?.value || "";
  const user = form?.elements?.user?.value || "";
  const sshPort = form?.elements?.ssh_port?.value || 22;
  const mode = getConnectionMode();
  if (!host || !user) {
    return null;
  }
  return makeServerKey(host, user, sshPort, mode);
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
  const connectionMode = getConnectionMode({ connection_mode: data.connection_mode });
  const proxySni = (data.proxy_sni || "").trim().toLowerCase();
  return {
    host: parsedHost.host,
    user: (data.user || "").trim(),
    ssh_port: parsedHost.port,
    password: data.password || null,
    key_content: keyContent || null,
    client_name: (data.client_name || "").trim(),
    listen_port: listenPort,
    proxy_sni: proxySni || null,
    safe_mode: connectionMode !== "vless_reality" && Boolean(safeToggle?.checked) && !simpleToggle.checked,
    connection_mode: connectionMode,
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
        mode: item.mode === "vless_reality" ? "vless_reality" : "amneziawg",
        listen_port: normalizeListenPort(item.listen_port),
        proxy_sni: String(item.proxy_sni || "").trim().toLowerCase() || undefined,
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
    const protocolLabel = t(`protocol_${server.mode || "amneziawg"}`);
    if (protocolLabel) {
      parts.push(`${t("meta_protocol")}: ${protocolLabel}`);
    }
    if (server.user) {
      parts.push(`SSH: ${server.user}`);
    }
    if (server.ssh_port) {
      parts.push(`${t("meta_ssh_port")}: ${server.ssh_port}`);
    }
    if (server.listen_port) {
      parts.push(`${t("meta_port")}: ${server.listen_port}`);
    }
    if (server.mode === "vless_reality" && server.proxy_sni) {
      parts.push(`${t("meta_sni")}: ${server.proxy_sni}`);
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
      setActiveTab("connect");
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
    mode: getConnectionMode({ connection_mode: entry.mode }),
    listen_port: normalizeListenPort(entry.listen_port),
    proxy_sni: String(entry.proxy_sni || "").trim().toLowerCase() || undefined,
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
  const key = makeServerKey(normalized.host, normalized.user, normalized.ssh_port, normalized.mode);
  const idx = servers.findIndex(
    (item) => makeServerKey(item.host, item.user, item.ssh_port || 22, item.mode) === key,
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
  if (connectionModeSelect) {
    connectionModeSelect.value = getConnectionMode({ connection_mode: server.mode });
  }
  if (form.elements.ssh_port) {
    const port = parseOptionalSshPort(server.ssh_port);
    form.elements.ssh_port.value = port ? String(port) : "";
  }
  if (form.elements.listen_port && server.listen_port) {
    form.elements.listen_port.value = server.listen_port;
  } else if (form.elements.listen_port) {
    form.elements.listen_port.value = "";
  }
  if (form.elements.proxy_sni) {
    form.elements.proxy_sni.value = server.proxy_sni || "";
  }
  if (form.elements.password) {
    form.elements.password.value = "";
  }
  if (form.elements.key_content) {
    form.elements.key_content.value = "";
  }
  const key = makeServerKey(server.host, server.user, server.ssh_port || 22, server.mode);
  setActiveServerKey(key);
  STATE.activeSessionId = server.session_id || null;
  if (rememberLoginToggle) {
    rememberLoginToggle.checked = Boolean(server.session_id);
  }
  updateModeUi({ connection_mode: server.mode });
  ensureListenPortDefaultForMode();
}

function removeServer(server) {
  const key = makeServerKey(server.host, server.user, server.ssh_port || 22, server.mode);
  const list = loadServers().filter(
    (item) => makeServerKey(item.host, item.user, item.ssh_port || 22, item.mode) !== key,
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
  const key = makeServerKey(server.host, server.user, server.ssh_port || 22, server.mode);
  const list = loadServers();
  const idx = list.findIndex(
    (item) => makeServerKey(item.host, item.user, item.ssh_port || 22, item.mode) === key,
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
      (item) => makeServerKey(item.host, item.user, item.ssh_port || 22, item.mode) === key,
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
  const payload = {
    protocol: getConnectionMode(data),
  };
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
  if (/error reading ssh protocol banner/i.test(message)) {
    return `${message}. ${t("error_banner_hint")}`;
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

function isJobNotFoundError(error) {
  return /job not found/i.test(`${error || ""}`);
}

async function tryRecoverProvisionFromServer(jobId, clientName, authData) {
  if (!authData?.host || !authData?.user) {
    return false;
  }
  const attempts = (STATE.missingJobPolls[jobId] || 0) + 1;
  STATE.missingJobPolls[jobId] = attempts;
  setStatus(t("status_job_tracker_lost"));
  if (attempts > 30) {
    throw new Error(t("status_job_tracker_timeout"));
  }
  if (attempts > 1 && attempts % 3 !== 0) {
    return false;
  }
  try {
    const status = await fetchServerStatus(authData);
    if (!status?.ok || !status.configured) {
      return false;
    }
    STATE.lastAuth = authData;
    STATE.checked = true;
    serverConfigured = true;
    if (reconfigureCheckbox) {
      reconfigureCheckbox.checked = false;
    }
    if (status.listen_port && form.elements.listen_port) {
      form.elements.listen_port.value = status.listen_port;
    }
    if (status.proxy_sni && form.elements.proxy_sni) {
      form.elements.proxy_sni.value = status.proxy_sni;
    }
    setServerMeta(status);
    updateStageVisibility();
    await refreshClients(authData);
    try {
      const exportName = clientName || authData.client_name || "client1";
      const exported = await exportClient(authData, exportName);
      setDownload(exported.config, exported.qr_png_base64, exported.client_name || exportName, {
        downloadId: exported.download_id,
        autoDownloadId: exported.auto_download_id || null,
        alternatives: exported.alternatives || null,
      });
      setStatus(isProxyMode(authData) ? t("download_ready_proxy") : t("download_ready"));
    } catch (exportErr) {
      setStatus(t("status_job_tracker_recovered"));
    }
    delete STATE.missingJobPolls[jobId];
    setProgressState("done");
    return true;
  } catch (err) {
    return false;
  }
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
    protocol: getConnectionMode(data),
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
  const proxyMode = isProxyMode();
  const shouldShow = !proxyMode && STATE.checked && !isUiConfigured();
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
  const requiresConfirm = !isProxyMode() && STATE.checked && !isUiConfigured() && !safeToggle.checked;
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
  const proxyMode = isProxyMode();
  if (!STATE.checked) {
    nextStepEl.textContent = t("next_step_initial");
    return;
  }
  if (isUiConfigured()) {
    nextStepEl.textContent = t("next_step_after_check_configured");
    return;
  }
  if (proxyMode) {
    nextStepEl.textContent = t("next_step_after_check_empty");
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
  const proxyMode = isProxyMode(data);
  const port = proxyMode
    ? data.listen_port || form.elements.listen_port?.value || t("auto_value")
    : data.listen_port || form.elements.listen_port?.value || "3478";
  const lines = [
    `${t("install_summary_host")}: ${data.host || "-"}`,
    `${t("install_summary_ssh")}: ${data.user || "-"}@${data.host || "-"}:${data.ssh_port || 22}`,
    `${proxyMode ? t("install_summary_proxy_port") : t("install_summary_udp")}: ${port}`,
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
    if (safeToggle && !isProxyMode()) {
      safeToggle.checked = true;
    }
  }
  setSafeVisibility();
  updateNextStepMessage();
  updateModeUi();
  updateAdvancedToggleUi();
  updateWizardUi();
}

function updateAdvancedToggleUi() {
  if (!advancedToggleBtn || !simpleToggle) {
    return;
  }
  const simpleMode = Boolean(simpleToggle.checked);
  advancedToggleBtn.textContent = simpleMode ? t("advanced_toggle_btn_show") : t("advanced_toggle_btn_hide");
  advancedToggleBtn.setAttribute("aria-expanded", simpleMode ? "false" : "true");
}

function ensureListenPortDefaultForMode() {
  if (!form?.elements?.listen_port) {
    return;
  }
  const mode = getConnectionMode();
  const currentPort = Number.parseInt(form.elements.listen_port.value || "", 10);
  if (mode === "vless_reality") {
    if (currentPort === 3478) {
      form.elements.listen_port.value = "";
    }
    return;
  }
  if (!Number.isFinite(currentPort)) {
    form.elements.listen_port.value = "3478";
  }
}

if (simpleToggle) {
  const storedSimpleMode = localStorage.getItem(SIMPLE_MODE_KEY);
  if (storedSimpleMode === "true" || storedSimpleMode === "false") {
    simpleToggle.checked = storedSimpleMode === "true";
  }
}

setSimpleMode(simpleToggle?.checked ?? true);
ensureListenPortDefaultForMode();
if (simpleToggle) {
  simpleToggle.addEventListener("change", () => {
    setSimpleMode(simpleToggle.checked);
    localStorage.setItem(SIMPLE_MODE_KEY, String(simpleToggle.checked));
  });
}
if (advancedToggleBtn && simpleToggle) {
  advancedToggleBtn.addEventListener("click", () => {
    simpleToggle.checked = !simpleToggle.checked;
    setSimpleMode(simpleToggle.checked);
    localStorage.setItem(SIMPLE_MODE_KEY, String(simpleToggle.checked));
    if (!simpleToggle.checked && form?.elements?.ssh_port) {
      form.elements.ssh_port.focus();
    }
  });
}

if (connectionModeSelect) {
  connectionModeSelect.addEventListener("change", () => {
    ensureListenPortDefaultForMode();
    STATE.safeTouched = false;
    serverConfigured = false;
    STATE.checked = false;
    STATE.wizardStep = 1;
    STATE.clients = [];
    STATE.qrByClient = {};
    STATE.qrOpen = null;
    if (serverStatusEl) {
      serverStatusEl.textContent = t("server_status_idle");
    }
    if (serverMetaEl) {
      serverMetaEl.textContent = "";
    }
    updateModeUi();
    updateStageVisibility();
    renderClients([]);
  });
}

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
    STATE.wizardStep = 1;
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
          makeServerKey(item.host, item.user, item.ssh_port || 22, item.mode) ===
          makeServerKey(
            form.elements.host.value,
            form.elements.user.value,
            form.elements.ssh_port?.value || 22,
            getConnectionMode(),
          ),
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
  const proxyMode = isProxyMode(STATE.lastAuth);
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
    const parts = proxyMode
      ? [`${t("meta_protocol")}: ${t("protocol_vless_reality")}`]
      : [
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
    configBtn.textContent = proxyMode ? t("client_download_proxy") : t("client_download");
    configBtn.disabled = isBusy;
    configBtn.addEventListener("click", async () => {
      try {
        setClientBusy(client.name, "export");
        setStatus(t("client_busy_export"));
        const result = await exportClient(STATE.lastAuth, client.name);
        setDownload(result.config, result.qr_png_base64, result.client_name, {
          downloadId: result.download_id,
          autoDownloadId: result.auto_download_id || null,
          alternatives: result.alternatives || null,
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
          autoDownloadId: result.auto_download_id || null,
          alternatives: result.alternatives || null,
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
    if (!proxyMode) {
      actions.appendChild(rotateBtn);
    }
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
    const configuredLabel = isProxyMode(data)
      ? t("status_server_configured_proxy")
      : t("status_server_configured");
    serverStatusEl.textContent = `${configuredLabel} · ${t("status_loading_clients")}`;
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
      mode: getConnectionMode(data),
      listen_port: data.listen_port || undefined,
      proxy_sni: data.proxy_sni || undefined,
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
  let status;
  try {
    status = await fetchJson(`/api/jobs/${jobId}`);
  } catch (err) {
    if (isJobNotFoundError(err)) {
      const recovered = await tryRecoverProvisionFromServer(jobId, clientName, authData);
      if (recovered) {
        clearInterval(pollTimer);
        pollTimer = null;
        if (provisionBtn) {
          provisionBtn.disabled = false;
        }
      }
      return;
    }
    throw err;
  }
  delete STATE.missingJobPolls[jobId];
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
    delete STATE.missingJobPolls[jobId];
    if (provisionBtn) {
      provisionBtn.disabled = false;
    }
    return;
  }

  if (status.status === "done") {
    clearInterval(pollTimer);
    pollTimer = null;
    delete STATE.missingJobPolls[jobId];
    const result = await fetchJson(`/api/jobs/${jobId}/result`);
    setDownload(result.config, result.qr_png_base64, clientName || "client1", {
      downloadId: result.download_id,
      autoDownloadId: result.auto_download_id || null,
      alternatives: result.alternatives || null,
    });
    const checks = result.checks || [];
    if (checks.length) {
      const checkText = checks
        .map((item) => `${item.name}: ${item.ok ? t("check_ok") : t("check_fail")}`)
        .join(" | ");
      setStatus(`${t("status_ready")} ${checkText}`);
    } else {
      setStatus(isProxyMode(authData) ? t("download_ready_proxy") : t("download_ready"));
    }
    if (provisionBtn) {
      provisionBtn.disabled = false;
    }
    serverConfigured = true;
    if (reconfigureCheckbox) {
      reconfigureCheckbox.checked = false;
    }
    updateStageVisibility();
    if (authData) {
      try {
        const freshStatus = await fetchServerStatus(authData);
        if (freshStatus?.ok && freshStatus.configured) {
          if (freshStatus.listen_port && form.elements.listen_port) {
            form.elements.listen_port.value = freshStatus.listen_port;
          }
          if (freshStatus.proxy_sni && form.elements.proxy_sni) {
            form.elements.proxy_sni.value = freshStatus.proxy_sni;
          }
          setServerMeta(freshStatus);
          upsertServer({
            host: authData.host,
            user: authData.user,
            ssh_port: authData.ssh_port || undefined,
            mode: getConnectionMode(authData),
            listen_port: freshStatus.listen_port || authData.listen_port || undefined,
            proxy_sni: freshStatus.proxy_sni || authData.proxy_sni || undefined,
            clients_count: freshStatus.clients_count,
            session_id: authData.remember_login ? authData.session_id || undefined : null,
          });
        }
      } catch (err) {
        // Non-fatal: profile is already provisioned.
      }
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
  if (reconfigureCheckbox) {
    reconfigureCheckbox.checked = false;
  }
  setWizardStep(1, { syncTab: true });
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
    setActiveServerKey(
      makeServerKey(
        authData.host,
        authData.user,
        authData.ssh_port || 22,
        getConnectionMode(authData),
      ),
    );
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
      if (isProxyMode(authData)) {
        serverStatusEl.textContent = serverConfigured
          ? t("status_server_configured_proxy")
          : t("status_server_needs_setup_proxy");
      } else {
        serverStatusEl.textContent = serverConfigured
          ? t("status_server_configured")
          : t("status_server_needs_setup");
      }
    }
    if (result.listen_port && form.elements.listen_port) {
      form.elements.listen_port.value = result.listen_port;
    }
    if (result.proxy_sni && form.elements.proxy_sni) {
      form.elements.proxy_sni.value = result.proxy_sni;
    }
    setServerMeta(result);
    updateStageVisibility();
    upsertServer({
      host: authData.host,
      user: authData.user,
      ssh_port: authData.ssh_port || undefined,
      mode: getConnectionMode(authData),
      listen_port: result.listen_port || authData.listen_port || undefined,
      proxy_sni: result.proxy_sni || authData.proxy_sni || undefined,
      clients_count: result.clients_count,
      session_id: authData.remember_login ? authData.session_id || undefined : null,
    });
    if (serverConfigured) {
      STATE.wizardStep = 3;
      revealProfilesTab();
      await refreshClients(authData);
    } else {
      STATE.wizardStep = 2;
      renderClients([]);
    }
    updateWizardUi();
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
        mode: getConnectionMode(authData),
        listen_port: authData.listen_port || undefined,
        proxy_sni: authData.proxy_sni || undefined,
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
    setWizardStep(1, { syncTab: true });
  } finally {
    if (checkServerBtn) {
      checkServerBtn.disabled = false;
    }
  }
}

async function runProvision() {
  const data = getFormData();
  setWizardStep(2, { syncTab: true });
  setActiveServerKey(
    makeServerKey(data.host, data.user, data.ssh_port || 22, getConnectionMode(data)),
  );
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
  const proxyMode = isProxyMode(data);
  if (!proxyMode && noviceMode && !data.safe_mode && !isUiConfigured() && !previewDone) {
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
  if (!proxyMode && !data.safe_mode) {
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
  if (!proxyMode && data.safe_mode) {
    if (provisionBtn) {
      provisionBtn.disabled = true;
    }
    setProgressVisible(true);
    revealProfilesTab();
    STATE.wizardStep = 2;
    updateWizardUi();
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
  STATE.wizardStep = 2;
  updateWizardUi();
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
      protocol: getConnectionMode(data),
    },
  };
  if (data.listen_port) {
    payload.options.listen_port = data.listen_port;
  }
  if (data.proxy_sni) {
    payload.options.proxy_sni = data.proxy_sni;
  }

  const currentClientName = data.client_name || "client1";

  try {
    const result = await fetchJson("/api/provision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    STATE.missingJobPolls[result.job_id] = 0;
    setStatus(proxyMode ? t("status_provisioning_proxy") : t("status_provisioning"));
    setProgressState("running");
    upsertServer({
      host: data.host,
      user: data.user,
      ssh_port: data.ssh_port || undefined,
      mode: getConnectionMode(data),
      listen_port: data.listen_port || undefined,
      proxy_sni: data.proxy_sni || undefined,
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
  setActiveServerKey(
    makeServerKey(data.host, data.user, data.ssh_port || 22, getConnectionMode(data)),
  );
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
  revealProfilesTab();
  scrollToCard(progressCard);
  setStatus(isProxyMode(data) ? t("status_adding_client_proxy") : t("status_adding_client"));
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
      autoDownloadId: result.auto_download_id || null,
      alternatives: result.alternatives || null,
    });
    setStatus(`${t("status_client_ready")}: ${result.client_name}`);
    setProgressState("done");
    upsertServer({
      host: data.host,
      user: data.user,
      ssh_port: data.ssh_port || undefined,
      mode: getConnectionMode(data),
      listen_port: data.listen_port || undefined,
      proxy_sni: data.proxy_sni || undefined,
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
