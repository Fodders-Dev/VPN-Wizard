from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_miniapp_uses_canonical_api_fallback_and_test_hooks() -> None:
    js = (ROOT / "web" / "miniapp" / "app.js").read_text(encoding="utf-8")
    assert 'const CANONICAL_API_BASE = "https://212-69-84-167.nip.io";' in js
    assert 'const CANONICAL_MINIAPP_URL = `${CANONICAL_API_BASE}/wizard/`;' in js
    assert 'new URL("/wizard/", window.location.origin)' in js
    assert 'new URL("/portal/", window.location.origin)' in js
    assert "tg.BackButton?.show()" in js
    assert "tg.BackButton?.onClick(returnToPortal)" in js
    assert "function resolveApiBaseFrom" in js
    assert "window.__VPNW_TEST__" in js
    config_js = (ROOT / "web" / "miniapp" / "config.js").read_text(encoding="utf-8")
    assert "vercel" in config_js
    assert "window.location.hostname" in config_js
    assert 'window.API_BASE = "https://212-69-84-167.nip.io";' in config_js


def test_miniapp_shell_is_single_flow_and_has_diagnostics_panel() -> None:
    html = (ROOT / "web" / "miniapp" / "index.html").read_text(encoding="utf-8")
    assert 'id="diagnostics-panel"' in html
    assert 'class="bottom-nav glass-panel"' in html
    assert 'data-page="connect"' in html
    assert 'id="user-input" autocomplete="username" placeholder="root" value="root" required' in html
    assert 'id="debug-log"' in html
    assert 'id="connect-progress-panel"' in html
    assert 'id="connect-checklist"' in html
    assert 'value="amneziawg"' in html
    assert 'value="xray"' in html
    assert 'id="relay-card"' in html
    assert 'id="relay-enabled-toggle"' in html
    assert 'value="shadowtls_ss"' not in html
    assert 'value="vless_reality"' not in html
    assert 'id="faq-sheet"' not in html
    assert 'class="product-switcher glass-panel"' in html
    assert 'href="/portal/"' in html
    assert 'aria-current="page"' in html


def test_connect_page_is_a_private_unified_portal() -> None:
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "Готовый Fodder VPN" in html
    assert "Настроить свой сервер" in html
    assert 'href="/wizard/"' in html
    assert 'href="/portal/" aria-current="page"' in html
    assert "tg.BackButton&&tg.BackButton.hide()" in html
    assert 'request("/api/auth/telegram/miniapp"' in html
    assert 'request("/api/portal/links")' in html
    # Telegram is the authority for this launch: a stale cookie from another
    # account must not win over the current initData.
    assert "init_data:tg.initData" in html
    assert "localStorage" not in html
    assert "Happ" not in html
    assert "Reality" not in html
    assert "Поделиться VPN с близким" in html
    assert "Открыть» и «Скопировать» — это одна и та же семейная ссылка" in html
    assert "Делиться выгодно" in html
    assert "Подарок подписчикам Fodder’s Dev" in html
    assert 'id="claim-offer"' in html
    assert 'request("/api/portal/links")' in html
    assert 'fetch("/api/portal/channel-offer/claim"' in html
    assert 'id="trial-countdown"' in html
    assert 'id="wizard-link-main"' in html
    assert "Подключение займёт около двух минут" in html


def test_free_profile_is_visibly_and_technically_scoped_to_france() -> None:
    portal = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    installer = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    server = (ROOT / "src" / "vpn_wizard" / "server.py").read_text(encoding="utf-8")
    assert "Один профиль на новом сервере во Франции" in portal
    assert 'trial:p.get("trial")==="1"' in installer
    assert "servers.filter(function(item){return item.id===u.server;})" in installer
    assert "The free profile is available on the France server only." in server


def test_portal_prices_match_the_bot() -> None:
    # The table used to carry hand-written roubles that matched nothing in the
    # bot. It may state prices again only because the bot was reconfigured to
    # produce exactly these three, verified through its own pricing engine:
    #
    #   99 ₽ = PRICE_30_DAYS 9900 + 200GB package 0    + 0 extra devices
    #  179 ₽ = 9900 + 500GB 2000  + 2 × PRICE_PER_DEVICE 3000
    #  299 ₽ = 9900 + 1TB   8000  + 4 × 3000
    #
    # If someone changes the bot's numbers, this test is the tripwire.
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    for price, plan in (("99 ₽", "Личный · 1 устройство"),
                        ("179 ₽", "Вместе · 3 устройства"),
                        ("299 ₽", "Семья · 5 устройств")):
        assert price in html, price
        assert plan in html, plan
    # The old invented ladder must not creep back.
    for invented in ("399 ₽", "1 490 ₽", "2 390 ₽", "3 290 ₽"):
        assert invented not in html, invented
    # Stars is the only method actually switched on in the bot.
    assert "Telegram Stars" in html
    # The trial is the hook, and it costs the visitor nothing to check.
    assert "7 дней бесплатно, карта не нужна" in html


def test_help_does_not_advertise_a_competitor() -> None:
    # amnezia.org sells its own VPN. Linking a paying customer there from our
    # own help text is showing them a rival's shop window.
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "https://amnezia.org" not in handler


def test_portal_tells_a_trial_apart_from_a_paid_subscription() -> None:
    # Remnawave only knows "entitled"; the billing bot knows it is a free week.
    # Without this the cabinet told someone whose trial ends tonight that their
    # subscription was active, and never mentioned paying.
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "links.is_trial" in html
    assert "Пробный период" in html
    # ...but money comes after the problem is solved, not before: the buy CTA
    # only replaces the connect CTA once the server has seen a real handshake.
    assert "state.everConnected" in html
    server = (ROOT / "src" / "vpn_wizard" / "server.py").read_text(encoding="utf-8")
    assert "is_trial: bool = False" in server
    assert "subscription_facts_of" in server


def test_portal_bot_links_always_carry_a_start_payload() -> None:
    # A bare t.me/<bot> link opens the chat and sends nothing, so the bot has no
    # message to answer: the user lands in a silent chat with no idea what to do.
    import re

    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    for link in re.findall(r"t\.me/foddervpnbot[^\"'\s]*", html):
        assert "?start=" in link, link


def test_invite_button_carries_a_deep_link_payload() -> None:
    # A bare t.me/<bot> link opens the chat and sends nothing, so the bot has
    # nothing to answer and the button looks broken. The invite must be a deep
    # link carrying the subscriber's own referral code, served by the API.
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "links.referral_url" in html
    assert 'id="copy-invite"' in html
    assert 'id="invite-url"' in html


def test_entry_urls_do_not_rely_on_a_cache_busting_version() -> None:
    # HTML freshness comes from the no-store header, so the /portal and /wizard
    # entry URLs never need a hand-bumped ?v= query. Static assets may still
    # carry their own version; only the page URLs are covered here.
    sources = [
        ROOT / "web" / "connect" / "index.html",
        ROOT / "web" / "connect" / "awg.html",
        ROOT / "web" / "miniapp" / "index.html",
        ROOT / "web" / "miniapp" / "app.js",
        ROOT / "src" / "vpn_wizard" / "server.py",
    ]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "/portal/?v=" not in text, path
        assert "/wizard/?v=" not in text, path


def test_connect_pages_share_one_design_system() -> None:
    # Every user-facing page draws from one stylesheet, so a token changed once
    # changes everywhere. Per-page CSS is what let the old pages drift apart.
    for page in ("index.html", "awg.html", "join.html"):
        html = (ROOT / "web" / "connect" / page).read_text(encoding="utf-8")
        assert '<link rel="stylesheet" href="atlas.css">' in html, page
        assert '<script src="atlas.js"></script>' in html, page
        assert 'name="color-scheme" content="light dark"' in html, page
        # Glass was replaced deliberately: text over a blurred backdrop is the
        # thing people with low vision cannot read, and it read as cheap.
        assert "backdrop-filter" not in html, page

    css = (ROOT / "web" / "connect" / "atlas.css").read_text(encoding="utf-8")
    assert "prefers-reduced-motion" in css
    assert "prefers-contrast" in css
    # Dark is the brand, but the system preference still decides.
    assert "prefers-color-scheme: dark" in css
    assert ":root[data-theme='light']" in css
    # The single most fragile rule in the file: without !important every screen
    # renders at once, stacked on top of each other.
    assert "display: none !important" in css


def test_shared_layer_ships_its_own_font() -> None:
    # telegram.org is unreachable for our audience without a VPN, and so is any
    # font CDN on a bad day. A page that has to wait on one is a blank page.
    css = (ROOT / "web" / "connect" / "atlas.css").read_text(encoding="utf-8")
    assert "fonts.googleapis.com" not in css
    assert "fonts.gstatic.com" not in css
    assert "url('fonts/onest-cyrillic.woff2')" in css
    for name in ("onest-cyrillic", "onest-latin", "onest-latin-ext"):
        weight = (ROOT / "web" / "connect" / "fonts" / f"{name}.woff2")
        assert weight.exists(), name
        assert weight.read_bytes()[:4] == b"wOF2", name


def test_portal_never_blocks_on_telegram_org() -> None:
    # The portal used to load the SDK with a plain synchronous <script src>.
    # For a Russian user without a VPN telegram.org never answers, so the
    # personal cabinet stayed blank until the connection timed out — for exactly
    # the people it exists for.
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert '<script src="https://telegram.org' not in html
    assert "sdk.async=true" in html
    assert "window.TelegramWebviewProxy" in html


def test_connect_page_mirrors_the_server_filename_rule() -> None:
    # The tunnel name in the QR caption, the browser download and the Telegram
    # download must be one name. The client used to keep the full server id and
    # slice to 15, so "netherlands" + device 2 told the user FVPN-netherland
    # while the file arrived as FVPN-nether-D2.
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert 'replace(/[^A-Za-z0-9_=+.-]/g,"")' in html
    assert ".slice(0,6)" in html
    assert 'name.slice(0,15)' in html
    server = (ROOT / "src" / "vpn_wizard" / "server.py").read_text(encoding="utf-8")
    assert 'r"[^A-Za-z0-9_=+.-]"' in server
    assert "[:6]" in server


def test_connect_page_does_not_claim_the_link_is_missing_while_checking() -> None:
    # "Персональную ссылку пришлёт тот, кто пригласил" is false for someone who
    # is holding the link — it was shown to everyone until /access answered.
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert 'id="checking-access"' in html
    assert '$("nolink").hidden=true;$("checking-access").hidden=false;' in html
    # ...and the paste box must survive an access failure: it is the only way
    # back for someone with a stale link who cannot reach Telegram.
    assert '$("nolink").hidden=false;box.hidden=false;' in html


def test_connect_page_shows_one_platform_at_a_time() -> None:
    # Without these rules every platform's instructions render at once and the
    # install step becomes a stack of near-identical buttons.
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert ".platform{display:none}" in html
    assert ".platform.on{display:block}" in html


def test_static_routes_keep_old_buttons_on_portal_and_preserve_wizard() -> None:
    source = (ROOT / "src" / "vpn_wizard" / "server.py").read_text(encoding="utf-8")
    assert 'PORTAL_ENTRY_URL = "/portal/"' in source
    assert '@app.get("/miniapp/", include_in_schema=False)' in source
    assert '"Cache-Control": "no-store, max-age=0"' in source
    assert '@app.get("/portal/", include_in_schema=False)' in source
    assert '@app.get("/wizard/", include_in_schema=False)' in source
    assert 'app.mount("/portal", StaticFiles(directory=str(connect_dir)' in source
    assert 'app.mount("/miniapp", StaticFiles(directory=str(connect_dir)' in source
    assert 'app.mount("/wizard", StaticFiles(directory=str(miniapp_dir)' in source


def test_awg_page_supports_private_family_links_without_telegram() -> None:
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert '<meta name="referrer" content="no-referrer">' in html
    assert '<link rel="icon" href="data:,">' in html
    assert 'id="personal-access"' in html
    assert 'id="family-access"' in html
    assert '"/api/awg/family/"' in html
    assert "Ни Telegram, ни регистрация не нужны" in html
    assert "amnezia-vpn/amneziawg-android/releases/download/2.0.1" in html
    assert "(или AmneziaVPN)" not in html
    # The platform switch is the segmented control itself; a second, visually
    # hidden set of radios only duplicated it in the focus order.
    assert 'data-plat="win"' in html
    assert 'data-plat="mac"' in html
    assert "amneziawg-windows-client/releases/latest" in html
    assert "amnezia-client/releases/latest" in html
    assert 'id="device-picker"' in html
    assert '"/access?token="' in html
    assert "У каждого устройства — свой ключ" in html


def test_bedolaga_exposes_family_link_with_the_api_token_namespace() -> None:
    handler = (
        ROOT
        / "deploy"
        / "bedolaga"
        / "overrides"
        / "app"
        / "handlers"
        / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    # The family token carries an epoch the API bumps on revoke, so the bot must
    # ask for the link instead of signing one against a stale epoch.
    assert "f'family:{int(telegram_id)}'" not in handler
    assert "/family-link" in handler
    assert "callback_data='fodders_awg_family'" in handler
    assert "Command('family', 'share')" in handler
    assert "Command('miniapp', 'portal')" in handler
    assert "Command('wizard', 'vpn1')" in handler
    assert "web_app=types.WebAppInfo(url=_portal_url())" in handler
    assert "web_app=types.WebAppInfo(url=_miniapp_url())" in handler


def test_bedolaga_configures_telegram_menu_button_for_the_portal() -> None:
    script = (
        ROOT
        / "deploy"
        / "bedolaga"
        / "overrides"
        / "scripts"
        / "configure_fodders_vpn1_menu.py"
    ).read_text(encoding="utf-8")
    assert "set_chat_menu_button" in script
    assert "WebAppInfo(url=portal_url)" in script
    assert "action': portal_url" in script
    assert "FODDERS_VPN1_MINIAPP_URL" in script
    assert "/portal/" in script


def test_connect_page_survives_the_telegram_webview() -> None:
    # Telegram's WebView ignores <a download> and target="_blank": the tap does
    # nothing at all, with no file and no error for the user.
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert "telegram-web-app.js" in html
    # ...but this is the page for people who CANNOT reach Telegram, so it must
    # never block on telegram.org. Load the SDK only inside Telegram, and async.
    assert '<script src="https://telegram.org' not in html
    assert "sdk.async=true" in html
    assert "window.TelegramWebviewProxy" in html
    assert "tg.downloadFile" in html
    assert "tg.openLink" in html
    assert "tg.openTelegramLink" in html
    # Only a real Mini App launch may hijack the click; a plain browser must keep
    # its native download.
    assert "if(!inTelegram)return;" in html


def test_portal_hands_external_links_to_telegram() -> None:
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "tg.openTelegramLink" in html
    assert "tg.openLink" in html


def test_portal_exposes_device_control() -> None:
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert 'id="devices-card"' in html
    assert 'id="devices-list"' in html
    assert "/devices" in html
    assert "/revoke" in html
    assert "/label" in html
    # Revoking is destructive and irreversible for whoever holds that config, so
    # it goes through an explicit confirm. window.confirm was replaced because it
    # cannot say which access dies, and Telegram's WebView renders it as a bare
    # system box with the origin in the title.
    assert "Atlas.confirmDanger" in html
    assert 'confirmLabel:"Отключить"' in html
    # Slot 2 is the family slot: the same key backs the family link, so revoking
    # it silently kills the relative's access too.
    assert "Семейная ссылка тоже перестанет работать." in html
    # A partially revoked key is still live somewhere; never report success.
    assert "могла остаться" in html


def test_bot_exposes_device_control() -> None:
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "Command('devices'" in handler
    assert "DEVICES_CALLBACK" in handler
    assert "DEVICE_REVOKE_CONFIRM_PREFIX" in handler
    # The confirm prefix extends the revoke prefix, so it must be registered first
    # or "are you sure?" would swallow the confirmation itself.
    assert handler.index("register(apply_device_revoke") < handler.index("register(confirm_device_revoke")
    assert "ForceReply" in handler


def test_config_caption_warns_about_the_android_recents_trap() -> None:
    # Android's "Recent files" view can surface the document without its .conf
    # name (shown as a BIN file), and AmneziaWG then refuses to open it. Observed
    # on a Huawei tablet; opening from Downloads works.
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "Загрузки" in handler
    assert "Недавние" in handler


def test_invite_link_is_personal_not_shared() -> None:
    # A single shared link credits nobody: the inviter gets no referral reward
    # and cannot grow their balance from people they bring in.
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "start=friends" not in html
    assert "links.referral_url" in html
    server = (ROOT / "src" / "vpn_wizard" / "server.py").read_text(encoding="utf-8")
    assert "referral_url" in server
    assert "BotApiClient" in server


def test_device_summary_does_not_count_suspended_as_occupied() -> None:
    # Suspended keys are retained, not in use; counting them produced "2 из 1".
    html = (ROOT / "web" / "connect" / "index.html").read_text(encoding="utf-8")
    assert "(d.servers||[]).length>0" in html
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "d.get('servers')" in handler


def test_connect_page_offers_operator_presets() -> None:
    # If the operator's DPI drops the default junk profile the tunnel simply never
    # comes up, with no error anywhere. The preset picker is the user's only lever.
    html = (ROOT / "web" / "connect" / "awg.html").read_text(encoding="utf-8")
    assert 'id="preset-box"' in html
    assert 'id="preset-buttons"' in html
    assert "d.presets" in html
    assert 'searchParams.set("preset"' in html
    # "default" is the plain profile and must not be sent as an override.
    assert 'u.preset!=="default"' in html


def test_bot_can_mint_an_invite() -> None:
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "Command('invite'" in handler
    assert "INVITE_CALLBACK" in handler
    assert "/invites" in handler


def test_metrics_dashboard_is_owner_scoped_and_private() -> None:
    html = (ROOT / "web" / "connect" / "stats.html").read_text(encoding="utf-8")
    assert "/api/metrics" in html
    # It reads a signed owner link; it must never be indexable or cached.
    assert 'name="robots" content="noindex, nofollow"' in html
    assert 'name="referrer" content="no-referrer"' in html
    # We sell privacy: the dashboard must state that no per-user tracking exists.
    assert "Ни кликов, ни маршрутов конкретных людей" in html


def test_bot_actions_are_discoverable_without_typing_commands() -> None:
    # A WebApp menu button replaces Telegram's "/" command list, so the commands
    # were invisible: the chat showed only "Open" and nothing explained the rest.
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "ReplyKeyboardMarkup" in handler
    assert "is_persistent=True" in handler
    for button in ("BTN_CONNECT", "BTN_DEVICES", "BTN_INVITE", "BTN_HELP"):
        assert button in handler
    # Exact-text filters only: a loose one would swallow promocodes and support
    # messages, which reach Bedolaga's handlers after ours.
    assert "F.text == BTN_CONNECT" in handler


def test_stars_screen_offers_a_way_out_when_stars_run_short() -> None:
    # Telegram's own "top up and pay" flow, offered when the buyer is short of
    # Stars, dies with PROVIDER_ACCOUNT_INVALID — on two accounts, on desktop
    # and Android, with both an invoice link and a native sendInvoice. Our bot
    # is not a party to that step: pre_checkout_query never arrives.
    #
    # Buying Stars unattached to any bot does work, and tg://stars_topup opens
    # exactly that, so the screen offers it rather than leaving a dead end.
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "balance" / "stars.py"
    ).read_text(encoding="utf-8")
    assert "tg://stars_topup?balance=" in handler
    # balance is the TOTAL desired balance, not the shortfall, per
    # https://core.telegram.org/api/links#stars-topup-links
    assert "url=f'tg://stars_topup?balance={stars_amount}'" in handler
    # The pay button must stay first, and the payload must stay parseable by
    # the pre-checkout validator. Compare inside the keyboard, not the file:
    # the docstring mentions the link before the code does.
    # Top-up goes FIRST: most people have no Stars at all, so paying straight
    # away ends in a cryptic English error for them, while someone who already
    # has enough is simply told so by Telegram. Safe either way; paying is not.
    keyboard = handler[handler.index("inline_keyboard=["):]
    assert keyboard.index("stars_topup") < keyboard.index("Оплатить")
    assert "payload=f'balance_{db_user.id}_{amount_kopeks}'" in handler


def test_bot_reports_the_real_reason_a_family_link_is_refused() -> None:
    # The API answers 403 with "Семейная ссылка доступна на тарифах от 3
    # устройств." The bot used to swallow that and print "Семейный доступ пока
    # не настроен. Напишите в техподдержку." — turning an ordinary plan limit
    # into an apparent outage, and sending the owner support tickets for it.
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "class FamilyUnavailable" in handler
    assert "raise FamilyUnavailable(detail)" in handler
    assert "unavailable.detail" in handler


def test_start_payload_decides_what_the_bot_answers() -> None:
    # Every portal link into the bot carries a payload, so the bot can answer the
    # question the person actually arrived with instead of a generic greeting.
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")
    assert "START_TOPICS" in handler
    for topic in ("'plan'", "'help'", "'portal'"):
        assert topic in handler
    # Money has to be one tap away once someone asks for it: this is Bedolaga's
    # own subscription screen, not a re-implementation of checkout.
    assert "callback_data='menu_subscription'" in handler


def test_every_command_is_listed_in_the_telegram_menu() -> None:
    import re

    script = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "scripts" / "configure_fodders_vpn1_menu.py"
    ).read_text(encoding="utf-8")
    handler = (
        ROOT / "deploy" / "bedolaga" / "overrides" / "app" / "handlers" / "fodders_vpn1.py"
    ).read_text(encoding="utf-8")

    registered: set[str] = set()
    for match in re.findall(r"Command\(([^)]*)\)", handler):
        registered.update(re.findall(r"'([a-z0-9_]+)'", match))
    listed = set(re.findall(r"descriptions\['([a-z0-9_]+)'\]", script)) | {"start", "help"}

    # Aliases need not be advertised, but every primary verb must be reachable
    # both as a handler and from the menu, or people cannot find it at all.
    for primary in ("awg", "devices", "invite", "family", "menu"):
        assert primary in registered, f"/{primary} has no handler"
        assert primary in listed, f"/{primary} is missing from the Telegram menu"
