#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
old_env=/etc/vpn-wizard.env
bedolaga_dir=/opt/bedolaga
bedolaga_env="$bedolaga_dir/.env"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
rollback_dir="/root/fodder-bot-cutover-$stamp"
install -d -m 700 "$rollback_dir"
cp -a "$old_env" "$rollback_dir/vpn-wizard.env"
cp -a "$bedolaga_env" "$rollback_dir/bedolaga.env"

rollback_required=1
rollback() {
    exit_code=$?
    if (( rollback_required )); then
        echo "cutover=failed rollback=starting" >&2
        (
            cd "$bedolaga_dir"
            docker compose stop bot >/dev/null 2>&1 || true
        )
        cp -a "$rollback_dir/vpn-wizard.env" "$old_env"
        cp -a "$rollback_dir/bedolaga.env" "$bedolaga_env"
        systemctl restart vpn-wizard
        echo "rollback=complete" >&2
    fi
    exit "$exit_code"
}
trap rollback ERR

old_token=$(grep -m1 '^VPNW_BOT_TOKEN=' "$old_env" | cut -d= -f2-)
new_token=$(grep -m1 '^BOT_TOKEN=' "$bedolaga_env" | cut -d= -f2-)
[[ -n "$old_token" && "$old_token" == "$new_token" ]]

identity=$(curl -fsS "https://api.telegram.org/bot${old_token}/getMe")
grep -q '"ok":true' <<<"$identity"

# The existing admin target is a private chat, so Telegram topic IDs from the
# upstream example configuration must be disabled. Otherwise startup and error
# notifications fail with "message thread not found".
for key in \
    ADMIN_NOTIFICATIONS_TOPIC_ID \
    ADMIN_NOTIFICATIONS_TICKET_TOPIC_ID \
    ADMIN_NOTIFICATIONS_NALOG_TOPIC_ID \
    SUSPICIOUS_NOTIFICATIONS_TOPIC_ID \
    BACKUP_SEND_TOPIC_ID; do
    sed -i "/^${key}=/d" "$bedolaga_env"
    printf '%s=0\n' "$key" >> "$bedolaga_env"
done

# Stop the only current poller before enabling the replacement.
systemctl stop vpn-wizard
sed -i '/^VPNW_BOT_TOKEN=/d' "$old_env"
sed -i '/^VPNW_TELEGRAM_AUTH_TOKEN=/d' "$old_env"
printf '\nVPNW_BOT_TOKEN=\nVPNW_TELEGRAM_AUTH_TOKEN=%s\n' "$old_token" >> "$old_env"
chmod 600 "$old_env"
systemctl start vpn-wizard

api_ready=0
for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8080/health >/dev/null; then
        api_ready=1
        break
    fi
    sleep 1
done
(( api_ready == 1 ))

cd "$bedolaga_dir"
docker compose up -d bot

bot_ready=0
for _ in $(seq 1 90); do
    state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' remnawave_bot)
    if [[ "$state" == healthy ]]; then
        bot_ready=1
        break
    fi
    if [[ "$state" == unhealthy || "$state" == exited || "$state" == dead ]]; then
        docker logs --tail 160 remnawave_bot >&2 || true
        false
    fi
    sleep 2
done
(( bot_ready == 1 ))

if docker logs --since "$stamp" remnawave_bot 2>&1 | grep -qiE 'Conflict: terminated by other getUpdates|TelegramConflictError'; then
    docker logs --tail 160 remnawave_bot >&2
    false
fi

# The legacy process must retain its API but no longer contain the token.
legacy_pid=$(systemctl show vpn-wizard -p MainPID --value)
[[ "$legacy_pid" =~ ^[1-9][0-9]*$ ]]
if tr '\0' '\n' <"/proc/$legacy_pid/environ" | grep -q '^VPNW_BOT_TOKEN=..'; then
    false
fi

rollback_required=0
trap - ERR

username=$(sed -n 's/.*"username":"\([^"]*\)".*/\1/p' <<<"$identity")
printf 'cutover=success\nbot=@%s\nlegacy_api=healthy\nbedolaga=healthy\nrollback_snapshot=%s\n' \
    "$username" \
    "$rollback_dir"
