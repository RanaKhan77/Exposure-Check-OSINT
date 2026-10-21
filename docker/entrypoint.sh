#!/usr/bin/env bash
# =============================================================================
# Exposure-Check-OSINT container entrypoint
#
# Design (security review 2026-10-21 hardened):
#  - .env PERSISTS in the storage volume (storage/app/env/.env) so a container
#    rebuild keeps the same APP_KEY + admin password (no silent re-keying).
#  - ADMIN_PASSWORD replaces its placeholder line (never appends - phpdotenv
#    is first-wins, appending after an empty placeholder bricks login).
#  - The generated password is printed ONCE (first boot only).
#  - Laravel scheduler runs in the background (license heartbeat/re-validation).
#  - No config:cache (own-use app; keeps env()/storage fallbacks simple and
#    honest - see AuthController reading config('app.admin_password')).
# =============================================================================
set -e

cd /var/www/html
PERSIST_DIR="storage/app/env"

# 1. Persistent .env (survives container recreation via the storage volume)
mkdir -p "$PERSIST_DIR"
if [ ! -f .env ]; then
    if [ -f "$PERSIST_DIR/.env" ]; then
        cp "$PERSIST_DIR/.env" .env
        echo "(restored .env from persistent volume)"
    else
        cp .env.example .env
    fi
fi

# 2. App key (only when missing - persists via the volume copy)
if ! grep -q '^APP_KEY=base64:' .env; then
    php artisan key:generate --force
fi

# 3. Admin password: .env wins; otherwise generate ONCE and persist it
if ! grep -q '^ADMIN_PASSWORD=.\+' .env; then
    GENERATED="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
    sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${GENERATED}|" .env
    echo "=============================================================="
    echo " First boot: generated admin password: ${GENERATED}"
    echo " Sign in at http://<host>:<port>/login"
    echo "=============================================================="
fi

# 4. Keep the persistent copy in sync
cp .env "$PERSIST_DIR/.env"

# 5. Storage perms + sqlite (DB lives in the persistent storage volume)
mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views \
         storage/logs storage/app/maigret storage/app/env
touch storage/app/database.sqlite
chown -R www-data:www-data storage bootstrap/cache 2>/dev/null || true

# 6. Migrations (idempotent)
php artisan migrate --force || echo "(migration warning - check storage perms)"

# 7. Laravel scheduler in the background (license validate/heartbeat)
nohup php artisan schedule:work >/dev/null 2>&1 &

# 8. Apache in the foreground
exec apache2-foreground
