#!/bin/sh
# docker/entrypoint.sh — CertiVault container start-up.
#   1. Listen on ${PORT} (Render sets PORT, default 10000); 80 otherwise,
#      so docker-compose ("8080:80") keeps working unchanged.
#   2. Run scripts/render_boot.php (schema import / safe migrations,
#      CV_SUPER_ADMIN_* bootstrap, CV_FILE_STORE=db restore). It never
#      fails the container; Apache starts even if the database is down.
#   3. Hand over to the image's normal command (apache2-foreground).
# Keep this file LF-only (.gitattributes: *.sh text eol=lf).
set -eu

APP_PORT="${PORT:-80}"
case "$APP_PORT" in
  ''|*[!0-9]*) echo "[entrypoint] invalid PORT '$APP_PORT', using 80" >&2; APP_PORT=80 ;;
esac

# Idempotent: also correct after a container restart with a different PORT.
sed -ri "s/^Listen [0-9]+$/Listen ${APP_PORT}/" /etc/apache2/ports.conf
sed -ri "s/<VirtualHost \*:[0-9]+>/<VirtualHost *:${APP_PORT}>/" /etc/apache2/sites-available/000-default.conf
echo "[entrypoint] Apache will listen on port ${APP_PORT}" >&2

cd /var/www/html

# Runtime directories must exist and be writable by Apache (www-data),
# including after a fresh start on an ephemeral filesystem.
mkdir -p private_data/uploads private_data/mail private_data/pins private_data/tlog \
         private_data/external_credentials public/qrcodes public/checkpoints

php scripts/render_boot.php || echo "[entrypoint] render_boot.php exited with an error; starting Apache anyway" >&2

# The boot script runs as root: hand everything it may have created
# (restored files, logs, lock files) to the web server user.
chown -R www-data:www-data private_data public/qrcodes public/checkpoints src/utils/phpqrcode/cache 2>/dev/null || true

exec "$@"
