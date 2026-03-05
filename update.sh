#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
#  update.sh — Pull latest image and restart the container safely
#
#  Usage (run on your server/TrueNAS host):
#    ./update.sh
#    ./update.sh --migrate     # also run DB migrations after update
# ─────────────────────────────────────────────────────────────────────────────

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
RUN_MIGRATE=0

for arg in "$@"; do
    [ "$arg" = "--migrate" ] && RUN_MIGRATE=1
done

echo "══════════════════════════════════════════"
echo " HR Payroll System — Update"
echo "══════════════════════════════════════════"

# 1. Pull latest image
echo ""
echo "▶ Pulling latest image..."
docker compose -f "$COMPOSE_FILE" pull

# 2. Backup DB before anything changes
echo ""
echo "▶ Backing up database..."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
docker compose -f "$COMPOSE_FILE" exec hr-system \
    sh -c "mkdir -p /app/db/backups && cp /app/db/hrpayroll.db /app/db/backups/hrpayroll_pre_update_$TIMESTAMP.db" \
    2>/dev/null || echo "  (container not running, skipping live backup)"

# 3. Run migrations if requested
if [ "$RUN_MIGRATE" -eq 1 ]; then
    echo ""
    echo "▶ Running migrations on live DB..."
    docker compose -f "$COMPOSE_FILE" exec hr-system sh /app/migrate.sh
fi

# 4. Recreate container with new image (volumes are untouched)
echo ""
echo "▶ Restarting container with new image..."
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans

echo ""
echo "✓ Update complete. Volumes (DB, files, templates) were not touched."
echo "  Backups are in the hr_db volume at /app/db/backups/"