#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
#  migrate.sh — Safe SQLite schema migration (no data loss)
#
#  Usage:
#    ./migrate.sh                          # auto-detects DB path
#    ./migrate.sh /app/db/hrpayroll.db    # explicit path
#
#  How it works:
#    - Always backs up the DB before touching it
#    - Uses ADD COLUMN (safe, non-destructive)
#    - For breaking changes (rename/remove column) uses the recreate pattern
#    - Tracks applied migrations in a _migrations table
# ─────────────────────────────────────────────────────────────────────────────

DB="${1:-/app/db/hrpayroll.db}"
BACKUP_DIR="${BACKUP_DIR:-/app/db/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ ! -f "$DB" ]; then
    echo "ERROR: Database not found at $DB"
    exit 1
fi

# ── Backup before any migration ──────────────────────────────────────────────
mkdir -p "$BACKUP_DIR"
BACKUP="$BACKUP_DIR/hrpayroll_pre_migrate_$TIMESTAMP.db"
cp "$DB" "$BACKUP"
echo "✓ Backup saved: $BACKUP"

# ── Ensure migrations tracking table exists ──────────────────────────────────
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS _migrations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL UNIQUE,
    applied_at TEXT   NOT NULL DEFAULT (datetime('now'))
);"

run_migration() {
    local name="$1"
    local sql="$2"

    # Skip if already applied
    ALREADY=$(sqlite3 "$DB" "SELECT count(*) FROM _migrations WHERE name='$name';")
    if [ "$ALREADY" -eq "1" ]; then
        echo "  skip  $name (already applied)"
        return
    fi

    echo "  apply $name ..."
    sqlite3 "$DB" "$sql" && \
    sqlite3 "$DB" "INSERT INTO _migrations (name) VALUES ('$name');" && \
    echo "  ✓     $name done" || \
    { echo "  ✗     $name FAILED — restoring backup"; cp "$BACKUP" "$DB"; exit 1; }
}

# ─────────────────────────────────────────────────────────────────────────────
#  DEFINE YOUR MIGRATIONS BELOW
#  Rules:
#   1. Never delete old migrations — only add new ones at the bottom
#   2. Never modify an already-applied migration — add a new one instead
#   3. For ADD COLUMN: just use ALTER TABLE
#   4. For RENAME/DROP column: use the recreate pattern (example below)
# ─────────────────────────────────────────────────────────────────────────────

echo "Running migrations on: $DB"
echo ""

# ── Example: Add a new column safely ─────────────────────────────────────────
# run_migration "0001_add_employee_notes" "
#     ALTER TABLE employees ADD COLUMN notes TEXT DEFAULT '';
# "

# ── Example: Add an index ─────────────────────────────────────────────────────
# run_migration "0002_index_employee_dept" "
#     CREATE INDEX IF NOT EXISTS idx_employees_department ON employees(department);
# "

# ── Example: Rename a column (recreate pattern) ───────────────────────────────
# This is the ONLY safe way to rename/drop columns in SQLite
# run_migration "0003_rename_salary_to_base_salary" "
#     BEGIN TRANSACTION;
#     CREATE TABLE employees_new AS SELECT
#         id, name, department,
#         salary AS base_salary,       -- rename here
#         created_at
#     FROM employees;
#     DROP TABLE employees;
#     ALTER TABLE employees_new RENAME TO employees;
#     COMMIT;
# "

# ── Example: Add a new table ──────────────────────────────────────────────────
# run_migration "0004_create_departments_table" "
#     CREATE TABLE IF NOT EXISTS departments (
#         id   INTEGER PRIMARY KEY AUTOINCREMENT,
#         name TEXT NOT NULL UNIQUE
#     );
# "

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "All migrations complete."
echo "Applied migrations:"
sqlite3 "$DB" "SELECT name, applied_at FROM _migrations ORDER BY id;"