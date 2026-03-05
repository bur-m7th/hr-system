# HR Payroll System — Docker Setup

## Quick Start (Portainer)

1. Push your image to a registry (GitHub Container Registry, Docker Hub, etc.)
2. In Portainer → **Stacks** → **Add Stack** → **Upload**
3. Upload `docker-compose.yml`
4. Set environment variable `APP_PORT` to your desired port (default: `8080`)
5. Deploy

---

## Changing the Port

You never need to edit the compose file. Just set `APP_PORT` in Portainer's
environment variables section before deploying:

| Variable   | Default | Example |
|------------|---------|---------|
| `APP_PORT` | `8080`  | `9090`  |

The port change propagates to both the container internal port and the host mapping automatically.

---

## Volumes (Your Data Lives Here)

| Volume          | What's inside                          |
|-----------------|----------------------------------------|
| `hr_db`         | `hrpayroll.db`, `.encryption_key`, `audit.log`, backups |
| `hr_files`      | Employee uploaded documents and photos |
| `hr_generated`  | Generated payslip `.docx` files        |
| `hr_templates`  | Payslip Word templates                 |

**These volumes are never deleted when you update or restart the container.**

---

## Updating Without Losing Data

```sh
# Simple update (just restart with new image)
./update.sh

# Update + run DB migrations
./update.sh --migrate
```

Or directly in Portainer: pull the new image, then redeploy the stack.
The volumes are attached independently — they survive container recreation.

---

## Schema Migrations (Changing DB Structure)

Edit `migrate.sh` and add your migration at the bottom:

```sh
# Adding a new column safely
run_migration "0001_add_employee_notes" "
    ALTER TABLE employees ADD COLUMN notes TEXT DEFAULT '';
"

# Renaming a column (recreate pattern — SQLite doesn't support RENAME COLUMN in older versions)
run_migration "0002_rename_salary" "
    BEGIN TRANSACTION;
    CREATE TABLE employees_new AS SELECT
        id, name, department,
        salary AS base_salary
    FROM employees;
    DROP TABLE employees;
    ALTER TABLE employees_new RENAME TO employees;
    COMMIT;
"
```

**Rules:**
- Never delete or edit existing migrations — only add new ones at the bottom
- Every migration runs exactly once (tracked in `_migrations` table)
- A backup is always made before migrations run
- If a migration fails, the backup is auto-restored

Run migrations:
```sh
# Inside the running container
docker exec hr-payroll sh /app/migrate.sh

# Or via update script
./update.sh --migrate
```

---

## Exporting Data to Excel

Run from inside the container or copy the script to your host.

```sh
# Export everything (all tables, one file)
docker exec hr-payroll python3 /app/scripts/export.py --all

# Export one employee (by name or ID)
docker exec hr-payroll python3 /app/scripts/export.py --employee "محمود"
docker exec hr-payroll python3 /app/scripts/export.py --employee 42

# Export a specific month
docker exec hr-payroll python3 /app/scripts/export.py --month 2026-02

# Export a department
docker exec hr-payroll python3 /app/scripts/export.py --department "Engineering"

# Export a department for a specific month
docker exec hr-payroll python3 /app/scripts/export.py --month 2026-02 --department "Engineering"
```

Exported files are saved to `/app/generated/exports/` inside the container,
which maps to the `hr_generated` volume on your host.

To copy an export out:
```sh
docker cp hr-payroll:/app/generated/exports/payroll_2026-02_20260301_120000.xlsx ./
```

---

## Building the Image

```sh
# Build locally
docker build -t hr-payroll-system:latest .

# Or build and push to GitHub Container Registry
docker build -t ghcr.io/bur-m7th/hr-system:latest .
docker push ghcr.io/bur-m7th/hr-system:latest
```

Then update the `image:` line in `docker-compose.yml` to match.

---

## First-Time Setup (Existing Data)

If you have an existing database you want to move into Docker:

```sh
# 1. Create the volume
docker volume create hr-system_hr_db

# 2. Copy your existing DB into the volume
docker run --rm \
  -v hr-system_hr_db:/app/db \
  -v $(pwd)/db:/source \
  alpine sh -c "cp /source/hrpayroll.db /app/db/ && cp /source/.encryption_key /app/db/"

# 3. Deploy normally via Portainer
```