# sql/migrations — incremental schema changes for existing databases

`sql/schema.sql` is the **authoritative, full schema** for a *fresh* install
(every `CREATE TABLE` uses `IF NOT EXISTS`). But a database that was created
before a new column existed will not pick that column up just by re-running
`schema.sql`. That is what the files in this folder are for.

## What lives here

One `*.sql` file per incremental change, named `YYYY-MM-DD_short_description.sql`.
Each file must be **idempotent** (safe to run more than once) — typically by using
MariaDB's `ADD COLUMN IF NOT EXISTS` / `DROP COLUMN IF EXISTS`, or an
`INSERT ... ON DUPLICATE KEY UPDATE`.

## How they are applied

`scripts/setup-db.ps1` runs every file in this directory (sorted by name, which
the date prefix keeps chronological) **after** loading `schema.sql` and
`seed.sql`. Because the migrations are idempotent:

- **Fresh install** → `schema.sql` already created the column, the migration is a
  harmless no-op.
- **Existing database** → `schema.sql` left the old table untouched, the migration
  adds the missing column.

To apply manually:

```powershell
Get-Content sql\migrations\2026-06-29_add_attempted_identifier.sql -Raw |
    C:\xampp\mysql\bin\mysql.exe --host=127.0.0.1 --user=root medishield_db
```

## Current migrations

| File | Purpose |
| --- | --- |
| `2026-06-29_add_attempted_identifier.sql` | Adds `audit_logs.attempted_identifier` (the email typed on a failed login). It is **not** part of the HMAC hash chain so it can be scrubbed after the retention window — see `scripts/purge-audit-pii.php`. |

## MySQL 8 note

`ADD COLUMN IF NOT EXISTS` is a MariaDB extension. MediShield targets the MariaDB
that ships with XAMPP. If you run against MySQL 8, remove the `IF NOT EXISTS`
clause and apply the migration exactly once.
