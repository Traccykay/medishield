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
| `2026-06-30_add_otp_codes.sql` | Adds the `otp_codes` table for the login second factor (2FA). Stores only a bcrypt hash of each short-lived one-time passcode. |
| `2026-06-30_add_account_activations.sql` | Adds the `account_activations` table for email activation links. Stores only a SHA-256 hash of each token. |
| `2026-07-19_add_reception_visit_workflow.sql` | Adds the receptionist role and administrative visit queue used to route arrivals through triage, consultation, lab, and pharmacy. |
| `2026-07-19_encrypt_vitals.sql` | Adds encrypted staging columns for legacy vital signs and symptoms. `scripts/setup-db.ps1` then runs `scripts/migrate-vitals-encryption.php`, which uses the configured AES-256-GCM key to encrypt every existing row before dropping every plaintext source column. This two-step mapping is explicit because SQL cannot safely generate the project `Crypto` format. It is safe to rerun: existing ciphertext is retained and a completed migration has no legacy columns left to process. |

## MySQL 8 note

`ADD COLUMN IF NOT EXISTS` is a MariaDB extension. MediShield targets the MariaDB
that ships with XAMPP. If you run against MySQL 8, remove the `IF NOT EXISTS`
clause and apply the migration exactly once.
