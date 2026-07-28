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
| `2026-07-20_add_visit_billing.sql` | Adds `billing_bills` and `billing_charges` for visit-linked cash and insurance payments. Each charge copies the chosen catalogue description and integer-KES price, preserving historical totals. |
| `2026-07-20_link_clinical_orders_to_visits.sql` | Links new diagnoses, lab orders, and prescriptions to their visit and stores the server-resolved catalog price. Legacy rows remain unlinked with a NULL visit/price because mapping them to a visit would be ambiguous; new application writes always supply both values. |
| `2026-07-20_add_prescription_refused_status.sql` | Adds the terminal `refused` prescription status. A pharmacy refusal remains auditable and returns the linked encounter to its assigned doctor rather than leaving it in the pharmacy queue. |
| `2026-07-24_add_request_throttles.sql` | Adds HMAC-scoped, fixed-window request budgets for login, OTP verification, and password-reset endpoints. The table contains no raw client IP addresses. |

## MySQL 8 note

`ADD COLUMN IF NOT EXISTS` is a MariaDB extension. MediShield targets the MariaDB
that ships with XAMPP. If you run against MySQL 8, remove the `IF NOT EXISTS`
clause and apply the migration exactly once.
