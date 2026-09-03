# `sql/` — Database Schema & Seed Data

SQL scripts that create and bootstrap the MediShield database (MySQL / MariaDB —
the engine XAMPP bundles).

| File | Purpose |
|------|---------|
| `schema.sql` | Creates all tables for the full system (spec §10), including the monotonic `users.auth_version` epoch and v2 forensic audit/head schema. Uses `CREATE TABLE IF NOT EXISTS`, so it is safe to re-run. |
| `seed.sql` | Production-safe seed entry point. It deliberately contains no user or deterministic credential. |
| `migrations/` | Idempotent incremental changes (`ALTER TABLE ...`) that bring an **existing** database up to date — because `CREATE TABLE IF NOT EXISTS` leaves an already-created table untouched. `setup-db.ps1` applies these after `schema.sql`. See `migrations/README.md`. |

## Loading
The easy way (creates the DB, loads both files, copies config):
```powershell
scripts\setup-db.ps1
```

Manually:
```powershell
mysql -u root -e "CREATE DATABASE IF NOT EXISTS medishield_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root medishield_db < sql\schema.sql
mysql -u root medishield_db < sql\seed.sql
```

## Initial administrator

Normal and fresh setup creates no administrator. After `scripts\setup-db.ps1`,
use the guarded CLI flow documented in the root README:

```powershell
php scripts\provision-initial-admin.php `
  --name="Initial Administrator" `
  --email="administrator@example.com" `
  --confirm-database=medishield_db `
  --confirm-initial-admin
```

This stores an inactive account with no usable password and sends an expiring
single-use activation link. Existing administrator rows are never replaced,
reset, or deleted. Deterministic credentials exist only in
`scripts\seed-ui-test-users.php`, whose disposable-database allowlist excludes
the normal application database.

## Notes
- Timestamps are stored in UTC. `audit_logs` is append-only to the web identity
  (`SELECT`, `INSERT`); `audit_chain_head` is separately limited to `SELECT`,
  `UPDATE`. Setup verifies exact metadata and empirical forbidden mutations.
- `users.auth_version` starts at 1 and only increases. Password, account-status,
  and role mutations advance it while invalidating unused OTPs in the same
  transaction, so stale pending or authenticated sessions cannot be revived.
- `audit_logs.attempted_identifier` stores the email typed on a failed login (so an
  admin can follow up on possibly-leaked credentials, even for unknown accounts).
  It is **PII held outside the HMAC hash chain** and is scrubbed after the retention
  window by `scripts/purge-audit-pii.php` — the one privileged, audited exception to
  the append-only rule (it nulls only this column, never deletes rows, and the
  scrub does not break the keyed chain).
- Existing rows are retained as format v1. Migration assigns sequence and key
  metadata in `log_id` order, then the initializer verifies v1 hashes before
  committing a keyed head. New rows are canonical format v2.
