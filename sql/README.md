# `sql/` — Database Schema & Seed Data

SQL scripts that create and bootstrap the MediShield database (MySQL / MariaDB —
the engine XAMPP bundles).

| File | Purpose |
|------|---------|
| `schema.sql` | Creates all tables for the full system (spec §10): `users`, `patients`, `patient_assignments`, `vitals`, `medical_records`, `lab_requests`, `lab_results`, `prescriptions`, `dispensing_records`, `audit_logs`. Uses `CREATE TABLE IF NOT EXISTS`, so it is safe to re-run. |
| `seed.sql` | Inserts the bootstrap **superadmin** account (`INSERT IGNORE`, safe to re-run). |

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

## Default superadmin
- **Email:** `superadmin@medishield.local`
- **Password:** `ChangeMe!2026`  (you are forced to change it on first login)

This account is used to register all other users. Re-generate the hash in
`seed.sql` for any non-demo deployment.

## Notes
- Only `users` is exercised by Deliverable 1; the other tables are created now so
  later modules slot in without migrations.
- Timestamps are stored in UTC. `audit_logs` is designed to be append-only — in a
  hardened deployment the application DB user is granted only `SELECT, INSERT` on it.
