# `scripts/` — Environment & Database Setup

This folder contains the reproducible setup automation for MediShield. The goal is
that **any engineer or agent can go from a clean Windows machine to a working,
test-passing environment by running these scripts in order** — no manual php.ini
edits, no guesswork.

Run them from the repository root in this order:

| # | Script | Elevation | What it does |
|---|--------|-----------|--------------|
| 1 | `install-dependencies.ps1` | **Administrator** | Bootstraps every prerequisite with a check-then-install pattern: installs **Chocolatey** if missing, then XAMPP 8.1 + Composer (via Chocolatey) if missing, then calls `configure-php-ini.ps1`, then runs `composer install`. Safe to re-run — already-installed tools are detected and skipped. |
| 2 | `configure-php-ini.ps1` | not required | Configures the target PHP's `php.ini` to the canonical MediShield baseline (extensions + settings). Called automatically by script #1, but can be run standalone. |
| 3 | `configure-xampp-apache.ps1` | **Administrator** | Preserves XAMPP's default localhost site, configures `medishield.local` with `public/` as its separate document root, enables overrides and `mod_rewrite`, suppresses Apache version details, validates syntax, restarts Apache, and probes public/denied paths. |
| 4 | `setup-db.ps1` | not required | Creates the database, applies every migration, verifies/initializes the keyed audit head, provisions exact web/maintenance grants, runs empirical grant checks, and generates distinct encryption/audit/anchor/throttle keys. It creates no application user. Persistent config generation/upgrades are delegated to `setup-config.ps1`. |
| 5 | `provision-initial-admin.php` | not required | One-time, explicit initial-admin bootstrap. Creates an inactive admin and delivers an expiring single-use activation link without generating or printing a password. |

### Initial administrator

After normal database setup, provision the first administrator explicitly:

```powershell
php scripts\provision-initial-admin.php `
  --name="Initial Administrator" `
  --email="administrator@example.com" `
  --confirm-database=medishield_db `
  --confirm-initial-admin
```

The database confirmation must exactly match `config\config.php`. The command
is replay-safe: if any admin row already exists, it preserves that row and sends
nothing. A delivery failure rolls back the new pending user and activation
token. Production execution additionally requires the SMTP transport and an
HTTPS application base URL. Normal web bootstrap enforces that same boundary
even earlier: exact production mode also requires a valid sender identity and
complete SMTP host, port, TLS mode, username, password, and timeout before any
session or database operation. The command records `USER_CREATED` and
`ACTIVATION_SENT` only after the inactive account and activation delivery
succeed.

### Maintenance scripts (run on a schedule, not part of setup)

| Script | When | What it does |
|--------|------|--------------|
| `initialize-audit-chain.php` | called by `setup-db.ps1` | Verifies preserved v1 rows without rehashing them, assigns deterministic metadata, and creates/validates the keyed singleton head. |
| `anchor-audit-chain.php` | trusted scheduler after setup and periodically | Appends an idempotent, monotonic, separately keyed JSONL commitment to the current valid database head. |
| `verify-audit-grants.php` | called by `setup-db.ps1` | Verifies exact grant metadata, runs rolled-back allow/deny probes for both identities, and appends `AUDIT_GRANTS_VERIFIED` on success. |
| `purge-audit-pii.php` | cron / Task Scheduler (e.g. daily) | Strictly enforces the retention floor, verifies integrity before/after bounded idempotent batches, nulls only `attempted_identifier`, and appends PHI-free `AUDIT_PII_SCRUBBED` evidence. |
| `migrate-vitals-encryption.php` | called by `setup-db.ps1` | Encrypts legacy plaintext vitals during the controlled schema upgrade. `setup-db.ps1` passes its selected database explicitly; the helper accepts only the configured database or a named disposable UI database. |
| `seed-ui-test-users.php` | Playwright global setup | Seeds deterministic role and forced-password fixtures only in `medishield_ui_test` or `medishield_ui_account_test`. |
| `seed-ui-dashboard-data.php` | selected Playwright scenarios | Seeds workflow data only in the same two disposable databases. |

Every PHP file in this directory rejects non-CLI execution before loading
Composer or application configuration. The initial-admin provisioner also
requires explicit operation and database confirmations. Both UI seed scripts
and `setup-ui-test-db.ps1` use the same exact disposable-database allowlist;
they cannot target `medishield_db` or an arbitrary database name. The
setup-time vitals migration validates its explicit target through the same
boundary, accepting either the configured normal database or a named
disposable database and rejecting every mismatched arbitrary override.

`setup-db.ps1` separates its selected execution database from the database names
stored in the shared ignored config. A normal setup aligns
`audit_maintenance_db.name` with the selected normal database without changing
existing passwords or cryptographic keys. A disposable UI setup keeps the
existing web and maintenance names (or the sample's normal name on first
generation) and supplies the disposable name, setup user, and setup password to
each PHP helper through process-scoped environment overrides. It therefore never
persists `medishield_ui_test` or `medishield_ui_account_test` into shared config.

| `setup-ui-test-db.ps1` | before Playwright UI tests | Rebuilds the disposable `medishield_ui_test` database. Playwright calls this automatically and never modifies development data. |
| `run-ui-tests.ps1` | before submitting UI-affecting or security-sensitive changes | Checks required runtimes, installs pinned Playwright dependencies/Chromium when absent, then runs the full isolated browser workflow and hostile-path security suites. Pass `-Demo` for a visible, slowed, recorded supervisor walkthrough. |
| `ensure-mysql.ps1` | automatically before database-dependent test runners, or manually for diagnosis | Idempotently verifies a real root connection; when stopped, starts a recognised Windows service, XAMPP, or Scoop MariaDB and waits for readiness. |
| `ensure-docker-desktop.ps1` | automatically before ZAP, or manually for diagnosis | Installs Docker Desktop through WinGet (or Chocolatey when WinGet is unavailable) if absent, starts it when its engine is stopped, and waits for a real Docker Engine response. |
| `run-zap-baseline.ps1` | before releasing security-sensitive changes | Runs Docker Desktop setup, rebuilds the disposable UI database, serves the app locally, then runs OWASP ZAP's passive baseline and writes HTML/JSON/XML reports to `test-results\zap`. |

### OWASP ZAP baseline

`run-zap-baseline.ps1` is intentionally passive. It may spider the disposable
application, but it does not submit active attack payloads. The script retries
the stable GHCR image and falls back to the official Docker Hub stable image if
that registry is unavailable. A ZAP `WARN` or `FAIL` makes the command fail;
review `test-results\zap\zap-baseline.html`, `.json`, and `.xml` to decide
whether to fix a real finding or record a specific, time-bound exception. Never
run an active scan against production or real patient data without explicit
written authorization.

```powershell
# Use the retention window from config (audit.pii_retention_days, default 90):
php scripts\purge-audit-pii.php

# Preview how many rows would be scrubbed, or use an override at/above the floor:
php scripts\purge-audit-pii.php --dry-run
php scripts\purge-audit-pii.php --days 30

# Commit the current valid database head to independent append-only storage:
php scripts\anchor-audit-chain.php

# Verify/start MySQL/MariaDB for test runners:
.\scripts\ensure-mysql.ps1

# Run passive OWASP ZAP scan (requires Docker Desktop):
.\scripts\run-zap-baseline.ps1

# Install if needed, then verify/start Docker Desktop before the ZAP scan:
.\scripts\ensure-docker-desktop.ps1
```

---

## `configure-php-ini.ps1` — the single source of truth for PHP config

PHP installs do **not** come ready for MediShield:

- **Scoop PHP** ships with *no active `php.ini`* — every extension is off.
- **Stock XAMPP** has several required extensions commented out.

Either way the app and the PHPUnit suite fail with confusing "class not found" /
"could not find driver" errors until `php.ini` is fixed. This script removes that
guesswork and guarantees every machine has an **identical** PHP runtime.

It is **idempotent** (safe to re-run) and:

1. Resolves the *real* PHP binary (it follows Scoop shims via `PHP_BINARY`).
2. Finds the loaded `php.ini`, or creates one from `php.ini-production` if none.
3. Points `extension_dir` at the install's `ext/` folder.
4. Enables every required extension and applies the baseline settings.
5. Writes `99-medishield-hardening.ini` into the last additional scan directory
   when the PHP package has later-loading overrides.
6. Verifies effective extensions and INI values and fails loudly on drift.

### Canonical configuration it enforces

**Extensions** (keep in sync whenever a new runtime dependency is added):

| Extension | Why MediShield needs it |
|-----------|-------------------------|
| `openssl` | AES-256-GCM crypto + secure random (`src/Security/Crypto.php`) |
| `mbstring` | multibyte-safe string handling |
| `pdo_mysql` | PDO driver for MySQL/MariaDB (production database) |
| `mysqli` | mysql driver parity used by `setup-db.ps1` checks |
| `pdo_sqlite` | PDO SQLite driver for the in-memory PHPUnit test database |
| `sqlite3` | SQLite support for the test suite |
| `fileinfo` | MIME detection for lab-result uploads (later deliverables) |
| `zip` | required by Composer to extract packages |

**INI settings:** `date.timezone = UTC`, `memory_limit = 256M`,
`display_errors = Off`, `display_startup_errors = Off`, `log_errors = On`,
`error_reporting = E_ALL`, `expose_php = Off`, and
`zend.exception_ignore_args = On`. The final setting keeps scalar function
arguments such as passwords, encryption keys, HMAC keys, OTPs, and other
credentials out of exception stack traces written to server logs.

### Usage

```powershell
# Configure whichever php.exe is first on PATH:
powershell -ExecutionPolicy Bypass -File scripts\configure-php-ini.ps1

# Configure a specific PHP (e.g. XAMPP):
powershell -ExecutionPolicy Bypass -File scripts\configure-php-ini.ps1 -PhpExe C:\xampp\php\php.exe
```

> **Adding a new PHP dependency?** Update the `$RequiredExtensions` list at the top
> of `configure-php-ini.ps1` (and the table above). That list is the one place the
> whole team relies on for a consistent environment.

---

## `configure-xampp-apache.ps1` - XAMPP web boundary

Run this script from an elevated PowerShell prompt after installing XAMPP. It
backs up every file it changes and creates two managed virtual hosts on the
selected port. The first/default `localhost` host reuses the `DocumentRoot`
already configured in XAMPP's main `httpd.conf`, so the XAMPP dashboard,
phpMyAdmin aliases, and unmatched `Host` requests retain their normal behavior.
The second host maps only `medishield.local` to the repository's `public/`
directory. The script updates the Windows hosts file, applies
`ServerTokens Prod` and `ServerSignature Off`, and validates Apache before a
restart. It then proves the running MediShield boundary with positive and
negative HTTP requests; static configuration checks alone are not treated as
runtime proof.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\configure-xampp-apache.ps1
```

Use `-XamppRoot C:\tools\xampp` for a nonstandard installation. The
`-SkipRestart -SkipHttpProbe` combination is available for controlled
configuration-only maintenance, but leaves HTTP behavior unverified. Passing a
non-default port, such as `-Port 8080`, adds a managed `Listen 8080` directive
when Apache does not already listen there and configures both virtual hosts on
that port.

---

## Note on this environment (no-admin fallback)

XAMPP installation requires Administrator rights. On machines without elevation,
PHP + Composer + MariaDB were installed at user level via **Scoop**
(MariaDB is the same engine XAMPP ships). `configure-php-ini.ps1` works against
both the Scoop PHP and a real XAMPP PHP, so the same baseline applies everywhere.
