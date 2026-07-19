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
| 3 | `setup-db.ps1` | not required | Creates the `medishield_db` database, loads `sql/schema.sql` + `sql/seed.sql`, applies every idempotent migration in `sql/migrations/`, and generates `config/config.php` from the sample template. |

### Maintenance scripts (run on a schedule, not part of setup)

| Script | When | What it does |
|--------|------|--------------|
| `purge-audit-pii.php` | cron / Task Scheduler (e.g. daily) | Scrubs PII (`attempted_identifier`, the email typed on a failed login) from `audit_logs` rows older than `audit.pii_retention_days`. Never deletes rows and never touches the hash chain, so `verifyChain()` stays ok. Needs a DB account with `UPDATE` on `audit_logs`. See `src/Audit/README.md`. |

| `setup-ui-test-db.ps1` | before Playwright UI tests | Rebuilds the disposable `medishield_ui_test` database. Playwright calls this automatically and never modifies development data. |
| `run-ui-tests.ps1` | before submitting UI-affecting changes | Checks required runtimes, installs pinned Playwright dependencies/Chromium when absent, then runs the full isolated browser workflow suite. Pass `-Demo` for a visible, slowed, recorded supervisor walkthrough. |

```powershell
# Use the retention window from config (audit.pii_retention_days, default 90):
php scripts\purge-audit-pii.php

# Preview how many rows would be scrubbed, or override the window:
php scripts\purge-audit-pii.php --dry-run
php scripts\purge-audit-pii.php --days 30
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
5. Verifies the result with `php -m` and fails loudly if anything is missing.

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

**INI settings:** `date.timezone = UTC`, `memory_limit = 256M`.

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

## Note on this environment (no-admin fallback)

XAMPP installation requires Administrator rights. On machines without elevation,
PHP + Composer + MariaDB were installed at user level via **Scoop**
(MariaDB is the same engine XAMPP ships). `configure-php-ini.ps1` works against
both the Scoop PHP and a real XAMPP PHP, so the same baseline applies everywhere.
