# AGENTS.md

## 1. Purpose

This file keeps all AI agents and engineers working on the MediShield repository aligned on the same security, coding, testing, and git conventions.

## 2. Project at a glance

MediShield is a plain PHP 8.1 + PDO + MySQL healthcare records system for XAMPP, built to demonstrate secure authentication, role-based access control, encrypted clinical data, tamper-evident audit logging, STRIDE threat modelling, and security testing. The authoritative project rules are in [`..\MediShield_Specification_v2.md`](..\MediShield_Specification_v2.md); also read [`README.md`](README.md) before making changes.

## 3. Golden security rules (NON-NEGOTIABLE)

- All database access must use PDO prepared statements with bound parameters; never concatenate SQL with user input.
- Escape all rendered output with `htmlspecialchars($value, ENT_QUOTES, 'UTF-8')`.
- Passwords must use `password_hash()` and `password_verify()` only; never store plaintext or encrypted passwords.
- Sensitive clinical fields must use AES-256-GCM through the project `Crypto` class only.
- Audit logs are append-only and must use the HMAC-SHA256 hash chain through `AuditChain` / the audit helper; never edit or delete audit rows in app code.
- Every protected page must enforce server-side `require_login()`, `require_role(...)`, and object-level ownership / assignment / queue checks. Hidden UI is not authorization.
- Every state-changing form must include and validate a CSRF token.
- Show generic errors to users; log real errors to `logs/app_errors.log`.
- Send security headers and use hardened session cookies: `HttpOnly`, `SameSite=Strict`, and `Secure` when HTTPS is active.

## 4. Coding conventions

- PHP follows PSR-12 style. Use `declare(strict_types=1);` where practical.
- Use the `MediShield\...` namespace. PSR-4 maps `MediShield\` to `src/`.
- Keep classes in `src/`, one class per file.
- Use spec section 25 naming exactly:
  - Roles: `patient`, `nurse`, `doctor`, `lab`, `pharmacist`, `admin`
  - User statuses: `active`, `inactive`
  - Request / prescription statuses: `pending`, `completed`, `dispensed`, `refused`
  - Audit statuses: `SUCCESS`, `FAILED`, `BLOCKED`
  - Anomaly flags: `NORMAL`, `SUSPICIOUS`, `HIGH_RISK`
  - Audit action vocabulary: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, `PATIENT_VIEW`, `PATIENT_REGISTERED`, `ASSIGNMENT_CHANGED`, `VITALS_RECORDED`, `DIAGNOSIS_ADDED`, `LAB_REQUESTED`, `LAB_RESULT_UPLOADED`, `PRESCRIPTION_ISSUED`, `MEDICATION_DISPENSED`, `USER_CREATED`, `USER_UPDATED`, `PASSWORD_RESET`, `ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`, `CSRF_REJECTED`, `UNAUTHORIZED_ACCESS`, `AUDIT_LOGS_VIEWED`, `INTEGRITY_VERIFIED`.
- Pages live in `public/`; reusable business/security logic lives in `src/` classes so it is unit-testable. Pages should be thin glue.
- SQL files live in `sql/`. Helper scripts live in `scripts/`.

## 5. Environment setup & reproducibility (READ BEFORE RUNNING ANYTHING)

The environment is reproduced entirely by the scripts in `scripts/` — never hand-edit
`php.ini`. Run, from the repo root, in order:

1. `scripts\install-dependencies.ps1` (Administrator) — installs XAMPP 8.1 + Composer, then calls `configure-php-ini.ps1`, then `composer install`.
2. `scripts\configure-php-ini.ps1` — **the single source of truth for PHP runtime config.** Idempotent; resolves the real PHP binary (follows Scoop shims via `PHP_BINARY`), creates `php.ini` from `php.ini-production` if missing, fixes `extension_dir`, enables every required extension, sets `date.timezone=UTC` / `memory_limit=256M`, and verifies with `php -m`.
3. `scripts\setup-db.ps1` — creates `medishield_db`, loads `sql\schema.sql` + `sql\seed.sql`, generates `config\config.php` from the sample.

**Required PHP extensions** (canonical list lives in `$RequiredExtensions` inside `configure-php-ini.ps1`): `openssl`, `mbstring`, `pdo_mysql`, `mysqli`, `pdo_sqlite`, `sqlite3`, `fileinfo`, `zip`.

- **When you add a new PHP dependency/extension, add it to `$RequiredExtensions` in `configure-php-ini.ps1`** (and the table in `scripts/README.md`) — do NOT just edit a local `php.ini`, or teammates will hit config drift.
- **No-admin machines:** XAMPP needs Administrator. Where elevation is unavailable, PHP + Composer + MariaDB are installed at user level via **Scoop** (MariaDB is the same engine XAMPP ships). `configure-php-ini.ps1` works against both the Scoop PHP and a real XAMPP PHP.
- Local runtime is **PHP 8.5** (bleeding edge); production target is PHP 8.1. PHPUnit is pinned `^11.5 || ^12.0` so it runs on both. Keep code compatible with PHP 8.1.
- Scoop's PHP ships with **no active `php.ini`** (every extension off) — running PHP/PHPUnit before `configure-php-ini.ps1` will fail with "class not found" / "could not find driver". Always configure first.

## 6. Documentation conventions

- **Every directory must contain a `README.md`** describing what that collection of files does, so any new engineer/agent can understand it without reading the code. When you add a new directory, add its README.
- Write thorough, doc-style comments on classes, scripts, and non-obvious logic — comments should act as documentation (purpose, why, security rationale), not restate the code.
- Keep `README.md`, `scripts/README.md`, per-directory READMEs, and this file in sync when conventions, structure, or workflows change.

## 7. Testing / TDD workflow

- Write a failing PHPUnit test first, then implement the change.
- Put pure logic tests in `tests/Unit`.
- Put database integration tests in `tests/Integration`, using injected PDO with SQLite in-memory (`tests/Support/TestSchema.php` builds the schema).
- Install dependencies with:

  ```powershell
  composer install
  ```

- Configure PHP (once per machine, or after pulling new extension requirements):

  ```powershell
  scripts\configure-php-ini.ps1
  ```

- Run tests with:

  ```powershell
  vendor\bin\phpunit
  ```

- All tests must pass before commit (current baseline: 46 passing).
- DB-dependent code must accept an injected `PDO` so it can be tested against SQLite. Use portable SQL so the same class runs on MySQL (prod) and SQLite (tests); gate MySQL-only syntax (e.g. `FOR UPDATE`) on the driver name.

## 8. Git / commit conventions

- All commits must be authored as `Traccykay <traccykay@gmail.com>`; repo-local git config is already set.
- Use conventional-commit style messages: `feat:`, `fix:`, `test:`, `docs:`, `chore:`.
- Keep commits small and focused.
- Never commit `config/config.php`, `config/secrets.php`, keys, credentials, or other secrets. Only commit safe samples such as `config.sample.php`.

## 9. Relevant reusable skills / agents

- `security-review` agent: run before merging security-sensitive changes, especially auth, crypto, RBAC, CSRF, session handling, audit logging, and input/output handling.
- Threat-modeling skills / agents: use when adding a new module, data flow, or trust boundary. Map findings to STRIDE and the controls in spec section 20.
- Azure-focused skills (`azure-*`, `microsoft-foundry`) are not applicable to this local XAMPP / PHP app and should not be invoked for MediShield work.

## 10. Definition of Done

- PHPUnit tests pass with `vendor\bin\phpunit`.
- Golden security rules are satisfied.
- RBAC and object-level authorization are enforced server-side.
- Sensitive clinical fields use AES-256-GCM via `Crypto`.
- State-changing forms have CSRF protection.
- Audit logging is wired for sensitive actions and uses the HMAC hash chain.
- User-facing errors are generic; details are logged to `logs/app_errors.log`.
- Any new directory has a `README.md`; any new PHP extension is added to `$RequiredExtensions` in `scripts/configure-php-ini.ps1`.
- `README.md` and this file are updated if conventions or workflows change.
