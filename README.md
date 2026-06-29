# MediShield — Secure Healthcare Records Management System

## Overview / Description

MediShield is a web-based healthcare records management system for securely managing patient records while demonstrating practical cybersecurity controls. It is intentionally focused: it is not a full hospital management system, but a security-first academic project showing how healthcare data can be protected and audited.

The system supports a simplified clinical workflow across six roles:

- **Patient** — views only their own profile and clinical records.
- **Nurse** — records vitals and observations for assigned patients.
- **Doctor** — reviews assigned patients, records diagnoses/treatment, requests labs, and issues prescriptions.
- **Laboratory Technician** — processes lab-request queues and uploads encrypted results.
- **Pharmacist** — processes prescription queues and records dispensing outcomes.
- **Administrator** — manages users, assignments, audit logs, anomaly alerts, and security status.

Cybersecurity is central to the project: authentication, role-based access control, object-level authorization, encrypted clinical data, tamper-evident audit logging, anomaly detection, STRIDE threat modelling, and security-testing readiness are core requirements.

## Key Security Features

- **Role-Based Access Control (RBAC):** server-side authorization for patient, nurse, doctor, lab, pharmacist, and admin roles.
- **Object-level authorization:** assigned-patient checks for nurses/doctors and queue-based access for lab/pharmacy workflows.
- **Password hashing:** passwords are stored with PHP `password_hash()` and verified with `password_verify()`.
- **AES-256-GCM encryption:** sensitive clinical fields are encrypted at rest using authenticated encryption.
- **HMAC hash-chained audit logs:** forensic audit entries are append-only and tamper-evident using HMAC-SHA256 with a server-side key.
- **Anomaly detection:** suspicious and high-risk activity is flagged, including repeated failed logins, unauthorized access, IDOR attempts, CSRF failures, and integrity failures.
- **CSRF protection:** state-changing forms use CSRF tokens.
- **Secure sessions:** session ID regeneration, hardened cookies, idle timeout, and absolute timeout.
- **STRIDE threat modelling:** used to identify and reduce spoofing, tampering, repudiation, information disclosure, denial-of-service, and elevation-of-privilege risks.

## Tech Stack

| Area | Technology |
| --- | --- |
| Backend | PHP 8.1, plain PHP + PDO |
| Database | MySQL 8 / MariaDB |
| Web Server | Apache via XAMPP |
| Frontend | HTML5, CSS3, Bootstrap 5 |
| Testing | PHPUnit |
| Security Testing | OWASP ZAP |

> Laravel and other PHP frameworks are intentionally not used; security controls are implemented explicitly in plain PHP.

## Project Structure

```text
medishield/
  config/ (config.sample.php, config.php[gitignored])
  public/ (WEB ROOT: index.php, login.php, logout.php, change_password.php, dashboard.php, unauthorized.php, admin/{dashboard,users,create_user}.php, assets/css/style.css)
  src/ (Support/, Database/, Security/, Auth/  — PSR-4 namespace MediShield\)
  includes/ (bootstrap.php, guard.php, headers.php, layout.php)
  sql/ (schema.sql, seed.sql)
  scripts/ (install-dependencies.ps1, configure-php-ini.ps1, setup-db.ps1, create-superadmin.php)
  tests/ (Unit/, Integration/)
```

## Prerequisites

- Windows with **XAMPP 8.1** installed or installable
- **PHP 8.1** with `pdo_mysql`, `openssl`, and `mbstring`
- **Composer**
- **Git for Windows**
- MySQL 8 or MariaDB through XAMPP

## Setup & Installation

1. **Clone the repository**

   ```powershell
   git clone <repository-url> medishield
   cd medishield
   ```

2. **Install dependencies**

   This script installs or verifies XAMPP, Composer, and PHP dependencies. It
   also calls `configure-php-ini.ps1` to enable every required PHP extension and
   apply the baseline INI settings, so the environment is identical on every
   machine.

   ```powershell
   .\scripts\install-dependencies.ps1
   ```

   > If PHP is already installed (or you are not running as Administrator), you can
   > configure `php.ini` on its own:
   >
   > ```powershell
   > .\scripts\configure-php-ini.ps1            # php.exe on PATH
   > .\scripts\configure-php-ini.ps1 -PhpExe C:\xampp\php\php.exe
   > ```
   >
   > See `scripts/README.md` for the canonical extension list. When you add a new
   > PHP dependency, update `$RequiredExtensions` in `configure-php-ini.ps1`.

3. **Create and seed the database**

   This creates `medishield_db` and loads `sql\schema.sql` and `sql\seed.sql`.

   ```powershell
   .\scripts\setup-db.ps1
   ```

4. **Configure the application**

   Copy the sample config to the local config file and adjust database credentials and security keys as needed. The setup script may perform this copy automatically.

   ```powershell
   Copy-Item .\config\config.sample.php .\config\config.php
   ```

   Ensure `config.php` contains strong local values for encryption and audit HMAC keys.

5. **Serve through XAMPP**

   The application is served from the **`public/`** folder (the web root). Two
   supported options:

   **Option A — copy the project into `htdocs` (simplest):**

   Copy the **entire `medishield` folder** into XAMPP's `htdocs`, so the path is:

   ```text
   C:\xampp\htdocs\medishield\        <- the whole repo (config, src, public, ...)
   C:\xampp\htdocs\medishield\public\ <- the only folder the browser reaches
   ```

   Start **Apache** and **MySQL** from the XAMPP Control Panel, then browse to:

   ```text
   http://localhost/medishield/public/
   ```

   The app auto-detects this sub-folder, so CSS, links, and redirects all work
   from `/medishield/public/...` without any edits.

   **Option B — virtual host with DocumentRoot = `public/` (cleaner URLs):**

   Point an Apache virtual host's `DocumentRoot` (and `<Directory>`) at the
   project's `public\` folder, then browse to `http://localhost/`. Keep `config/`,
   `src/`, `includes/`, `sql/`, and `vendor/` **outside** the web root — only
   `public/` should be reachable over HTTP.

   > Do **not** open `http://localhost/medishield/` (without `/public/`): the web
   > root is `public/`, so the entry point is `.../public/index.php`. Opening the
   > repo root will show a directory listing or 404, not the app.

   **Option C — quick run without XAMPP (PHP built-in server):**

   ```powershell
   php -S 127.0.0.1:8000 -t public
   # then open http://127.0.0.1:8000/
   ```

## Default Superadmin Credentials

Use these credentials for the first login:

| Field | Value |
| --- | --- |
| Email | `superadmin@medishield.local` |
| Password | `ChangeMe!2026` |

The default password must be changed on first login. The superadmin account is used to register all other users and assign roles.

## Running Tests

The project follows a test-driven development approach for core security and authentication behavior.

```powershell
composer install
vendor\bin\phpunit
```

If needed, PHPUnit can also be run through PHP directly:

```powershell
php vendor/bin/phpunit
```

## Deliverable Status

### Deliverable 1

Deliverable 1 includes:

- Login and logout with secure sessions (id regeneration, idle + absolute timeout)
- Seeded superadmin account (forced password change at first login)
- Admin "registration" flow: create users and assign one of the six roles
- Admin user management: list users, activate/deactivate accounts
- Admin dashboard with security monitoring: recent audit events, failed-login /
  anomaly counts, and audit-chain integrity status
- Role-Based Access Control enforced server-side (admin area is admin-only)
- Forensic audit logging (HMAC hash-chain) wired into every security event
- Database schema + seed and a reproducible XAMPP setup
- Unit and integration tests (TDD): run with `php vendor/bin/phpunit`

### Later Deliverables

Planned later work includes:

- Nurse vitals module
- Doctor consultation, diagnosis, lab request, and prescription module
- Laboratory result upload module
- Pharmacy dispensing module
- Audit-log viewer and integrity verification UI
- Security monitoring dashboard and anomaly views
- OWASP ZAP scan, triage, and remediation

## Contributing

All commits should be authored as:

```text
Traccykay <traccykay@gmail.com>
```

See `AGENTS.md` for repository conventions.

## License

MIT License placeholder.

This repository is an academic project for demonstrating secure healthcare-record management, cybersecurity controls, and forensic audit logging. It is not intended for production clinical use without further security, privacy, legal, and compliance review.