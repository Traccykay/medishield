# MediShield — Secure Healthcare Records Management System

## Overview / Description

MediShield is a web-based healthcare records management system for securely managing patient records while demonstrating practical cybersecurity controls. It is intentionally focused: it is not a full hospital management system, but a security-first academic project showing how healthcare data can be protected and audited.

The system supports a simplified clinical workflow across seven roles:

- **Patient** — views only their own profile and clinical records.
- **Receptionist** — searches/registers demographics, records cash or insurance
  payment choice, and adds arrivals to the triage queue; cannot access clinical records.
- **Nurse** — records vitals and observations for assigned patients.
- **Doctor** — reviews assigned patients, records diagnoses/treatment, requests labs, and issues prescriptions.
- **Laboratory Technician** — processes lab-request queues and uploads encrypted results.
- **Pharmacist** — processes prescription queues and records dispensing outcomes.
- **Administrator** — manages users, assignments, audit logs, anomaly alerts, and security status.

The operational flow is reception → triage nurse → available doctor → lab or
pharmacy. Nurses record vitals and symptoms, doctors are shown as unavailable
while in an active consultation, and the demo catalog displays standard lab-test
and medication prices in Kenyan shillings.

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

## First-time setup on Windows

These instructions assume no PHP experience. You only need a Windows computer,
internet access, and permission to install development tools. Do not edit PHP
files or database files to get started.

### What you will install

| Tool | Why it is needed | How it is installed |
| --- | --- | --- |
| Git | Downloads future updates from GitHub | Install [Git for Windows](https://git-scm.com/download/win) before step 1. |
| XAMPP, PHP, Composer | Runs the application and its PHP tests | The project installer adds them for you. |
| MySQL/MariaDB | Stores the local demo data | Included with XAMPP. |
| Node.js LTS | Runs the browser UI tests and demonstration | Install the current LTS release from [nodejs.org](https://nodejs.org/). |

### 1. Download the project

Open **PowerShell** and choose a folder where you keep projects, for example
your Documents folder. Then copy and run:

```powershell
cd $HOME\Documents
git clone https://github.com/Traccykay/medishield.git
cd medishield
```

If `git` is not recognized, install Git for Windows from the link above, close
PowerShell, open it again, and repeat the commands. If you cannot install Git,
download the repository ZIP from GitHub, extract it, and open PowerShell in the
extracted `medishield` folder instead.

### 2. Install the application requirements

Open **PowerShell as Administrator**: search for PowerShell in the Start menu,
right-click it, then select **Run as administrator**. Change to the cloned
folder and run:

```powershell
cd $HOME\Documents\medishield
.\scripts\install-dependencies.ps1
```

This may take several minutes. It installs missing XAMPP, PHP, Composer, and
other PHP requirements, then downloads the PHP libraries. A successful run
returns you to the prompt without an error.

Install Node.js LTS separately if it is not already installed, then open a new
PowerShell window and check it:

```powershell
node --version
npm --version
```

Each command should print a version number.

### 3. Start the database and create local data

1. Open the **XAMPP Control Panel** from the Start menu.
2. Select **Start** next to **MySQL**. Its status should turn green.
3. In a normal PowerShell window at the repository folder, run:

   ```powershell
   .\scripts\setup-db.ps1
   ```

This creates a local database named `medishield_db`, adds example administrator
data, applies upgrades, and creates your private `config\config.php` file. The
configuration file is intentionally not uploaded to GitHub.

### 4. Start the application

In the same PowerShell window, run:

```powershell
php -S 127.0.0.1:8000 -t public
```

Leave that window open; it is the local web server. Open
<http://127.0.0.1:8000/> in a browser. To stop the server later, return to that
window and press `Ctrl+C`.

### 5. Sign in for the first time

| Field | Value |
| --- | --- |
| Email | `medishield.superadmin@gmail.com` |
| Password | `ChangeMe!2026` |

The first sign-in requires a password change and an OTP. During local
development the OTP is written to the newest file in `logs\mail\`; open that
file in Notepad and copy the code into the browser.

> For a development demo, the generated `config\config.php` uses local sample
> keys. Never use those keys, the example administrator password, or the local
> email-file delivery mechanism for real patient data.

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

### Browser UI tests and supervisor demonstration

Browser UI tests act like a scripted user: they open the real application,
sign in with test-only accounts, click through the hospital workflow, and check
the result at each step. They use a separate `medishield_ui_test` database and
delete/recreate **only that test database** on every run. Your `medishield_db`
demo data is not changed.

Before running them, ensure XAMPP MySQL is running. From the repository root,
run:

```powershell
.\scripts\run-ui-tests.ps1
```

The runner installs the exact Node dependencies and Chromium browser it needs
when absent. A successful run ends with `3 passed`. If it fails, open the
`test-results` folder to find a screenshot, video, and trace explaining where.
See [`e2e/README.md`](e2e/README.md) for troubleshooting.

For a live, scripted walkthrough rather than manual login/logout, run:

```powershell
.\scripts\run-ui-tests.ps1 -Demo
```

This opens Chromium, slows each test action, and records successful scenarios.
Do not click in the browser while it is running. It is the recommended
supervisor walkthrough because it repeats the same checked workflow every time.

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