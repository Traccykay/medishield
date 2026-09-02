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
and medication prices in Kenyan shillings. A doctor can submit multiple
catalog lab tests and prescriptions in one encounter; each order is linked to
that visit and records the server-resolved catalog price. A pharmacy refusal is
a terminal, reasoned outcome: the order cannot re-enter the queue and the
encounter returns to the assigned doctor for review.

Cybersecurity is central to the project: authentication, role-based access control, object-level authorization, encrypted clinical data, tamper-evident audit logging, anomaly detection, STRIDE threat modelling, and security-testing readiness are core requirements.

## Key Security Features

- **Role-Based Access Control (RBAC):** server-side authorization for patient, receptionist, nurse, doctor, lab, pharmacist, and admin roles.
- **Object-level authorization:** nurses require an active patient assignment;
  doctors require both that assignment and ownership of the current active
  `with_doctor` visit; lab/pharmacy access is queue-based.
- **Password hashing:** passwords are stored with PHP `password_hash()` and verified with `password_verify()`.
- **AES-256-GCM encryption:** sensitive clinical fields are encrypted at rest using authenticated encryption.
- **HMAC hash-chained audit logs:** forensic audit entries are append-only and tamper-evident using HMAC-SHA256 with a server-side key.
- **Anomaly detection:** suspicious and high-risk activity is flagged, including repeated failed logins, unauthorized access, IDOR attempts, CSRF failures, and integrity failures.
- **CSRF protection:** state-changing forms use CSRF tokens.
- **Secure sessions:** strict cookie-only session IDs, post-MFA regeneration,
  fail-closed pending/idle/absolute timeouts, and a monotonic account epoch that
  revokes pending and authenticated sessions after password, status, or role changes.
- **Request throttling:** HMAC-scoped fixed-window budgets limit login, OTP, and password-reset storms without storing raw IP addresses.
- **Auditable least privilege:** the web database identity cannot update or delete audit rows; a separate maintenance identity can clear only retention-approved audit PII.
- **Production transport boundary:** production rejects plaintext HTTP and trusts `X-Forwarded-Proto` only from explicitly configured TLS proxies.
- **STRIDE threat modelling:** used to identify and reduce spoofing, tampering, repudiation, information disclosure, denial-of-service, and elevation-of-privilege risks.

## Tech Stack

| Area | Technology |
| --- | --- |
| Backend | PHP 8.1, plain PHP + PDO |
| Database | MySQL 8 / MariaDB |
| Web Server | Apache via XAMPP |
| Frontend | HTML5, CSS3, Bootstrap 5 |
| Testing | PHPUnit and Playwright |
| Security Testing | PHPUnit security tests, Playwright hostile-path regression harness, and OWASP ZAP passive baseline scan |

> Laravel and other PHP frameworks are intentionally not used; security controls are implemented explicitly in plain PHP.

## Project Structure

```text
medishield/
  config/ (config.sample.php, config.php[gitignored])
  public/ (WEB ROOT: index.php, login.php, logout.php, change_password.php, dashboard.php, unauthorized.php, admin/{dashboard,users,create_user}.php, assets/css/style.css)
  src/ (Support/, Database/, Security/, Auth/  — PSR-4 namespace MediShield\)
  includes/ (bootstrap.php, guard.php, headers.php, layout.php)
  sql/ (schema.sql, seed.sql)
  scripts/ (install-dependencies.ps1, configure-php-ini.ps1, setup-db.ps1, provision-initial-admin.php)
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

This creates a local database named `medishield_db`, applies upgrades, provisions
a non-root web database account, and creates your private `config\config.php`
file with unique encryption and audit keys. It deliberately creates no
application users and prints no login credential. The configuration file is
intentionally not uploaded to GitHub.

### 4. Provision the initial administrator

Normal setup has no default login. Choose the initial administrator's real name
and email address, bind the command explicitly to the configured database, and
run:

```powershell
php scripts\provision-initial-admin.php `
  --name="Initial Administrator" `
  --email="administrator@example.com" `
  --confirm-database=medishield_db `
  --confirm-initial-admin
```

The command creates an **inactive** admin with no usable password, sends an
expiring single-use activation link through the configured mail transport, and
never prints a password or token. It refuses to run without both confirmation
options. If any administrator already exists, it makes no changes, so rerunning
it cannot replace or reset an existing account.

In local development, the `log` mail transport writes the activation message to
the newest file under `logs\mail\`. In production, provisioning refuses to run
unless SMTP and an HTTPS `mail.app_base_url` are configured.

### 5. Start the application

In the same PowerShell window, run:

```powershell
php -S 127.0.0.1:8000 -t public public/router.php
```

Leave that window open; it is the local web server. Open
<http://127.0.0.1:8000/> in a browser. To stop the server later, return to that
window and press `Ctrl+C`.

#### Apache/XAMPP document root

For Apache, the intended deployment points `DocumentRoot` directly at this
repository's `public\` directory. Do not use the repository root as a document
root: it also contains configuration, source, logs, SQL, tests, and maintenance
scripts that are not web resources.

If the repository is temporarily copied to `C:\xampp\htdocs\medishield`, the
checked-in root `.htaccess` denies every request except the `/public` subtree,
and `public\.htaccess` additionally denies include-only partials, documentation,
dotfiles, backups, and development-only files. This fallback requires Apache's
`mod_rewrite` module and `AllowOverride All`. A dedicated virtual host targeting
`C:\xampp\htdocs\medishield\public` remains the recommended arrangement.

After changing Apache configuration, restart Apache and perform the exposure
checks in [`SECURITY_TESTING.md`](SECURITY_TESTING.md). Passing tests against
PHP's built-in server does not prove that Apache applies these restrictions.

### 6. Activate and sign in for the first time

Open the activation link delivered in step 4 and choose the initial
administrator's password. Then sign in with that email and password. The login
OTP is delivered through the same configured mail transport; during local
development it appears in the newest file under `logs\mail\`.

> The installer generates unique local keys. For a real deployment, set
> `environment` to `production`, use HTTPS with a valid certificate, store keys
> in a managed secret service, and configure SMTP before provisioning the initial
> administrator. If TLS terminates at a reverse proxy, configure only that
> proxy's immediate IP in `transport.trusted_proxy_ips` and ensure it overwrites
> (rather than forwards) `X-Forwarded-Proto`; never trust public client IPs.

### Production startup configuration gate

The exact configuration value `environment => 'production'` activates a
fail-closed startup check. It runs immediately after the application error-log
destination is installed and before sessions, database access, audit logging,
OTP/reset/activation token issuance, or mailer construction.

Production requires all of the following:

- `mail.transport` is exactly `smtp`; `log`, missing, and unknown values are rejected.
- `mail.app_base_url` is an HTTPS URL with a host and no embedded credentials,
  query string, or fragment.
- `mail.from_email` is valid, `mail.from_name` is non-empty, and
  `mail.smtp.host`, `port`, `encryption` (`tls` or `ssl`), `username`,
  `password`, and `timeout` are complete and valid.

Startup failures are logged with a fixed diagnostic and reach the browser only
through the existing generic 500 response. Configuration values and credentials
are never rendered. Outside production, the local dump workflow remains
available only through an explicit `mail.transport => 'log'`; missing and
unknown transports fail closed rather than silently selecting file delivery.

## Running Tests

MediShield has complementary test suites. A passing feature-path test proves a
workflow works; a passing bad-path test proves that a hostile request does not
leak data or change state. Run the suites that cover the area you changed, then
run the full browser suite for user-facing or security-sensitive work.

First-time PHP setup:

```powershell
.\scripts\configure-php-ini.ps1
composer install
```

| Suite | Purpose | Command |
| --- | --- | --- |
| PHPUnit unit | Fast checks of security primitives and isolated rules, including crypto, CSRF, RBAC, passwords, audit-chain logic, and mail delivery. | `composer test:unit` |
| PHPUnit integration | Services and repositories with a fresh in-memory SQLite database: authentication, activation/OTP, session revocation, audit retention, user/patient access, and clinical workflows. | `composer test:integration` |
| All PHP tests | Runs both PHPUnit suites. It does not need MySQL or change local application data. | `composer test` |
| Playwright workflow | Exercises the real browser-based hospital workflow using disposable role-specific accounts. | `.\scripts\run-ui-tests.ps1` |
| Playwright security harness | Exercises hostile browser requests: role/object-reference denial, live doctor-assignment revocation with nurse-queue recovery and released doctor capacity, deterministic method/CSRF rejection across all mutation controllers, malformed-array no-mutation checks, stored-XSS encoding, security headers, and generic authentication failures. The standard UI runner executes it with the workflow tests. | `.\scripts\run-ui-tests.ps1` |
| OWASP ZAP passive baseline | Scans the disposable local application for passive OWASP-style HTTP findings and writes HTML, JSON, and XML reports. Requires Docker Desktop. | `.\scripts\run-zap-baseline.ps1` |

The browser and ZAP runners both call `scripts\ensure-mysql.ps1`: it checks a
live SQL connection first, then supports Windows services, default XAMPP, and
Scoop MariaDB before recreating **only** `medishield_ui_test`. They never
change the normal `medishield_db` database. To run just the security harness after its prerequisites are available, use:

```powershell
npx.cmd playwright test request-boundary security-hostile
```

On failure, inspect `test-results` for the screenshot, video, and trace. See
[`tests/README.md`](tests/README.md) for PHP-suite details and
[`e2e/README.md`](e2e/README.md) for browser-test setup and troubleshooting.
See [`SECURITY_TESTING.md`](SECURITY_TESTING.md) for all runner prerequisites,
ZAP reports, and the safe active-scan boundary.

### OWASP ZAP context

The ZAP runner is a repeatable **passive** scan, not an authorization to attack
the application. It rebuilds only `medishield_ui_test`, starts a local PHP
server, and scans it from a disposable Docker container. It installs or starts
Docker Desktop when needed, tries the ZAP stable GHCR image with bounded
retries, then falls back to the official Docker Hub stable image if GHCR is
unavailable.

The command fails on ZAP `WARN` or `FAIL` alerts and writes reviewable evidence
to `test-results\zap\zap-baseline.html`, `.json`, and `.xml`. Treat a warning as
a finding to investigate and regression-test, not as a result to suppress merely
to make the command green. Active scans can submit state-changing payloads and
must be separately authorized against an explicitly disposable environment.

### Browser UI tests and supervisor demonstration

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
- CLI-only initial-admin provisioning with an inactive, single-use activation flow
- Admin "registration" flow: create users and assign one of the seven roles
- Admin user management: list users, activate/deactivate accounts
- Admin dashboard with security monitoring: recent audit events, failed-login /
  anomaly counts, and audit-chain integrity status
- Role-Based Access Control enforced server-side (admin area is admin-only)
- Forensic audit logging (HMAC hash-chain) wired into every security event
- Database schema + seed and a reproducible XAMPP setup
- Unit and integration tests (TDD): run with `composer test`

### Later Deliverables

Planned later work includes:

- Nurse vitals module
- Doctor consultation, diagnosis, lab request, and prescription module
- Laboratory result upload module
- Pharmacy dispensing module
- Audit-log viewer and integrity verification UI
- Security monitoring dashboard and anomaly views
- OWASP ZAP active scan, only with explicit authorization against a disposable
  environment

## Contributing

All commits should be authored as:

```text
Traccykay <traccykay@gmail.com>
```

See `AGENTS.md` for repository conventions.

## License

MIT License placeholder.

This repository is an academic project for demonstrating secure healthcare-record management, cybersecurity controls, and forensic audit logging. It is not intended for production clinical use without further security, privacy, legal, and compliance review.