# Security Testing Runbook

MediShield uses complementary automated checks. Run all applicable layers after
security-sensitive changes; no one layer proves the whole security posture.

| Layer | Command | What it verifies |
| --- | --- | --- |
| PHP unit + integration | `composer test` | Crypto, CSRF, RBAC, audit-chain integrity, throttling, authentication, OTP, and data-access behavior. Does not need MySQL. |
| Browser workflows + hostile paths | `.\scripts\run-ui-tests.ps1` | The real rendered application, role/ownership denial, CSRF no-write behavior, stored-XSS encoding, headers, generic authentication failures, reset-link revocation, and reset-storm throttling. |
| OWASP ZAP passive baseline | `.\scripts\run-zap-baseline.ps1` | Spidered unauthenticated HTTP responses, passive OWASP-style findings, and ZAP HTML/JSON/XML reports. Requires Docker Desktop. |

## Reliable test database startup

All database-dependent runners call `scripts\ensure-mysql.ps1`. It first checks
whether MySQL/MariaDB is ready and changes nothing when it is. If stopped, it
tries a Windows service, XAMPP, then the installed Scoop MariaDB server and
waits for a real SQL connection before proceeding.

Run it directly when diagnosing a test environment:

```powershell
.\scripts\ensure-mysql.ps1
.\scripts\setup-ui-test-db.ps1
```

`setup-ui-test-db.ps1` recreates **only** `medishield_ui_test`; it does not
modify the normal `medishield_db` data. It rejects every database name except
`medishield_ui_test` and `medishield_ui_account_test`. If startup fails, read the actionable
error, inspect the relevant database log, fix the database installation, and
run the command again. Do not manually alter the disposable test database.

## Apache/XAMPP exposure verification

The automated browser and ZAP runners use PHP's built-in server with `public`
as its document root. They therefore do not prove that an XAMPP/Apache
installation applies the repository `.htaccess` boundary. From an elevated
PowerShell prompt, the supported setup and runtime verification is:

```powershell
.\scripts\configure-xampp-apache.ps1
```

The script backs up changed configuration, enables `mod_rewrite`, preserves a
first/default `localhost` virtual host using XAMPP's existing main
`DocumentRoot`, and creates a separate `medishield.local` virtual host. This
keeps the XAMPP dashboard, phpMyAdmin aliases, and unmatched `Host` requests on
the normal XAMPP site instead of routing them into MediShield. It also applies
`ServerTokens Prod` and `ServerSignature Off`, validates Apache syntax,
restarts Apache, and executes the exposure matrix. A non-default `-Port` adds
the corresponding `Listen` directive when needed. A configuration-only run
using `-SkipRestart -SkipHttpProbe` is not runtime verification.

The supported Apache configuration keeps the existing XAMPP document root as
the default host and grants MediShield overrides only in the repository's
`public` directory:

```apache
ServerTokens Prod
ServerSignature Off
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot "C:/xampp/htdocs"
</VirtualHost>

<VirtualHost *:80>
    ServerName medishield.local
    DocumentRoot "C:/personal/Capstone/medishield/public"
    <Directory "C:/personal/Capstone/medishield/public">
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

For the protected legacy URL layout
`http://localhost/medishield/public/`, the parent
`C:\xampp\htdocs` directory must also permit `.htaccess` overrides so the root
fallback rule is evaluated. Confirm that `mod_rewrite` is loaded, restart
Apache, and request each path below:

```text
/login.php                          expected 200
/assets/css/style.css               expected 200
/scripts/seed-ui-test-users.php     expected 403 or 404
/logs/app_errors.log                expected 403 or 404
/sql/schema.sql                     expected 403 or 404
/src/Auth/AuthService.php           expected 403 or 404
/tests/README.md                    expected 403 or 404
/config/config.php                  expected 403 or 404
/composer.lock                      expected 403 or 404
/package-lock.json                  expected 403 or 404
/.git/config                        expected 403 or 404
/partials/bill_charges.php          expected 403 or 404
/Partials/bill_charges.php          expected 403 or 404
/PARTIALS/bill_charges.php          expected 403 or 404
/README.md                          expected 403 or 404
```

The denied response must not contain PHP exceptions, filesystem paths, database
details, or file contents. Record the observed Apache results separately from
the static PHPUnit configuration-contract tests.

## OWASP ZAP passive baseline

The test setup calls `scripts\ensure-docker-desktop.ps1`: it detects Docker
Desktop, installs it through WinGet (or Chocolatey when WinGet is unavailable)
if absent, starts it if its engine is stopped, and waits for a real Docker Engine
response before ZAP begins. The official Docker per-user Windows installation is
used where supported. The runner pulls ZAP's stable GHCR image and falls back
to its documented Docker Hub stable image if GHCR is unavailable, rebuilds the
disposable UI database, starts PHP on `127.0.0.1:8766`, and scans it through
Docker's `host.docker.internal` bridge:

The local PHP server uses `public/router.php` so static files receive the same
security headers as Apache/XAMPP responses. Apache receives those headers from
`public/.htaccess`.

```powershell
.\scripts\run-zap-baseline.ps1
# Equivalent shortcut:
npm run test:zap
```

Reports are written to `test-results\zap\`:

- `zap-baseline.html` — reviewer-friendly report.
- `zap-baseline.json` — machine-readable findings for CI or issue creation.
- `zap-baseline.xml` — tool-compatible export.

The runner exits non-zero when ZAP produces a `WARN` or `FAIL` alert. Triage
each finding: fix the root cause and add a regression test, or document a
specific accepted false positive with an expiry/review owner. Do not suppress a
finding merely to make the command green.

## Active scans and authorization

`run-zap-baseline.ps1` is intentionally passive. Active ZAP scans can submit
payloads, create records, trigger emails, or otherwise mutate state. Run them
only with written authorization and only against a disposable, explicitly
scoped environment such as `medishield_ui_test`—never against production or
real patient data. Preserve the ZAP reports and turn confirmed findings into
code fixes plus hostile-path regression coverage.

## Failure evidence

- PHPUnit prints the failing class, test, and assertion.
- Playwright stores screenshots, video, and traces under `test-results\`.
- ZAP stores all reports under `test-results\zap\`.
- Application-side detail is logged to `logs\app_errors.log`; users see generic
  errors by design.
