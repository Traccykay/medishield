# Security Testing Runbook

MediShield uses complementary automated checks. Run all applicable layers after
security-sensitive changes; no one layer proves the whole security posture.

| Layer | Command | What it verifies |
| --- | --- | --- |
| PHP unit + integration | `composer test` | Crypto, CSRF, RBAC, audit-chain integrity, throttling, authentication, OTP, and data-access behavior. Does not need MySQL. |
| Locked dependency audit | `.\scripts\audit-dependencies.ps1` | Strict Composer validation/advisories, PHP 8.1 lock compatibility, script-free npm clean reconciliation, npm advisories, and available registry signatures over exact locked versions. |
| Real MariaDB concurrency tests | `$env:MEDISHIELD_MARIADB_AUDIT_TEST='1'; vendor\bin\phpunit --filter 'MariaDb.*ConcurrencyTest'` | Applies the v2 audit migration twice, preserves v1 HMACs, checks audit constraints and concurrent appends, and proves that two contending lab-result submissions cannot both claim one pending request. |
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

The script backs up changed configuration, enables `mod_rewrite` and
`mod_headers`, preserves a
first/default `localhost` virtual host using XAMPP's existing main
`DocumentRoot`, and creates a separate `medishield.local` virtual host. This
keeps the XAMPP dashboard, phpMyAdmin aliases, and unmatched `Host` requests on
the normal XAMPP site instead of routing them into MediShield. MediShield uses
`Require local` by default; `-AllowRemoteAccess` is the explicit remote opt-in.
The script applies `ServerTokens Prod`, `ServerSignature Off`, and
`TraceEnable Off`, disables indexes, MultiViews, and path info, validates
Apache syntax, verifies both modules through `httpd.exe -M`, restarts Apache,
and executes the exposure matrix. A non-default `-Port` adds the corresponding
`Listen` directive when needed. A configuration-only run using
`-SkipRestart -SkipHttpProbe` is not runtime verification.

The supported Apache configuration keeps the existing XAMPP document root as
the default host and grants MediShield overrides only in the repository's
`public` directory:

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot "C:/xampp/htdocs"
</VirtualHost>

<VirtualHost *:80>
    ServerName medishield.local
    DocumentRoot "C:/personal/Capstone/medishield/public"
    <Directory "C:/personal/Capstone/medishield/public">
        Options -Indexes -MultiViews
        AcceptPathInfo Off
        AllowOverride All
        Require local
    </Directory>
</VirtualHost>
```

For the protected legacy URL layout
`http://localhost/medishield/public/`, the parent
`C:\xampp\htdocs` directory must also permit `.htaccess` overrides so the root
fallback rule is evaluated. This legacy root fallback is explicitly a runtime
unknown until tested on the target installation; do not infer its behavior from
the dedicated-vhost or built-in-server results. Confirm that `mod_rewrite` and
`mod_headers` are loaded, restart Apache, and request each path below:

```text
/login.php                          expected 200
/assets/css/style.css               expected 200, text/css; charset=utf-8, cacheable
/assets/css/                        expected 403 or 404, no listing
/runtime-probe-missing              expected controlled 404
/README.md                          expected 403 or 404
/.htaccess                          expected 403 or 404
/router.php                         expected 403 or 404
/assets/README.md                   expected 403 or 404
/assets/css/style.css.map           expected 403 or 404
/login.php.bak                      expected 403 or 404
/manifest.json                      expected 403 or 404
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
TRACE /login.php                    expected 405
Host: unexpected.invalid            must use the default site, not MediShield
```

Every MediShield response in the matrix must have exactly one copy of each core
security header, including `Referrer-Policy: no-referrer` and
`X-Content-Type-Options: nosniff`. Dynamic/session responses must be
`Cache-Control: no-store, private`; the stylesheet must not contain `no-store`,
must include its CSS rules, and must render in the browser. Denied/error bodies
must not contain PHP exceptions, filesystem paths, database details, file
contents, or a directory listing. Record observed Apache results separately
from static PHPUnit configuration-contract tests.

The checked-in local vhost is HTTP-only. It does **not** exercise TLS or prove
HSTS. A production TLS vhost must set
`Strict-Transport-Security: max-age=31536000; includeSubDomains` at Apache (or
the trusted edge) so static assets and Apache-generated errors are covered.
Enable it only after HTTPS is valid for every covered host.

No application-level canonical-host check is inferred from
`mail.app_base_url`: that setting governs emailed links, while the HTTP runtime
must continue to support loopback development and the protected subfolder
fallback. The generated Apache vhost instead derives its host boundary from the
explicit `-HostName` parameter and proves that an unexpected `Host` is handled
by the separate default site. Add an application canonical-host check only if a
dedicated runtime host setting is introduced and tested for each supported
layout.

## OWASP ZAP passive baseline

Docker Desktop must already be installed from the official vendor instructions.
`scripts\ensure-docker-desktop.ps1` resolves only known application paths,
requires a valid Docker Inc. Authenticode signature, starts the application if
its engine is stopped, and waits for a real Docker Engine response. It does not
install Docker because this repository has no reviewed exact Desktop installer
version/digest; `-SkipInstall` makes that preinstallation-only choice explicit
for automation.

The runner uses only reviewed immutable image reference
`ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`.
It performs bounded retries against that reference and has no mutable tag,
registry, or local-image fallback. Before database setup it rejects an occupied
port. It starts PHP on `127.0.0.1:8766` with a per-run wrapper and requires the
same unpredictable nonce in the identity response body and header, so a
different process cannot be mistaken for the disposable target. It then
rebuilds only `medishield_ui_test` and scans through Docker's
`host.docker.internal` bridge.

The local PHP server uses the fail-closed `public/router.php`. It executes only
enumerated page routes, serves only the enumerated stylesheet with an explicit
MIME/cache policy, and owns controlled 403/404 responses instead of falling
through to PHP's default file server. Apache receives the corresponding static
headers and denial rules from `public/.htaccess`.

```powershell
.\scripts\run-zap-baseline.ps1
# Equivalent shortcut:
npm run test:zap
```

Each run is isolated under `test-results\zap\runs\<run-id>\`:

- `zap-run-manifest.json` — run ID, UTC timestamps, exact target/command,
  immutable digest, discovered image version/ID, command/overall exits, report
  validation, and cleanup result.
- `reports\zap-baseline.html` — reviewer-friendly report.
- `reports\zap-baseline.json` — machine-readable findings for CI or issue creation.
- `reports\zap-baseline.xml` — tool-compatible export.

The report directory must be new and empty; stale legacy top-level reports are
removed before a run and stale content in a selected run directory is rejected.
All three reports must be nonempty and parse as their declared format. The
container is uniquely named, runs as `zap`, drops every capability, enables
`no-new-privileges`, uses a read-only root filesystem and bounded tmpfs mounts,
and joins a uniquely named network. Cleanup targets only those exact names and
is time-bounded. The primary ZAP exit is preserved when cleanup also fails;
cleanup failure changes an otherwise successful run to failure.

The runner exits non-zero when ZAP produces a `WARN` or `FAIL` alert, reports
are invalid, identity cannot be proven, or cleanup fails. Triage each finding:
fix the root cause and add a regression test, or document a specific accepted
false positive with an expiry/review owner. Do not suppress a finding merely to
make the command green.

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
- ZAP stores a unique manifest and validated report set under
  `test-results\zap\runs\<run-id>\`.
- Application-side detail is logged to `logs\app_errors.log`; users see generic
  errors by design.

## Forensic verification and anchor checks

```powershell
# Verify exact grants and rolled-back forbidden mutations (normally run by setup):
$env:MEDISHIELD_SETUP_DB_USER = 'root'
$env:MEDISHIELD_SETUP_DB_PASS = ''
php scripts\verify-audit-grants.php

# After a valid local chain is established, append the current head externally:
php scripts\anchor-audit-chain.php

# Retention preview and bounded live run:
php scripts\purge-audit-pii.php --dry-run
php scripts\purge-audit-pii.php --days 90 --batch-size 250
```

Expected integrity states are `PASS`, `FAIL`, and `UNKNOWN`; absence of the
external anchor, a wrong key, or a verification exception must never be
reported as `PASS`. Preserve the anchor file separately before destructive
rollback tests.
