# MediShield Security Remediation Handoff

## Scope and status

This handoff covers the six focused remediation commits on
`security/zap-remediation`, followed by Phase 7 verification. Nothing was
pushed. The normal `medishield_db` database was not rebuilt or used by browser
or ZAP testing; those runners use the allowlisted `medishield_ui_test`
database.

The branch preserves the seven-role workflow: `patient`, `receptionist`,
`nurse`, `doctor`, `lab`, `pharmacist`, and `admin`.

## Changes made

1. **Web and maintenance boundaries**
   - Made `public/` the intended web root.
   - Added repository-root fail-closed Apache protection for non-public files.
   - Made maintenance and seed PHP scripts CLI-only before bootstrap.
   - Restricted deterministic UI fixtures to allowlisted disposable databases.

2. **Early safe failure handling**
   - Installed a dependency-free browser error boundary before Composer,
     configuration, and database bootstrap.
   - Made browser errors generic while preserving server-side diagnostics.
   - Moved `bill_charges.php` outside the web root.
   - Enforced production PHP diagnostic settings and documented Apache
     fingerprint reduction.

3. **Clinical authorization**
   - Centralized doctor access in `DoctorPatientAuthorizer`.
   - Required both a current patient assignment and ownership of the active
     `with_doctor` visit.
   - Rechecked authorization inside write transactions.
   - Made assignment revocation return an active visit to the nurse queue and
     release doctor capacity without erasing clinical history.

4. **Authentication and request boundaries**
   - Removed the universal seeded administrator from normal setup.
   - Added CLI-only, one-time initial-admin provisioning through an inactive
     account and expiring activation.
   - Added `auth_version` so password, status, and role changes invalidate
     pending MFA and authenticated sessions.
   - Made OTP and activation redemption transaction-safe and single-use.
   - Normalized visible login failures and enforced pending, idle, and absolute
     session timeouts.
   - Centralized HTTP method and CSRF enforcement across mutation controllers.
   - Made logout and administrator password reset POST-only.

5. **Forensic auditing**
   - Preserved historical v1 audit hashes while making all new records v2.
   - Added domain-separated, length-prefixed HMAC canonicalization.
   - Added sequence/event IDs, a keyed singleton chain head, consistent
     snapshot verification, concurrency controls, exact database-grant checks,
     PII retention evidence, and independently keyed external anchors.
   - Defined honest `PASS`, `FAIL`, and `UNKNOWN` outcomes. Missing external
     evidence never becomes `PASS`.
   - Expanded PHI-free security and workflow audit coverage.

6. **Runtime and supply-chain hardening**
   - Replaced the permissive PHP development-server fallback with an explicit
     route and asset allowlist.
   - Added correct CSS MIME handling, controlled 403/404 responses,
     `Referrer-Policy: no-referrer`, and private `no-store` responses.
   - Centralized validated local redirects and POST `303` behavior.
   - Expanded Apache configuration automation and live exposure probes.
   - Restored the PHP 8.1-compatible PHPUnit 10.5 line.
   - Pinned Playwright exactly and bound npm artifacts to official registry
     URLs with SHA-512 integrity.
   - Removed elevated remote package-manager bootstrap execution and separated
     machine installation from standard-user project dependency installation.
   - Pinned ZAP to an immutable digest and added unique run identity, nonce
     proof, hardened container settings, validated reports, durable manifests,
     bounded cleanup, preserved diagnostics, and honest executable exit codes.

7. **Final protocol verification**
   - Corrected `HEAD` handling on mixed GET/POST pages so it follows the safe
     read path without a response body.
   - Made method rejections advertise truthful `Allow` headers: `GET, HEAD,
     POST` on mixed pages and `POST` on mutation-only routes.
   - Added unit and live built-in-server regressions for both behaviors.

## Files modified

The complete authoritative inventory after the final commit is:

```powershell
git diff --name-status main...HEAD
```

The principal groups and purposes are:

| Files | Purpose |
| --- | --- |
| `.htaccess`, `public/.htaccess`, `public/router.php` | Fail-closed HTTP exposure boundaries. |
| `includes/bootstrap.php`, `error_boundary.php`, `guard.php`, `headers.php`, `layout.php` | Early errors, request guards, headers, redirects, and safe denial rendering. |
| `src/Auth/*`, `src/Support/BootstrapConfigValidator.php`, `src/Support/LocalUrl.php` | Authentication epoch, MFA/session validation, doctor authorization, safe configuration, and local URLs. |
| `src/Audit/*`, `src/Security/AuditChain.php` | Versioned audit integrity, concurrency, retention, head state, and external anchors. |
| `src/Clinical/*`, `src/Visit/*`, affected `public/*` controllers | Transactional authorization and preserved seven-role healthcare workflows. |
| `scripts/configure-php-ini.ps1`, `configure-xampp-apache.ps1`, `install-dependencies.ps1`, `audit-dependencies.ps1` | Reproducible PHP/Apache/dependency hardening. |
| `scripts/run-ui-tests.ps1`, `run-zap-baseline.ps1`, `ensure-docker-desktop.ps1` | Disposable browser and passive-scanner execution. |
| `composer.*`, `package*.json` | PHP 8.1-compatible and integrity-bound dependency locks. |
| `tests/Unit/*`, `tests/Integration/*`, `tests/Support/*`, `e2e/*` | Regression, hostile-path, concurrency, migration, and workflow evidence. |
| `README.md`, `SECURITY_TESTING.md`, directory READMEs, `docs/*`, `AGENTS.md` | Security model, operations, testing, and seven-role documentation. |

## Database changes

Two idempotent migrations were added and are mirrored in `sql/schema.sql` and
`tests/Support/TestSchema.php`:

- `sql/migrations/2026-09-02_add_auth_version.sql`
  adds the session-revocation epoch.
- `sql/migrations/2026-09-03_forensic_audit_v2.sql`
  adds v2 audit metadata, ordering/uniqueness constraints, and keyed head state.

`sql/seed.sql` no longer creates a universal administrator. Existing data is
preserved by the migrations; deterministic credentials are confined to
disposable UI-test setup.

## Configuration changes

### PHP

Run:

```powershell
.\scripts\configure-php-ini.ps1
```

It enforces and verifies `display_errors=Off`,
`display_startup_errors=Off`, `log_errors=On`, `error_reporting=E_ALL`,
`expose_php=Off`, and `zend.exception_ignore_args=On`.

### Apache/XAMPP

From an elevated PowerShell prompt with XAMPP installed, run:

```powershell
.\scripts\configure-xampp-apache.ps1
```

The script backs up configuration, enables required modules, creates the
`medishield.local` virtual host with `public/` as its document root, keeps the
normal XAMPP host as the default, applies `ServerTokens Prod`,
`ServerSignature Off`, and `TraceEnable Off`, restarts Apache, and executes the
exposure matrix. Do not use `-AllowRemoteAccess` unless remote access is an
explicit requirement.

This step was **not executed in this environment because XAMPP is absent**.
PHP development-server and static Apache tests do not prove XAMPP behavior.

### Application operations

- Run `scripts\setup-db.ps1` to apply schema and migrations.
- Provision the first administrator with
  `scripts\provision-initial-admin.php`; normal setup creates no login.
- Configure production HTTPS and SMTP before production bootstrap.
- Schedule `php scripts\anchor-audit-chain.php` in a trusted context and store
  the anchor/key separately from the web tier. Setup does not schedule it.

## Tests run and results

| Test | Result |
| --- | --- |
| Focused Phase 6 PHPUnit suites | **PASS** — 98 tests, 715 assertions. |
| Final toolchain regression suite | **PASS** — 11 tests, 121 assertions. |
| Final full PHPUnit suite | **PASS** — 428 tests, 1,930 assertions; 3 opt-in MariaDB tests skipped in the ordinary run. |
| Opt-in real MariaDB audit suite | **PASS** — 3 tests, 27 assertions against `medishield_ui_account_test`. |
| Full Playwright suite | **PASS** — 36 scenarios in approximately 8.3 minutes against `medishield_ui_test`. |
| Manual hostile HTTP matrix | **PASS** — protected scripts, Git data, and traversal returned 403; unknown/path-info routes returned 404; malformed array input remained controlled; no sensitive leakage observed. |
| Passive OWASP ZAP baseline | **PASS** — manifest status and exit code were successful, no retained alert was at or above WARN, HTML/JSON/XML reports validated, and exact cleanup succeeded. The reports retain 3 Informational alert types across 9 instances. |
| Composer install/validation/audit/PHP 8.1 graph | **PASS** — no advisories and no package prohibits PHP 8.1. |
| npm clean installation through the configured TLS proxy | **PASS** — exact SHA-512 lock installed. |
| npm advisory audit through the configured TLS proxy | **PASS** — 0 vulnerabilities. |
| npm official-registry signature audit | **UNVERIFIED** — the local TLS handshake failed; the proxy does not expose supported signature metadata. |
| PHP syntax, changed JavaScript syntax, PowerShell parser, `git diff --check` | **PASS**. |
| XAMPP/Apache live exposure matrix | **UNVERIFIED** — XAMPP is not installed. |

The final successful ZAP evidence is under:

`test-results\zap\runs\zap-20260903T044202954Z-9c20cbc33810\`

## OWASP ZAP findings addressed

No preserved, machine-comparable pre-remediation ZAP report exists in the
current evidence directory, so a numeric before/after comparison would be
fabricated. The original handover findings were mapped as follows:

| Original finding class | Remediation and verification |
| --- | --- |
| Verbose errors, paths, SQL/stack/database details | Early error boundary, hardened PHP diagnostics, generic browser responses; PHPUnit, Playwright, and manual leakage probes passed. |
| Repository/config/source/log/script exposure | `public/` web root, root fallback protection, explicit runtime allowlist, CLI guards; hostile requests returned controlled 403/404. |
| Server fingerprinting and weak headers | `expose_php=Off`, Apache token/signature guidance, CSP and related headers, `no-referrer`, private `no-store`; built-in runtime tests and ZAP passed. Apache remains runtime-unverified. |
| Directly executable partial | Billing partial moved outside `public/`; route inventory tests enforce the boundary. |
| Authentication enumeration/default credentials | Uniform failures, dummy-hash path, one-time inactive-admin provisioning, disposable-only deterministic accounts; auth and browser tests passed. |
| Session/MFA replay and stale authorization | `auth_version`, transactional single-use redemption, timeouts, post-MFA regeneration; integration and browser tests passed. |
| CSRF/method inconsistency | Central request guard across mutation routes; hostile no-write and method tests passed. |
| Doctor IDOR/revoked assignment access | Joined assignment-plus-active-visit authorization and transactional recheck; integration and hostile browser tests passed. |
| Audit truncation/tampering ambiguity | v2 chain, keyed head, row-coverage checks, external anchors, honest states; SQLite and real MariaDB concurrency/tamper tests passed. |
| Mutable/unbounded test tooling | Exact Composer/npm locks, separated installer privilege, digest-pinned isolated ZAP runner, validated reports and cleanup. |

The post-remediation passive scan covers only the unauthenticated URLs the
spider discovered. It does not replace authenticated RBAC/IDOR/CSRF testing,
which is supplied by PHPUnit and Playwright.

## Remaining findings and risks

1. **Apache/XAMPP runtime is unverified.** Risk: checked-in intent may differ
   from the installed Apache build or local configuration. Next action: install
   XAMPP, run `configure-xampp-apache.ps1` without skip switches, and retain the
   probe output.
2. **npm registry signatures are unverified in this environment.** Risk:
   SHA-512 authenticates the locked bytes but the registry signature layer was
   not independently checked. Next action: rerun
   `scripts\audit-dependencies.ps1` from a network where strict-TLS access to
   `registry.npmjs.org` succeeds.
3. **External rollback anchoring is operational, not automatically scheduled.**
   Until a trusted scheduler writes an independently stored anchor, rollback
   status is correctly `UNKNOWN`. Next action: schedule and separately protect
   `anchor-audit-chain.php`, its key, and its output.
4. **Admin audit pages perform repeated full-chain verification.** Risk:
   request latency grows with the append-only log and may become a
   denial-of-service concern at scale. Next action: reuse one verification
   result per request and reserve full verification for an explicit operator
   action; do not weaken current integrity semantics without tests.
5. **Local secret-file ACLs inherit from the parent directory.** Risk: another
   local account on a shared workstation may read `config/config.php`. Next
   action: add explicit Windows ACL hardening to setup.
6. **Password-reset links share the 48-hour activation TTL.** Tokens are
   single-use and hash-stored, but a shorter dedicated reset TTL is preferable.
7. **Legacy v1 audit rows remain weaker by design.** New writes are v2; v1 is
   verification compatibility only.
8. **Whole-tier compromise remains outside an in-database HMAC guarantee.** A
   compromise of the database, web filesystem, audit key, anchor key, and
   anchor storage can forge all local evidence. Operational separation is
   required.
9. **The authoritative external specification was edited outside this Git
   repository during Phase 5.** `C:\personal\Capstone\MediShield_Specification_v2.md`
   cannot be included in this branch commit and had no original backup.

## Manual steps required

1. Install/review the pinned XAMPP prerequisite as documented.
2. Run `.\scripts\configure-php-ini.ps1`.
3. Run elevated `.\scripts\configure-xampp-apache.ps1` and retain its successful
   module, syntax, header, host-routing, and exposure probes.
4. Run `.\scripts\setup-db.ps1` against the intended environment.
5. Provision the first administrator through the CLI-only provisioning command.
6. Configure production HTTPS/SMTP and separately schedule external audit
   anchoring.
7. Rerun `.\scripts\audit-dependencies.ps1` where official npm signature
   metadata is reachable over verified TLS.

## Git status

At handoff-writing time:

- Branch: `security/zap-remediation`
- Phase commits:
  - `21ff196` — `fix: harden web and maintenance boundaries`
  - `7864423` — `fix: establish early safe error handling`
  - `76082d7` — `fix: enforce assignment revocation on clinical access`
  - `95ae66a` — `fix: harden authentication and request boundaries`
  - `48b6c74` — `fix: strengthen forensic audit integrity`
  - `57e57b8` — `fix: harden runtime and dependency boundaries`
- The final Phase 7 commit carries the `HEAD`/`Allow` guard correction, its
  regressions, and these handoff documents; its hash is recorded in Git after
  this file is reviewed.
- Nothing has been pushed.
