# `tests/` — PHP automated tests

If you are new to PHP, you do not need to understand the test code to run it.
These checks exercise application rules directly, such as login protection,
encryption, patient validation, and workflow state changes. They complement
the real-browser suites in [`../e2e/`](../e2e/): unit and integration tests
make failures quick to diagnose, while browser tests verify the actual request
and rendering boundary.

For cloning and first-time installation, start with the [root README](../README.md).

## Layout

| Folder | Contents |
|--------|----------|
| `Unit/` | Isolated security and validation tests — crypto, password policy, CSRF, RBAC, audit-chain logic, local mail delivery, and trusted-proxy HTTPS decisions. |
| `Integration/` | Tests that exercise classes against a real in-memory SQLite database through an injected `PDO`. |
| `Support/` | Shared test helpers, including `TestSchema.php`, which creates the temporary test database. |

The two PHPUnit suites cover the same production classes from different
angles:

- **Unit** checks isolated controls such as encryption integrity, password
  rules, CSRF verification, RBAC decisions, audit hashes, local mail delivery,
  fail-closed production bootstrap/mail configuration, credential-free setup,
  disposable-database allowlisting, local URL validation, the router allowlist,
  a raw-socket PHP development-server subprocess, and checked-in Apache/CLI
  boundaries.
- **Integration** checks stateful services and SQL with a clean SQLite
  database: account activation and OTP, login lockout, IP-scoped request
  throttling, replay-safe initial-admin provisioning, session revocation, audit
  logging and retention, snapshot-consistent verification, user/patient
  authorization, visits, and clinical workflow data. Opt-in MariaDB tests add
  real audit-writer and lab-result row-lock contention.

Browser suites live in [`../e2e/`](../e2e/) and are deliberately separate
because they need PHP, MySQL/MariaDB, and Chromium:

- **Workflow regression** follows normal staff workflows through the rendered
  application.
- **Security hostile-path harness** sends attacker-style requests and validates
  the safe outcome: authorization denial without patient disclosure, centralized
  method/CSRF rejection across every mutation controller without a write,
  malformed array rejection without coercion or a 500 response, hostile markup
  rendered as text, applied stylesheet/MIME/cache behavior, router exposure and
  traversal denial, unique required response headers, 303 POST redirects,
  generic login failures that do not enumerate accounts, and password-reset
  throttling with no follow-on email.
- **OWASP ZAP passive baseline** independently spiders the disposable UI site
  and reports passive HTTP findings. It needs Docker Desktop; see
  [`../SECURITY_TESTING.md`](../SECURITY_TESTING.md).

## Running the suite

1. Open PowerShell in the repository folder.
2. Ensure PHP requirements and Composer libraries are installed:

   ```powershell
   .\scripts\configure-php-ini.ps1
   composer install
   ```

3. Run the checks:

   ```powershell
   composer test
   ```

A successful run ends with `OK`. These tests use a temporary in-memory
database, so they do not require MySQL and do not alter your local application
data.

Run one PHP suite when iterating:

```powershell
composer test:unit
composer test:integration
```

Suites are defined in `../phpunit.xml` (`Unit` and `Integration`). For the
browser workflow and hostile-path harness, run the reusable isolated runner:

```powershell
.\scripts\run-ui-tests.ps1
```

To focus only on the hostile-path harness after its browser prerequisites are
available:

```powershell
.\node_modules\.bin\playwright.cmd test request-boundary security-hostile
```

To run OWASP ZAP after Docker Desktop is running:

```powershell
npm run test:zap
```

Audit both exact lock files without executing npm lifecycle scripts:

```powershell
.\scripts\audit-dependencies.ps1
```

## Conventions for contributors

- Write a failing test before changing behavior, then make it pass.
- Database-dependent classes accept an injected `PDO`, so production code works
  with MySQL/MariaDB while these tests use SQLite.
- Use a fixed `Clock` for time-dependent logic so tests remain repeatable.
- For security-relevant work, add a hostile-path test alongside the expected
  behavior. Assert both the rejection and the protected side effect: no
  unauthorized record data, no state mutation after CSRF failure, no executable
  markup, or no account-identifying error.
