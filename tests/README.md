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
| `Unit/` | Isolated security and validation tests — crypto, password policy, CSRF, RBAC, audit-chain logic, and local mail delivery. |
| `Integration/` | Tests that exercise classes against a real in-memory SQLite database through an injected `PDO`. |
| `Support/` | Shared test helpers, including `TestSchema.php`, which creates the temporary test database. |

The two PHPUnit suites cover the same production classes from different
angles:

- **Unit** checks isolated controls such as encryption integrity, password
  rules, CSRF verification, RBAC decisions, audit hashes, and local mail
  delivery.
- **Integration** checks stateful services and SQL with a clean SQLite
  database: account activation and OTP, login lockout, session revocation,
  audit logging and retention, user/patient authorization, visits, and
  clinical workflow data.

Browser suites live in [`../e2e/`](../e2e/) and are deliberately separate
because they need PHP, MySQL/MariaDB, and Chromium:

- **Workflow regression** follows normal staff workflows through the rendered
  application.
- **Security hostile-path harness** sends attacker-style requests and validates
  the safe outcome: authorization denial without patient disclosure,
  CSRF rejection without a write, hostile markup rendered as text, required
  response headers, and generic login failures that do not enumerate accounts.

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
npx.cmd playwright test e2e\security-hostile.spec.js
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
