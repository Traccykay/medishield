# `tests/` — PHP automated tests

If you are new to PHP, you do not need to understand the test code to run it.
These checks exercise the application's rules directly, such as login
protection, encryption, patient validation, and workflow state changes. Run
them after changing PHP code, or before sharing a change with someone else.

For cloning and first-time installation, start with the [root README](../README.md).

## Layout

| Folder | Contents |
|--------|----------|
| `Unit/` | Pure-logic tests with no I/O — crypto, password policy, CSRF, RBAC, and the audit hash chain. |
| `Integration/` | Tests that exercise classes against a real in-memory SQLite database through an injected `PDO`. |
| `Support/` | Shared test helpers, including `TestSchema.php`, which creates the temporary test database. |

## Running the suite

1. Open PowerShell in the repository folder.
2. Ensure PHP requirements and Composer libraries are installed:

   ```powershell
   .\scripts\configure-php-ini.ps1
   composer install
   ```

3. Run the checks:

   ```powershell
   .\vendor\bin\phpunit
   ```

A successful run ends with `OK`. These tests use a temporary in-memory
database, so they do not require MySQL and do not alter your local application
data.

Suites are defined in `../phpunit.xml` (`Unit` and `Integration`).

## Conventions for contributors

- Write a failing test before changing behavior, then make it pass.
- Database-dependent classes accept an injected `PDO`, so production code works
  with MySQL/MariaDB while these tests use SQLite.
- Use a fixed `Clock` for time-dependent logic so tests remain repeatable.
