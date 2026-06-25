# `tests/` — Automated Test Suite (TDD)

MediShield is built test-first. Every behaviour in `src/` has a corresponding
test here, and the suite must be green before any commit.

## Layout

| Folder | Contents |
|--------|----------|
| `Unit/` | Pure-logic tests with no I/O — crypto, password policy, CSRF, RBAC, audit hash chain. Fast and deterministic. |
| `Integration/` | Tests that exercise classes against a real (in-memory SQLite) database via an injected `PDO` — repositories and services. |
| `Support/` | Shared test helpers (e.g. `TestSchema.php`, which builds the SQLite schema the integration tests run against). |

## Running the suite

```powershell
# One-time / after pulling new extension requirements:
scripts\configure-php-ini.ps1

composer install
vendor\bin\phpunit
```

Suites are defined in `../phpunit.xml` (`Unit` and `Integration`). Current
baseline: **46 tests passing**.

## Conventions

- **Write a failing test first, then implement** (red → green → refactor).
- DB-dependent classes accept an injected `PDO`, so the same production code runs
  against MySQL/MariaDB in prod and in-memory SQLite in tests. Use portable SQL;
  gate MySQL-only syntax (e.g. `FOR UPDATE`) on the PDO driver name.
- Use a fixed `Clock` for time-dependent logic (lockout windows, timestamps) so
  tests are deterministic.
- Namespaces map PSR-4 `MediShield\Tests\` → `tests/`.
