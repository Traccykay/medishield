# `tests/Support/` — Shared Test Helpers

Reusable helpers used by the test suites. They are not tests themselves.

| File | Responsibility |
|------|----------------|
| `bootstrap_config_probe.php` | Subprocess entry point that injects isolated configuration into the real bootstrap and marks any DB/credential/mail continuation for ordering assertions. |
| `TestSchema.php` | Builds the application schema in memory or in a WAL-backed named SQLite file, including forensic row/head constraints and non-blocking audit-snapshot tests. |
| `audit_concurrency_worker.php` | Bounded subprocess writer used only by the opt-in real MariaDB concurrency test. |

## Conventions

- Keep helpers thin and side-effect-free; they should make tests easier to read,
  not hide behaviour under test.
- When `sql/schema.sql` changes in a way the tests depend on, update the matching
  DDL here so the in-memory schema stays representative.
