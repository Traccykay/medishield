# `tests/Support/` — Shared Test Helpers

Reusable helpers used by the test suites. They are not tests themselves.

| File | Responsibility |
|------|----------------|
| `TestSchema.php` | Builds the database schema (currently `users` and `audit_logs`) inside an in-memory SQLite `PDO`, so integration tests get a clean, isolated database without needing a running MySQL/MariaDB server. The DDL mirrors the relevant parts of `sql/schema.sql` using portable types. |

## Conventions

- Keep helpers thin and side-effect-free; they should make tests easier to read,
  not hide behaviour under test.
- When `sql/schema.sql` changes in a way the tests depend on, update the matching
  DDL here so the in-memory schema stays representative.
