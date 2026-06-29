# `tests/Integration/` — Database Integration Tests

These tests exercise repositories and services against a **real (in-memory
SQLite) database** through an injected `PDO`. They prove the SQL and the
service orchestration actually work end-to-end, not just in isolation.

| Test | Covers (`src/...`) |
|------|--------------------|
| `UserRepositoryTest.php` | `Auth/UserRepository` — create / find / uniqueness, failed-login counting, lock/unlock, status changes. |
| `AuthServiceTest.php` | `Auth/AuthService` — login success/failure, anti-enumeration timing, lockout at the configured threshold, `SUSPICIOUS`/`HIGH_RISK` flags, force-password-change, and **failed-login attribution** (a wrong password against a real account exposes `target_user_id`/`target_user_role` for the audit log; an unknown email does not). |
| `UserServiceTest.php` | `Auth/UserService` — admin user creation (validation, password policy, unique email, hashing) and `changePassword()` (verifies current password, enforces policy, rejects reuse). |
| `AuditLoggerTest.php` | `Audit/AuditLogger` — append-only HMAC hash-chain writes, `verifyChain()` tamper detection, `recent()` newest-first reads with limit clamping, and the **`attempted_identifier`** column (stored/returned, defaults to NULL, and is NOT part of the hash chain so it can be scrubbed later). |
| `AuditRetentionTest.php` | `Audit/AuditRetention` — the PII scrub: `purgeIdentifiersOlderThan()` nulls `attempted_identifier` only on rows older than the cutoff, returns the affected count, **keeps `verifyChain()` ok**, and never deletes a row. |

## How the DB is provided

Each test builds a fresh schema via `tests/Support/TestSchema.php` and passes the
`PDO` into the class under test. Because production classes use portable SQL
(MySQL-only syntax is gated on the driver name), the exact same code runs here on
SQLite and in production on MySQL/MariaDB.

Run just this group: `vendor\bin\phpunit --testsuite Integration`.
