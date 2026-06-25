# `tests/Integration/` — Database Integration Tests

These tests exercise repositories and services against a **real (in-memory
SQLite) database** through an injected `PDO`. They prove the SQL and the
service orchestration actually work end-to-end, not just in isolation.

| Test | Covers (`src/...`) |
|------|--------------------|
| `UserRepositoryTest.php` | `Auth/UserRepository` — create / find / uniqueness, failed-login counting, lock/unlock, status changes. |
| `AuthServiceTest.php` | `Auth/AuthService` — login success/failure, anti-enumeration timing, lockout at the configured threshold, `SUSPICIOUS`/`HIGH_RISK` flags, force-password-change. |
| `UserServiceTest.php` | `Auth/UserService` — admin user creation: validation, password policy, unique email, hashing. |
| `AuditLoggerTest.php` | `Audit/AuditLogger` — append-only HMAC hash-chain writes and `verifyChain()` tamper detection. |

## How the DB is provided

Each test builds a fresh schema via `tests/Support/TestSchema.php` and passes the
`PDO` into the class under test. Because production classes use portable SQL
(MySQL-only syntax is gated on the driver name), the exact same code runs here on
SQLite and in production on MySQL/MariaDB.

Run just this group: `vendor\bin\phpunit --testsuite Integration`.
