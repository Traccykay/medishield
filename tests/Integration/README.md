# `tests/Integration/` — Database Integration Tests

These tests exercise repositories and services against a **real (in-memory
SQLite) database** through an injected `PDO`. They prove the SQL and the
service orchestration actually work end-to-end, not just in isolation.

| Test | Covers (`src/...`) |
|------|--------------------|
| `UserRepositoryTest.php` | `Auth/UserRepository` — create / find / uniqueness, failed-login counting, lock/unlock, status changes. |
| `AuthServiceTest.php` | `Auth/AuthService` — login success/failure, anti-enumeration timing, lockout at the configured threshold, `SUSPICIOUS`/`HIGH_RISK` flags, force-password-change, and **failed-login attribution** (a wrong password against a real account exposes `target_user_id`/`target_user_role` for the audit log; an unknown email does not). |
| `ActivationServiceTest.php` | `Auth/ActivationService` — hashed, expiring, single-use account-activation tokens and password validation. |
| `OtpServiceTest.php` | `Auth/OtpService` — hashed one-time codes, expiry, retries, lockout, and replacement-code invalidation. |
| `UserServiceTest.php` | `Auth/UserService` — account creation, validation, password changes, and pending-user state. |
| `SessionValidatorTest.php` | `Auth/SessionValidator` — server-side validation and revocation of preserved sessions after account deactivation, password change/reset, or malformed session data. |
| `AuditLoggerTest.php` | `Audit/AuditLogger` — append-only HMAC hash-chain writes, `verifyChain()` tamper detection, `recent()` newest-first reads with limit clamping, and the **`attempted_identifier`** column (stored/returned, defaults to NULL, and is NOT part of the hash chain so it can be scrubbed later). |
| `AuditRetentionTest.php` | `Audit/AuditRetention` — the PII scrub: `purgeIdentifiersOlderThan()` nulls `attempted_identifier` only on rows older than the cutoff, returns the affected count, **keeps `verifyChain()` ok**, and never deletes a row. |
| `PatientServiceTest.php` | `Patient/PatientService` — demographics validation, staff assignment, search, and patient/nurse/admin access rules. Doctor encounter policy is covered separately by `DoctorPatientAuthorizerTest`. |
| `DoctorPatientAuthorizerTest.php` | `Auth/DoctorPatientAuthorizer` — the assignment-plus-owned-active-visit truth table, mismatched doctor/patient/visit denial, inactive states, SQLite lock-syntax compatibility, list filtering, and immediate revocation. |
| `VisitWorkflowTest.php` | `Visit/...` — receptionist arrival, transactional nurse-to-doctor routing, atomic doctor revocation with nurse-queue recovery and rollback, unchanged nurse unassignment, availability, immediate authorization denial, and payment validation. |
| `ClinicalWorkflowTest.php` | `Clinical/...` — vital validation, encrypted clinical fields, tamper detection, lab processing, pharmacy dispensing, revocation-safe doctor mutations, pre-lookup authorization, and doctor/status-scoped order counts. |

## How the DB is provided

Each test builds a fresh schema via `tests/Support/TestSchema.php` and passes the
`PDO` into the class under test. Because production classes use portable SQL
(MySQL-only syntax is gated on the driver name), the exact same code runs here on
SQLite and in production on MySQL/MariaDB.

Run just this group: `composer test:integration`; run all PHP tests with
`composer test`.
