# `tests/Integration/` — Database Integration Tests

These tests exercise repositories and services against a **real (in-memory
SQLite) database** through an injected `PDO`. They prove the SQL and the
service orchestration actually work end-to-end, not just in isolation.

| Test | Covers (`src/...`) |
|------|--------------------|
| `UserRepositoryTest.php` | `Auth/UserRepository` — create/find, lockout counters, monotonic auth epochs, role/status/password revocation, atomic OTP invalidation, and rollback on failure. |
| `AuthServiceTest.php` | `Auth/AuthService` — one externally visible failure state across unknown, inactive, wrong-password, fifth-attempt, and locked accounts while preserving precise internal outcomes, attribution, anomaly flags, and lock audit action. |
| `ActivationServiceTest.php` | `Auth/ActivationService` — hashed, expiring, conditionally single-use activation/reset tokens, transactional credential updates, and rollback on OTP-invalidation failure. |
| `InitialAdminProvisionerTest.php` | `Auth/InitialAdminProvisioner` — inactive initial-admin creation, activation delivery, replay no-op, existing-admin preservation, hostile input rejection, and rollback on delivery failure. |
| `OtpServiceTest.php` | `Auth/OtpService` — hashed one-time codes, transactional conditional consumption, expiry burning, retries, lockout burning, replay denial, and replacement-code invalidation. |
| `UserServiceTest.php` | `Auth/UserService` — account creation, validation, password changes, and pending-user state. |
| `SessionValidatorTest.php` | `Auth/SessionValidator` — pending-MFA age/state binding plus server-side epoch revocation after password, status, role, or lock transitions; malformed timestamps fail closed. |
| `AuditLoggerTest.php` | `Audit/AuditLogger` — v2 appends, authenticated key-check/head enforcement, correct-key tamper versus wrong-key classification, complete physical sequence coverage, format downgrade precedence, same-snapshot recent-row quarantine, local and partial PASS/FAIL/UNKNOWN verification, caller-transaction rejection, two file-backed SQLite connections, and non-chained `attempted_identifier`. |
| `AuditMigrationTest.php` | `Audit/AuditChainInitializer` — deterministic missing-v1 metadata, byte-for-byte historical HMAC preservation, no renumbering of pre-existing sequence metadata, idempotent initialization, and a valid keyed head. |
| `AuditAnchorStoreTest.php` | `Audit/AuditAnchorStore` — monotonic/idempotent JSONL anchors, wrong-key UNKNOWN, unanchored-suffix UNKNOWN, and whole-database rollback FAIL. |
| `AuditRetentionTest.php` | `Audit/AuditRetention` — bounded/idempotent PII scrub batches that null only `attempted_identifier`, preserve rows, and keep local verification PASS. |
| `MariaDbAuditConcurrencyTest.php` | Opt-in real MariaDB proof: migration twice, v1 preservation, fresh and upgrade-path positive-sequence constraints, refusal without repair of a pre-existing zero sequence, `ascii_bin`/unique schema checks, and two concurrent append processes. |
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
