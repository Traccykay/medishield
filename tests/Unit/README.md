# `tests/Unit/` — Pure-logic Unit Tests

Fast, deterministic tests with **no database or filesystem I/O**. They cover the
security-critical building blocks in isolation:

| Test | Covers (`src/...`) |
|------|--------------------|
| `CryptoTest.php` | `Security/Crypto` — AES-256-GCM round-trip, tamper detection, key-length validation. |
| `PasswordPolicyTest.php` | `Security/PasswordPolicy` — length / character-class rules, email-equality rejection. |
| `CsrfTest.php` | `Security/Csrf` — token generation and constant-time verification. |
| `RbacTest.php` | `Auth/Rbac` — role validity, area access, dashboard routing, admin-only user management. |
| `AuditChainTest.php` | `Security/AuditChain` — HMAC-SHA256 hash computation and chain linkage. |

These tests need no `config.php` and no running database. Run the whole suite
with `vendor\bin\phpunit`, or just this group with
`vendor\bin\phpunit --testsuite Unit`.
