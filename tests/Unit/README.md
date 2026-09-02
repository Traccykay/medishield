# `tests/Unit/` — Pure-logic Unit Tests

Fast, deterministic tests with no database dependency. They cover
security-critical building blocks in isolation; `LogMailerTest` uses a
temporary mail-dump directory to verify the local delivery adapter:

| Test | Covers (`src/...`) |
|------|--------------------|
| `CryptoTest.php` | `Security/Crypto` — AES-256-GCM round-trip, tamper detection, key-length validation. |
| `PasswordPolicyTest.php` | `Security/PasswordPolicy` — length / character-class rules, email-equality rejection. |
| `CsrfTest.php` | `Security/Csrf` — token generation and constant-time verification. |
| `RbacTest.php` | `Auth/Rbac` — role validity, area access, dashboard routing, admin-only user management. |
| `AuditChainTest.php` | `Security/AuditChain` — HMAC-SHA256 hash computation and chain linkage. |
| `LogMailerTest.php` | `Mail/LogMailer` — safe local mail-dump creation and message writing. |
| `DisposableDatabaseTest.php` | `Support/DisposableDatabase` — UI seed scripts accept only named disposable databases. |
| `DeploymentBoundaryTest.php` | Checked-in Apache rules and CLI-only maintenance-script entry guards. |
| `ApacheConfiguratorTest.php` | PowerShell 5.1/7 native-command compatibility, generated vhost/listener boundaries, denied-response inspection, and rollback command routing. |
| `ErrorBoundaryTest.php` | Subprocess failures prove early bootstrap/configuration diagnostics are logged but never rendered, while scalar secret arguments are omitted from exception traces. |

These tests need no `config.php` and no running database. Run the whole suite
with `composer test`, or just this group with `composer test:unit`.
