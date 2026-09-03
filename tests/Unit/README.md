# `tests/Unit/` — Pure-logic Unit Tests

Fast, deterministic tests with no database dependency. They cover
security-critical building blocks in isolation; `LogMailerTest` uses a
temporary mail-dump directory to verify the local delivery adapter:

| Test | Covers (`src/...`) |
|------|--------------------|
| `CryptoTest.php` | `Security/Crypto` — AES-256-GCM round-trip, tamper detection, key-length validation. |
| `PasswordPolicyTest.php` | `Security/PasswordPolicy` — 12-character minimum, character-class rules, and email-equality rejection. |
| `CsrfTest.php` | `Security/Csrf` — token generation and constant-time verification. |
| `RequestGuardTest.php` | `includes/guard.php` — terminating method/CSRF rejection, safe actor attribution, exactly-one audit attempts, and fail-closed behavior when audit storage fails. |
| `RbacTest.php` | `Auth/Rbac` — role validity, area access, dashboard routing, admin-only user management. |
| `AuditChainTest.php` | `Security/AuditChain` — stable v1/v2 vectors, domain-separated length-prefix ambiguity resistance, null/empty distinction, sequence/key/network/agent binding, a keyed-head MAC that authenticates `key_check`, and minimum key length. |
| `AuditRetentionPolicyTest.php` | `Audit/AuditRetentionPolicy` — strict CLI option parsing, duplicate/unknown rejection, retention floor, and bounded batch size. |
| `LogMailerTest.php` | `Mail/LogMailer` — safe local mail-dump creation and message writing. |
| `MailerFactoryTest.php` | `Mail/MailerFactory` — exact transport selection, production log rejection, and no unknown/missing fallback. |
| `BootstrapConfigValidatorTest.php` | `Support/BootstrapConfigValidator` — distinct >=32-byte encryption/audit/anchor/throttle keys, safe anchor path, development/test log compatibility, and production SMTP/HTTPS requirements. |
| `BootstrapConfigurationTest.php` | Real bootstrap subprocesses — validation ordering, generic browser failures with no sensitive output, no DB/token/mail continuation on rejection, production SMTP/HTTPS acceptance, and development log delivery. |
| `DisposableDatabaseTest.php` | `Support/DisposableDatabase` — UI seeds accept only named disposable databases, while setup helpers accept the configured target or a named disposable target and reject arbitrary overrides. |
| `ClockTest.php` | `Support/Clock` — exact UTC database timestamp parsing rejects missing, non-canonical, and normalized-impossible values. |
| `DeploymentBoundaryTest.php` | Checked-in Apache rules, strict/cookie-only session bootstrap ordering, CLI-only maintenance-script guards, credential-free production setup, explicit initial-admin confirmation, selected-database propagation, and subprocess enforcement by disposable migration/seed helpers. |
| `SetupConfigUpgradeTest.php` | Real PowerShell config generation/upgrades — disposable setup cannot persist disposable database names, normal setup repairs only maintenance-name drift, existing secrets are preserved, and fresh normal generation keeps both database blocks aligned. |
| `ApacheConfiguratorTest.php` | PowerShell 5.1/7 native-command compatibility, generated vhost/listener boundaries, denied-response inspection, and rollback command routing. |
| `ErrorBoundaryTest.php` | Subprocess failures prove early bootstrap/configuration diagnostics are logged but never rendered, while scalar secret arguments are omitted from exception traces. |
| `ToolchainHardeningTest.php` | PHP 8.1 Composer lock compatibility, exact npm provenance, locked audits, installer privilege/source boundaries, local Playwright invocation, and pinned/isolated ZAP lifecycle behavior. |

These tests need no `config.php` and no running database. Run the whole suite
with `composer test`, or just this group with `composer test:unit`.
