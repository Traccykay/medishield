# `src/Security/` — Security Primitives

The cryptographic and anti-abuse building blocks of MediShield. Each class is
small, single-purpose, and unit-tested.

| Class | Responsibility | Spec |
|-------|----------------|------|
| `PasswordPolicy` | Validates password strength rules (length, character classes, not-equal-to-email). Does **not** hash. | §9.1 |
| `Csrf` | Generates and timing-safely verifies per-session CSRF tokens for forms. | §17 |
| `Crypto` | AES-256-GCM authenticated encryption/decryption of sensitive clinical fields. Tampered ciphertext fails to decrypt. | §11 |
| `AuditChain` | Computes the HMAC-SHA256 hash-chain value for an audit-log row, making the log tamper-evident. | §9.8 |

## Key rules
- **Passwords are hashed, never encrypted** (`password_hash`/`password_verify`),
  and never pass through `Crypto`.
- `Crypto` and `AuditChain` use **separate** keys (`encryption_key_hex` vs
  `audit_hmac_key_hex` in config).
- These classes hold no global state and never touch `$_SESSION`/`$_POST`
  directly — callers pass data in — which is what keeps them testable.
