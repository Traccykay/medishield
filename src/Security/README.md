# `src/Security/` — Security Primitives

The cryptographic and anti-abuse building blocks of MediShield. Each class is
small, single-purpose, and unit-tested.

| Class | Responsibility | Spec |
|-------|----------------|------|
| `PasswordPolicy` | Validates password strength rules (length, character classes, not-equal-to-email). Does **not** hash. | §9.1 |
| `Csrf` | Generates and timing-safely verifies per-session CSRF tokens for forms. | §17 |
| `Crypto` | AES-256-GCM authenticated encryption/decryption of sensitive clinical fields. Tampered ciphertext fails to decrypt. | §11 |
| `AuditChain` | Computes legacy v1 hashes, canonical v2 row HMACs, and keyed-head MACs that authenticate the stored key check. Enforces a 32-byte minimum key. | §9.8 |
| `RequestThrottle` | Persists fixed-window request budgets under an HMAC-derived action/IP scope; raw IP addresses are not stored. | STRIDE DoS |
| `TransportSecurity` | Accepts direct HTTPS or a forwarding header from an explicitly trusted TLS proxy only. | STRIDE tampering/disclosure |

## Key rules
- **Passwords are hashed, never encrypted** (`password_hash`/`password_verify`),
  and never pass through `Crypto`.
- `Crypto`, `AuditChain`, external audit anchors, and `RequestThrottle` use four
  distinct keys. Bootstrap rejects short, malformed, or reused keys.
- These classes hold no global state and never touch `$_SESSION`/`$_POST`
  directly — callers pass data in — which is what keeps them testable.
- `TransportSecurity` must not be configured with public client IPs. A trusted
  proxy is an infrastructure hop that terminates TLS and overwrites
  `X-Forwarded-Proto`, not a browser.
