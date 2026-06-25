# `src/Audit/` — Forensic Audit Logging

| Class | Responsibility |
|-------|----------------|
| `AuditLogger` | Appends tamper-evident rows to `audit_logs` and verifies the chain. Each write is serialized in a transaction (locks the chain tip on MySQL) so the HMAC hash chain never breaks under concurrency. Provides `verifyChain()` for the integrity check. |

Works hand-in-hand with `Security\AuditChain` (which computes the per-row HMAC).
The logger is **append-only** — it has no update/delete methods by design (spec §9.8).

```php
$logger->log([
    'user_id' => 1, 'user_role' => 'admin',
    'action' => 'USER_CREATED', 'module' => 'User Management',
    'affected_record_id' => 42, 'ip_address' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
    'status' => 'SUCCESS', 'anomaly_flag' => 'NORMAL',
]);
```
