# `src/Audit/` — Forensic Audit Logging

| Class | Responsibility |
|-------|----------------|
| `AuditLogger` | Appends tamper-evident rows to `audit_logs` and verifies the chain. Each write is serialized in a transaction (locks the chain tip on MySQL) so the HMAC hash chain never breaks under concurrency. Provides `verifyChain()` for the integrity check. |
| `AuditRetention` | **Privileged maintenance** component that scrubs PII (`attempted_identifier`) from rows older than the retention window, WITHOUT touching the hash chain. The single, deliberate exception to the append-only rule — see below. |

Works hand-in-hand with `Security\AuditChain` (which computes the per-row HMAC).
`AuditLogger` is **append-only** — it has no update/delete methods by design (spec §9.8).

```php
$logger->log([
    'user_id' => 1, 'user_role' => 'admin',
    'action' => 'USER_CREATED', 'module' => 'User Management',
    'affected_record_id' => 42, 'ip_address' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
    'status' => 'SUCCESS', 'anomaly_flag' => 'NORMAL',
]);
```

## `attempted_identifier` — capturing the typed email on failed logins

A failed login records the email/username that was typed in
`audit_logs.attempted_identifier`. This works even when the email matches **no
account** (an unknown attacker email) — giving an administrator the only
identifier available to follow up on possibly-leaked credentials ("who did
what"). `login.php` passes it on `LOGIN_FAILED` and `CSRF_REJECTED`.

This column is **deliberately excluded from the HMAC hash chain**
(`AuditLogger::log()` builds `$entry` for `computeHash()` from the other fields
only). That single design choice is what makes the PII scrub safe.

## PII retention scrub (`AuditRetention`)

`attempted_identifier` is personal data, so we must not keep it forever.
`AuditRetention::purgeIdentifiersOlderThan($cutoff)` sets it to `NULL` on rows
older than the cutoff and returns the count. Because the column is outside the
hash chain, nulling it **does not change any `current_hash`** and
`verifyChain()` still returns ok. It **never deletes a row** and **never edits a
chained field** — the forensic "who/when" record survives; only the personal
identifier is removed.

It lives in a separate class (not on `AuditLogger`) on purpose:

- It is invoked only by the out-of-band maintenance task
  `scripts/purge-audit-pii.php` (cron / Task Scheduler), never by a web request.
- It needs a DB account with `UPDATE` on `audit_logs`; the application's own DB
  user is granted only `SELECT`+`INSERT`, so the scrub cannot be triggered from
  the request path even if the app were compromised.

The retention window is `audit.pii_retention_days` in `config/config.php`
(default 90).

### Tradeoffs & decisions (for the team)

- **Store the email vs. hash/anonymise it.** We store it in clear so an admin can
  actually read and act on it. We accept that risk and bound it with a time-boxed
  scrub instead of permanent retention.
- **Outside the hash chain vs. inside it.** Inside the chain, scrubbing PII would
  recompute/break every downstream hash and destroy tamper-evidence. Outside the
  chain, the integrity guarantee covers the forensic facts while the PII stays
  independently removable. This is the key tradeoff that makes "keep it, then
  clean it" possible.
- **Separate maintenance class + restricted DB grant vs. a method on the logger.**
  Keeping the only mutation path out of request code preserves the simple,
  auditable invariant "the app never edits audit rows", and defence-in-depth (the
  app's DB user physically cannot run the UPDATE).
