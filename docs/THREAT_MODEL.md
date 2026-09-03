# Phase 5 forensic audit threat model

## Assets and trust boundaries

The protected assets are the order, content, attribution, and completeness of
`audit_logs`; the current database commitment in `audit_chain_head`; and the
independent commitments in `audit_anchor_path`.

Three trust zones are intentionally separate:

1. The web process holds the audit-row key and may insert rows plus update the
   singleton head. It cannot update or delete audit rows.
2. The maintenance process can read rows and null only
   `attempted_identifier`. It has no chained-field or delete privilege.
3. The anchor writer holds a different key and writes append-only JSONL outside
   the web root. Rollback protection is credible only when that key and storage
   are administered independently from the database/application host.

## Threats, controls, and outcomes

| Threat | Control | Verification outcome |
| --- | --- | --- |
| Edit a v2 row, including IP/user agent | Canonical HMAC binds all chained fields | `FAIL` |
| Ambiguous delimiter serialization | Typed length-prefixed v2 canonical format | Distinct hashes |
| Delete or reorder a middle row | Monotonic unique `seq` plus hash linkage | `FAIL` |
| Create two children of one row | Unique `previous_hash`, locked singleton head, CAS | Write rejected / `FAIL` |
| Concurrent empty-chain writes | Head exists before writes and is locked first | Linear sequence; no genesis fork |
| Delete a suffix or all rows, leaving head | Keyed `head_mac` and head-to-row comparison | `FAIL` |
| Replace rows and head with an older valid DB snapshot | Independent monotonic anchor | `FAIL` when anchor is newer; otherwise `UNKNOWN` |
| Verify with wrong/missing key, head, anchor, or unreadable dependency | Fail-honest result model | `UNKNOWN`, never `PASS` |
| Retention of failed-login identifier | Column is outside row HMAC; bounded privileged scrub | Chain unchanged; scrub evidence appended |
| Compromise web DB identity | Exact grants deny row UPDATE/DELETE | Mutation denied and grant check audited |

## Verification semantics

- `PASS` means the complete local chain and keyed head are valid and the latest
  independent anchor exactly matches that head.
- `FAIL` requires positive evidence of mismatch, corruption, fork/gap/deletion,
  or rollback behind a newer anchor.
- `UNKNOWN` means the evidence cannot decide. Examples are a wrong key, missing
  anchor/head, dependency error, partial range/tip, or valid rows newer than the
  latest anchor.

An `INTEGRITY_VERIFIED` event is appended after the assessed tip. It records
that result but is not recursively included in the claim it describes.

## Residual limitations

- If one attacker controls the application process, filesystem, database, audit
  key, anchor key, and anchor storage, they can forge all local evidence.
- An anchor protects only through its sequence; newer unanchored rows remain an
  explicit `UNKNOWN`.
- Audit logging is evidence, not transaction rollback. Domain services commit
  first. A failed post-commit append is emitted as structured operational
  telemetry and returned as failure to critical callers; it does not silently
  undo or falsely deny the committed clinical/payment write.
- `attempted_identifier` is intentionally mutable PII and is not covered by the
  row HMAC. Only the maintenance identity may null it.
