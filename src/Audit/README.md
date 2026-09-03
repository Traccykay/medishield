# `src/Audit/` - forensic audit subsystem

| Class | Responsibility |
| --- | --- |
| `AuditLogger` | Owns each append transaction, locks the singleton head first, writes one v2 row, and advances the keyed head with a compare-and-swap guard. Provides bounded tip/range/full verification. |
| `AuditChainInitializer` | Idempotently verifies historical v1 rows, assigns deterministic metadata in `log_id` order without rewriting hashes, and creates the keyed singleton head. |
| `AuditAnchorStore` | Writes monotonic, idempotent, separately keyed JSONL head commitments outside the web root and compares them with the database head. |
| `AuditRetention` | Uses bounded, replay-safe transactions to null only expired `attempted_identifier` values. |
| `AuditRetentionPolicy` | Strictly parses retention CLI options and enforces the configured minimum retention floor and batch bound. |

`Security\AuditChain` performs cryptography. It rejects keys shorter than 32
bytes and retains the original v1 algorithm solely for existing rows.

## v2 row commitment

Every new row stores `seq`, `event_id`, `key_id`, and `format_version=2`.
The HMAC uses a domain-separated, type-aware, length-prefixed encoding over:

`format_version`, `seq`, `event_id`, `key_id`, `user_id`, `user_role`,
`action`, `module`, `affected_record_id`, `ip_address`, `user_agent`, `status`,
`anomaly_flag`, `created_at`, and `previous_hash`.

Length prefixes remove the ambiguity of v1's `|` delimiter. Null and empty
string are distinct. `attempted_identifier` remains deliberately outside the
chain so the retention task can remove that PII without rewriting forensic
history.

## Atomic append and failure behavior

`AuditLogger::log()` refuses a caller-owned transaction. It begins its own
transaction, locks `audit_chain_head` first (`FOR UPDATE` on MySQL/MariaDB;
`BEGIN IMMEDIATE` on SQLite), validates the authenticated `key_check` and
`head_mac`, inserts one row, then advances the head with a bounded
compare-and-swap. The head MAC covers `key_check`, the last sequence (which is
the expected contiguous row count), tip hash, key id, format version, and
update time. Unique `seq`, `event_id`, and
`previous_hash` constraints prevent gaps, duplicate retries, and forks;
`CHECK (seq >= 1)` rejects non-positive physical rows. Retryable
lock/deadlock conflicts are retried a bounded number of times.

Domain services commit independently. A later audit failure must never roll
back or falsely report an already-committed clinical/payment change.
`ms_audit_log()` therefore returns `false` and emits a PHI-free structured
`AUDIT_APPEND_FAILED` diagnostic. Authentication completion is the stricter
case: if `LOGIN_SUCCESS` cannot be appended after MFA/session regeneration,
the new session is destroyed and access remains denied.

## Verification states

- `PASS`: all requested evidence was cryptographically checked. Overall
  `verifyChain()` reaches `PASS` only when the independent anchor exactly
  matches the valid database head.
- `FAIL`: evidence proves a row/hash/link/sequence/head/anchor mismatch or a
  rollback behind a newer external anchor.
- `UNKNOWN`: verification could not decide, including wrong keys, missing
  head/anchor, read errors, partial tip/range checks, or an unanchored suffix.

`verifyLocalFull()` can return `PASS` for database-local consistency, but that
does not claim whole-database rollback resistance. Before bounded hash batches,
it compares the physical row `COUNT`, `MIN(seq)`, and `MAX(seq)` with the
authenticated head so zero, negative, or above-head rows cannot be omitted.
Every full, tip, range, and anchored verification owns a read transaction:
MySQL/MariaDB explicitly uses a read-only `REPEATABLE READ` transaction with a
consistent snapshot, while SQLite uses a deferred read transaction. File-backed
SQLite must use WAL so concurrent appends can commit during a long scan;
rollback-journal mode returns `UNKNOWN / CONSISTENT_SNAPSHOT_UNAVAILABLE`
instead of taking a long-lived read lock. In-memory SQLite remains supported.
Head, coverage, row batches, and anchor comparison therefore describe one
database version. Verification called from a caller-owned transaction returns
the same `UNKNOWN` reason without committing or rolling back that transaction,
because its isolation level and snapshot age cannot be proven.

An actual wrong configured key remains `UNKNOWN`; an unchanged head MAC
recomputed with the expected key check is positive evidence that key-check-only
corruption is `FAIL`. Structural/linkage evidence is evaluated before any
wrong-key classification, and malformed row-format metadata is `FAIL` once the
configured key is established. Tip/range verification is bounded and returns
`UNKNOWN` when omitted history prevents a complete claim. UI and CLI surfaces
render only safe reason codes, never exception text or key material. The admin
UI quarantines recent rows whenever local verification is not `PASS`, and
`recent()` returns rows only from the same transaction snapshot that passed
local verification, excluding sequences outside the head's committed
`1..last_seq` range.

The admin audit route classifies verification evidence by what actually
happened. `PASS` is `SUCCESS/NORMAL`; positive `FAIL` evidence is
`FAILED/HIGH_RISK`; inability to perform or authenticate verification is
`FAILED/SUSPICIOUS`. `EXTERNAL_ANCHOR_MISSING` and
`UNANCHORED_DATABASE_SUFFIX` are expected freshness limitations after a
successful local verification, so they are `SUCCESS/NORMAL`, not attacks or
blocked operations. A suffix result is not appended as another
`INTEGRITY_VERIFIED` row because that self-referential event would extend the
very suffix it reports. `AUDIT_LOGS_VIEWED` is still recorded, so normal
application activity can correctly make the latest external anchor stale until
the independently administered anchor schedule advances it.

## External anchors and limitations

Run `php scripts\anchor-audit-chain.php` on a trusted schedule. The configured
`audit_anchor_path` is outside `public/`; each JSONL record has an increasing
sequence, the database head, an anchor-chain link, key check, and MAC under the
separate `audit_anchor_hmac_key_hex`. Repeating the same head is a no-op.

The file is independent evidence only if its storage administration and key are
independent from the database/application host. If an attacker controls the
application, filesystem, database, and both keys, this design cannot prove
authenticity. It also cannot detect rollback newer than the latest anchor.
Setup deliberately does not create an initial anchor: a file created
automatically by the same application host and administrator would not establish
an independent trust boundary. Deployment must schedule the anchor command onto
separately administered storage.

## Retention and grants

`scripts/purge-audit-pii.php` validates the local chain before and after bounded
scrub batches, refuses a `--days` value below
`audit.minimum_pii_retention_days`, and writes one chained
`AUDIT_PII_SCRUBBED` event containing only the row count. A post-commit event
failure exits non-zero so the evidence gap is never silent; rerunning the scrub
is safe because already-null rows are skipped.

`scripts/verify-audit-grants.php` compares exact schema/table/column metadata
and performs rolled-back empirical probes. A successful run appends
`AUDIT_GRANTS_VERIFIED`.
