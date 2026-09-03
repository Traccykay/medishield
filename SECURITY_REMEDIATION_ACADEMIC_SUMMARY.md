# MediShield Security Remediation: Academic Summary

## Project purpose

MediShield is a seven-role healthcare-records demonstration built in plain PHP,
PDO, and MariaDB. The remediation work was designed to make each control easy
to explain and prove:

> Threat identified → control implemented → attack/test attempted → response
> observed → forensic evidence retained.

## Demonstrable security stories

| Threat | Control | Test or attack | Observed result | Evidence |
| --- | --- | --- | --- | --- |
| Source, configuration, log, or maintenance-script disclosure | `public/` web root, root protection, explicit route/asset allowlist, CLI-only scripts | Requests for `/.git/config`, `/scripts/setup-db.ps1`, traversal, backups, and unknown paths | Controlled 403/404; no sensitive content | Built-in runtime tests, manual HTTP matrix, Playwright hostile paths |
| Stack trace, SQL, path, or secret disclosure | Error boundary before normal bootstrap; production PHP diagnostics disabled | Bootstrap/database failures and malformed requests | Generic browser response; detail logged server-side | Error-boundary PHPUnit tests and hostile browser tests |
| Default/shared administrator compromise | No normal seed administrator; CLI-only inactive first-admin provisioning | Fresh setup and repeated provisioning | No usable default credential; one-time activation path | Provisioner integration tests |
| Login enumeration and replay | Uniform login failures, dummy hash, throttling, hashed OTP, single-use redemption | Invalid users/passwords/OTP reuse and request storms | Same visible error, bounded attempts, replay denied | Auth/OTP/throttle PHPUnit and Playwright tests |
| Stale session after role/status/password change | Monotonic `auth_version` bound to pending MFA and authenticated sessions | Change authoritative account state during a session | Old session and pending MFA rejected | Session integration and browser tests |
| Long-lived password-reset link | Dedicated 60-minute active-account reset lifetime, independent of 48-hour inactive-account activation | Check at 59/60 minutes and replay after use | Valid inside reset window; expired at cutoff; activation unchanged; replay denied | Activation-service integration tests |
| CSRF or wrong-method mutation | Central POST/CSRF guard | Missing/wrong/array token, GET on action-only routes, unsupported methods | 403/405 before mutation; `CSRF_REJECTED` audit | Request-guard PHPUnit and browser matrix |
| Doctor IDOR after assignment revocation | Current assignment **and** active visit required; transactional recheck | Change patient/visit IDs and revoke assignment mid-workflow | Access denied; visit returns to nurse queue; capacity released | Authorization/workflow integration and hostile browser tests |
| Stored XSS | Central output escaping with `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` | Store HTML/script-shaped clinical input | Payload rendered as text, not executed | Playwright hostile XSS scenario |
| SQL injection | PDO prepared statements and bound parameters | Injection-shaped login/search/form values | Query structure unchanged; no unauthorized result | Unit/integration/browser tests and source review |
| Concurrent duplicate lab result | Conditional database claim of the exact pending request plus unique result constraint | Two pre-connected MariaDB workers contend behind a held row lock | Both reach contention; exactly one completes the request and inserts one result | SQLite workflow tests and real MariaDB concurrency test |
| Audit edit, fork, gap, truncation, or rollback ambiguity | v2 HMAC records, keyed head, sequence coverage, consistent snapshots, external anchors | Row edits/deletes, suffix removal, concurrent writers, rollback evidence removal | `FAIL` for proven tampering; `UNKNOWN` when external proof is absent; never false `PASS` | Audit PHPUnit, migration tests, real MariaDB concurrency suite |
| Scanner/toolchain drift | Exact dependency locks, SHA-512 npm artifacts, immutable ZAP digest | Clean installs, advisory checks, repeated isolated passive scan | Reproducible packages; ZAP manifest passed with no retained alert at or above WARN, validated reports, and cleanup | Lockfiles, audit commands, ZAP manifest and reports |

## Verification result

- **PHPUnit:** 433 tests, 1,940 assertions passed; the ordinary run skipped
  four opt-in MariaDB tests.
- **Real MariaDB concurrency tests:** 4 tests, 42 assertions passed, including
  measured lab-result row-lock contention.
- **Playwright:** 36 end-to-end healthcare and hostile-path scenarios passed
  after the last code change.
- **Passive ZAP:** successful manifest and exit code, no retained alert at or
  above WARN, all reports validated, and exact cleanup. The reports retain
  five Informational alert types across fifteen instances. It ran after the
  last code change.
- **Manual HTTP probes:** protected and traversal-shaped paths were denied,
  unknown routes were controlled, CSS MIME was correct, and no sensitive
  disclosure was observed.
- **Syntax and patch checks:** PHP, JavaScript, PowerShell, and Git whitespace
  checks passed.

## Important interpretation

The passing passive ZAP scan covers unauthenticated URLs discovered by its
spider. It does not prove role or object authorization. Those controls are
demonstrated by authenticated PHPUnit and Playwright scenarios.

The built-in PHP runtime was exercised, but XAMPP is absent from the test
machine. Apache module, virtual-host, and `.htaccess` behavior therefore remains
unverified until `scripts\configure-xampp-apache.ps1` completes its live probe.

Audit integrity also has a deliberate trust boundary. The database head proves
database-only edits and truncation when the attacker lacks the application
HMAC key. Independently detecting whole-database rollback requires a separately
protected external anchor. Without one, the honest result is `UNKNOWN`.

Each admin audit page already verifies the full chain exactly once per request.
Request-scoped caching would not remove that one linear scan, while
cross-request caching could present a stale integrity verdict. The academic
deployment therefore accepts the scalability cost rather than weakening the
forensic guarantee.

## Presentation takeaway

MediShield now demonstrates defense in depth without hiding limitations:

1. prevent unsafe requests at the web and request boundaries;
2. authorize every role and healthcare object server-side;
3. encrypt sensitive clinical content;
4. record security-relevant actions in tamper-evident evidence;
5. test both expected workflows and hostile cases;
6. report `UNKNOWN` when the environment cannot prove a claim.
