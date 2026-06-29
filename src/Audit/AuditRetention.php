<?php

declare(strict_types=1);

namespace MediShield\Audit;

use PDO;

/**
 * AuditRetention
 * --------------
 * Privileged MAINTENANCE component for scrubbing personal data (PII) out of the
 * forensic audit log after a retention window, while leaving the tamper-evident
 * hash chain fully intact (spec §9.8 + privacy / data-minimisation requirements).
 *
 * Why a separate class (and not a method on AuditLogger)?
 * ------------------------------------------------------
 * AuditLogger runs in the normal request path and is, by the system's golden
 * rule, strictly APPEND-ONLY (it never UPDATEs or DELETEs). The PII scrub is the
 * one narrow, deliberate exception to that rule, so it is isolated here:
 *   - It is invoked only by an out-of-band maintenance task
 *     (scripts/purge-audit-pii.php), never by any page or login flow.
 *   - It requires a DB account with UPDATE privilege on audit_logs. The
 *     application's own DB user is granted only SELECT+INSERT, so even a
 *     compromised web request physically cannot perform this scrub.
 *
 * What it touches — and what it must NEVER touch
 * ----------------------------------------------
 *   - It ONLY sets `attempted_identifier` (the typed email) to NULL.
 *   - That column is intentionally NOT part of the HMAC hash chain
 *     (see AuditLogger::log / verifyChain), so nulling it does not change any
 *     row's current_hash and verifyChain() keeps returning ok.
 *   - It NEVER deletes rows and NEVER edits a chained field. The forensic
 *     "who did what / when" record survives; only the personal identifier of the
 *     person whose data we are no longer permitted to retain is removed.
 */
final class AuditRetention
{
    public function __construct(private PDO $pdo)
    {
    }

    /**
     * Null out `attempted_identifier` on every audit row created strictly before
     * $cutoff that still has one. Returns the number of rows scrubbed.
     *
     * Idempotent: rows already scrubbed (NULL) are skipped, so re-running is safe
     * and returns 0 once there is nothing left older than the cutoff.
     */
    public function purgeIdentifiersOlderThan(\DateTimeImmutable $cutoff): int
    {
        // created_at is stored as 'Y-m-d H:i:s' (UTC). That format sorts
        // lexicographically the same as chronologically, so a string '<' compare
        // is correct and works identically on MySQL/MariaDB and SQLite.
        $stmt = $this->pdo->prepare(
            'UPDATE audit_logs
                SET attempted_identifier = NULL
              WHERE attempted_identifier IS NOT NULL
                AND created_at < :cutoff'
        );
        $stmt->execute([':cutoff' => $cutoff->format('Y-m-d H:i:s')]);

        return $stmt->rowCount();
    }
}
