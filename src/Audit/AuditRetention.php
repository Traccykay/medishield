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
 *     (see AuditChain v1/v2 canonicalization), so nulling it does not change any
 *     row's current_hash and local verification remains PASS.
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
        $total = 0;
        do {
            $affected = $this->purgeBatch($cutoff, 500);
            $total += $affected;
        } while ($affected === 500);

        return $total;
    }

    public function countEligible(\DateTimeImmutable $cutoff): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*)
               FROM audit_logs
              WHERE attempted_identifier IS NOT NULL
                AND created_at < :cutoff'
        );
        $stmt->execute([':cutoff' => $cutoff->format('Y-m-d H:i:s')]);
        return (int) $stmt->fetchColumn();
    }

    /**
     * Scrub at most one bounded batch. Each batch owns its transaction, making a
     * retry safe and limiting a failed operation's lock footprint.
     */
    public function purgeBatch(\DateTimeImmutable $cutoff, int $batchSize = 500): int
    {
        if ($batchSize < 1 || $batchSize > 1000) {
            throw new \InvalidArgumentException('Audit retention batch size must be between 1 and 1000.');
        }
        if ($this->pdo->inTransaction()) {
            throw new \LogicException('Audit retention batch must own its transaction.');
        }

        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
            $this->pdo->exec('BEGIN IMMEDIATE');
        } else {
            $this->pdo->beginTransaction();
        }

        try {
            $select = $this->pdo->prepare(
                'SELECT log_id
                   FROM audit_logs
                  WHERE attempted_identifier IS NOT NULL
                    AND created_at < :cutoff
                  ORDER BY log_id ASC
                  LIMIT ' . $batchSize
            );
            $select->execute([':cutoff' => $cutoff->format('Y-m-d H:i:s')]);
            $ids = array_map('intval', $select->fetchAll(PDO::FETCH_COLUMN));
            if ($ids === []) {
                $this->pdo->commit();
                return 0;
            }

            $placeholders = [];
            $params = [];
            foreach ($ids as $index => $id) {
                $placeholder = ':id' . $index;
                $placeholders[] = $placeholder;
                $params[$placeholder] = $id;
            }
            $update = $this->pdo->prepare(
                'UPDATE audit_logs
                    SET attempted_identifier = NULL
                  WHERE attempted_identifier IS NOT NULL
                    AND log_id IN (' . implode(', ', $placeholders) . ')'
            );
            $update->execute($params);
            $affected = $update->rowCount();
            $this->pdo->commit();
            return $affected;
        } catch (\Throwable $error) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }
}
