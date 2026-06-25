<?php

declare(strict_types=1);

namespace MediShield\Audit;

use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use PDO;

/**
 * AuditLogger
 * -----------
 * Writes tamper-evident entries to the `audit_logs` table (spec §9.8).
 *
 * Every write is serialized inside a single transaction:
 *   1. Lock + read the most recent row's current_hash (the chain tip).
 *   2. Compute this row's current_hash = HMAC(key, fields | previous_hash).
 *   3. INSERT the new row.
 *   4. COMMIT.
 *
 * Serializing this way guarantees the hash chain stays unbroken even if two
 * requests log at the same instant. On MySQL/MariaDB the read uses `FOR UPDATE`
 * to take a row lock; SQLite (used in tests) serializes via the transaction.
 *
 * This class never UPDATEs or DELETEs — the log is append-only by design.
 */
final class AuditLogger
{
    public function __construct(
        private PDO $pdo,
        private AuditChain $chain,
        private Clock $clock
    ) {
    }

    /**
     * Append an audit entry and return its new log_id.
     *
     * @param array{
     *   user_id?: int|null,
     *   user_role?: string,
     *   action: string,
     *   module: string,
     *   affected_record_id?: int|string|null,
     *   ip_address?: string,
     *   user_agent?: string|null,
     *   status?: string,
     *   anomaly_flag?: string
     * } $event
     */
    public function log(array $event): int
    {
        $createdAt = $this->clock->nowString();
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        $this->pdo->beginTransaction();
        try {
            // 1. Read the chain tip, locking it on MySQL so concurrent writers serialize.
            $sql = 'SELECT current_hash FROM audit_logs ORDER BY log_id DESC LIMIT 1';
            if ($driver === 'mysql') {
                $sql .= ' FOR UPDATE';
            }
            $previousHash = $this->pdo->query($sql)->fetchColumn();
            if ($previousHash === false) {
                $previousHash = AuditChain::GENESIS;
            }

            // 2. Normalise fields and compute the chained hash.
            $entry = [
                'user_id'            => $event['user_id'] ?? null,
                'user_role'          => $event['user_role'] ?? 'guest',
                'action'             => $event['action'],
                'module'             => $event['module'],
                'affected_record_id' => $event['affected_record_id'] ?? null,
                'status'             => $event['status'] ?? 'SUCCESS',
                'anomaly_flag'       => $event['anomaly_flag'] ?? 'NORMAL',
                'created_at'         => $createdAt,
            ];
            $currentHash = $this->chain->computeHash($entry, (string) $previousHash);

            // 3. Insert.
            $stmt = $this->pdo->prepare(
                'INSERT INTO audit_logs
                    (user_id, user_role, action, module, affected_record_id,
                     ip_address, user_agent, status, anomaly_flag,
                     previous_hash, current_hash, created_at)
                 VALUES
                    (:user_id, :user_role, :action, :module, :affected_record_id,
                     :ip_address, :user_agent, :status, :anomaly_flag,
                     :previous_hash, :current_hash, :created_at)'
            );
            $stmt->execute([
                ':user_id'            => $entry['user_id'],
                ':user_role'          => $entry['user_role'],
                ':action'             => $entry['action'],
                ':module'             => $entry['module'],
                ':affected_record_id' => $entry['affected_record_id'],
                ':ip_address'         => $event['ip_address'] ?? '0.0.0.0',
                ':user_agent'         => $event['user_agent'] ?? null,
                ':status'             => $entry['status'],
                ':anomaly_flag'       => $entry['anomaly_flag'],
                ':previous_hash'      => (string) $previousHash,
                ':current_hash'       => $currentHash,
                ':created_at'         => $createdAt,
            ]);

            $id = (int) $this->pdo->lastInsertId();
            $this->pdo->commit();
            return $id;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Verify the integrity of the whole chain.
     *
     * @return array{ok:bool, first_bad_log_id:?int} ok=true means untampered.
     */
    public function verifyChain(): array
    {
        $rows = $this->pdo->query(
            'SELECT log_id, user_id, user_role, action, module, affected_record_id,
                    status, anomaly_flag, previous_hash, current_hash, created_at
             FROM audit_logs ORDER BY log_id ASC'
        )->fetchAll();

        $expectedPrev = AuditChain::GENESIS;
        foreach ($rows as $row) {
            if ((string) $row['previous_hash'] !== $expectedPrev) {
                return ['ok' => false, 'first_bad_log_id' => (int) $row['log_id']];
            }
            $recomputed = $this->chain->computeHash([
                'user_id'            => $row['user_id'],
                'user_role'          => $row['user_role'],
                'action'             => $row['action'],
                'module'             => $row['module'],
                'affected_record_id' => $row['affected_record_id'],
                'status'             => $row['status'],
                'anomaly_flag'       => $row['anomaly_flag'],
                'created_at'         => $row['created_at'],
            ], (string) $row['previous_hash']);

            if (!hash_equals((string) $row['current_hash'], $recomputed)) {
                return ['ok' => false, 'first_bad_log_id' => (int) $row['log_id']];
            }
            $expectedPrev = (string) $row['current_hash'];
        }

        return ['ok' => true, 'first_bad_log_id' => null];
    }

    /**
     * Return the most recent audit entries, newest first, for the admin security
     * monitoring view (spec §6.6, §9.8). Read-only: the log itself stays
     * append-only. $limit is clamped to a sane range so a caller can never request
     * an unbounded or non-positive page size.
     *
     * @return list<array<string,mixed>>
     */
    public function recent(int $limit = 50): array
    {
        $limit = max(1, min($limit, 500));

        // LIMIT cannot be bound as a parameter portably across MySQL/SQLite, so we
        // cast to int ourselves (the clamp above guarantees it is a safe integer).
        $stmt = $this->pdo->query(
            'SELECT log_id, user_id, user_role, action, module, affected_record_id,
                    ip_address, user_agent, status, anomaly_flag, created_at
             FROM audit_logs ORDER BY log_id DESC LIMIT ' . (int) $limit
        );

        return $stmt->fetchAll();
    }
}
