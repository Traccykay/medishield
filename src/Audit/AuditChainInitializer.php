<?php

declare(strict_types=1);

namespace MediShield\Audit;

use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use PDO;

/**
 * One-time/idempotent initializer for the keyed chain-head commitment.
 *
 * Missing legacy metadata is assigned deterministically in log_id order.
 * Existing positive sequence values are never renumbered: ambiguous or
 * non-contiguous metadata fails verification instead of being repaired.
 */
final class AuditChainInitializer
{
    public function __construct(
        private PDO $pdo,
        private AuditChain $chain,
        private Clock $clock
    ) {
    }

    /**
     * @return array<string,mixed>
     */
    public function initialize(): array
    {
        if ($this->pdo->inTransaction()) {
            throw new \LogicException('Audit-chain initialization must own its transaction.');
        }

        $this->beginWriteTransaction();
        try {
            $head = $this->readHead(true);
            if ($head !== null) {
                $this->assertExistingHead($head);
                $this->pdo->commit();
                $verification = (new AuditLogger(
                    $this->pdo,
                    $this->chain,
                    $this->clock
                ))->verifyLocalFull();
                if ($verification['state'] !== 'PASS') {
                    throw new \RuntimeException('The initialized audit chain is not locally valid.');
                }
                return $head;
            }

            $rows = $this->pdo->query(
                'SELECT log_id, seq, event_id, key_id, format_version,
                        user_id, user_role, action, module, affected_record_id,
                        ip_address, user_agent, status, anomaly_flag,
                        previous_hash, current_hash, created_at
                   FROM audit_logs
                  ORDER BY log_id ASC'
            )->fetchAll();

            $expectedPrevious = AuditChain::GENESIS;
            $lastSeq = 0;
            $lastLogId = null;
            $headHash = AuditChain::GENESIS;
            $assign = $this->pdo->prepare(
                'UPDATE audit_logs
                    SET seq = :seq, event_id = :event_id,
                        key_id = :key_id, format_version = :format_version
                  WHERE log_id = :log_id'
            );

            foreach ($rows as $index => $row) {
                $sequence = $index + 1;
                $storedSequence = isset($row['seq']) ? (int) $row['seq'] : 0;
                $formatVersion = isset($row['format_version']) ? (int) $row['format_version'] : 0;
                $eventId = (string) ($row['event_id'] ?? '');
                $keyId = (string) ($row['key_id'] ?? '');
                $nextSequence = $storedSequence === 0 ? $sequence : $storedSequence;
                $nextEventId = $eventId === '' ? 'legacy-' . (int) $row['log_id'] : $eventId;
                $nextKeyId = $keyId === '' || (
                    $formatVersion === AuditChain::FORMAT_V1
                    && $keyId === 'legacy-v1'
                )
                    ? $this->chain->keyId()
                    : $keyId;
                $nextFormatVersion = $formatVersion === 0
                    ? AuditChain::FORMAT_V1
                    : $formatVersion;

                if (
                    $nextSequence !== $storedSequence
                    || $nextEventId !== $eventId
                    || $nextKeyId !== $keyId
                    || $nextFormatVersion !== $formatVersion
                ) {
                    $assign->execute([
                        ':seq' => $nextSequence,
                        ':event_id' => $nextEventId,
                        ':key_id' => $nextKeyId,
                        ':format_version' => $nextFormatVersion,
                        ':log_id' => (int) $row['log_id'],
                    ]);
                    $row['seq'] = $nextSequence;
                    $row['event_id'] = $nextEventId;
                    $row['key_id'] = $nextKeyId;
                    $row['format_version'] = $nextFormatVersion;
                }

                if ((int) $row['seq'] !== $sequence) {
                    throw new \RuntimeException('Historical audit rows are not in deterministic sequence order.');
                }
                if ((string) $row['previous_hash'] !== $expectedPrevious) {
                    throw new \RuntimeException('Historical audit chain linkage is invalid.');
                }

                $recomputed = $this->chain->computeHash(
                    $row,
                    (string) $row['previous_hash'],
                    (int) $row['format_version']
                );
                if (!hash_equals((string) $row['current_hash'], $recomputed)) {
                    throw new \RuntimeException('Historical audit row hash is invalid.');
                }

                $expectedPrevious = (string) $row['current_hash'];
                $lastSeq = $sequence;
                $lastLogId = (int) $row['log_id'];
                $headHash = (string) $row['current_hash'];
            }

            $head = [
                'singleton_id' => 1,
                'last_seq' => $lastSeq,
                'last_log_id' => $lastLogId,
                'head_hash' => $headHash,
                'key_id' => $this->chain->keyId(),
                'format_version' => AuditChain::FORMAT_V2,
                'key_check' => $this->chain->keyCheck(),
                'updated_at' => $this->clock->nowString(),
            ];
            $head['head_mac'] = $this->chain->computeHeadMac($head);

            $insert = $this->pdo->prepare(
                'INSERT INTO audit_chain_head
                    (singleton_id, last_seq, last_log_id, head_hash, key_id,
                     format_version, key_check, head_mac, updated_at)
                 VALUES
                    (1, :last_seq, :last_log_id, :head_hash, :key_id,
                     :format_version, :key_check, :head_mac, :updated_at)'
            );
            $insert->execute([
                ':last_seq' => $head['last_seq'],
                ':last_log_id' => $head['last_log_id'],
                ':head_hash' => $head['head_hash'],
                ':key_id' => $head['key_id'],
                ':format_version' => $head['format_version'],
                ':key_check' => $head['key_check'],
                ':head_mac' => $head['head_mac'],
                ':updated_at' => $head['updated_at'],
            ]);

            $this->pdo->commit();
            $verification = (new AuditLogger(
                $this->pdo,
                $this->chain,
                $this->clock
            ))->verifyLocalFull();
            if ($verification['state'] !== 'PASS') {
                throw new \RuntimeException('The initialized audit chain is not locally valid.');
            }
            return $head;
        } catch (\Throwable $error) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }

    /**
     * @return array<string,mixed>|null
     */
    private function readHead(bool $lock): ?array
    {
        $sql = 'SELECT * FROM audit_chain_head WHERE singleton_id = 1';
        if ($lock && $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
            $sql .= ' FOR UPDATE';
        }
        $row = $this->pdo->query($sql)->fetch();

        return $row === false ? null : $row;
    }

    /**
     * @param array<string,mixed> $head
     */
    private function assertExistingHead(array $head): void
    {
        if (!$this->chain->matchesKeyCheck((string) $head['key_check'])) {
            throw new \RuntimeException('The configured audit key does not match the initialized chain.');
        }
        if ((string) $head['key_id'] !== $this->chain->keyId()) {
            throw new \RuntimeException('The configured audit key id does not match the initialized chain.');
        }
        $expected = $this->chain->computeHeadMac($head);
        if (!hash_equals((string) $head['head_mac'], $expected)) {
            throw new \RuntimeException('The audit chain head commitment is invalid.');
        }
    }

    private function beginWriteTransaction(): void
    {
        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
            $this->pdo->exec('BEGIN IMMEDIATE');
            return;
        }
        $this->pdo->beginTransaction();
    }
}
