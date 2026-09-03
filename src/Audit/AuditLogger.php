<?php

declare(strict_types=1);

namespace MediShield\Audit;

use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use PDO;
use PDOException;

/**
 * Atomic append-only writer and bounded verifier for the forensic audit chain.
 *
 * The singleton chain head is always locked before an append. This serializes
 * both an empty chain and a populated chain, avoiding the genesis-fork race that
 * locking only the latest audit row cannot prevent.
 */
final class AuditLogger
{
    private const VERIFY_BATCH_SIZE = 500;
    private const MAX_PARTIAL_ROWS = 1000;

    public function __construct(
        private PDO $pdo,
        private AuditChain $chain,
        private Clock $clock,
        private int $maxAppendAttempts = 3,
        private ?\Closure $verificationCheckpoint = null
    ) {
        if ($this->maxAppendAttempts < 1 || $this->maxAppendAttempts > 10) {
            throw new \InvalidArgumentException('Audit append attempts must be between 1 and 10.');
        }
        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
            $this->pdo->exec('PRAGMA busy_timeout = 5000');
        }
    }

    /**
     * @param array<string,mixed> $event
     */
    public function log(array $event): int
    {
        if ($this->pdo->inTransaction()) {
            throw new \LogicException(
                'Audit append must not run inside a caller-owned domain transaction.'
            );
        }

        $normalized = $this->normalizeEvent($event);
        $eventId = bin2hex(random_bytes(16));
        $lastError = null;

        for ($attempt = 1; $attempt <= $this->maxAppendAttempts; $attempt++) {
            try {
                $this->beginWriteTransaction();
                $head = $this->readHead(true);
                if ($head === null) {
                    throw new \RuntimeException(
                        'Audit chain head is not initialized. Run scripts\\initialize-audit-chain.php.'
                    );
                }
                $this->assertWritableHead($head);

                $sequence = (int) $head['last_seq'] + 1;
                $entry = [
                    'seq' => $sequence,
                    'event_id' => $eventId,
                    'key_id' => $this->chain->keyId(),
                    'format_version' => AuditChain::FORMAT_V2,
                    ...$normalized,
                ];
                $currentHash = $this->chain->computeHash(
                    $entry,
                    (string) $head['head_hash'],
                    AuditChain::FORMAT_V2
                );

                $insert = $this->pdo->prepare(
                    'INSERT INTO audit_logs
                        (seq, event_id, key_id, format_version,
                         user_id, user_role, action, module, affected_record_id,
                         ip_address, user_agent, status, anomaly_flag,
                         attempted_identifier, previous_hash, current_hash, created_at)
                     VALUES
                        (:seq, :event_id, :key_id, :format_version,
                         :user_id, :user_role, :action, :module, :affected_record_id,
                         :ip_address, :user_agent, :status, :anomaly_flag,
                         :attempted_identifier, :previous_hash, :current_hash, :created_at)'
                );
                $insert->execute([
                    ':seq' => $sequence,
                    ':event_id' => $eventId,
                    ':key_id' => $entry['key_id'],
                    ':format_version' => AuditChain::FORMAT_V2,
                    ':user_id' => $entry['user_id'],
                    ':user_role' => $entry['user_role'],
                    ':action' => $entry['action'],
                    ':module' => $entry['module'],
                    ':affected_record_id' => $entry['affected_record_id'],
                    ':ip_address' => $entry['ip_address'],
                    ':user_agent' => $entry['user_agent'],
                    ':status' => $entry['status'],
                    ':anomaly_flag' => $entry['anomaly_flag'],
                    ':attempted_identifier' => $normalized['attempted_identifier'],
                    ':previous_hash' => (string) $head['head_hash'],
                    ':current_hash' => $currentHash,
                    ':created_at' => $entry['created_at'],
                ]);
                $logId = (int) $this->pdo->lastInsertId();

                $nextHead = [
                    'last_seq' => $sequence,
                    'last_log_id' => $logId,
                    'head_hash' => $currentHash,
                    'key_id' => $this->chain->keyId(),
                    'format_version' => AuditChain::FORMAT_V2,
                    'key_check' => $this->chain->keyCheck(),
                    'updated_at' => $normalized['created_at'],
                ];
                $headMac = $this->chain->computeHeadMac($nextHead);
                $update = $this->pdo->prepare(
                    'UPDATE audit_chain_head
                        SET last_seq = :last_seq, last_log_id = :last_log_id,
                            head_hash = :head_hash, key_id = :key_id,
                            format_version = :format_version, key_check = :key_check,
                            head_mac = :head_mac, updated_at = :updated_at
                      WHERE singleton_id = 1
                        AND last_seq = :expected_last_seq
                        AND head_mac = :expected_head_mac'
                );
                $update->execute([
                    ':last_seq' => $sequence,
                    ':last_log_id' => $logId,
                    ':head_hash' => $currentHash,
                    ':key_id' => $this->chain->keyId(),
                    ':format_version' => AuditChain::FORMAT_V2,
                    ':key_check' => $this->chain->keyCheck(),
                    ':head_mac' => $headMac,
                    ':updated_at' => $normalized['created_at'],
                    ':expected_last_seq' => (int) $head['last_seq'],
                    ':expected_head_mac' => (string) $head['head_mac'],
                ]);
                if ($update->rowCount() !== 1) {
                    throw new \RuntimeException('Audit chain head changed during append.');
                }

                $this->pdo->commit();
                return $logId;
            } catch (\Throwable $error) {
                $lastError = $error;
                if ($this->pdo->inTransaction()) {
                    $this->pdo->rollBack();
                }

                $persisted = $this->findEventId($eventId);
                if ($persisted !== null) {
                    return $persisted;
                }
                if ($attempt >= $this->maxAppendAttempts || !$this->isRetryable($error)) {
                    throw $error;
                }

                usleep(($attempt * 10_000) + random_int(0, 5_000));
            }
        }

        throw $lastError ?? new \RuntimeException('Audit append failed.');
    }

    /**
     * Verify local rows and the keyed database head. This can establish local
     * consistency, but not whole-database rollback resistance.
     *
     * @return array<string,mixed>
     */
    public function verifyLocalFull(): array
    {
        if ($this->pdo->inTransaction()) {
            return $this->snapshotUnavailable('local-full');
        }

        try {
            $this->beginConsistentReadSnapshot();
        } catch (\Throwable) {
            return $this->snapshotUnavailable('local-full');
        }

        try {
            $result = $this->verifyLocalFullSnapshot();
            $this->pdo->commit();
            return $result;
        } catch (\Throwable) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return $this->result('UNKNOWN', 'VERIFICATION_ERROR', 'local-full');
        }
    }

    /**
     * @return array<string,mixed>
     */
    private function verifyLocalFullSnapshot(): array
    {
        $head = $this->readHead(false);
        $this->signalVerificationCheckpoint('local-full:head-read');
        if ($head === null) {
            return $this->result('UNKNOWN', 'CHAIN_HEAD_MISSING', 'local-full');
        }

        $headSequence = self::nonNegativeInt($head['last_seq'] ?? null);
        if ($headSequence === null) {
            return $this->result('FAIL', 'HEAD_METADATA_INVALID', 'local-full');
        }
        try {
            $headAuthentication = $this->assessHeadAuthentication($head);
        } catch (\InvalidArgumentException) {
            return $this->result(
                'FAIL',
                'HEAD_METADATA_INVALID',
                'local-full',
                0,
                null,
                null,
                $headSequence
            );
        }

        $coverage = $this->pdo->query(
            'SELECT COUNT(*) AS row_count, MIN(seq) AS min_seq, MAX(seq) AS max_seq
               FROM audit_logs'
        )->fetch();
        if ($coverage === false) {
            throw new \RuntimeException('Audit physical coverage could not be read.');
        }
        $rowCount = (int) $coverage['row_count'];
        $minimumSequence = self::nullableInt($coverage['min_seq']);
        $maximumSequence = self::nullableInt($coverage['max_seq']);
        $coverageMatches = $rowCount === $headSequence
            && (
                ($headSequence === 0 && $minimumSequence === null && $maximumSequence === null)
                || (
                    $headSequence > 0
                    && $minimumSequence === 1
                    && $maximumSequence === $headSequence
                )
            );
        if (!$coverageMatches) {
            $firstBadSequence = $minimumSequence !== null && $minimumSequence < 1
                ? $minimumSequence
                : (
                    $maximumSequence !== null && $maximumSequence > $headSequence
                        ? $maximumSequence
                        : null
                );
            return $this->result(
                'FAIL',
                'PHYSICAL_ROW_COVERAGE_MISMATCH',
                'local-full',
                0,
                null,
                $firstBadSequence,
                $headSequence
            );
        }

        $expectedSequence = 1;
        $expectedPrevious = AuditChain::GENESIS;
        $lastLogId = null;
        $checked = 0;
        $matchingRowMacs = 0;
        $firstHashFailure = null;
        $firstFormatFailure = null;

        while (true) {
            $stmt = $this->pdo->prepare(
                'SELECT log_id, seq, event_id, key_id, format_version,
                        user_id, user_role, action, module, affected_record_id,
                        ip_address, user_agent, status, anomaly_flag,
                        previous_hash, current_hash, created_at
                   FROM audit_logs
                  WHERE seq >= :from_seq
                  ORDER BY seq ASC
                  LIMIT ' . self::VERIFY_BATCH_SIZE
            );
            $stmt->execute([':from_seq' => $expectedSequence]);
            $rows = $stmt->fetchAll();
            if ($rows === []) {
                break;
            }

            foreach ($rows as $row) {
                $failure = $this->verifyRowStructure(
                    $row,
                    $expectedSequence,
                    $expectedPrevious,
                    'local-full',
                    $checked
                );
                if ($failure !== null) {
                    return $failure;
                }

                $formatVersion = (int) $row['format_version'];
                if (!in_array(
                    $formatVersion,
                    [AuditChain::FORMAT_V1, AuditChain::FORMAT_V2],
                    true
                )) {
                    $firstFormatFailure ??= $this->result(
                        'FAIL',
                        'ROW_FORMAT_VERSION_INVALID',
                        'local-full',
                        $checked,
                        (int) $row['log_id'],
                        (int) $row['seq'],
                        $headSequence
                    );
                } else {
                    $recomputed = $this->chain->computeHash(
                        $row,
                        (string) $row['previous_hash'],
                        $formatVersion
                    );
                    if (hash_equals((string) $row['current_hash'], $recomputed)) {
                        $matchingRowMacs++;
                    } else {
                        $firstHashFailure ??= $this->result(
                            'FAIL',
                            'ROW_HASH_INVALID',
                            'local-full',
                            $checked,
                            (int) $row['log_id'],
                            (int) $row['seq'],
                            $headSequence
                        );
                    }
                }

                $expectedPrevious = (string) $row['current_hash'];
                $lastLogId = (int) $row['log_id'];
                $expectedSequence++;
                $checked++;
            }

            if (count($rows) < self::VERIFY_BATCH_SIZE) {
                break;
            }
        }

        $actualLastSequence = $expectedSequence - 1;
        if (
            $actualLastSequence !== $headSequence
            || $expectedPrevious !== (string) $head['head_hash']
            || $lastLogId !== self::nullableInt($head['last_log_id'])
        ) {
            return $this->result(
                'FAIL',
                'HEAD_ROW_MISMATCH',
                'local-full',
                $checked,
                null,
                null,
                $headSequence
            );
        }

        $configuredKeyEstablished = $headAuthentication['key_check_matches']
            || $headAuthentication['head_mac_matches']
            || $headAuthentication['recovered_key_check_mac_matches']
            || $headAuthentication['recovered_format_mac_matches']
            || $matchingRowMacs > 0;

        if (!$configuredKeyEstablished) {
            return $this->result(
                'UNKNOWN',
                'AUDIT_KEY_MISMATCH',
                'local-full',
                $checked,
                null,
                null,
                $headSequence
            );
        }
        if ($firstFormatFailure !== null) {
            return $firstFormatFailure;
        }
        if ($firstHashFailure !== null) {
            return $firstHashFailure;
        }
        if (!$headAuthentication['key_check_matches']) {
            return $this->result(
                'FAIL',
                'HEAD_KEY_CHECK_INVALID',
                'local-full',
                $checked,
                null,
                null,
                $headSequence
            );
        }
        if (!$headAuthentication['key_id_matches']) {
            if ($headAuthentication['head_mac_matches']) {
                return $this->result(
                    'UNKNOWN',
                    'AUDIT_KEY_ID_MISMATCH',
                    'local-full',
                    $checked,
                    null,
                    null,
                    $headSequence
                );
            }
            return $this->result(
                'FAIL',
                'HEAD_KEY_ID_INVALID',
                'local-full',
                $checked,
                null,
                null,
                $headSequence
            );
        }
        if (!$headAuthentication['head_mac_matches']) {
            return $this->result(
                'FAIL',
                'HEAD_MAC_INVALID',
                'local-full',
                $checked,
                null,
                null,
                $headSequence
            );
        }
        if ((int) $head['format_version'] !== AuditChain::FORMAT_V2) {
            return $this->result(
                'UNKNOWN',
                'UNSUPPORTED_HEAD_FORMAT_VERSION',
                'local-full',
                $checked,
                null,
                null,
                $headSequence
            );
        }

        return $this->result(
            'PASS',
            'LOCAL_CHAIN_VALID',
            'local-full',
            $checked,
            null,
            null,
            $headSequence
        );
    }

    /**
     * Overall verification requires an independently stored anchor. Without one,
     * whole-database rollback cannot be decided and the result is UNKNOWN.
     *
     * @return array<string,mixed>
     */
    public function verifyChain(?AuditAnchorStore $anchors = null): array
    {
        if ($this->pdo->inTransaction()) {
            return $this->snapshotUnavailable('full-with-anchor');
        }

        try {
            $this->beginConsistentReadSnapshot();
        } catch (\Throwable) {
            return $this->snapshotUnavailable('full-with-anchor');
        }

        try {
            $local = $this->verifyLocalFullSnapshot();
            if ($local['state'] !== 'PASS') {
                $this->pdo->commit();
                return $local;
            }
            if ($anchors === null) {
                $this->pdo->commit();
                return [
                    ...$local,
                    'state' => 'UNKNOWN',
                    'ok' => false,
                    'reason' => 'EXTERNAL_ANCHOR_MISSING',
                    'scope' => 'full-with-anchor',
                    'local_state' => 'PASS',
                    'limitations' => [
                        'Whole-database rollback cannot be assessed without an independent monotonic anchor.',
                    ],
                ];
            }

            $head = $this->readHead(false);
            if ($head === null) {
                throw new \RuntimeException('Verified audit head disappeared from its snapshot.');
            }
            $anchor = $anchors->verifyHead($head);
            $this->pdo->commit();
            return [
                ...$local,
                ...$anchor,
                'ok' => ($anchor['state'] ?? 'UNKNOWN') === 'PASS',
                'scope' => 'full-with-anchor',
                'local_state' => 'PASS',
            ];
        } catch (\Throwable) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return $this->result('UNKNOWN', 'VERIFICATION_ERROR', 'full-with-anchor');
        }
    }

    /**
     * @return array<string,mixed>
     */
    public function verifyTip(int $limit = 100): array
    {
        $limit = max(1, min($limit, self::MAX_PARTIAL_ROWS));

        if ($this->pdo->inTransaction()) {
            return $this->snapshotUnavailable('tip');
        }

        try {
            $this->beginConsistentReadSnapshot();
        } catch (\Throwable) {
            return $this->snapshotUnavailable('tip');
        }

        try {
            $result = $this->verifyTipSnapshot($limit);
            $this->pdo->commit();
            return $result;
        } catch (\Throwable) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return $this->result('UNKNOWN', 'VERIFICATION_ERROR', 'tip');
        }
    }

    /**
     * @return array<string,mixed>
     */
    private function verifyTipSnapshot(int $limit): array
    {
        $head = $this->readHead(false);
        $this->signalVerificationCheckpoint('tip:head-read');
        $headResult = $this->validateHeadForVerification($head, 'tip');
        if ($headResult !== null) {
            return $headResult;
        }
        $stmt = $this->pdo->query(
            'SELECT log_id, seq, event_id, key_id, format_version,
                    user_id, user_role, action, module, affected_record_id,
                    ip_address, user_agent, status, anomaly_flag,
                    previous_hash, current_hash, created_at
               FROM audit_logs
              ORDER BY seq DESC
              LIMIT ' . $limit
        );
        $rows = array_reverse($stmt->fetchAll());
        if ($rows === []) {
            return $this->result(
                'UNKNOWN',
                'PARTIAL_VERIFICATION',
                'tip',
                0,
                null,
                null,
                (int) $head['last_seq']
            );
        }

        $firstSequence = (int) $rows[0]['seq'];
        $expectedPrevious = $this->previousHashForSequence($firstSequence);
        $expectedSequence = $firstSequence;
        $checked = 0;
        foreach ($rows as $row) {
            $failure = $this->verifyRow(
                $row,
                $expectedSequence,
                $expectedPrevious,
                'tip',
                $checked
            );
            if ($failure !== null) {
                return $failure;
            }
            $expectedPrevious = (string) $row['current_hash'];
            $expectedSequence++;
            $checked++;
        }

        $last = $rows[count($rows) - 1];
        if (
            (int) $last['seq'] !== (int) $head['last_seq']
            || (string) $last['current_hash'] !== (string) $head['head_hash']
        ) {
            return $this->result(
                'FAIL',
                'HEAD_ROW_MISMATCH',
                'tip',
                $checked,
                (int) $last['log_id'],
                (int) $last['seq'],
                (int) $head['last_seq']
            );
        }

        return $this->result(
            'UNKNOWN',
            'PARTIAL_VERIFICATION',
            'tip',
            $checked,
            null,
            null,
            (int) $head['last_seq']
        );
    }

    /**
     * @return array<string,mixed>
     */
    public function verifyRange(int $fromSequence, int $toSequence): array
    {
        if (
            $fromSequence < 1
            || $toSequence < $fromSequence
            || ($toSequence - $fromSequence + 1) > self::MAX_PARTIAL_ROWS
        ) {
            throw new \InvalidArgumentException('Audit verification range is invalid or too large.');
        }

        if ($this->pdo->inTransaction()) {
            return $this->snapshotUnavailable('range');
        }

        try {
            $this->beginConsistentReadSnapshot();
        } catch (\Throwable) {
            return $this->snapshotUnavailable('range');
        }

        try {
            $result = $this->verifyRangeSnapshot($fromSequence, $toSequence);
            $this->pdo->commit();
            return $result;
        } catch (\Throwable) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return $this->result('UNKNOWN', 'VERIFICATION_ERROR', 'range');
        }
    }

    /**
     * @return array<string,mixed>
     */
    private function verifyRangeSnapshot(int $fromSequence, int $toSequence): array
    {
        $head = $this->readHead(false);
        $headResult = $this->validateHeadForVerification($head, 'range');
        if ($headResult !== null) {
            return $headResult;
        }

        $stmt = $this->pdo->prepare(
            'SELECT log_id, seq, event_id, key_id, format_version,
                    user_id, user_role, action, module, affected_record_id,
                    ip_address, user_agent, status, anomaly_flag,
                    previous_hash, current_hash, created_at
               FROM audit_logs
              WHERE seq BETWEEN :from_seq AND :to_seq
              ORDER BY seq ASC'
        );
        $stmt->execute([':from_seq' => $fromSequence, ':to_seq' => $toSequence]);
        $rows = $stmt->fetchAll();
        $expectedCount = $toSequence - $fromSequence + 1;
        if (count($rows) !== $expectedCount) {
            return $this->result(
                'FAIL',
                'SEQUENCE_GAP',
                'range',
                count($rows),
                null,
                $fromSequence,
                (int) $head['last_seq']
            );
        }

        $expectedPrevious = $this->previousHashForSequence($fromSequence);
        $expectedSequence = $fromSequence;
        $checked = 0;
        foreach ($rows as $row) {
            $failure = $this->verifyRow(
                $row,
                $expectedSequence,
                $expectedPrevious,
                'range',
                $checked
            );
            if ($failure !== null) {
                return $failure;
            }
            $expectedPrevious = (string) $row['current_hash'];
            $expectedSequence++;
            $checked++;
        }

        return $this->result(
            'UNKNOWN',
            'PARTIAL_VERIFICATION',
            'range',
            $checked,
            null,
            null,
            (int) $head['last_seq']
        );
    }

    /**
     * @return array<string,mixed>
     */
    public function head(): array
    {
        $head = $this->readHead(false);
        if ($head === null) {
            throw new \RuntimeException('Audit chain head is missing.');
        }
        return $head;
    }

    /**
     * Return only head-bounded rows from a transaction snapshot that passed
     * complete local verification. Unverified rows are quarantined as an empty
     * result; database read failures still propagate to the caller.
     *
     * @return list<array<string,mixed>>
     */
    public function recent(int $limit = 50): array
    {
        $limit = max(1, min($limit, 500));
        if ($this->pdo->inTransaction()) {
            return [];
        }

        try {
            $this->beginConsistentReadSnapshot();
        } catch (\Throwable) {
            return [];
        }

        try {
            $verification = $this->verifyLocalFullSnapshot();
            $rows = $verification['state'] === 'PASS'
                ? $this->pdo->query(
                    'SELECT logs.log_id, logs.seq, logs.event_id, logs.key_id,
                            logs.format_version, logs.user_id, logs.user_role,
                            logs.action, logs.module, logs.affected_record_id,
                            logs.ip_address, logs.user_agent, logs.status,
                            logs.anomaly_flag, logs.attempted_identifier, logs.created_at
                       FROM audit_logs AS logs
                       JOIN audit_chain_head AS head ON head.singleton_id = 1
                      WHERE logs.seq BETWEEN 1 AND head.last_seq
                      ORDER BY logs.seq DESC
                      LIMIT ' . $limit
                )->fetchAll()
                : [];
            $this->pdo->commit();

            return $rows;
        } catch (\Throwable $error) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }

    /**
     * @param array<string,mixed> $event
     * @return array<string,mixed>
     */
    private function normalizeEvent(array $event): array
    {
        $action = self::boundedRequiredString($event['action'] ?? null, 'action', 150);
        $module = self::boundedRequiredString($event['module'] ?? null, 'module', 100);
        $role = self::boundedRequiredString($event['user_role'] ?? 'guest', 'user_role', 50);
        $status = (string) ($event['status'] ?? 'SUCCESS');
        if (!in_array($status, ['SUCCESS', 'FAILED', 'BLOCKED'], true)) {
            throw new \InvalidArgumentException('Audit status is invalid.');
        }
        $anomaly = (string) ($event['anomaly_flag'] ?? 'NORMAL');
        if (!in_array($anomaly, ['NORMAL', 'SUSPICIOUS', 'HIGH_RISK'], true)) {
            throw new \InvalidArgumentException('Audit anomaly flag is invalid.');
        }

        $userId = $event['user_id'] ?? null;
        if ($userId !== null && (!is_int($userId) || $userId < 1)) {
            throw new \InvalidArgumentException('Audit user id is invalid.');
        }
        $affected = $event['affected_record_id'] ?? null;
        if ($affected !== null && !is_int($affected) && !is_string($affected)) {
            throw new \InvalidArgumentException('Audit affected record id is invalid.');
        }
        if ($affected !== null && strlen((string) $affected) > 100) {
            throw new \InvalidArgumentException('Audit affected record id is too long.');
        }

        $ipAddress = self::boundedRequiredString(
            $event['ip_address'] ?? '0.0.0.0',
            'ip_address',
            45
        );
        $userAgent = $event['user_agent'] ?? null;
        if ($userAgent !== null && !is_string($userAgent)) {
            throw new \InvalidArgumentException('Audit user agent is invalid.');
        }
        $attemptedIdentifier = $event['attempted_identifier'] ?? null;
        if ($attemptedIdentifier !== null && !is_string($attemptedIdentifier)) {
            throw new \InvalidArgumentException('Audit attempted identifier is invalid.');
        }

        return [
            'user_id' => $userId,
            'user_role' => $role,
            'action' => $action,
            'module' => $module,
            'affected_record_id' => $affected === null ? null : (string) $affected,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent === null ? null : substr($userAgent, 0, 2048),
            'status' => $status,
            'anomaly_flag' => $anomaly,
            'attempted_identifier' => $attemptedIdentifier === null
                ? null
                : substr($attemptedIdentifier, 0, 255),
            'created_at' => $this->clock->nowString(),
        ];
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
    private function assertWritableHead(array $head): void
    {
        if (!$this->chain->matchesKeyCheck((string) $head['key_check'])) {
            throw new \RuntimeException('Configured audit key does not match the chain head.');
        }
        if ((string) $head['key_id'] !== $this->chain->keyId()) {
            throw new \RuntimeException('Configured audit key id does not match the chain head.');
        }
        if (!hash_equals(
            (string) $head['head_mac'],
            $this->chain->computeHeadMac($head)
        )) {
            throw new \RuntimeException('Audit chain head MAC is invalid.');
        }
    }

    /**
     * @param array<string,mixed>|null $head
     * @return array<string,mixed>|null
     */
    private function validateHeadForVerification(?array $head, string $scope): ?array
    {
        if ($head === null) {
            return $this->result('UNKNOWN', 'CHAIN_HEAD_MISSING', $scope);
        }
        $headSequence = self::nonNegativeInt($head['last_seq'] ?? null);
        if ($headSequence === null) {
            return $this->result('FAIL', 'HEAD_METADATA_INVALID', $scope);
        }
        try {
            $authentication = $this->assessHeadAuthentication($head);
        } catch (\InvalidArgumentException) {
            return $this->result(
                'FAIL',
                'HEAD_METADATA_INVALID',
                $scope,
                0,
                null,
                null,
                $headSequence
            );
        }
        if (!$authentication['key_check_matches']) {
            if (
                $authentication['recovered_key_check_mac_matches']
                || $authentication['recovered_format_mac_matches']
            ) {
                return $this->result(
                    'FAIL',
                    'HEAD_KEY_CHECK_INVALID',
                    $scope,
                    0,
                    null,
                    null,
                    $headSequence
                );
            }
            return $this->result(
                'UNKNOWN',
                'AUDIT_KEY_MISMATCH',
                $scope,
                0,
                null,
                null,
                $headSequence
            );
        }
        if (!$authentication['key_id_matches']) {
            if (!$authentication['head_mac_matches']) {
                return $this->result(
                    'FAIL',
                    'HEAD_KEY_ID_INVALID',
                    $scope,
                    0,
                    null,
                    null,
                    $headSequence
                );
            }
            return $this->result(
                'UNKNOWN',
                'AUDIT_KEY_ID_MISMATCH',
                $scope,
                0,
                null,
                null,
                $headSequence
            );
        }
        if (!$authentication['head_mac_matches']) {
            return $this->result(
                'FAIL',
                'HEAD_MAC_INVALID',
                $scope,
                0,
                null,
                null,
                $headSequence
            );
        }
        if ((int) $head['format_version'] !== AuditChain::FORMAT_V2) {
            return $this->result(
                'UNKNOWN',
                'UNSUPPORTED_HEAD_FORMAT_VERSION',
                $scope,
                0,
                null,
                null,
                $headSequence
            );
        }
        return null;
    }

    /**
     * @param array<string,mixed> $head
     * @return array<string,bool>
     */
    private function assessHeadAuthentication(array $head): array
    {
        $storedMac = (string) ($head['head_mac'] ?? '');
        $keyCheckMatches = $this->chain->matchesKeyCheck(
            (string) ($head['key_check'] ?? '')
        );
        $headMacMatches = strlen($storedMac) === 64
            && hash_equals($storedMac, $this->chain->computeHeadMac($head));

        $expectedKeyCheckHead = [
            ...$head,
            'key_check' => $this->chain->keyCheck(),
        ];
        $recoveredKeyCheckMacMatches = strlen($storedMac) === 64
            && hash_equals(
                $storedMac,
                $this->chain->computeHeadMac($expectedKeyCheckHead)
            );

        $expectedFormatHead = [
            ...$expectedKeyCheckHead,
            'format_version' => AuditChain::FORMAT_V2,
        ];
        $recoveredFormatMacMatches = strlen($storedMac) === 64
            && hash_equals(
                $storedMac,
                $this->chain->computeHeadMac($expectedFormatHead)
            );

        return [
            'key_check_matches' => $keyCheckMatches,
            'key_id_matches' => (string) ($head['key_id'] ?? '') === $this->chain->keyId(),
            'head_mac_matches' => $headMacMatches,
            'recovered_key_check_mac_matches' => $recoveredKeyCheckMacMatches,
            'recovered_format_mac_matches' => $recoveredFormatMacMatches,
        ];
    }

    /**
     * @param array<string,mixed> $row
     * @return array<string,mixed>|null
     */
    private function verifyRowStructure(
        array $row,
        int $expectedSequence,
        string $expectedPrevious,
        string $scope,
        int $checked
    ): ?array {
        $sequence = (int) $row['seq'];
        if ($sequence !== $expectedSequence) {
            return $this->result(
                'FAIL',
                'SEQUENCE_GAP',
                $scope,
                $checked,
                (int) $row['log_id'],
                $sequence
            );
        }
        if ((string) $row['previous_hash'] !== $expectedPrevious) {
            return $this->result(
                'FAIL',
                'CHAIN_LINK_MISMATCH',
                $scope,
                $checked,
                (int) $row['log_id'],
                $sequence
            );
        }

        return null;
    }

    /**
     * @param array<string,mixed> $row
     * @return array<string,mixed>|null
     */
    private function verifyRow(
        array $row,
        int $expectedSequence,
        string $expectedPrevious,
        string $scope,
        int $checked
    ): ?array {
        $structureFailure = $this->verifyRowStructure(
            $row,
            $expectedSequence,
            $expectedPrevious,
            $scope,
            $checked
        );
        if ($structureFailure !== null) {
            return $structureFailure;
        }

        $sequence = (int) $row['seq'];
        $formatVersion = (int) $row['format_version'];
        if (!in_array($formatVersion, [AuditChain::FORMAT_V1, AuditChain::FORMAT_V2], true)) {
            return $this->result(
                'FAIL',
                'ROW_FORMAT_VERSION_INVALID',
                $scope,
                $checked,
                (int) $row['log_id'],
                $sequence
            );
        }
        $recomputed = $this->chain->computeHash(
            $row,
            (string) $row['previous_hash'],
            $formatVersion
        );
        if (!hash_equals((string) $row['current_hash'], $recomputed)) {
            return $this->result(
                'FAIL',
                'ROW_HASH_INVALID',
                $scope,
                $checked,
                (int) $row['log_id'],
                $sequence
            );
        }
        return null;
    }

    private function previousHashForSequence(int $sequence): string
    {
        if ($sequence === 1) {
            return AuditChain::GENESIS;
        }
        $stmt = $this->pdo->prepare(
            'SELECT current_hash FROM audit_logs WHERE seq = :seq'
        );
        $stmt->execute([':seq' => $sequence - 1]);
        $hash = $stmt->fetchColumn();
        if ($hash === false) {
            throw new \RuntimeException('Audit sequence boundary is missing.');
        }
        return (string) $hash;
    }

    private function beginWriteTransaction(): void
    {
        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
            $this->pdo->exec('BEGIN IMMEDIATE');
            return;
        }
        $this->pdo->beginTransaction();
    }

    private function beginConsistentReadSnapshot(): void
    {
        $driver = (string) $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if ($driver === 'mysql') {
            $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
            $this->pdo->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
            return;
        }
        if ($driver === 'sqlite') {
            $databases = $this->pdo->query('PRAGMA database_list')->fetchAll(PDO::FETCH_ASSOC);
            $mainFile = '';
            foreach ($databases as $database) {
                if (($database['name'] ?? '') === 'main') {
                    $mainFile = (string) ($database['file'] ?? '');
                    break;
                }
            }
            $journalMode = strtolower(
                (string) $this->pdo->query('PRAGMA journal_mode')->fetchColumn()
            );
            if ($mainFile !== '' && $journalMode !== 'wal') {
                throw new \RuntimeException(
                    'File-backed SQLite audit verification requires WAL journal mode.'
                );
            }
            $this->pdo->exec('BEGIN DEFERRED TRANSACTION');
            return;
        }

        throw new \RuntimeException('Audit verification does not support this database driver.');
    }

    /**
     * @return array<string,mixed>
     */
    private function snapshotUnavailable(string $scope): array
    {
        return $this->result('UNKNOWN', 'CONSISTENT_SNAPSHOT_UNAVAILABLE', $scope);
    }

    private function signalVerificationCheckpoint(string $checkpoint): void
    {
        if ($this->verificationCheckpoint !== null) {
            ($this->verificationCheckpoint)($checkpoint);
        }
    }

    private function findEventId(string $eventId): ?int
    {
        try {
            $stmt = $this->pdo->prepare(
                'SELECT log_id FROM audit_logs WHERE event_id = :event_id'
            );
            $stmt->execute([':event_id' => $eventId]);
            $id = $stmt->fetchColumn();
            return $id === false ? null : (int) $id;
        } catch (\Throwable) {
            return null;
        }
    }

    private function isRetryable(\Throwable $error): bool
    {
        if (!$error instanceof PDOException) {
            return $error->getMessage() === 'Audit chain head changed during append.';
        }
        $sqlState = (string) $error->getCode();
        $driverCode = (int) ($error->errorInfo[1] ?? 0);
        $message = strtolower($error->getMessage());

        return in_array($sqlState, ['23000', '40001', 'HY000'], true)
            && (
                in_array($driverCode, [5, 6, 1205, 1213], true)
                || str_contains($message, 'locked')
                || str_contains($message, 'deadlock')
                || str_contains($message, 'unique')
                || str_contains($message, 'duplicate')
            );
    }

    /**
     * @return array<string,mixed>
     */
    private function result(
        string $state,
        string $reason,
        string $scope,
        int $checkedRows = 0,
        ?int $firstBadLogId = null,
        ?int $firstBadSequence = null,
        ?int $headSequence = null
    ): array {
        return [
            'state' => $state,
            'ok' => $state === 'PASS',
            'reason' => $reason,
            'scope' => $scope,
            'checked_rows' => $checkedRows,
            'first_bad_log_id' => $firstBadLogId,
            'first_bad_seq' => $firstBadSequence,
            'head_seq' => $headSequence,
            'anchor_seq' => null,
            'limitations' => [],
        ];
    }

    private static function boundedRequiredString(mixed $value, string $field, int $max): string
    {
        if (!is_string($value) || $value === '' || strlen($value) > $max) {
            throw new \InvalidArgumentException('Audit string field is invalid: ' . $field);
        }
        return $value;
    }

    private static function nullableInt(mixed $value): ?int
    {
        return $value === null || $value === '' ? null : (int) $value;
    }

    private static function nonNegativeInt(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value >= 0 ? $value : null;
        }
        if (is_string($value) && preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) === 1) {
            return (int) $value;
        }

        return null;
    }
}
