<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Audit\AuditChainInitializer;
use MediShield\Audit\AuditLogger;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for the append-only, hash-chained audit log (spec §9.8).
 */
final class AuditLoggerTest extends TestCase
{
    private \PDO $pdo;
    private AuditLogger $logger;

    protected function setUp(): void
    {
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $this->pdo = TestSchema::pdo();
        $chain = AuditChain::fromHexKey(str_repeat('cd', 32), 'audit-primary-2026');
        (new AuditChainInitializer($this->pdo, $chain, $clock))->initialize();
        $this->logger = new AuditLogger($this->pdo, $chain, $clock);
    }

    private function sampleEvent(string $action): array
    {
        return [
            'user_id' => 1, 'user_role' => 'admin',
            'action' => $action, 'module' => 'Authentication',
            'affected_record_id' => null, 'ip_address' => '127.0.0.1',
            'user_agent' => 'phpunit', 'status' => 'SUCCESS', 'anomaly_flag' => 'NORMAL',
        ];
    }

    public function testFirstEntryUsesGenesisAndVersionTwoMetadata(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $row = $this->pdo->query('SELECT * FROM audit_logs ORDER BY log_id ASC')->fetch();
        self::assertSame(AuditChain::GENESIS, $row['previous_hash']);
        self::assertSame(1, (int) $row['seq']);
        self::assertSame('audit-primary-2026', $row['key_id']);
        self::assertSame(AuditChain::FORMAT_V2, (int) $row['format_version']);
        self::assertNotSame('', $row['current_hash']);
    }

    public function testEntriesFormALinkedChain(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->logger->log($this->sampleEvent('USER_CREATED'));
        $this->logger->log($this->sampleEvent('LOGOUT'));

        $rows = $this->pdo->query('SELECT * FROM audit_logs ORDER BY log_id ASC')->fetchAll();
        self::assertCount(3, $rows);
        // Each row's previous_hash equals the prior row's current_hash.
        self::assertSame($rows[0]['current_hash'], $rows[1]['previous_hash']);
        self::assertSame($rows[1]['current_hash'], $rows[2]['previous_hash']);
    }

    public function testVerifyChainPassesForUntamperedLog(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->logger->log($this->sampleEvent('USER_CREATED'));

        $result = $this->logger->verifyLocalFull();
        self::assertSame('PASS', $result['state']);
        self::assertTrue($result['ok']);
        self::assertNull($result['first_bad_log_id']);
    }

    public function testVerifyChainWithoutIndependentAnchorIsUnknown(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));

        $result = $this->logger->verifyChain();

        self::assertSame('UNKNOWN', $result['state']);
        self::assertFalse($result['ok']);
        self::assertSame('EXTERNAL_ANCHOR_MISSING', $result['reason']);
    }

    public function testVerifyChainDetectsTampering(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->logger->log($this->sampleEvent('USER_CREATED'));

        // Simulate an attacker editing an existing row directly in the database.
        $this->pdo->exec("UPDATE audit_logs SET action = 'NOTHING_SUSPICIOUS' WHERE log_id = 1");

        $result = $this->logger->verifyLocalFull();
        self::assertSame('FAIL', $result['state']);
        self::assertSame(1, $result['first_bad_log_id']);
    }

    public function testVerifyLocalFullDetectsMiddleAndTailDeletion(): void
    {
        foreach (['LOGIN_SUCCESS', 'USER_CREATED', 'LOGOUT'] as $action) {
            $this->logger->log($this->sampleEvent($action));
        }
        $this->pdo->exec('DELETE FROM audit_logs WHERE seq = 2');
        self::assertSame('FAIL', $this->logger->verifyLocalFull()['state']);

        $this->setUp();
        foreach (['LOGIN_SUCCESS', 'USER_CREATED', 'LOGOUT'] as $action) {
            $this->logger->log($this->sampleEvent($action));
        }
        $this->pdo->exec('DELETE FROM audit_logs WHERE seq = 3');
        $result = $this->logger->verifyLocalFull();
        self::assertSame('FAIL', $result['state']);
        self::assertSame('PHYSICAL_ROW_COVERAGE_MISMATCH', $result['reason']);
    }

    public function testVerifyLocalFullDetectsDeletionOfAllRows(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec('DELETE FROM audit_logs');

        self::assertSame('FAIL', $this->logger->verifyLocalFull()['state']);
    }

    public function testVerifyLocalFullDetectsSequenceGap(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->logger->log($this->sampleEvent('LOGOUT'));
        $this->pdo->exec('UPDATE audit_logs SET seq = 4 WHERE seq = 2');

        $result = $this->logger->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('PHYSICAL_ROW_COVERAGE_MISMATCH', $result['reason']);
    }

    public function testVerifyLocalFullRejectsPhysicalSequenceZeroAndRecentQuarantinesIt(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->insertForgedSequence(0);

        $result = $this->logger->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('PHYSICAL_ROW_COVERAGE_MISMATCH', $result['reason']);
        self::assertNotContains('FORGED_SEQUENCE', array_column($this->logger->recent(10), 'action'));
    }

    public function testVerifyLocalFullRejectsPhysicalNegativeSequence(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->insertForgedSequence(-1);

        $result = $this->logger->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('PHYSICAL_ROW_COVERAGE_MISMATCH', $result['reason']);
    }

    public function testSchemaRejectsNonPositiveAuditSequence(): void
    {
        $this->expectException(\PDOException::class);
        $this->insertForgedSequence(0, false);
    }

    public function testSchemaRejectsForkedPreviousHash(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $row = $this->pdo->query('SELECT * FROM audit_logs WHERE seq = 1')->fetch();

        $this->expectException(\PDOException::class);
        $insert = $this->pdo->prepare(
            'INSERT INTO audit_logs
                (seq, event_id, key_id, format_version, user_id, user_role,
                 action, module, affected_record_id, ip_address, user_agent,
                 status, anomaly_flag, attempted_identifier, previous_hash,
                 current_hash, created_at)
             VALUES
                (2, :event_id, :key_id, 2, NULL, :role, :action, :module,
                 NULL, :ip, NULL, :status, :anomaly, NULL, :previous,
                 :current, :created)'
        );
        $insert->execute([
            ':event_id' => str_repeat('f', 32),
            ':key_id' => 'audit-primary-2026',
            ':role' => 'system',
            ':action' => 'LOGOUT',
            ':module' => 'test',
            ':ip' => '127.0.0.1',
            ':status' => 'SUCCESS',
            ':anomaly' => 'NORMAL',
            ':previous' => $row['previous_hash'],
            ':current' => str_repeat('a', 64),
            ':created' => '2026-01-01 12:00:00',
        ]);
    }

    public function testSQLiteFileDatabaseSupportsTwoIndependentWriters(): void
    {
        $path = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Support'
            . DIRECTORY_SEPARATOR . 'audit-sqlite-' . bin2hex(random_bytes(6)) . '.sqlite';
        try {
            $clock = new Clock(static fn () => new \DateTimeImmutable(
                '2026-01-01 12:00:00',
                new \DateTimeZone('UTC')
            ));
            $firstPdo = TestSchema::filePdo($path);
            $chain = AuditChain::fromHexKey(str_repeat('cd', 32), 'audit-primary-2026');
            (new AuditChainInitializer($firstPdo, $chain, $clock))->initialize();
            $secondPdo = new \PDO('sqlite:' . $path);
            $secondPdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            $first = new AuditLogger($firstPdo, $chain, $clock);
            $second = new AuditLogger($secondPdo, $chain, $clock);

            for ($index = 0; $index < 10; $index++) {
                ($index % 2 === 0 ? $first : $second)->log(
                    $this->sampleEvent('LOGIN_SUCCESS')
                );
            }

            self::assertSame('PASS', $first->verifyLocalFull()['state']);
            self::assertSame(
                10,
                (int) $firstPdo->query('SELECT COUNT(DISTINCT seq) FROM audit_logs')->fetchColumn()
            );
        } finally {
            unset($first, $second, $firstPdo, $secondPdo);
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    public function testVerifyLocalFullUsesOneSnapshotWhileAConcurrentAppendCommits(): void
    {
        $this->assertSnapshotIsStableAcrossConcurrentAppend('local-full');
    }

    public function testVerifyTipUsesOneSnapshotWhileAConcurrentAppendCommits(): void
    {
        $this->assertSnapshotIsStableAcrossConcurrentAppend('tip');
    }

    public function testRecentReturnsOnlyRowsFromTheSnapshotThatPassedFullVerification(): void
    {
        $path = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Support'
            . DIRECTORY_SEPARATOR . 'audit-recent-snapshot-' . bin2hex(random_bytes(6)) . '.sqlite';
        try {
            [$readerPdo, $writerPdo, $chain, $clock] = $this->snapshotConnections($path);
            $writer = new AuditLogger($writerPdo, $chain, $clock);
            $writer->log($this->sampleEvent('LOGIN_SUCCESS'));
            $appendCount = 0;
            $reader = new AuditLogger(
                $readerPdo,
                $chain,
                $clock,
                3,
                static function (string $checkpoint) use ($writer, &$appendCount): void {
                    if ($checkpoint !== 'local-full:head-read') {
                        return;
                    }
                    $appendCount++;
                    $writer->log([
                        'user_id' => 1,
                        'user_role' => 'admin',
                        'action' => 'USER_CREATED',
                        'module' => 'Authentication',
                        'affected_record_id' => null,
                        'ip_address' => '127.0.0.1',
                        'user_agent' => 'phpunit',
                        'status' => 'SUCCESS',
                        'anomaly_flag' => 'NORMAL',
                    ]);
                }
            );

            $recent = $reader->recent(10);

            self::assertSame(1, $appendCount);
            self::assertCount(1, $recent);
            self::assertSame('LOGIN_SUCCESS', $recent[0]['action']);
            self::assertSame(
                2,
                (int) $writerPdo->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn()
            );
        } finally {
            unset($reader, $writer, $readerPdo, $writerPdo);
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    public function testVerificationInsideCallerTransactionIsUnknownAndLeavesItOwned(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->beginTransaction();

        try {
            foreach ([
                $this->logger->verifyLocalFull(),
                $this->logger->verifyTip(1),
                $this->logger->verifyRange(1, 1),
                $this->logger->verifyChain(),
            ] as $result) {
                self::assertSame('UNKNOWN', $result['state']);
                self::assertSame('CONSISTENT_SNAPSHOT_UNAVAILABLE', $result['reason']);
                self::assertTrue($this->pdo->inTransaction());
            }
            self::assertSame([], $this->logger->recent(1));
            self::assertTrue($this->pdo->inTransaction());
        } finally {
            $this->pdo->rollBack();
        }
    }

    public function testFileSQLiteRollbackJournalReturnsUnknownInsteadOfTakingReadLock(): void
    {
        $path = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Support'
            . DIRECTORY_SEPARATOR . 'audit-rollback-journal-'
            . bin2hex(random_bytes(6)) . '.sqlite';
        try {
            $clock = new Clock(static fn () => new \DateTimeImmutable(
                '2026-01-01 12:00:00',
                new \DateTimeZone('UTC')
            ));
            $pdo = TestSchema::filePdo($path);
            $chain = AuditChain::fromHexKey(str_repeat('cd', 32), 'audit-primary-2026');
            (new AuditChainInitializer($pdo, $chain, $clock))->initialize();
            self::assertSame('delete', $pdo->query('PRAGMA journal_mode = DELETE')->fetchColumn());
            $logger = new AuditLogger($pdo, $chain, $clock);

            $result = $logger->verifyLocalFull();

            self::assertSame('UNKNOWN', $result['state']);
            self::assertSame('CONSISTENT_SNAPSHOT_UNAVAILABLE', $result['reason']);
            self::assertFalse($pdo->inTransaction());
        } finally {
            unset($logger, $pdo);
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    public function testVerifyLocalFullDetectsHeadMacTampering(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec(
            "UPDATE audit_chain_head SET head_mac = '" . str_repeat('f', 64) . "'"
        );

        $result = $this->logger->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('HEAD_MAC_INVALID', $result['reason']);
    }

    public function testVerifyWithWrongAuditKeyIsUnknownRatherThanPass(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $wrong = new AuditLogger(
            $this->pdo,
            AuditChain::fromHexKey(str_repeat('ef', 32), 'audit-primary-2026'),
            new Clock()
        );

        $result = $wrong->verifyLocalFull();

        self::assertSame('UNKNOWN', $result['state']);
        self::assertSame('AUDIT_KEY_MISMATCH', $result['reason']);
    }

    public function testVerifyKeyCheckOnlyTamperingIsFail(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec(
            "UPDATE audit_chain_head SET key_check = '" . str_repeat('f', 64) . "'"
        );

        $result = $this->logger->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('HEAD_KEY_CHECK_INVALID', $result['reason']);
    }

    public function testVerifyRowAndKeyCheckTamperingRemainsFail(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec("UPDATE audit_logs SET action = 'FORGED_ACTION' WHERE seq = 1");
        $this->pdo->exec(
            "UPDATE audit_chain_head SET key_check = '" . str_repeat('f', 64) . "'"
        );

        $result = $this->logger->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('ROW_HASH_INVALID', $result['reason']);
    }

    public function testVerifyFormatDowngradeAndKeyCheckTamperingRemainsFail(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec('UPDATE audit_logs SET format_version = 1 WHERE seq = 1');
        $this->pdo->exec(
            "UPDATE audit_chain_head SET key_check = '" . str_repeat('f', 64) . "'"
        );

        $result = $this->logger->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('ROW_HASH_INVALID', $result['reason']);
    }

    public function testVerifyUnsupportedRowFormatWithAuthenticatedHeadIsFail(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec('UPDATE audit_logs SET format_version = 99 WHERE seq = 1');

        $result = $this->logger->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('ROW_FORMAT_VERSION_INVALID', $result['reason']);
    }

    public function testVerifyLinkageEvidenceTakesPrecedenceOverWrongKeyAndUnknownFormat(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->logger->log($this->sampleEvent('LOGOUT'));
        $this->pdo->exec('UPDATE audit_logs SET format_version = 99 WHERE seq = 1');
        $this->pdo->exec("UPDATE audit_logs SET previous_hash = 'BROKEN-LINK' WHERE seq = 2");
        $wrong = new AuditLogger(
            $this->pdo,
            AuditChain::fromHexKey(str_repeat('ef', 32), 'audit-primary-2026'),
            new Clock()
        );

        $result = $wrong->verifyLocalFull();

        self::assertSame('FAIL', $result['state']);
        self::assertSame('CHAIN_LINK_MISMATCH', $result['reason']);
    }

    public function testVerifyWithMissingHeadIsUnknownRatherThanPass(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec('DELETE FROM audit_chain_head');

        $result = $this->logger->verifyLocalFull();

        self::assertSame('UNKNOWN', $result['state']);
        self::assertSame('CHAIN_HEAD_MISSING', $result['reason']);
    }

    public function testVerifyDatabaseErrorIsUnknownAndSafe(): void
    {
        $this->pdo->exec('DROP TABLE audit_chain_head');

        $result = $this->logger->verifyLocalFull();

        self::assertSame('UNKNOWN', $result['state']);
        self::assertSame('VERIFICATION_ERROR', $result['reason']);
        self::assertArrayNotHasKey('exception', $result);
    }

    public function testV2HashCoversIpAddressAndUserAgent(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec("UPDATE audit_logs SET ip_address = '203.0.113.99', user_agent = 'forged'");

        self::assertSame('FAIL', $this->logger->verifyLocalFull()['state']);
    }

    public function testTipAndRangeChecksAreBoundedAndNeverClaimFullIntegrity(): void
    {
        foreach (['LOGIN_SUCCESS', 'USER_CREATED', 'LOGOUT'] as $action) {
            $this->logger->log($this->sampleEvent($action));
        }

        $tip = $this->logger->verifyTip(2);
        $range = $this->logger->verifyRange(2, 3);

        self::assertSame('UNKNOWN', $tip['state']);
        self::assertSame(2, $tip['checked_rows']);
        self::assertSame('PARTIAL_VERIFICATION', $tip['reason']);
        self::assertSame('UNKNOWN', $range['state']);
        self::assertSame(2, $range['checked_rows']);
        self::assertSame('PARTIAL_VERIFICATION', $range['reason']);
    }

    public function testAppendRefusesCallerOwnedTransactionWithoutRollingItBack(): void
    {
        $this->pdo->beginTransaction();

        try {
            $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
            self::fail('Audit append accepted a caller-owned transaction.');
        } catch (\LogicException) {
            self::assertTrue($this->pdo->inTransaction());
        } finally {
            $this->pdo->rollBack();
        }
    }

    public function testRecentReturnsNewestFirst(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->logger->log($this->sampleEvent('USER_CREATED'));
        $this->logger->log($this->sampleEvent('LOGOUT'));

        $recent = $this->logger->recent(10);

        self::assertCount(3, $recent);
        // Newest first => the last action logged is at index 0.
        self::assertSame('LOGOUT', $recent[0]['action']);
        self::assertSame('LOGIN_SUCCESS', $recent[2]['action']);
    }

    public function testRecentQuarantinesRowsWhenLocalVerificationFails(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->pdo->exec("UPDATE audit_logs SET action = 'FORGED_ACTION' WHERE seq = 1");

        self::assertSame([], $this->logger->recent(10));
        self::assertSame('FAIL', $this->logger->verifyLocalFull()['state']);
    }

    public function testStoresAndReturnsAttemptedIdentifier(): void
    {
        // A failed login against a known/unknown email records what was typed.
        $event = $this->sampleEvent('LOGIN_FAILED');
        $event['attempted_identifier'] = 'attacker@example.com';
        $this->logger->log($event);

        $recent = $this->logger->recent(1);
        self::assertSame('attacker@example.com', $recent[0]['attempted_identifier']);
    }

    public function testAttemptedIdentifierDefaultsToNull(): void
    {
        // Most events (e.g. a successful login) carry no typed identifier.
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));

        $recent = $this->logger->recent(1);
        self::assertNull($recent[0]['attempted_identifier']);
    }

    public function testAttemptedIdentifierIsNotPartOfHashChain(): void
    {
        // Storing PII outside the hash chain is what lets us scrub it later
        // without breaking integrity verification. Prove it: mutating the column
        // directly must NOT make verifyChain() fail.
        $event = $this->sampleEvent('LOGIN_FAILED');
        $event['attempted_identifier'] = 'leaked@example.com';
        $this->logger->log($event);
        $this->logger->log($this->sampleEvent('LOGOUT'));

        self::assertSame('PASS', $this->logger->verifyLocalFull()['state']);

        // Simulate the PII scrub editing only the non-chained column.
        $this->pdo->exec('UPDATE audit_logs SET attempted_identifier = NULL WHERE log_id = 1');

        self::assertTrue(
            $this->logger->verifyLocalFull()['ok'],
            'Nulling the non-chained attempted_identifier must not break the chain.'
        );
    }

    public function testRecentRespectsLimit(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        }

        self::assertCount(2, $this->logger->recent(2));
    }

    public function testRecentClampsNonPositiveLimitToOne(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->logger->log($this->sampleEvent('LOGOUT'));

        // A zero/negative limit must not return everything (or error); it clamps to 1.
        self::assertCount(1, $this->logger->recent(0));
    }

    private function insertForgedSequence(int $sequence, bool $bypassChecks = true): void
    {
        if ($bypassChecks) {
            $this->pdo->exec('PRAGMA ignore_check_constraints = ON');
        }

        try {
            $insert = $this->pdo->prepare(
                'INSERT INTO audit_logs
                    (seq, event_id, key_id, format_version, user_id, user_role,
                     action, module, affected_record_id, ip_address, user_agent,
                     status, anomaly_flag, attempted_identifier, previous_hash,
                     current_hash, created_at)
                 VALUES
                    (:seq, :event_id, :key_id, 2, NULL, :role, :action, :module,
                     NULL, :ip, NULL, :status, :anomaly, NULL, :previous,
                     :current, :created)'
            );
            $insert->execute([
                ':seq' => $sequence,
                ':event_id' => 'forged-sequence-' . $sequence,
                ':key_id' => 'audit-primary-2026',
                ':role' => 'system',
                ':action' => 'FORGED_SEQUENCE',
                ':module' => 'test',
                ':ip' => '127.0.0.1',
                ':status' => 'SUCCESS',
                ':anomaly' => 'NORMAL',
                ':previous' => 'FORGED-PREVIOUS-' . $sequence,
                ':current' => str_repeat('f', 64),
                ':created' => '2026-01-01 12:00:00',
            ]);
        } finally {
            if ($bypassChecks) {
                $this->pdo->exec('PRAGMA ignore_check_constraints = OFF');
            }
        }
    }

    private function assertSnapshotIsStableAcrossConcurrentAppend(string $scope): void
    {
        $path = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Support'
            . DIRECTORY_SEPARATOR . 'audit-' . $scope . '-snapshot-'
            . bin2hex(random_bytes(6)) . '.sqlite';
        try {
            [$readerPdo, $writerPdo, $chain, $clock] = $this->snapshotConnections($path);
            $writer = new AuditLogger($writerPdo, $chain, $clock);
            $writer->log($this->sampleEvent('LOGIN_SUCCESS'));
            $appendCount = 0;
            $reader = new AuditLogger(
                $readerPdo,
                $chain,
                $clock,
                3,
                static function (string $checkpoint) use ($writer, $scope, &$appendCount): void {
                    if ($checkpoint !== $scope . ':head-read') {
                        return;
                    }
                    $appendCount++;
                    $writer->log([
                        'user_id' => 1,
                        'user_role' => 'admin',
                        'action' => 'USER_CREATED',
                        'module' => 'Authentication',
                        'affected_record_id' => null,
                        'ip_address' => '127.0.0.1',
                        'user_agent' => 'phpunit',
                        'status' => 'SUCCESS',
                        'anomaly_flag' => 'NORMAL',
                    ]);
                }
            );

            $result = $scope === 'local-full'
                ? $reader->verifyLocalFull()
                : $reader->verifyTip(1);

            self::assertSame(1, $appendCount);
            self::assertSame($scope === 'local-full' ? 'PASS' : 'UNKNOWN', $result['state']);
            self::assertNotSame('HEAD_ROW_MISMATCH', $result['reason']);
            self::assertSame(1, $result['checked_rows']);
            self::assertSame(1, $result['head_seq']);
            self::assertSame(
                2,
                (int) $writerPdo->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn()
            );
        } finally {
            unset($reader, $writer, $readerPdo, $writerPdo);
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    /**
     * @return array{0:\PDO,1:\PDO,2:AuditChain,3:Clock}
     */
    private function snapshotConnections(string $path): array
    {
        $clock = new Clock(static fn () => new \DateTimeImmutable(
            '2026-01-01 12:00:00',
            new \DateTimeZone('UTC')
        ));
        $readerPdo = TestSchema::filePdo($path);
        $writerPdo = new \PDO('sqlite:' . $path);
        $writerPdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $writerPdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        $chain = AuditChain::fromHexKey(str_repeat('cd', 32), 'audit-primary-2026');
        (new AuditChainInitializer($readerPdo, $chain, $clock))->initialize();

        return [$readerPdo, $writerPdo, $chain, $clock];
    }
}
