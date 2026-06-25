<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

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
        $chain = AuditChain::fromHexKey(str_repeat('cd', 32));
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

    public function testFirstEntryUsesGenesisPreviousHash(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $row = $this->pdo->query('SELECT * FROM audit_logs ORDER BY log_id ASC')->fetch();
        self::assertSame(AuditChain::GENESIS, $row['previous_hash']);
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

        $result = $this->logger->verifyChain();
        self::assertTrue($result['ok']);
        self::assertNull($result['first_bad_log_id']);
    }

    public function testVerifyChainDetectsTampering(): void
    {
        $this->logger->log($this->sampleEvent('LOGIN_SUCCESS'));
        $this->logger->log($this->sampleEvent('USER_CREATED'));

        // Simulate an attacker editing an existing row directly in the database.
        $this->pdo->exec("UPDATE audit_logs SET action = 'NOTHING_SUSPICIOUS' WHERE log_id = 1");

        $result = $this->logger->verifyChain();
        self::assertFalse($result['ok']);
        self::assertSame(1, $result['first_bad_log_id']);
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
}
