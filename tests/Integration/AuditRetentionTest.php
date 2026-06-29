<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Audit\AuditLogger;
use MediShield\Audit\AuditRetention;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for the PII-retention scrub (spec §9.8, §10 privacy).
 *
 * `attempted_identifier` captures the email a user typed on a failed login so an
 * administrator can follow up on possibly-leaked credentials. Because that value
 * is PII, it must be removable after a retention window. AuditRetention performs
 * that scrub — nulling ONLY the non-chained PII column — so:
 *   - the append-only hash chain (verifyChain) stays valid, and
 *   - "who did what" rows are never deleted, only the personal data is removed.
 */
final class AuditRetentionTest extends TestCase
{
    private \PDO $pdo;
    private \DateTimeImmutable $now;
    private AuditLogger $logger;
    private AuditRetention $retention;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-06-01 12:00:00', new \DateTimeZone('UTC'));
        // A clock that reads the mutable $this->now so tests can "advance time".
        $clock = new Clock(fn (): \DateTimeImmutable => $this->now);
        $this->pdo = TestSchema::pdo();
        $chain = AuditChain::fromHexKey(str_repeat('cd', 32));
        $this->logger = new AuditLogger($this->pdo, $chain, $clock);
        $this->retention = new AuditRetention($this->pdo);
    }

    private function logFailedLoginAt(string $when, string $email): void
    {
        $this->now = new \DateTimeImmutable($when, new \DateTimeZone('UTC'));
        $this->logger->log([
            'user_id' => null, 'user_role' => 'guest',
            'action' => 'LOGIN_FAILED', 'module' => 'Authentication',
            'ip_address' => '127.0.0.1', 'user_agent' => 'phpunit',
            'status' => 'FAILURE', 'anomaly_flag' => 'SUSPICIOUS',
            'attempted_identifier' => $email,
        ]);
    }

    public function testPurgeNullsIdentifiersOlderThanCutoff(): void
    {
        $this->logFailedLoginAt('2026-01-01 09:00:00', 'old@example.com');   // old
        $this->logFailedLoginAt('2026-05-30 09:00:00', 'recent@example.com'); // recent

        $cutoff = new \DateTimeImmutable('2026-03-01 00:00:00', new \DateTimeZone('UTC'));
        $affected = $this->retention->purgeIdentifiersOlderThan($cutoff);

        self::assertSame(1, $affected, 'Only the one old row should be scrubbed.');

        $rows = $this->pdo->query(
            'SELECT attempted_identifier FROM audit_logs ORDER BY log_id ASC'
        )->fetchAll(\PDO::FETCH_COLUMN);

        self::assertNull($rows[0], 'Old PII must be removed.');
        self::assertSame('recent@example.com', $rows[1], 'Recent PII must be kept.');
    }

    public function testPurgeKeepsHashChainValid(): void
    {
        $this->logFailedLoginAt('2026-01-01 09:00:00', 'old@example.com');
        $this->logFailedLoginAt('2026-05-30 09:00:00', 'recent@example.com');

        self::assertTrue($this->logger->verifyChain()['ok']);

        $cutoff = new \DateTimeImmutable('2026-03-01 00:00:00', new \DateTimeZone('UTC'));
        $this->retention->purgeIdentifiersOlderThan($cutoff);

        self::assertTrue(
            $this->logger->verifyChain()['ok'],
            'Scrubbing PII must never break the audit hash chain.'
        );
    }

    public function testPurgeReturnsZeroWhenNothingToScrub(): void
    {
        $this->logFailedLoginAt('2026-05-30 09:00:00', 'recent@example.com');

        $cutoff = new \DateTimeImmutable('2026-01-01 00:00:00', new \DateTimeZone('UTC'));
        self::assertSame(0, $this->retention->purgeIdentifiersOlderThan($cutoff));
    }

    public function testPurgeNeverDeletesRows(): void
    {
        $this->logFailedLoginAt('2026-01-01 09:00:00', 'old@example.com');

        $cutoff = new \DateTimeImmutable('2026-03-01 00:00:00', new \DateTimeZone('UTC'));
        $this->retention->purgeIdentifiersOlderThan($cutoff);

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn();
        self::assertSame(1, $count, 'The audit row itself must remain — only PII is removed.');
    }
}
