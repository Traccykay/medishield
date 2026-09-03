<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Audit\AuditAnchorStore;
use MediShield\Audit\AuditChainInitializer;
use MediShield\Audit\AuditLogger;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

final class AuditAnchorStoreTest extends TestCase
{
    private \PDO $pdo;
    private AuditLogger $logger;
    private AuditAnchorStore $anchors;
    private string $anchorPath;

    protected function setUp(): void
    {
        $clock = new Clock(static fn () => new \DateTimeImmutable(
            '2026-09-03 00:00:00',
            new \DateTimeZone('UTC')
        ));
        $this->pdo = TestSchema::pdo();
        $chain = AuditChain::fromHexKey(str_repeat('cd', 32), 'audit-primary-2026');
        (new AuditChainInitializer($this->pdo, $chain, $clock))->initialize();
        $this->logger = new AuditLogger($this->pdo, $chain, $clock);
        $this->anchorPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Support'
            . DIRECTORY_SEPARATOR . 'audit-anchor-' . bin2hex(random_bytes(6)) . '.jsonl';
        $this->anchors = AuditAnchorStore::fromHexKey(
            $this->anchorPath,
            str_repeat('ef', 32),
            'anchor-primary-2026',
            $clock
        );
    }

    protected function tearDown(): void
    {
        if (is_file($this->anchorPath)) {
            unlink($this->anchorPath);
        }
    }

    public function testAppendCurrentHead_ThenVerify_ReturnsPass(): void
    {
        $this->logger->log($this->event('LOGIN_SUCCESS'));

        self::assertTrue($this->anchors->anchor($this->logger->head()));
        self::assertSame('PASS', $this->logger->verifyChain($this->anchors)['state']);
    }

    public function testAnchor_SameHeadTwice_IsIdempotent(): void
    {
        $this->logger->log($this->event('LOGIN_SUCCESS'));
        $head = $this->logger->head();

        self::assertTrue($this->anchors->anchor($head));
        self::assertFalse($this->anchors->anchor($head));
        self::assertCount(1, file($this->anchorPath, FILE_IGNORE_NEW_LINES));
    }

    public function testVerify_WholeDatabaseRollbackBehindAnchor_ReturnsFail(): void
    {
        $this->logger->log($this->event('LOGIN_SUCCESS'));
        $rowOne = $this->pdo->query('SELECT * FROM audit_logs WHERE seq = 1')->fetch();
        $headOne = $this->logger->head();
        $this->anchors->anchor($headOne);

        $this->logger->log($this->event('LOGOUT'));
        $this->anchors->anchor($this->logger->head());

        $this->pdo->exec('DELETE FROM audit_logs');
        $columns = array_keys($rowOne);
        $insert = $this->pdo->prepare(
            'INSERT INTO audit_logs (' . implode(', ', $columns) . ') VALUES ('
            . implode(', ', array_map(static fn (string $name): string => ':' . $name, $columns)) . ')'
        );
        $insert->execute(array_combine(
            array_map(static fn (string $name): string => ':' . $name, $columns),
            array_values($rowOne)
        ));
        $update = $this->pdo->prepare(
            'UPDATE audit_chain_head
                SET last_seq = :last_seq, last_log_id = :last_log_id,
                    head_hash = :head_hash, key_id = :key_id,
                    format_version = :format_version, key_check = :key_check,
                    head_mac = :head_mac, updated_at = :updated_at
              WHERE singleton_id = 1'
        );
        $update->execute([
            ':last_seq' => $headOne['last_seq'],
            ':last_log_id' => $headOne['last_log_id'],
            ':head_hash' => $headOne['head_hash'],
            ':key_id' => $headOne['key_id'],
            ':format_version' => $headOne['format_version'],
            ':key_check' => $headOne['key_check'],
            ':head_mac' => $headOne['head_mac'],
            ':updated_at' => $headOne['updated_at'],
        ]);

        $result = $this->logger->verifyChain($this->anchors);
        self::assertSame('FAIL', $result['state']);
        self::assertSame('DATABASE_ROLLBACK_DETECTED', $result['reason']);
    }

    public function testVerify_WithWrongAnchorKey_ReturnsUnknown(): void
    {
        $this->logger->log($this->event('LOGIN_SUCCESS'));
        $this->anchors->anchor($this->logger->head());
        $wrong = AuditAnchorStore::fromHexKey(
            $this->anchorPath,
            str_repeat('aa', 32),
            'anchor-primary-2026',
            new Clock()
        );

        $result = $this->logger->verifyChain($wrong);

        self::assertSame('UNKNOWN', $result['state']);
        self::assertSame('ANCHOR_KEY_MISMATCH', $result['reason']);
    }

    public function testVerify_WithUnanchoredSuffix_ReturnsUnknown(): void
    {
        $this->logger->log($this->event('LOGIN_SUCCESS'));
        $this->anchors->anchor($this->logger->head());
        $this->logger->log($this->event('LOGOUT'));

        $result = $this->logger->verifyChain($this->anchors);

        self::assertSame('UNKNOWN', $result['state']);
        self::assertSame('UNANCHORED_DATABASE_SUFFIX', $result['reason']);
    }

    private function event(string $action): array
    {
        return [
            'user_id' => 1,
            'user_role' => 'admin',
            'action' => $action,
            'module' => 'auth',
            'ip_address' => '127.0.0.1',
            'user_agent' => 'phpunit',
            'status' => 'SUCCESS',
            'anomaly_flag' => 'NORMAL',
        ];
    }
}
