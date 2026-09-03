<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Audit\AuditChainInitializer;
use MediShield\Audit\AuditLogger;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

final class AuditMigrationTest extends TestCase
{
    public function testInitialize_PreservesHistoricalVersionOneHashesInLogIdOrder(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        $pdo->exec(
            'CREATE TABLE audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                seq INTEGER NULL,
                event_id TEXT NULL,
                key_id TEXT NULL,
                format_version INTEGER NULL,
                user_id INTEGER NULL,
                user_role TEXT NOT NULL,
                action TEXT NOT NULL,
                module TEXT NOT NULL,
                affected_record_id TEXT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT NULL,
                status TEXT NOT NULL,
                anomaly_flag TEXT NOT NULL,
                attempted_identifier TEXT NULL,
                previous_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )'
        );
        $pdo->exec(
            'CREATE TABLE audit_chain_head (
                singleton_id INTEGER PRIMARY KEY,
                last_seq INTEGER NOT NULL,
                last_log_id INTEGER NULL,
                head_hash TEXT NOT NULL,
                key_id TEXT NOT NULL,
                format_version INTEGER NOT NULL,
                key_check TEXT NOT NULL,
                head_mac TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )'
        );
        $clock = new Clock(static fn () => new \DateTimeImmutable(
            '2026-09-03 00:00:00',
            new \DateTimeZone('UTC')
        ));
        $chain = AuditChain::fromHexKey(str_repeat('cd', 32), 'audit-primary-2026');
        $previous = AuditChain::GENESIS;
        $storedHashes = [];
        foreach (['LOGIN_FAILED', 'ACCOUNT_LOCKED'] as $action) {
            $entry = [
                'user_id' => 7,
                'user_role' => 'doctor',
                'action' => $action,
                'module' => 'auth',
                'affected_record_id' => null,
                'status' => 'FAILED',
                'anomaly_flag' => 'HIGH_RISK',
                'created_at' => '2026-01-01 12:00:00',
            ];
            $current = $chain->computeHash($entry, $previous, AuditChain::FORMAT_V1);
            $insert = $pdo->prepare(
                'INSERT INTO audit_logs
                    (user_id, user_role, action, module, affected_record_id,
                     ip_address, user_agent, status, anomaly_flag,
                     attempted_identifier, previous_hash, current_hash, created_at)
                 VALUES
                    (:user_id, :user_role, :action, :module, :affected_record_id,
                     :ip_address, :user_agent, :status, :anomaly_flag,
                     :attempted_identifier, :previous_hash, :current_hash, :created_at)'
            );
            $insert->execute([
                ':user_id' => $entry['user_id'],
                ':user_role' => $entry['user_role'],
                ':action' => $entry['action'],
                ':module' => $entry['module'],
                ':affected_record_id' => null,
                ':ip_address' => '127.0.0.1',
                ':user_agent' => 'legacy',
                ':status' => $entry['status'],
                ':anomaly_flag' => $entry['anomaly_flag'],
                ':attempted_identifier' => 'legacy@example.com',
                ':previous_hash' => $previous,
                ':current_hash' => $current,
                ':created_at' => $entry['created_at'],
            ]);
            $storedHashes[] = $current;
            $previous = $current;
        }

        $initializer = new AuditChainInitializer($pdo, $chain, $clock);
        $initializer->initialize();
        $firstHead = $pdo->query('SELECT * FROM audit_chain_head')->fetch();
        $initializer->initialize();

        $rows = $pdo->query(
            'SELECT seq, event_id, key_id, format_version, current_hash
               FROM audit_logs ORDER BY log_id'
        )->fetchAll();
        self::assertSame([1, 2], array_map('intval', array_column($rows, 'seq')));
        self::assertSame(['legacy-1', 'legacy-2'], array_column($rows, 'event_id'));
        self::assertSame(
            ['audit-primary-2026', 'audit-primary-2026'],
            array_column($rows, 'key_id')
        );
        self::assertSame([1, 1], array_map('intval', array_column($rows, 'format_version')));
        self::assertSame($storedHashes, array_column($rows, 'current_hash'));
        self::assertSame(
            $firstHead,
            $pdo->query('SELECT * FROM audit_chain_head')->fetch(),
            'Initialization must be idempotent.'
        );
        self::assertSame(
            'PASS',
            (new AuditLogger($pdo, $chain, $clock))->verifyLocalFull()['state']
        );
    }

    public function testInitialize_RefusesPreExistingSequenceInsteadOfRenumberingIt(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(static fn () => new \DateTimeImmutable(
            '2026-09-03 00:00:00',
            new \DateTimeZone('UTC')
        ));
        $chain = AuditChain::fromHexKey(str_repeat('cd', 32), 'audit-primary-2026');
        $entry = [
            'user_id' => 7,
            'user_role' => 'doctor',
            'action' => 'LOGIN_FAILED',
            'module' => 'auth',
            'affected_record_id' => null,
            'status' => 'FAILED',
            'anomaly_flag' => 'HIGH_RISK',
            'created_at' => '2026-01-01 12:00:00',
        ];
        $insert = $pdo->prepare(
            'INSERT INTO audit_logs
                (seq, event_id, key_id, format_version, user_id, user_role,
                 action, module, affected_record_id, ip_address, user_agent,
                 status, anomaly_flag, attempted_identifier, previous_hash,
                 current_hash, created_at)
             VALUES
                (2, :event_id, :key_id, 1, :user_id, :user_role,
                 :action, :module, NULL, :ip_address, :user_agent,
                 :status, :anomaly_flag, NULL, :previous_hash,
                 :current_hash, :created_at)'
        );
        $insert->execute([
            ':event_id' => 'legacy-1',
            ':key_id' => 'legacy-v1',
            ':user_id' => $entry['user_id'],
            ':user_role' => $entry['user_role'],
            ':action' => $entry['action'],
            ':module' => $entry['module'],
            ':ip_address' => '127.0.0.1',
            ':user_agent' => 'legacy',
            ':status' => $entry['status'],
            ':anomaly_flag' => $entry['anomaly_flag'],
            ':previous_hash' => AuditChain::GENESIS,
            ':current_hash' => $chain->computeHash(
                $entry,
                AuditChain::GENESIS,
                AuditChain::FORMAT_V1
            ),
            ':created_at' => $entry['created_at'],
        ]);

        try {
            (new AuditChainInitializer($pdo, $chain, $clock))->initialize();
            self::fail('Initializer silently renumbered pre-existing forensic metadata.');
        } catch (\RuntimeException $error) {
            self::assertSame(
                'Historical audit rows are not in deterministic sequence order.',
                $error->getMessage()
            );
        }

        self::assertSame(2, (int) $pdo->query('SELECT seq FROM audit_logs')->fetchColumn());
        self::assertSame(
            0,
            (int) $pdo->query('SELECT COUNT(*) FROM audit_chain_head')->fetchColumn()
        );
    }
}
