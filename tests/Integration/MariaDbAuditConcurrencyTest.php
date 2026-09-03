<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Audit\AuditChainInitializer;
use MediShield\Audit\AuditLogger;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use PHPUnit\Framework\TestCase;

/**
 * Opt-in real MariaDB proof. Run with MEDISHIELD_MARIADB_AUDIT_TEST=1.
 */
final class MariaDbAuditConcurrencyTest extends TestCase
{
    private const DATABASE = 'medishield_ui_account_test';

    private ?\PDO $root = null;
    private array $config = [];

    protected function setUp(): void
    {
        if (getenv('MEDISHIELD_MARIADB_AUDIT_TEST') !== '1') {
            self::markTestSkipped('Real MariaDB audit test is opt-in.');
        }
        $this->config = require dirname(__DIR__, 2) . '/config/config.php';
        $password = getenv('MEDISHIELD_SETUP_DB_PASS');
        $this->root = new \PDO(
            'mysql:host=127.0.0.1;port=3306;charset=utf8mb4',
            (string) (getenv('MEDISHIELD_SETUP_DB_USER') ?: 'root'),
            is_string($password) ? $password : '',
            [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            ]
        );
        $this->root->exec('DROP DATABASE IF EXISTS `' . self::DATABASE . '`');
        $this->root->exec(
            'CREATE DATABASE `' . self::DATABASE
            . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
        );
        $this->root->exec('USE `' . self::DATABASE . '`');
    }

    protected function tearDown(): void
    {
        if ($this->root !== null) {
            $this->root->exec('DROP DATABASE IF EXISTS `' . self::DATABASE . '`');
        }
    }

    public function testMigrationTwicePreservesV1RowsAndConcurrentWritersRemainLinear(): void
    {
        $this->root->exec(
            "CREATE TABLE audit_logs (
                log_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
                user_id INT UNSIGNED NULL,
                user_role VARCHAR(50) NOT NULL,
                action VARCHAR(150) NOT NULL,
                module VARCHAR(100) NOT NULL,
                affected_record_id VARCHAR(100) NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT NULL,
                status ENUM('SUCCESS','FAILED','BLOCKED') NOT NULL,
                anomaly_flag ENUM('NORMAL','SUSPICIOUS','HIGH_RISK') NOT NULL,
                attempted_identifier VARCHAR(255) NULL,
                previous_hash VARCHAR(255) NOT NULL,
                current_hash VARCHAR(255) NOT NULL,
                created_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        $chain = AuditChain::fromHexKey(
            (string) $this->config['audit_hmac_key_hex'],
            (string) $this->config['audit_key_id']
        );
        $previous = AuditChain::GENESIS;
        $hashes = [];
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
            $stmt = $this->root->prepare(
                'INSERT INTO audit_logs
                    (user_id, user_role, action, module, affected_record_id,
                     ip_address, user_agent, status, anomaly_flag,
                     attempted_identifier, previous_hash, current_hash, created_at)
                 VALUES
                    (7, :role, :action, :module, NULL, :ip, :agent, :status,
                     :anomaly, :identifier, :previous, :current, :created_at)'
            );
            $stmt->execute([
                ':role' => 'doctor',
                ':action' => $action,
                ':module' => 'auth',
                ':ip' => '127.0.0.1',
                ':agent' => 'legacy',
                ':status' => 'FAILED',
                ':anomaly' => 'HIGH_RISK',
                ':identifier' => 'legacy@example.com',
                ':previous' => $previous,
                ':current' => $current,
                ':created_at' => $entry['created_at'],
            ]);
            $hashes[] = $current;
            $previous = $current;
        }

        $migration = file_get_contents(
            dirname(__DIR__, 2) . '/sql/migrations/2026-09-03_forensic_audit_v2.sql'
        );
        self::assertIsString($migration);
        $this->executeSqlScript($migration);

        $clock = new Clock(static fn () => new \DateTimeImmutable(
            '2026-09-03 00:00:00',
            new \DateTimeZone('UTC')
        ));
        (new AuditChainInitializer($this->root, $chain, $clock))->initialize();
        $this->executeSqlScript($migration);
        self::assertSame(
            $hashes,
            $this->root->query('SELECT current_hash FROM audit_logs ORDER BY log_id')
                ->fetchAll(\PDO::FETCH_COLUMN)
        );

        $webUser = (string) $this->config['db']['user'];
        $this->root->exec(
            "GRANT SELECT, INSERT ON `" . self::DATABASE . "`.audit_logs"
            . " TO '" . str_replace("'", "''", $webUser) . "'@'127.0.0.1'"
        );
        $this->root->exec(
            "GRANT SELECT, UPDATE ON `" . self::DATABASE . "`.audit_chain_head"
            . " TO '" . str_replace("'", "''", $webUser) . "'@'127.0.0.1'"
        );

        $processes = [];
        $worker = dirname(__DIR__) . '/Support/audit_concurrency_worker.php';
        for ($workerNumber = 0; $workerNumber < 2; $workerNumber++) {
            $processes[] = proc_open(
                [PHP_BINARY, $worker, self::DATABASE, '20'],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
                dirname(__DIR__, 2)
            );
            self::assertIsResource($processes[$workerNumber]);
            $processes[$workerNumber] = [$processes[$workerNumber], $pipes];
        }
        foreach ($processes as [$process, $pipes]) {
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            self::assertSame(0, proc_close($process), $stdout . $stderr);
        }

        $applicationConfig = $this->config;
        $applicationConfig['db']['name'] = self::DATABASE;
        $pdo = \MediShield\Database\Connection::fromConfig($applicationConfig);
        $verification = (new AuditLogger($pdo, $chain, $clock))->verifyLocalFull();

        self::assertSame('PASS', $verification['state']);
        self::assertSame(42, $verification['checked_rows']);
        self::assertSame(
            42,
            (int) $pdo->query('SELECT COUNT(DISTINCT seq) FROM audit_logs')->fetchColumn()
        );

        $writerPdo = \MediShield\Database\Connection::fromConfig($applicationConfig);
        $writer = new AuditLogger($writerPdo, $chain, $clock);
        $readerPdo = \MediShield\Database\Connection::fromConfig($applicationConfig);
        $readerPdo->exec('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED');
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
                    'action' => 'INTEGRITY_VERIFIED',
                    'module' => 'test',
                    'affected_record_id' => null,
                    'ip_address' => '127.0.0.1',
                    'user_agent' => 'phpunit',
                    'status' => 'SUCCESS',
                    'anomaly_flag' => 'NORMAL',
                ]);
            }
        );

        $concurrentVerification = $reader->verifyLocalFull();

        self::assertSame(1, $appendCount);
        self::assertSame('PASS', $concurrentVerification['state']);
        self::assertSame(42, $concurrentVerification['checked_rows']);
        self::assertSame(42, $concurrentVerification['head_seq']);
        self::assertSame(
            43,
            (int) $writerPdo->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn()
        );

        $this->root->exec("UPDATE audit_logs SET action = 'FORGED_ACTION' WHERE seq = 1");
        $tampered = (new AuditLogger($readerPdo, $chain, $clock))->verifyLocalFull();
        self::assertSame('FAIL', $tampered['state']);
        self::assertSame('ROW_HASH_INVALID', $tampered['reason']);

        $definition = (string) $this->root->query('SHOW CREATE TABLE audit_logs')->fetch()['Create Table'];
        self::assertStringContainsString('ascii_bin', $definition);
        self::assertStringContainsString('uq_audit_previous_hash', $definition);
        self::assertStringContainsString('chk_audit_seq_positive', $definition);

        $this->expectException(\PDOException::class);
        $this->root->exec(
            "INSERT INTO audit_logs
                (seq, event_id, key_id, format_version, user_id, user_role,
                 action, module, affected_record_id, ip_address, user_agent,
                 status, anomaly_flag, attempted_identifier, previous_hash,
                 current_hash, created_at)
             VALUES
                (0, 'forged-zero', 'audit-primary-2026', 2, NULL, 'system',
                 'FORGED_SEQUENCE', 'test', NULL, '127.0.0.1', NULL,
                 'SUCCESS', 'NORMAL', NULL, 'FORGED-PREVIOUS-ZERO',
                 '" . str_repeat('f', 64) . "', '2026-01-01 12:00:00')"
        );
    }

    public function testMigrationRefusesExistingSequenceZeroWithoutRepairingIt(): void
    {
        $this->root->exec(
            "CREATE TABLE audit_logs (
                log_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
                seq BIGINT UNSIGNED NULL,
                event_id VARCHAR(64) NULL,
                key_id VARCHAR(64) NULL,
                format_version SMALLINT UNSIGNED NULL,
                user_id INT UNSIGNED NULL,
                user_role VARCHAR(50) NOT NULL,
                action VARCHAR(150) NOT NULL,
                module VARCHAR(100) NOT NULL,
                affected_record_id VARCHAR(100) NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT NULL,
                status ENUM('SUCCESS','FAILED','BLOCKED') NOT NULL,
                anomaly_flag ENUM('NORMAL','SUSPICIOUS','HIGH_RISK') NOT NULL,
                attempted_identifier VARCHAR(255) NULL,
                previous_hash VARCHAR(255) NOT NULL,
                current_hash VARCHAR(255) NOT NULL,
                created_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        $this->root->exec(
            "INSERT INTO audit_logs
                (seq, event_id, key_id, format_version, user_id, user_role,
                 action, module, affected_record_id, ip_address, user_agent,
                 status, anomaly_flag, attempted_identifier, previous_hash,
                 current_hash, created_at)
             VALUES
                (0, 'preexisting-zero', 'legacy-v1', 1, NULL, 'system',
                 'LOGIN_FAILED', 'auth', NULL, '127.0.0.1', NULL,
                 'FAILED', 'HIGH_RISK', NULL, 'GENESIS',
                 '" . str_repeat('f', 64) . "', '2026-01-01 12:00:00')"
        );
        $migration = file_get_contents(
            dirname(__DIR__, 2) . '/sql/migrations/2026-09-03_forensic_audit_v2.sql'
        );
        self::assertIsString($migration);

        try {
            $this->executeSqlScript($migration);
            self::fail('Migration silently accepted a pre-existing non-positive sequence.');
        } catch (\PDOException) {
            self::assertSame(
                0,
                (int) $this->root->query('SELECT seq FROM audit_logs')->fetchColumn()
            );
            self::assertSame(
                1,
                (int) $this->root->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn()
            );
        }
    }

    public function testFreshSchemaAndRepeatedMigrationEnforcePositiveSequence(): void
    {
        $schema = file_get_contents(dirname(__DIR__, 2) . '/sql/schema.sql');
        $migration = file_get_contents(
            dirname(__DIR__, 2) . '/sql/migrations/2026-09-03_forensic_audit_v2.sql'
        );
        self::assertIsString($schema);
        self::assertIsString($migration);

        $this->executeSqlScript($schema);
        $this->executeSqlScript($migration);
        $this->executeSqlScript($migration);

        $definition = (string) $this->root->query('SHOW CREATE TABLE audit_logs')
            ->fetch()['Create Table'];
        self::assertStringContainsString('chk_audit_seq_positive', $definition);

        $this->expectException(\PDOException::class);
        $this->root->exec(
            "INSERT INTO audit_logs
                (seq, event_id, key_id, format_version, user_id, user_role,
                 action, module, affected_record_id, ip_address, user_agent,
                 status, anomaly_flag, attempted_identifier, previous_hash,
                 current_hash, created_at)
             VALUES
                (0, 'fresh-zero', 'audit-primary-2026', 2, NULL, 'system',
                 'FORGED_SEQUENCE', 'test', NULL, '127.0.0.1', NULL,
                 'SUCCESS', 'NORMAL', NULL, 'FRESH-PREVIOUS-ZERO',
                 '" . str_repeat('f', 64) . "', '2026-01-01 12:00:00')"
        );
    }

    private function executeSqlScript(string $sql): void
    {
        foreach (preg_split('/;\s*(?:\r\n|\r|\n|$)/', $sql) ?: [] as $statement) {
            $statement = trim($statement);
            if ($statement === '') {
                continue;
            }
            $result = $this->root->query($statement);
            if ($result !== false) {
                $result->closeCursor();
            }
        }
    }
}
