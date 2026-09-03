<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Opt-in real MariaDB proof that the pending-to-completed transition is the
 * concurrency gate for lab-result creation.
 */
final class MariaDbClinicalConcurrencyTest extends TestCase
{
    private const DATABASE = 'medishield_ui_account_test';

    private ?\PDO $root = null;
    private array $barrierFiles = [];

    protected function setUp(): void
    {
        if (getenv('MEDISHIELD_MARIADB_AUDIT_TEST') !== '1') {
            self::markTestSkipped('Real MariaDB concurrency tests are opt-in.');
        }

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
        foreach ($this->barrierFiles as $path) {
            if (is_file($path)) {
                unlink($path);
            }
        }
        if ($this->root !== null) {
            $this->root->exec('DROP DATABASE IF EXISTS `' . self::DATABASE . '`');
        }
    }

    public function testConcurrentLabResultSubmissions_CannotBothSucceed(): void
    {
        $this->root->exec(
            "CREATE TABLE lab_requests (
                lab_request_id INT UNSIGNED PRIMARY KEY,
                patient_id INT UNSIGNED NOT NULL,
                status ENUM('pending','completed') NOT NULL
            ) ENGINE=InnoDB"
        );
        $this->root->exec(
            "CREATE TABLE lab_results (
                lab_result_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
                lab_request_id INT UNSIGNED NOT NULL UNIQUE,
                patient_id INT UNSIGNED NOT NULL,
                lab_technician_id INT UNSIGNED NOT NULL,
                result_encrypted TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                CONSTRAINT fk_result_request
                    FOREIGN KEY (lab_request_id) REFERENCES lab_requests(lab_request_id)
            ) ENGINE=InnoDB"
        );
        $this->root->exec(
            "INSERT INTO lab_requests (lab_request_id, patient_id, status)
             VALUES (1, 7, 'pending')"
        );

        $config = require dirname(__DIR__, 2) . '/config/config.php';
        $webUser = str_replace("'", "''", (string) $config['db']['user']);
        $this->root->exec(
            "GRANT SELECT, UPDATE ON `" . self::DATABASE . "`.lab_requests"
            . " TO '" . $webUser . "'@'127.0.0.1'"
        );
        $this->root->exec(
            "GRANT SELECT, INSERT ON `" . self::DATABASE . "`.lab_results"
            . " TO '" . $webUser . "'@'127.0.0.1'"
        );

        $barrier = sys_get_temp_dir() . DIRECTORY_SEPARATOR
            . 'medishield-lab-' . bin2hex(random_bytes(8));
        $goPath = $barrier . '.go';
        $this->barrierFiles[] = $goPath;
        $readyPaths = [];
        $processes = [];
        $workerPath = dirname(__DIR__) . '/Support/lab_result_concurrency_worker.php';

        foreach ([101, 102] as $technicianId) {
            $workerId = bin2hex(random_bytes(8));
            $readyPath = $barrier . '.' . $workerId . '.ready';
            $this->barrierFiles[] = $readyPath;
            $readyPaths[] = $readyPath;
            $process = proc_open(
                [PHP_BINARY, $workerPath, self::DATABASE, '1', '7', (string) $technicianId, $barrier, $workerId],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
                dirname(__DIR__, 2)
            );
            self::assertIsResource($process);
            $processes[] = [$process, $pipes];
        }

        $deadline = microtime(true) + 15.0;
        while (count(array_filter($readyPaths, 'is_file')) !== count($readyPaths)) {
            if (microtime(true) >= $deadline) {
                self::fail('Lab-result workers did not reach the concurrency barrier.');
            }
            usleep(10_000);
        }

        $this->root->beginTransaction();
        $locked = $this->root->query(
            'SELECT lab_request_id FROM lab_requests WHERE lab_request_id = 1 FOR UPDATE'
        )->fetchColumn();
        self::assertSame(1, (int) $locked);
        self::assertNotFalse(file_put_contents($goPath, 'go', LOCK_EX));
        usleep(750_000);
        $this->root->commit();

        $outputs = [];
        foreach ($processes as [$process, $pipes]) {
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            self::assertSame(0, proc_close($process), $stdout . $stderr);
            $decoded = json_decode($stdout, true);
            self::assertIsArray($decoded, $stdout);
            $outputs[] = $decoded;
        }

        $statuses = array_column($outputs, 'status');
        sort($statuses);
        self::assertSame(['created', 'rejected'], $statuses);
        foreach ($outputs as $output) {
            self::assertGreaterThanOrEqual(
                500.0,
                (float) $output['elapsed_ms'],
                'Both workers must reach the UPDATE while the parent holds the row lock.'
            );
        }
        self::assertSame(1, (int) $this->root->query('SELECT COUNT(*) FROM lab_results')->fetchColumn());
        self::assertSame('completed', $this->root->query(
            'SELECT status FROM lab_requests WHERE lab_request_id = 1'
        )->fetchColumn());
    }
}
