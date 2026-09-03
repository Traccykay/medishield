<?php

declare(strict_types=1);

use MediShield\Audit\AuditLogger;
use MediShield\Database\Connection;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("This grant verification script may only be run from the command line.\n");
}

require_once __DIR__ . '/../vendor/autoload.php';

$configPath = __DIR__ . '/../config/config.php';
if (!is_file($configPath)) {
    fwrite(STDERR, "AUDIT_GRANTS_VERIFIED FAIL: generated configuration is missing.\n");
    exit(1);
}

try {
    $config = require $configPath;
    $database = (string) (getenv('MEDISHIELD_SETUP_DB_NAME') ?: $config['db']['name']);
    $adminConfig = $config;
    $adminConfig['db']['name'] = $database;
    $adminConfig['db']['user'] = (string) (getenv('MEDISHIELD_SETUP_DB_USER') ?: '');
    $adminPassword = getenv('MEDISHIELD_SETUP_DB_PASS');
    $adminConfig['db']['pass'] = is_string($adminPassword) ? $adminPassword : '';
    if ($adminConfig['db']['user'] === '') {
        throw new \RuntimeException('Setup database identity is required.');
    }

    $admin = Connection::fromConfig($adminConfig);
    $tables = $admin->prepare(
        'SELECT table_name
           FROM information_schema.tables
          WHERE table_schema = :database
            AND table_type = :table_type
          ORDER BY table_name'
    );
    $tables->execute([':database' => $database, ':table_type' => 'BASE TABLE']);
    $tableNames = $tables->fetchAll(\PDO::FETCH_COLUMN);

    $webUser = (string) $config['db']['user'];
    $maintenanceUser = (string) $config['audit_maintenance_db']['user'];
    $webExpected = [];
    foreach ($tableNames as $table) {
        $privileges = match ($table) {
            'audit_logs' => ['INSERT', 'SELECT'],
            'audit_chain_head' => ['SELECT', 'UPDATE'],
            default => ['DELETE', 'INSERT', 'SELECT', 'UPDATE'],
        };
        foreach ($privileges as $privilege) {
            $webExpected[] = $table . ':' . $privilege;
        }
    }
    sort($webExpected);

    assertExactTablePrivileges($admin, $database, $webUser, '127.0.0.1', $webExpected);
    assertExactColumnPrivileges($admin, $database, $webUser, '127.0.0.1', []);
    assertNoSchemaPrivileges($admin, $database, $webUser, '127.0.0.1');

    assertExactTablePrivileges(
        $admin,
        $database,
        $maintenanceUser,
        '127.0.0.1',
        ['audit_logs:SELECT']
    );
    assertExactColumnPrivileges(
        $admin,
        $database,
        $maintenanceUser,
        '127.0.0.1',
        ['audit_logs:attempted_identifier:UPDATE']
    );
    assertNoSchemaPrivileges($admin, $database, $maintenanceUser, '127.0.0.1');

    $webConfig = $config;
    $webConfig['db']['name'] = $database;
    $maintenanceConfig = $config;
    $maintenanceConfig['db'] = $config['audit_maintenance_db'];
    $maintenanceConfig['db']['name'] = $database;

    $web = Connection::fromConfig($webConfig);
    $maintenance = Connection::fromConfig($maintenanceConfig);
    assertTransactionStatement($web, 'UPDATE audit_logs SET action = action LIMIT 1', false);
    assertTransactionStatement($web, 'DELETE FROM audit_logs LIMIT 1', false);
    assertTransactionStatement(
        $web,
        'UPDATE audit_chain_head SET updated_at = updated_at WHERE singleton_id = 1',
        true
    );
    assertTransactionStatement(
        $maintenance,
        'UPDATE audit_logs SET attempted_identifier = attempted_identifier LIMIT 1',
        true
    );
    assertTransactionStatement(
        $maintenance,
        'UPDATE audit_logs SET action = action LIMIT 1',
        false
    );
    assertTransactionStatement($maintenance, 'DELETE FROM audit_logs LIMIT 1', false);

    $chain = AuditChain::fromHexKey(
        (string) $config['audit_hmac_key_hex'],
        (string) $config['audit_key_id']
    );
    (new AuditLogger($web, $chain, new Clock()))->log([
        'user_id' => null,
        'user_role' => 'system',
        'action' => 'AUDIT_GRANTS_VERIFIED',
        'module' => 'maintenance',
        'ip_address' => '127.0.0.1',
        'user_agent' => 'MediShield CLI',
        'status' => 'SUCCESS',
        'anomaly_flag' => 'NORMAL',
    ]);

    fwrite(STDOUT, "AUDIT_GRANTS_VERIFIED PASS\n");
    exit(0);
} catch (\Throwable) {
    fwrite(STDERR, "AUDIT_GRANTS_VERIFIED FAIL\n");
    exit(1);
}

/**
 * @param string[] $expected
 */
function assertExactTablePrivileges(
    \PDO $pdo,
    string $database,
    string $user,
    string $host,
    array $expected
): void {
    $stmt = $pdo->prepare(
        'SELECT table_name, privilege_type
           FROM information_schema.table_privileges
          WHERE grantee = :grantee AND table_schema = :database'
    );
    $stmt->execute([
        ':grantee' => "'" . $user . "'@'" . $host . "'",
        ':database' => $database,
    ]);
    $actual = array_map(
        static fn (array $row): string => $row['table_name'] . ':' . $row['privilege_type'],
        $stmt->fetchAll()
    );
    sort($actual);
    sort($expected);
    if ($actual !== $expected) {
        throw new \RuntimeException('Table grants do not match the required exact set.');
    }
}

/**
 * @param string[] $expected
 */
function assertExactColumnPrivileges(
    \PDO $pdo,
    string $database,
    string $user,
    string $host,
    array $expected
): void {
    $stmt = $pdo->prepare(
        'SELECT table_name, column_name, privilege_type
           FROM information_schema.column_privileges
          WHERE grantee = :grantee AND table_schema = :database'
    );
    $stmt->execute([
        ':grantee' => "'" . $user . "'@'" . $host . "'",
        ':database' => $database,
    ]);
    $actual = array_map(
        static fn (array $row): string => $row['table_name'] . ':'
            . $row['column_name'] . ':' . $row['privilege_type'],
        $stmt->fetchAll()
    );
    sort($actual);
    sort($expected);
    if ($actual !== $expected) {
        throw new \RuntimeException('Column grants do not match the required exact set.');
    }
}

function assertNoSchemaPrivileges(
    \PDO $pdo,
    string $database,
    string $user,
    string $host
): void {
    $stmt = $pdo->prepare(
        'SELECT COUNT(*)
           FROM information_schema.schema_privileges
          WHERE grantee = :grantee AND table_schema = :database'
    );
    $stmt->execute([
        ':grantee' => "'" . $user . "'@'" . $host . "'",
        ':database' => $database,
    ]);
    if ((int) $stmt->fetchColumn() !== 0) {
        throw new \RuntimeException('Schema-level grants are not permitted.');
    }
}

function assertTransactionStatement(\PDO $pdo, string $sql, bool $shouldSucceed): void
{
    $succeeded = false;
    $pdo->beginTransaction();
    try {
        $pdo->exec($sql);
        $succeeded = true;
    } catch (\PDOException) {
        $succeeded = false;
    } finally {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
    }

    if ($succeeded !== $shouldSucceed) {
        throw new \RuntimeException('Empirical privilege result did not match policy.');
    }
}
