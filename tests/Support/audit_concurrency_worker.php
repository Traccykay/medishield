<?php

declare(strict_types=1);

use MediShield\Audit\AuditLogger;
use MediShield\Database\Connection;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$database = (string) ($argv[1] ?? '');
$count = filter_var($argv[2] ?? null, FILTER_VALIDATE_INT);
if ($database !== 'medishield_ui_account_test' || $count === false || $count < 1 || $count > 100) {
    fwrite(STDERR, "Invalid audit concurrency worker input.\n");
    exit(2);
}

$config = require dirname(__DIR__, 2) . '/config/config.php';
$config['db']['name'] = $database;
$chain = AuditChain::fromHexKey(
    (string) $config['audit_hmac_key_hex'],
    (string) $config['audit_key_id']
);
$logger = new AuditLogger(Connection::fromConfig($config), $chain, new Clock(), 8);

for ($index = 0; $index < $count; $index++) {
    $logger->log([
        'user_id' => null,
        'user_role' => 'system',
        'action' => 'INTEGRITY_VERIFIED',
        'module' => 'concurrency_test',
        'affected_record_id' => 'worker-row:' . $index,
        'ip_address' => '127.0.0.1',
        'user_agent' => 'MediShield concurrency worker',
        'status' => 'SUCCESS',
        'anomaly_flag' => 'NORMAL',
    ]);
}

exit(0);
