<?php

declare(strict_types=1);

use MediShield\Audit\AuditChainInitializer;
use MediShield\Database\Connection;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("This initialization script may only be run from the command line.\n");
}

require_once __DIR__ . '/../vendor/autoload.php';

$configPath = __DIR__ . '/../config/config.php';
if (!is_file($configPath)) {
    fwrite(STDERR, "Audit initialization failed: generated configuration is missing.\n");
    exit(1);
}

try {
    $config = require $configPath;
    $setupUser = getenv('MEDISHIELD_SETUP_DB_USER');
    if (is_string($setupUser) && $setupUser !== '') {
        $setupName = getenv('MEDISHIELD_SETUP_DB_NAME');
        $setupPassword = getenv('MEDISHIELD_SETUP_DB_PASS');
        if (is_string($setupName) && $setupName !== '') {
            $config['db']['name'] = $setupName;
        }
        $config['db']['user'] = $setupUser;
        $config['db']['pass'] = is_string($setupPassword) ? $setupPassword : '';
    }

    $chain = AuditChain::fromHexKey(
        (string) $config['audit_hmac_key_hex'],
        (string) ($config['audit_key_id'] ?? 'primary')
    );
    $head = (new AuditChainInitializer(
        Connection::fromConfig($config),
        $chain,
        new Clock()
    ))->initialize();

    printf(
        "Audit chain initialized: seq=%d key_id=%s format=v%d\n",
        (int) $head['last_seq'],
        (string) $head['key_id'],
        (int) $head['format_version']
    );
    exit(0);
} catch (\Throwable) {
    fwrite(STDERR, "Audit initialization failed. No audit hashes were rewritten.\n");
    exit(1);
}
