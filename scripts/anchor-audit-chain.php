<?php

declare(strict_types=1);

use MediShield\Audit\AuditAnchorStore;
use MediShield\Audit\AuditLogger;
use MediShield\Database\Connection;
use MediShield\Security\AuditChain;
use MediShield\Support\DisposableDatabase;
use MediShield\Support\Clock;

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("This anchor script may only be run from the command line.\n");
}

require_once __DIR__ . '/../vendor/autoload.php';

$configPath = __DIR__ . '/../config/config.php';
if (!is_file($configPath)) {
    fwrite(STDERR, "Audit anchor failed: generated configuration is missing.\n");
    exit(1);
}

try {
    $config = require $configPath;
    $selectedDatabase = getenv('MEDISHIELD_AUDIT_DB_NAME');
    if (is_string($selectedDatabase) && $selectedDatabase !== '') {
        $config['db']['name'] = DisposableDatabase::requireSetupTarget(
            (string) $config['db']['name'],
            $selectedDatabase
        );
    }
    $selectedAnchorPath = getenv('MEDISHIELD_AUDIT_ANCHOR_PATH');
    if (is_string($selectedAnchorPath) && $selectedAnchorPath !== '') {
        $config['audit_anchor_path'] = $selectedAnchorPath;
    }
    $clock = new Clock();
    $chain = AuditChain::fromHexKey(
        (string) $config['audit_hmac_key_hex'],
        (string) $config['audit_key_id']
    );
    $logger = new AuditLogger(Connection::fromConfig($config), $chain, $clock);
    $local = $logger->verifyLocalFull();
    if ($local['state'] !== 'PASS') {
        throw new \RuntimeException('Local audit chain is not verifiable.');
    }

    $anchors = AuditAnchorStore::fromHexKey(
        (string) $config['audit_anchor_path'],
        (string) $config['audit_anchor_hmac_key_hex'],
        (string) $config['audit_anchor_key_id'],
        $clock
    );
    $appended = $anchors->anchor($logger->head());
    printf(
        "Audit anchor %s: seq=%d\n",
        $appended ? 'appended' : 'already current',
        (int) $logger->head()['last_seq']
    );
    exit(0);
} catch (\Throwable) {
    fwrite(STDERR, "Audit anchor failed. The database head was not reported as anchored.\n");
    exit(1);
}
