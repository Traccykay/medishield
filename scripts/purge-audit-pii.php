<?php

declare(strict_types=1);

use MediShield\Audit\AuditAnchorStore;
use MediShield\Audit\AuditLogger;
use MediShield\Audit\AuditRetention;
use MediShield\Audit\AuditRetentionPolicy;
use MediShield\Database\Connection;
use MediShield\Security\AuditChain;
use MediShield\Support\Clock;
use MediShield\Support\DisposableDatabase;

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("This maintenance script may only be run from the command line.\n");
}

require_once __DIR__ . '/../vendor/autoload.php';

$configPath = __DIR__ . '/../config/config.php';
if (!is_file($configPath)) {
    fwrite(STDERR, "AUDIT_PII_PURGE FAIL: generated configuration is missing.\n");
    exit(1);
}

try {
    $config = require $configPath;
    $selectedDatabase = getenv('MEDISHIELD_AUDIT_DB_NAME');
    if (is_string($selectedDatabase) && $selectedDatabase !== '') {
        $selectedDatabase = DisposableDatabase::requireSetupTarget(
            (string) $config['db']['name'],
            $selectedDatabase
        );
        $config['db']['name'] = $selectedDatabase;
        $config['audit_maintenance_db']['name'] = $selectedDatabase;
    }
    $selectedAnchorPath = getenv('MEDISHIELD_AUDIT_ANCHOR_PATH');
    if (is_string($selectedAnchorPath) && $selectedAnchorPath !== '') {
        $config['audit_anchor_path'] = $selectedAnchorPath;
    }
    $policy = AuditRetentionPolicy::fromArguments($argv, (array) ($config['audit'] ?? []));
    $maintenanceConfig = $config['audit_maintenance_db'] ?? null;
    if (!is_array($maintenanceConfig)) {
        throw new \RuntimeException('Audit maintenance database identity is missing.');
    }

    $clock = new Clock();
    $chain = AuditChain::fromHexKey(
        (string) $config['audit_hmac_key_hex'],
        (string) $config['audit_key_id']
    );
    $logger = new AuditLogger(Connection::fromConfig($config), $chain, $clock);
    $anchors = AuditAnchorStore::fromHexKey(
        (string) $config['audit_anchor_path'],
        (string) $config['audit_anchor_hmac_key_hex'],
        (string) $config['audit_anchor_key_id'],
        $clock
    );
    $beforeLocal = $logger->verifyLocalFull();
    if ($beforeLocal['state'] !== 'PASS') {
        throw new \RuntimeException('Local audit verification failed before retention.');
    }
    $beforeOverall = $logger->verifyChain($anchors);
    if ($beforeOverall['state'] === 'FAIL') {
        throw new \RuntimeException('External anchor detected a rollback before retention.');
    }

    $maintenanceRuntime = $config;
    $maintenanceRuntime['db'] = $maintenanceConfig;
    $retention = new AuditRetention(Connection::fromConfig($maintenanceRuntime));
    $now = $clock->now();
    $cutoff = $now->sub(new \DateInterval('P' . $policy->retentionDays . 'D'));

    if ($policy->dryRun) {
        printf(
            "AUDIT_PII_PURGE DRY_RUN eligible=%d cutoff=%s retention_days=%d\n",
            $retention->countEligible($cutoff),
            $cutoff->format('Y-m-d H:i:s'),
            $policy->retentionDays
        );
        exit(0);
    }

    $scrubbed = 0;
    do {
        $batch = $retention->purgeBatch($cutoff, $policy->batchSize);
        $scrubbed += $batch;
    } while ($batch === $policy->batchSize);

    $afterLocal = $logger->verifyLocalFull();
    if ($afterLocal['state'] !== 'PASS') {
        throw new \RuntimeException('Local audit verification failed after retention.');
    }
    $afterScrubOverall = $logger->verifyChain($anchors);
    if ($afterScrubOverall['state'] === 'FAIL') {
        throw new \RuntimeException('External anchor detected a rollback after retention.');
    }

    if ($scrubbed > 0) {
        $logger->log([
            'user_id' => null,
            'user_role' => 'system',
            'action' => 'AUDIT_PII_SCRUBBED',
            'module' => 'maintenance',
            'affected_record_id' => 'rows:' . $scrubbed,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'MediShield CLI',
            'status' => 'SUCCESS',
            'anomaly_flag' => 'NORMAL',
        ]);
    }

    $finalLocal = $logger->verifyLocalFull();
    if ($finalLocal['state'] !== 'PASS') {
        throw new \RuntimeException('Local audit verification failed after scrub evidence.');
    }
    $finalOverall = $logger->verifyChain($anchors);

    printf(
        "AUDIT_PII_PURGE PASS scrubbed=%d cutoff=%s local_before=PASS local_after=PASS anchor=%s\n",
        $scrubbed,
        $cutoff->format('Y-m-d H:i:s'),
        (string) $finalOverall['state']
    );
    exit(0);
} catch (\Throwable) {
    fwrite(STDERR, "AUDIT_PII_PURGE FAIL\n");
    exit(1);
}
