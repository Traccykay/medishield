<?php

declare(strict_types=1);

/**
 * purge-audit-pii.php — scheduled MAINTENANCE task (run from CLI / cron / Task
 * Scheduler, NEVER from a web request).
 * ----------------------------------------------------------------------------
 * Removes the personal data (`attempted_identifier`, the email typed on a failed
 * login) from audit rows older than the configured retention window, so we keep
 * the forensic record of "who did what / when" while not retaining PII longer
 * than necessary (data minimisation).
 *
 * What it does NOT do:
 *   - It never deletes an audit row.
 *   - It never edits a hash-chained field, so AuditLogger::verifyChain() stays ok
 *     (attempted_identifier is deliberately outside the chain).
 *
 * Privilege note: this needs a DB account with UPDATE on audit_logs. The web
 * app's own DB user is granted only SELECT+INSERT, so the scrub cannot be
 * triggered from the request path even if the app were compromised.
 *
 * Usage:
 *   php scripts/purge-audit-pii.php            # use audit.pii_retention_days from config
 *   php scripts/purge-audit-pii.php --days 30  # override the retention window
 *   php scripts/purge-audit-pii.php --dry-run  # report how many rows WOULD be scrubbed
 *
 * Exit code 0 on success, 1 on failure.
 */

use MediShield\Audit\AuditRetention;
use MediShield\Database\Connection;

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("This maintenance script may only be run from the command line.\n");
}

require_once __DIR__ . '/../vendor/autoload.php';

// --- Load configuration (real config preferred, sample as fallback) ----------
$configReal   = __DIR__ . '/../config/config.php';
$configSample = __DIR__ . '/../config/config.sample.php';
$config       = require (is_file($configReal) ? $configReal : $configSample);

// --- Parse arguments ---------------------------------------------------------
$args         = $argv;
$dryRun       = in_array('--dry-run', $args, true);
$retentionDays = (int) ($config['audit']['pii_retention_days'] ?? 90);

$daysIndex = array_search('--days', $args, true);
if ($daysIndex !== false && isset($args[$daysIndex + 1])) {
    $retentionDays = max(0, (int) $args[$daysIndex + 1]);
}

date_default_timezone_set('UTC');
$now    = new DateTimeImmutable('now', new DateTimeZone('UTC'));
$cutoff = $now->sub(new DateInterval('P' . $retentionDays . 'D'));

printf(
    "MediShield audit PII purge\n  retention : %d days\n  cutoff    : %s UTC\n  mode      : %s\n",
    $retentionDays,
    $cutoff->format('Y-m-d H:i:s'),
    $dryRun ? 'DRY RUN (no changes)' : 'LIVE'
);

try {
    $pdo = Connection::fromConfig($config);

    if ($dryRun) {
        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM audit_logs
              WHERE attempted_identifier IS NOT NULL AND created_at < :cutoff'
        );
        $stmt->execute([':cutoff' => $cutoff->format('Y-m-d H:i:s')]);
        $count = (int) $stmt->fetchColumn();
        printf("Would scrub %d row(s).\n", $count);
        exit(0);
    }

    $scrubbed = (new AuditRetention($pdo))->purgeIdentifiersOlderThan($cutoff);
    printf("Scrubbed attempted_identifier on %d row(s).\n", $scrubbed);
    exit(0);
} catch (\Throwable $e) {
    fwrite(STDERR, 'Purge failed: ' . $e->getMessage() . "\n");
    exit(1);
}
