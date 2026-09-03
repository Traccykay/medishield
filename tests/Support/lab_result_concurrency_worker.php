<?php

declare(strict_types=1);

use MediShield\Clinical\ClinicalRepository;
use MediShield\Database\Connection;
use MediShield\Support\Clock;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$database = (string) ($argv[1] ?? '');
$labRequestId = filter_var($argv[2] ?? null, FILTER_VALIDATE_INT);
$patientId = filter_var($argv[3] ?? null, FILTER_VALIDATE_INT);
$labTechnicianId = filter_var($argv[4] ?? null, FILTER_VALIDATE_INT);
$barrier = (string) ($argv[5] ?? '');
$workerId = (string) ($argv[6] ?? '');

if (
    $database !== 'medishield_ui_account_test'
    || $labRequestId === false
    || $patientId === false
    || $labTechnicianId === false
    || !preg_match('/^[a-f0-9]{16}$/', $workerId)
    || !str_starts_with($barrier, sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'medishield-lab-')
) {
    fwrite(STDERR, "Invalid lab-result concurrency worker input.\n");
    exit(2);
}

$config = require dirname(__DIR__, 2) . '/config/config.php';
$config['db']['name'] = $database;
$repository = new ClinicalRepository(Connection::fromConfig($config), new Clock());

$readyPath = $barrier . '.' . $workerId . '.ready';
if (file_put_contents($readyPath, 'ready', LOCK_EX) === false) {
    fwrite(STDERR, "Unable to signal lab-result worker readiness.\n");
    exit(3);
}

$deadline = microtime(true) + 15.0;
while (!is_file($barrier . '.go')) {
    if (microtime(true) >= $deadline) {
        fwrite(STDERR, "Timed out waiting for lab-result concurrency barrier.\n");
        exit(4);
    }
    usleep(10_000);
}

$startedAt = hrtime(true);
$resultId = $repository->createLabResult(
    (int) $labRequestId,
    (int) $patientId,
    (int) $labTechnicianId,
    'encrypted-result-' . $workerId
);

$output = json_encode([
    'status' => $resultId === null ? 'rejected' : 'created',
    'result_id' => $resultId,
    'elapsed_ms' => (hrtime(true) - $startedAt) / 1_000_000,
], JSON_UNESCAPED_SLASHES);
if ($output === false) {
    fwrite(STDERR, "Unable to encode lab-result worker output.\n");
    exit(5);
}
fwrite(STDOUT, $output);
exit(0);
