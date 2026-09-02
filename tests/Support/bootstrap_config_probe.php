<?php

declare(strict_types=1);

$encodedConfig = getenv('MEDISHIELD_BOOTSTRAP_PROBE_CONFIG');
$workingDirectory = getenv('MEDISHIELD_BOOTSTRAP_PROBE_DIRECTORY');
if (!is_string($encodedConfig) || $encodedConfig === '' || !is_string($workingDirectory) || $workingDirectory === '') {
    throw new RuntimeException('Bootstrap probe configuration is missing.');
}

$decodedConfig = base64_decode($encodedConfig, true);
if (!is_string($decodedConfig)) {
    throw new RuntimeException('Bootstrap probe configuration is malformed.');
}

$GLOBALS['medishield_bootstrap_probe_config'] = json_decode(
    $decodedConfig,
    true,
    512,
    JSON_THROW_ON_ERROR
);

function ms_config(): array
{
    return $GLOBALS['medishield_bootstrap_probe_config'];
}

function ms_db(): PDO
{
    $workingDirectory = getenv('MEDISHIELD_BOOTSTRAP_PROBE_DIRECTORY');
    if (is_string($workingDirectory) && $workingDirectory !== '') {
        file_put_contents($workingDirectory . DIRECTORY_SEPARATOR . 'database.marker', 'accessed');
    }

    throw new RuntimeException('Bootstrap database probe reached.');
}

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
if (getenv('MEDISHIELD_BOOTSTRAP_PROBE_HTTPS') === '1') {
    $_SERVER['HTTPS'] = 'on';
}

require dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'bootstrap.php';

$action = getenv('MEDISHIELD_BOOTSTRAP_PROBE_ACTION');
if ($action === 'complete') {
    file_put_contents($workingDirectory . DIRECTORY_SEPARATOR . 'next-stage.marker', 'reached');
    echo 'BOOTSTRAP_COMPLETE';
    exit;
}

if ($action === 'credential-flow') {
    try {
        ms_db();
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() !== 'Bootstrap database probe reached.') {
            throw $exception;
        }
    }
    file_put_contents(
        $workingDirectory . DIRECTORY_SEPARATOR . 'token.marker',
        'bootstrap-probe-credential'
    );
    ms_mailer()->send(
        'probe-recipient@example.test',
        'Bootstrap Probe',
        'Probe credential',
        'Credential: bootstrap-probe-credential'
    );
    echo 'CREDENTIAL_FLOW_COMPLETE';
    exit;
}

throw new RuntimeException('Bootstrap probe action is invalid.');
