<?php

declare(strict_types=1);

use MediShield\Database\Connection;
use MediShield\Database\VitalEncryptionMigration;
use MediShield\Security\Crypto;

require_once __DIR__ . '/../vendor/autoload.php';

$configPath = __DIR__ . '/../config/config.php';
$config = require (is_file($configPath) ? $configPath : __DIR__ . '/../config/config.sample.php');
$setupUser = getenv('MEDISHIELD_SETUP_DB_USER');
$setupPass = getenv('MEDISHIELD_SETUP_DB_PASS');
if (is_string($setupUser) && $setupUser !== '') {
    $config['db']['user'] = $setupUser;
    $config['db']['pass'] = is_string($setupPass) ? $setupPass : '';
}

(new VitalEncryptionMigration(
    Connection::fromConfig($config),
    Crypto::fromHexKey($config['encryption_key_hex'])
))->migrate();
