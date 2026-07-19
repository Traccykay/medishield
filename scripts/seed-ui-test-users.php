<?php

declare(strict_types=1);

use MediShield\Database\Connection;

require_once __DIR__ . '/../vendor/autoload.php';

$configPath = __DIR__ . '/../config/config.php';
$config = require (is_file($configPath) ? $configPath : __DIR__ . '/../config/config.sample.php');
$database = getenv('MEDISHIELD_DB_NAME');
if (is_string($database) && $database !== '') {
    $config['db']['name'] = $database;
}

$pdo = Connection::fromConfig($config);
$accounts = [
    ['UI Receptionist', 'ui.receptionist@medishield.test', 'receptionist'],
    ['UI Nurse', 'ui.nurse@medishield.test', 'nurse'],
    ['UI Doctor', 'ui.doctor@medishield.test', 'doctor'],
    ['UI Lab', 'ui.lab@medishield.test', 'lab'],
    ['UI Pharmacist', 'ui.pharmacist@medishield.test', 'pharmacist'],
];
$delete = $pdo->prepare('DELETE FROM users WHERE email = :email');
$insert = $pdo->prepare(
    'INSERT INTO users
        (full_name, email, password_hash, role, status, failed_login_count, locked_until, must_change_password, created_at, updated_at)
     VALUES
        (:full_name, :email, :password_hash, :role, :status, 0, NULL, 0, UTC_TIMESTAMP(), UTC_TIMESTAMP())'
);

foreach ($accounts as [$name, $email, $role]) {
    $delete->execute([':email' => $email]);
    $insert->execute([
        ':full_name' => $name,
        ':email' => $email,
        ':password_hash' => password_hash('UiTest!2026', PASSWORD_DEFAULT),
        ':role' => $role,
        ':status' => 'active',
    ]);
}
