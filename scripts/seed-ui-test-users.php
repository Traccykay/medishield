<?php

declare(strict_types=1);

use MediShield\Database\Connection;
use MediShield\Support\DisposableDatabase;

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}

require_once __DIR__ . '/../vendor/autoload.php';

$configPath = __DIR__ . '/../config/config.php';
$config = require (is_file($configPath) ? $configPath : __DIR__ . '/../config/config.sample.php');
$database = DisposableDatabase::requireUiTestName(
    (string) (getenv('MEDISHIELD_DB_NAME') ?: 'medishield_ui_test')
);
$config['db']['name'] = $database;

$pdo = Connection::fromConfig($config);
$accounts = [
    ['UI Receptionist', 'ui.receptionist@medishield.test', 'receptionist'],
    ['UI Nurse', 'ui.nurse@medishield.test', 'nurse'],
    ['UI Doctor', 'ui.doctor@medishield.test', 'doctor'],
    ['UI Other Doctor', 'ui.other-doctor@medishield.test', 'doctor'],
    ['UI Lab', 'ui.lab@medishield.test', 'lab'],
    ['UI Pharmacist', 'ui.pharmacist@medishield.test', 'pharmacist'],
    ['UI Patient', 'ui.patient@medishield.test', 'patient'],
    ['UI Billing Patient', 'ui.billing-patient@medishield.test', 'patient'],
    ['UI Other Billing Patient', 'ui.other-billing-patient@medishield.test', 'patient'],
    ['UI Administrator', 'ui.admin@medishield.test', 'admin'],
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

$findUser = $pdo->prepare('SELECT user_id FROM users WHERE email = :email LIMIT 1');
$findUser->execute([':email' => 'ui.receptionist@medishield.test']);
$receptionistId = (int) $findUser->fetchColumn();
$findUser->execute([':email' => 'ui.billing-patient@medishield.test']);
$billingPatientUserId = (int) $findUser->fetchColumn();
$findUser->execute([':email' => 'ui.other-billing-patient@medishield.test']);
$otherBillingPatientUserId = (int) $findUser->fetchColumn();

$patientInsert = $pdo->prepare(
    'INSERT INTO patients
        (user_id, patient_number, full_name, date_of_birth, gender, phone, address, emergency_contact, created_at)
     VALUES
        (:user_id, :patient_number, :full_name, :date_of_birth, :gender, :phone, NULL, :emergency_contact, UTC_TIMESTAMP())'
);
foreach ([
    [$billingPatientUserId, 'MSH-UI-BILLING-1', 'UI Billing Patient'],
    [$otherBillingPatientUserId, 'MSH-UI-BILLING-2', 'UI Other Billing Patient'],
] as [$userId, $number, $name]) {
    $patientInsert->execute([
        ':user_id' => $userId,
        ':patient_number' => $number,
        ':full_name' => $name,
        ':date_of_birth' => '1990-01-01',
        ':gender' => 'female',
        ':phone' => '0712345678',
        ':emergency_contact' => 'Test contact 0712345679',
    ]);
}

$findPatient = $pdo->prepare('SELECT patient_id FROM patients WHERE patient_number = :number LIMIT 1');
$visitInsert = $pdo->prepare(
    'INSERT INTO visits
        (patient_id, receptionist_id, nurse_id, doctor_id, active_doctor_id, payment_method, insurer, status, created_at, updated_at)
     VALUES
        (:patient_id, :receptionist_id, NULL, NULL, NULL, :payment_method, :insurer, :status, UTC_TIMESTAMP(), UTC_TIMESTAMP())'
);
foreach ([
    ['MSH-UI-BILLING-1', 'cash', null],
    ['MSH-UI-BILLING-2', 'insurance', 'AAR Insurance'],
] as [$number, $method, $insurer]) {
    $findPatient->execute([':number' => $number]);
    $visitInsert->execute([
        ':patient_id' => (int) $findPatient->fetchColumn(),
        ':receptionist_id' => $receptionistId,
        ':payment_method' => $method,
        ':insurer' => $insurer,
        ':status' => 'completed',
    ]);
}
