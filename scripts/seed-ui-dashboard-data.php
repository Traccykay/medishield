<?php

declare(strict_types=1);

/**
 * Adds a representative, role-scoped care workflow to the disposable browser-test
 * database. This deliberately uses the same services as the application for
 * clinical writes so encrypted fields, assignment checks, and workflow statuses
 * remain valid. It refuses to run outside the isolated UI database.
 */

use MediShield\Auth\UserRepository;
use MediShield\Clinical\ClinicalRepository;
use MediShield\Clinical\ClinicalService;
use MediShield\Database\Connection;
use MediShield\Patient\PatientRepository;
use MediShield\Patient\PatientService;
use MediShield\Security\Crypto;
use MediShield\Support\Clock;
use MediShield\Visit\VisitRepository;

require_once __DIR__ . '/../vendor/autoload.php';

if (getenv('MEDISHIELD_DB_NAME') !== 'medishield_ui_test') {
    throw new RuntimeException('Dashboard UI data may only be seeded into medishield_ui_test.');
}

$configPath = __DIR__ . '/../config/config.php';
$config = require (is_file($configPath) ? $configPath : __DIR__ . '/../config/config.sample.php');
$config['db']['name'] = 'medishield_ui_test';

$pdo = Connection::fromConfig($config);
$clock = new Clock();
$users = new UserRepository($pdo, $clock);
$patients = new PatientRepository($pdo, $clock);
$patientService = new PatientService($patients, $users);
$visits = new VisitRepository($pdo, $clock);
$clinicalRepository = new ClinicalRepository($pdo, $clock);
$clinical = new ClinicalService(
    $clinicalRepository,
    $patients,
    Crypto::fromHexKey($config['encryption_key_hex'])
);

/** @return array<string,mixed> */
$account = static function (string $email) use ($users): array {
    $user = $users->findByEmail($email);
    if ($user === null) {
        throw new RuntimeException('Run seed-ui-test-users.php before seeding dashboard data.');
    }
    return $user;
};

$receptionist = $account('ui.receptionist@medishield.test');
$nurse = $account('ui.nurse@medishield.test');
$doctor = $account('ui.doctor@medishield.test');
$lab = $account('ui.lab@medishield.test');
$pharmacist = $account('ui.pharmacist@medishield.test');
$patientUser = $account('ui.patient@medishield.test');
$admin = $account('ui.admin@medishield.test');

/** @return int */
$registerPatient = static function (
    string $name,
    string $number,
    ?int $userId = null
) use ($patientService): int {
    $result = $patientService->registerPatient([
        'user_id' => $userId,
        'full_name' => $name,
        'date_of_birth' => '1990-01-01',
        'gender' => 'female',
        'phone' => '0712345678',
        'address' => 'UI Test Clinic',
        'emergency_contact' => 'UI Contact 0723456789',
    ], $number);

    if (!$result['ok'] || $result['patient_id'] === null) {
        throw new RuntimeException('Unable to create dashboard patient: ' . implode(' ', $result['errors']));
    }
    return $result['patient_id'];
};

/** @param array{ok:bool,errors:string[]} $result */
$requireOk = static function (array $result, string $action): void {
    if (!$result['ok']) {
        throw new RuntimeException($action . ' failed: ' . implode(' ', $result['errors']));
    }
};

$dashboardPatient = $registerPatient('UI Dashboard Patient', 'MSH-0000000000000001', (int) $patientUser['user_id']);
$receptionPatient = $registerPatient('UI Reception Queue', 'MSH-0000000000000002');
$nursePatient = $registerPatient('UI Nurse Queue', 'MSH-0000000000000003');
$doctorPatient = $registerPatient('UI Doctor Consultation', 'MSH-0000000000000004');
$labPatient = $registerPatient('UI Lab Queue', 'MSH-0000000000000005');
$pharmacyPatient = $registerPatient('UI Pharmacy Queue', 'MSH-0000000000000006');

foreach ([$dashboardPatient, $nursePatient] as $patientId) {
    $requireOk(
        $patientService->assignPatient($patientId, (int) $nurse['user_id'], (int) $admin['user_id']),
        'Nurse assignment'
    );
}
foreach ([$dashboardPatient, $doctorPatient, $labPatient, $pharmacyPatient] as $patientId) {
    $requireOk(
        $patientService->assignPatient($patientId, (int) $doctor['user_id'], (int) $admin['user_id']),
        'Doctor assignment'
    );
}

$receptionVisit = $visits->create($receptionPatient, (int) $receptionist['user_id'], 'cash', null);

$nurseVisit = $visits->create($nursePatient, (int) $receptionist['user_id'], 'cash', null);
$visits->updateState($nurseVisit, 'with_nurse', (int) $nurse['user_id']);

$labVisit = $visits->create($labPatient, (int) $receptionist['user_id'], 'cash', null);
$visits->updateState($labVisit, 'with_nurse', (int) $nurse['user_id']);
if (!$visits->assignAvailableDoctor($labVisit, (int) $nurse['user_id'], (int) $doctor['user_id'])) {
    throw new RuntimeException('Unable to assign lab queue patient to doctor.');
}
$visits->updateState($labVisit, 'lab');

$pharmacyVisit = $visits->create($pharmacyPatient, (int) $receptionist['user_id'], 'insurance', 'AAR Insurance');
$visits->updateState($pharmacyVisit, 'with_nurse', (int) $nurse['user_id']);
if (!$visits->assignAvailableDoctor($pharmacyVisit, (int) $nurse['user_id'], (int) $doctor['user_id'])) {
    throw new RuntimeException('Unable to assign pharmacy queue patient to doctor.');
}
$visits->updateState($pharmacyVisit, 'pharmacy');

$doctorVisit = $visits->create($doctorPatient, (int) $receptionist['user_id'], 'cash', null);
$visits->updateState($doctorVisit, 'with_nurse', (int) $nurse['user_id']);
if (!$visits->assignAvailableDoctor($doctorVisit, (int) $nurse['user_id'], (int) $doctor['user_id'])) {
    throw new RuntimeException('Unable to assign current consultation to doctor.');
}

$requireOk($clinical->recordVitals($dashboardPatient, (int) $nurse['user_id'], [
    'temperature_c' => '36.8',
    'systolic_mmhg' => '118',
    'diastolic_mmhg' => '76',
    'pulse_bpm' => '70',
    'weight_kg' => '65',
    'symptoms' => 'Routine dashboard test observation',
]), 'Vitals recording');

$dashboardRecord = $clinical->addDiagnosis(
    $dashboardPatient,
    (int) $doctor['user_id'],
    'Dashboard follow-up',
    'Continue observation'
);
$requireOk($dashboardRecord, 'Dashboard diagnosis');
$dashboardRecordId = (int) $dashboardRecord['record_id'];

$completedLab = $clinical->requestLab(
    $dashboardPatient,
    (int) $doctor['user_id'],
    $dashboardRecordId,
    'Blood glucose',
    'Routine follow-up'
);
$requireOk($completedLab, 'Completed lab request');
$requireOk(
    $clinical->uploadLabResult((int) $completedLab['lab_request_id'], (int) $lab['user_id'], '5.2 mmol/L'),
    'Lab result upload'
);

$dispensedPrescription = $clinical->issuePrescription(
    $dashboardPatient,
    (int) $doctor['user_id'],
    $dashboardRecordId,
    'Paracetamol 500 mg',
    'One tablet every six hours',
    'Take after meals'
);
$requireOk($dispensedPrescription, 'Dispensed prescription');
$requireOk(
    $clinical->dispense((int) $dispensedPrescription['prescription_id'], (int) $pharmacist['user_id'], 'dispensed', null),
    'Prescription dispensing'
);

$labRecord = $clinical->addDiagnosis($labPatient, (int) $doctor['user_id'], 'Lab review', null);
$requireOk($labRecord, 'Lab diagnosis');
$pendingLab = $clinical->requestLab(
    $labPatient,
    (int) $doctor['user_id'],
    (int) $labRecord['record_id'],
    'Full blood count',
    'Investigate symptoms'
);
$requireOk($pendingLab, 'Pending lab request');

$pharmacyRecord = $clinical->addDiagnosis($pharmacyPatient, (int) $doctor['user_id'], 'Pharmacy review', null);
$requireOk($pharmacyRecord, 'Pharmacy diagnosis');
$pendingPrescription = $clinical->issuePrescription(
    $pharmacyPatient,
    (int) $doctor['user_id'],
    (int) $pharmacyRecord['record_id'],
    'Paracetamol 500 mg',
    'One tablet every six hours',
    'Take after meals'
);
$requireOk($pendingPrescription, 'Pending prescription');

echo "Dashboard UI data seeded for visit {$receptionVisit}.\n";
