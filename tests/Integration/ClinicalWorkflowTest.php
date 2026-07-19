<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\UserRepository;
use MediShield\Clinical\ClinicalRepository;
use MediShield\Clinical\ClinicalService;
use MediShield\Database\VitalEncryptionMigration;
use MediShield\Patient\PatientRepository;
use MediShield\Patient\PatientService;
use MediShield\Security\Crypto;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

final class ClinicalWorkflowTest extends TestCase
{
    private \PDO $pdo;
    private UserRepository $users;
    private PatientService $patients;
    private PatientRepository $patientRepo;
    private ClinicalRepository $clinicalRepo;
    private ClinicalService $clinical;

    protected function setUp(): void
    {
        $this->pdo = TestSchema::pdo();
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $this->users = new UserRepository($this->pdo, $clock);
        $this->patientRepo = new PatientRepository($this->pdo, $clock);
        $this->patients = new PatientService($this->patientRepo, $this->users);
        $this->clinicalRepo = new ClinicalRepository($this->pdo, $clock);
        $crypto = new Crypto(str_repeat('a', 32));
        $this->clinical = new ClinicalService($this->clinicalRepo, $this->patientRepo, $crypto);
    }

    public function testNurseRecordsValidatedVitalsForAssignedPatient(): void
    {
        [$patientId, $nurseId] = $this->assignedPatientAndStaff('nurse');
        $symptoms = 'Mild cough';

        $result = $this->clinical->recordVitals($patientId, $nurseId, [
            'temperature_c' => '37.2',
            'systolic_mmhg' => '120',
            'diastolic_mmhg' => '80',
            'pulse_bpm' => '72',
            'weight_kg' => '66.5',
            'symptoms' => $symptoms,
        ]);

        self::assertTrue($result['ok']);
        self::assertIsInt($result['vitals_id']);
        $stored = $this->pdo->query(
            'SELECT temperature_encrypted, systolic_encrypted, diastolic_encrypted,
                    pulse_encrypted, weight_encrypted, symptoms_encrypted
               FROM vitals'
        )->fetch();

        self::assertIsArray($stored);
        foreach ([
            'temperature_encrypted' => '37.2',
            'systolic_encrypted' => '120',
            'diastolic_encrypted' => '80',
            'pulse_encrypted' => '72',
            'weight_encrypted' => '66.5',
            'symptoms_encrypted' => $symptoms,
        ] as $field => $plaintext) {
            self::assertNotSame($plaintext, $stored[$field]);
        }

        $vitals = $this->clinical->decryptVitals($this->clinicalRepo->vitalsForPatient($patientId));
        self::assertSame('37.2', $vitals[0]['temperature_c']);
        self::assertSame('120', $vitals[0]['systolic_mmhg']);
        self::assertSame('80', $vitals[0]['diastolic_mmhg']);
        self::assertSame('72', $vitals[0]['pulse_bpm']);
        self::assertSame('66.5', $vitals[0]['weight_kg']);
        self::assertSame($symptoms, $vitals[0]['symptoms']);
    }

    public function testDecryptVitals_WithTamperedCiphertext_ThrowsIntegrityFailure(): void
    {
        [$patientId, $nurseId] = $this->assignedPatientAndStaff('nurse');
        $this->clinical->recordVitals($patientId, $nurseId, [
            'temperature_c' => '37.2',
            'systolic_mmhg' => '120',
            'diastolic_mmhg' => '80',
            'pulse_bpm' => '72',
            'weight_kg' => '66.5',
            'symptoms' => 'Mild cough',
        ]);
        $stored = $this->pdo->query('SELECT temperature_encrypted FROM vitals')->fetchColumn();
        self::assertIsString($stored);
        $raw = base64_decode($stored, true);
        self::assertIsString($raw);
        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] ^ "\x01";
        $tampered = base64_encode($raw);
        $update = $this->pdo->prepare('UPDATE vitals SET temperature_encrypted = :value');
        $update->execute([':value' => $tampered]);

        $this->expectException(\RuntimeException::class);
        $this->clinical->decryptVitals($this->clinicalRepo->vitalsForPatient($patientId));
    }

    public function testVitalEncryptionMigration_EncryptsLegacyRowsAndCanBeRepeated(): void
    {
        $this->pdo->exec('DROP TABLE vitals');
        $this->pdo->exec(
            'CREATE TABLE vitals (
                vitals_id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                nurse_id INTEGER NOT NULL,
                temperature_c REAL NOT NULL,
                systolic_mmhg INTEGER NOT NULL,
                diastolic_mmhg INTEGER NOT NULL,
                pulse_bpm INTEGER NOT NULL,
                weight_kg REAL NOT NULL,
                symptoms TEXT NULL,
                created_at TEXT NOT NULL,
                temperature_encrypted TEXT NULL,
                systolic_encrypted TEXT NULL,
                diastolic_encrypted TEXT NULL,
                pulse_encrypted TEXT NULL,
                weight_encrypted TEXT NULL,
                symptoms_encrypted TEXT NULL
            )'
        );
        $this->pdo->exec(
            "INSERT INTO vitals
                (patient_id, nurse_id, temperature_c, systolic_mmhg, diastolic_mmhg, pulse_bpm, weight_kg, symptoms, created_at)
             VALUES (1, 2, 38.1, 130, 85, 90, 70.5, 'Fever', '2026-01-01 12:00:00')"
        );
        $crypto = new Crypto(str_repeat('a', 32));
        $migration = new VitalEncryptionMigration($this->pdo, $crypto);

        $migration->migrate();
        $migration->migrate();

        $columns = $this->pdo->query('PRAGMA table_info(vitals)')->fetchAll();
        self::assertNotContains('temperature_c', array_column($columns, 'name'));
        $stored = $this->pdo->query('SELECT temperature_encrypted, symptoms_encrypted FROM vitals')->fetch();
        self::assertIsArray($stored);
        self::assertNotSame('38.1', $stored['temperature_encrypted']);
        self::assertNotSame('Fever', $stored['symptoms_encrypted']);
        self::assertSame('38.1', $crypto->decrypt($stored['temperature_encrypted']));
        self::assertSame('Fever', $crypto->decrypt($stored['symptoms_encrypted']));
    }

    public function testNurseVitalsRejectsOutOfRangeValues(): void
    {
        [$patientId, $nurseId] = $this->assignedPatientAndStaff('nurse');

        $result = $this->clinical->recordVitals($patientId, $nurseId, [
            'temperature_c' => '80',
            'systolic_mmhg' => '10',
            'diastolic_mmhg' => '80',
            'pulse_bpm' => '72',
            'weight_kg' => '66.5',
        ]);

        self::assertFalse($result['ok']);
        self::assertNotEmpty($result['errors']);
    }

    public function testDoctorDiagnosisLabAndPrescriptionFlowUsesEncryptedFields(): void
    {
        [$patientId, $doctorId] = $this->assignedPatientAndStaff('doctor');

        $record = $this->clinical->addDiagnosis($patientId, $doctorId, 'Malaria suspected', 'Start observation');
        self::assertTrue($record['ok']);
        $recordId = (int) $record['record_id'];

        $stored = $this->clinicalRepo->findRecord($recordId);
        self::assertNotSame('Malaria suspected', $stored['diagnosis_encrypted']);
        self::assertSame('Malaria suspected', $this->clinical->decrypt($stored['diagnosis_encrypted']));

        $lab = $this->clinical->requestLab($patientId, $doctorId, $recordId, 'Blood smear', 'Confirm malaria');
        self::assertTrue($lab['ok']);

        $rx = $this->clinical->issuePrescription($patientId, $doctorId, $recordId, 'Artemether', '20mg twice daily', 'After meals');
        self::assertTrue($rx['ok']);

        $pendingLabs = $this->clinicalRepo->labRequests('pending');
        $pendingRx = $this->clinicalRepo->prescriptions('pending');
        self::assertCount(1, $pendingLabs);
        self::assertCount(1, $pendingRx);
        self::assertNotSame('Artemether', $pendingRx[0]['medication_encrypted']);
    }

    public function testLabUploadCompletesRequestAndStoresEncryptedResult(): void
    {
        [$patientId, $doctorId] = $this->assignedPatientAndStaff('doctor');
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, 'Diagnosis', null)['record_id'];
        $requestId = (int) $this->clinical->requestLab($patientId, $doctorId, $recordId, 'CBC', null)['lab_request_id'];
        $labId = $this->users->create('Lee Lab', 'lee.lab@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'lab');

        $result = $this->clinical->uploadLabResult($requestId, $labId, 'Normal count');

        self::assertTrue($result['ok']);
        self::assertCount(0, $this->clinicalRepo->labRequests('pending'));
        $results = $this->clinicalRepo->labResultsForPatient($patientId);
        self::assertSame('Normal count', $this->clinical->decrypt($results[0]['result_encrypted']));
    }

    public function testPharmacistDispensesPendingPrescription(): void
    {
        [$patientId, $doctorId] = $this->assignedPatientAndStaff('doctor');
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, 'Diagnosis', null)['record_id'];
        $rxId = (int) $this->clinical->issuePrescription($patientId, $doctorId, $recordId, 'Drug', 'Dose', null)['prescription_id'];
        $pharmacistId = $this->users->create('Pam Pharm', 'pam@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'pharmacist');

        $result = $this->clinical->dispense($rxId, $pharmacistId, 'dispensed', 'Issued');

        self::assertTrue($result['ok']);
        self::assertCount(0, $this->clinicalRepo->prescriptions('pending'));
        self::assertCount(1, $this->clinicalRepo->dispensingForPatient($patientId));
    }

    public function testPrescriptionsForPatient_ReturnsPendingAndDispensedHistory(): void
    {
        [$patientId, $doctorId] = $this->assignedPatientAndStaff('doctor');
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, 'Diagnosis', null)['record_id'];
        $pendingId = (int) $this->clinical->issuePrescription(
            $patientId,
            $doctorId,
            $recordId,
            'Pending drug',
            'Daily',
            null
        )['prescription_id'];
        $dispensedId = (int) $this->clinical->issuePrescription(
            $patientId,
            $doctorId,
            $recordId,
            'Dispensed drug',
            'Twice daily',
            null
        )['prescription_id'];
        $pharmacistId = $this->users->create(
            'Pam Pharm',
            'pam@example.com',
            password_hash('Str0ng!Pass1', PASSWORD_DEFAULT),
            'pharmacist'
        );
        $this->clinical->dispense($dispensedId, $pharmacistId, 'dispensed', null);

        $history = $this->clinicalRepo->prescriptionsForPatient($patientId);

        self::assertCount(2, $history);
        self::assertSame($dispensedId, (int) $history[0]['prescription_id']);
        self::assertSame('dispensed', $history[0]['status']);
        self::assertSame($pendingId, (int) $history[1]['prescription_id']);
        self::assertSame('pending', $history[1]['status']);
        self::assertSame([], $this->clinicalRepo->prescriptionsForPatient($patientId + 999));
    }

    /**
     * @return array{0:int,1:int}
     */
    private function assignedPatientAndStaff(string $role): array
    {
        $adminId = $this->users->create('Admin', 'admin' . $role . '@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'admin');
        $staffId = $this->users->create('Staff', 'staff' . $role . '@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), $role);
        $created = $this->patients->registerPatient([
            'patient_number' => 'MSH-' . strtoupper($role),
            'full_name' => 'Demo Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ]);
        $patientId = (int) $created['patient_id'];
        $this->patients->assignPatient($patientId, $staffId, $adminId);
        return [$patientId, $staffId];
    }
}
