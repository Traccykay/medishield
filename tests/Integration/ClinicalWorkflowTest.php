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
use MediShield\Visit\VisitRepository;
use MediShield\Visit\VisitService;
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
        $this->clinical = new ClinicalService(
            $this->clinicalRepo,
            $this->patientRepo,
            $crypto,
            new VisitRepository($this->pdo, $clock)
        );
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
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();

        $record = $this->clinical->addDiagnosis($patientId, $doctorId, $visitId, 'Malaria suspected', 'Start observation');
        self::assertTrue($record['ok']);
        $recordId = (int) $record['record_id'];

        $stored = $this->clinicalRepo->findRecord($recordId);
        self::assertNotSame('Malaria suspected', $stored['diagnosis_encrypted']);
        self::assertSame('Malaria suspected', $this->clinical->decrypt($stored['diagnosis_encrypted']));

        $lab = $this->clinical->requestLab($patientId, $doctorId, $visitId, $recordId, 'Blood smear', 'Confirm malaria');
        self::assertTrue($lab['ok']);

        $rx = $this->clinical->issuePrescription($patientId, $doctorId, $visitId, $recordId, 'Artemether', '20mg twice daily', 'After meals');
        self::assertTrue($rx['ok']);

        $pendingLabs = $this->clinicalRepo->labRequests('pending');
        $pendingRx = $this->clinicalRepo->prescriptions('pending');
        self::assertCount(1, $pendingLabs);
        self::assertCount(1, $pendingRx);
        self::assertNotSame('Artemether', $pendingRx[0]['medication_encrypted']);
    }

    public function testDoctorSubmitConsultation_LinksMultipleCatalogOrdersToEncounter(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();

        $result = $this->clinical->submitConsultation(
            $patientId,
            $doctorId,
            $visitId,
            'Respiratory infection',
            'Rest and fluids',
            ['Blood glucose', 'Urinalysis'],
            [
                [
                    'medication' => 'Paracetamol 500 mg',
                    'dosage' => 'One tablet every six hours',
                    'instructions' => 'Take after meals',
                ],
                [
                    'medication' => 'Cetirizine 10 mg',
                    'dosage' => 'One tablet at night',
                    'instructions' => '',
                ],
            ]
        );

        self::assertTrue($result['ok']);
        self::assertIsInt($result['record_id']);
        self::assertCount(2, $result['lab_request_ids']);
        self::assertCount(2, $result['prescription_ids']);

        $record = $this->clinicalRepo->findRecord((int) $result['record_id']);
        self::assertSame($visitId, (int) $record['visit_id']);
        self::assertNotSame('Respiratory infection', $record['diagnosis_encrypted']);

        $labs = $this->clinicalRepo->labRequests('pending');
        self::assertCount(2, $labs);
        self::assertSame([$visitId, $visitId], array_map(static fn (array $lab): int => (int) $lab['visit_id'], $labs));
        self::assertSame([400, 500], array_map(static fn (array $lab): int => (int) $lab['catalog_price_kes'], array_reverse($labs)));

        $prescriptions = $this->clinicalRepo->prescriptions('pending');
        self::assertCount(2, $prescriptions);
        self::assertSame([$visitId, $visitId], array_map(static fn (array $rx): int => (int) $rx['visit_id'], $prescriptions));
        self::assertSame([150, 220], array_map(static fn (array $rx): int => (int) $rx['catalog_price_kes'], array_reverse($prescriptions)));
        self::assertNotSame('Paracetamol 500 mg', $prescriptions[1]['medication_encrypted']);
    }

    public function testDoctorSubmitConsultation_WithUnauthorizedDoctor_DoesNotCreateClinicalData(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();
        $otherDoctorId = $this->users->create('Other Doctor', 'other-doctor@example.com', 'hash', 'doctor');

        $result = $this->clinical->submitConsultation(
            $patientId,
            $otherDoctorId,
            $visitId,
            'Unauthorized diagnosis',
            null,
            ['Blood glucose'],
            [['medication' => 'Paracetamol 500 mg', 'dosage' => 'Daily', 'instructions' => null]]
        );

        self::assertFalse($result['ok']);
        self::assertContains('You are not assigned to this patient.', $result['errors']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM medical_records')->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM lab_requests')->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM prescriptions')->fetchColumn());
    }

    public function testDoctorSubmitConsultation_WithTamperedCatalogValue_DoesNotCreatePartialOrder(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();

        $result = $this->clinical->submitConsultation(
            $patientId,
            $doctorId,
            $visitId,
            'Diagnosis',
            null,
            ['Blood glucose', 'Free lab test'],
            [['medication' => 'Paracetamol 500 mg', 'dosage' => 'Daily', 'instructions' => null]]
        );

        self::assertFalse($result['ok']);
        self::assertContains('Select only catalog lab tests.', $result['errors']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM medical_records')->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM lab_requests')->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM prescriptions')->fetchColumn());
    }

    public function testLabUploadCompletesRequestAndStoresEncryptedResult(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, $visitId, 'Diagnosis', null)['record_id'];
        $requestId = (int) $this->clinical->requestLab($patientId, $doctorId, $visitId, $recordId, 'Complete blood count (CBC)', null)['lab_request_id'];
        $labId = $this->users->create('Lee Lab', 'lee.lab@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'lab');

        $result = $this->clinical->uploadLabResult($requestId, $labId, 'Normal count');

        self::assertTrue($result['ok']);
        self::assertCount(0, $this->clinicalRepo->labRequests('pending'));
        $results = $this->clinicalRepo->labResultsForPatient($patientId);
        self::assertSame('Normal count', $this->clinical->decrypt($results[0]['result_encrypted']));
    }

    public function testPharmacistDispensesPendingPrescription(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, $visitId, 'Diagnosis', null)['record_id'];
        $rxId = (int) $this->clinical->issuePrescription($patientId, $doctorId, $visitId, $recordId, 'Paracetamol 500 mg', 'Dose', null)['prescription_id'];
        $pharmacistId = $this->users->create('Pam Pharm', 'pam@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'pharmacist');
        $this->routeVisitToPharmacy($visitId, $doctorId);

        $result = $this->clinical->dispense($rxId, $pharmacistId, 'dispensed', 'Issued');

        self::assertTrue($result['ok']);
        self::assertCount(0, $this->clinicalRepo->prescriptions('pending'));
        self::assertCount(1, $this->clinicalRepo->dispensingForPatient($patientId));
    }

    public function testPharmacyRefusal_ReturnsEncounterToAssignedDoctorAndRemovesAllLinkedOrdersFromPharmacyQueue(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, $visitId, 'Diagnosis', null)['record_id'];
        $refusedId = (int) $this->clinical->issuePrescription(
            $patientId,
            $doctorId,
            $visitId,
            $recordId,
            'Paracetamol 500 mg',
            'Daily',
            null
        )['prescription_id'];
        $pendingId = (int) $this->clinical->issuePrescription(
            $patientId,
            $doctorId,
            $visitId,
            $recordId,
            'Cetirizine 10 mg',
            'Nightly',
            null
        )['prescription_id'];
        $pharmacistId = $this->users->create(
            'Pam Pharm',
            'refusal-pharmacist@example.com',
            password_hash('Str0ng!Pass1', PASSWORD_DEFAULT),
            'pharmacist'
        );
        $this->routeVisitToPharmacy($visitId, $doctorId);

        $result = $this->clinical->dispense($refusedId, $pharmacistId, 'refused', 'Medication is unavailable.');

        self::assertTrue($result['ok']);
        self::assertSame('with_doctor', $this->visit($visitId)['status']);
        self::assertSame($doctorId, (int) $this->visit($visitId)['doctor_id']);
        self::assertSame('refused', $this->clinicalRepo->findPrescription($refusedId)['status']);
        self::assertSame('pending', $this->clinicalRepo->findPrescription($pendingId)['status']);
        self::assertSame([], $this->clinicalRepo->pharmacyPrescriptions());
        self::assertSame([$patientId], array_map(
            static fn (array $visit): int => (int) $visit['patient_id'],
            $this->visitService()->doctorVisits($doctorId)
        ));

        $records = $this->clinicalRepo->dispensingForPatient($patientId);
        self::assertCount(1, $records);
        self::assertSame('refused', $records[0]['status']);
        self::assertSame('Medication is unavailable.', $records[0]['remarks']);
    }

    public function testPharmacyRefusal_WithoutReasonOrByNonPharmacist_DoesNotMutateThePrescription(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, $visitId, 'Diagnosis', null)['record_id'];
        $rxId = (int) $this->clinical->issuePrescription(
            $patientId,
            $doctorId,
            $visitId,
            $recordId,
            'Paracetamol 500 mg',
            'Daily',
            null
        )['prescription_id'];
        $pharmacistId = $this->users->create(
            'Pam Pharm',
            'validation-pharmacist@example.com',
            password_hash('Str0ng!Pass1', PASSWORD_DEFAULT),
            'pharmacist'
        );
        $this->routeVisitToPharmacy($visitId, $doctorId);

        $withoutReason = $this->clinical->dispense($rxId, $pharmacistId, 'refused', '  ');
        $wrongRole = $this->clinical->dispense($rxId, $doctorId, 'refused', 'Medication is unavailable.');

        self::assertFalse($withoutReason['ok']);
        self::assertContains('Refusal remarks are required.', $withoutReason['errors']);
        self::assertFalse($wrongRole['ok']);
        self::assertContains('Pharmacist not found.', $wrongRole['errors']);
        self::assertSame('pending', $this->clinicalRepo->findPrescription($rxId)['status']);
        self::assertCount(0, $this->clinicalRepo->dispensingForPatient($patientId));
        self::assertSame('pharmacy', $this->visit($visitId)['status']);
    }

    public function testPharmacyOutcome_WhenPrescriptionWasAlreadyResolved_DoesNotCreateAnotherRecordOrTransitionVisit(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, $visitId, 'Diagnosis', null)['record_id'];
        $rxId = (int) $this->clinical->issuePrescription(
            $patientId,
            $doctorId,
            $visitId,
            $recordId,
            'Paracetamol 500 mg',
            'Daily',
            null
        )['prescription_id'];
        $pharmacistId = $this->users->create(
            'Pam Pharm',
            'stale-pharmacist@example.com',
            password_hash('Str0ng!Pass1', PASSWORD_DEFAULT),
            'pharmacist'
        );
        $this->routeVisitToPharmacy($visitId, $doctorId);
        self::assertTrue($this->clinical->dispense($rxId, $pharmacistId, 'refused', 'Medication is unavailable.')['ok']);

        $stale = $this->clinical->dispense($rxId, $pharmacistId, 'dispensed', 'Late retry');

        self::assertFalse($stale['ok']);
        self::assertContains('Prescription is not pending.', $stale['errors']);
        self::assertCount(1, $this->clinicalRepo->dispensingForPatient($patientId));
        self::assertSame('with_doctor', $this->visit($visitId)['status']);
    }

    public function testPrescriptionsForPatient_ReturnsPendingAndDispensedHistory(): void
    {
        [$patientId, $doctorId, $visitId] = $this->doctorConsultation();
        $recordId = (int) $this->clinical->addDiagnosis($patientId, $doctorId, $visitId, 'Diagnosis', null)['record_id'];
        $pendingId = (int) $this->clinical->issuePrescription(
            $patientId,
            $doctorId,
            $visitId,
            $recordId,
            'Paracetamol 500 mg',
            'Daily',
            null
        )['prescription_id'];
        $dispensedId = (int) $this->clinical->issuePrescription(
            $patientId,
            $doctorId,
            $visitId,
            $recordId,
            'Cetirizine 10 mg',
            'Twice daily',
            null
        )['prescription_id'];
        $pharmacistId = $this->users->create(
            'Pam Pharm',
            'pam@example.com',
            password_hash('Str0ng!Pass1', PASSWORD_DEFAULT),
            'pharmacist'
        );
        $this->routeVisitToPharmacy($visitId, $doctorId);
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

    /**
     * @return array{0:int,1:int,2:int}
     */
    private function doctorConsultation(): array
    {
        $receptionistId = $this->users->create('Reception', 'reception@example.com', 'hash', 'receptionist');
        $nurseId = $this->users->create('Nurse', 'nurse@example.com', 'hash', 'nurse');
        $doctorId = $this->users->create('Doctor', 'doctor@example.com', 'hash', 'doctor');
        $patientId = (int) $this->patients->registerPatient([
            'patient_number' => 'MSH-CONSULTATION',
            'full_name' => 'Consultation Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ])['patient_id'];
        $visits = new VisitService(new VisitRepository($this->pdo, new Clock(
            static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
        )), $this->patientRepo, $this->users);
        $visit = $visits->createVisit($patientId, $receptionistId, 'cash', null);
        $visits->moveToNurse((int) $visit['visit_id'], $nurseId);
        $visits->assignDoctor((int) $visit['visit_id'], $nurseId, $doctorId);

        return [$patientId, $doctorId, (int) $visit['visit_id']];
    }

    private function routeVisitToPharmacy(int $visitId, int $doctorId): void
    {
        $result = $this->visitService()->routeFromDoctor($visitId, $doctorId, 'pharmacy');
        self::assertTrue($result['ok']);
    }

    private function visitService(): VisitService
    {
        return new VisitService(
            new VisitRepository($this->pdo, new Clock(
                static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
            )),
            $this->patientRepo,
            $this->users
        );
    }

    private function visit(int $visitId): array
    {
        $visit = (new VisitRepository($this->pdo, new Clock(
            static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
        )))->findById($visitId);
        self::assertIsArray($visit);
        return $visit;
    }
}
