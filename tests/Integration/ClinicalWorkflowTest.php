<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\UserRepository;
use MediShield\Clinical\ClinicalRepository;
use MediShield\Clinical\ClinicalService;
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

        $result = $this->clinical->recordVitals($patientId, $nurseId, [
            'temperature_c' => '37.2',
            'systolic_mmhg' => '120',
            'diastolic_mmhg' => '80',
            'pulse_bpm' => '72',
            'weight_kg' => '66.5',
            'symptoms' => 'Mild cough',
        ]);

        self::assertTrue($result['ok']);
        self::assertIsInt($result['vitals_id']);
        self::assertCount(1, $this->clinicalRepo->vitalsForPatient($patientId));
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
