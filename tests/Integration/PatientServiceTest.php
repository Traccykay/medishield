<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\UserRepository;
use MediShield\Patient\PatientRepository;
use MediShield\Patient\PatientService;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration coverage for the patient-management and assignment backbone
 * required by spec section 9.3.
 */
final class PatientServiceTest extends TestCase
{
    private \PDO $pdo;
    private Clock $clock;
    private UserRepository $users;
    private PatientRepository $patients;
    private PatientService $service;

    protected function setUp(): void
    {
        $this->pdo = TestSchema::pdo();
        $this->clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $this->users = new UserRepository($this->pdo, $this->clock);
        $this->patients = new PatientRepository($this->pdo, $this->clock);
        $this->service = new PatientService($this->patients, $this->users);
    }

    public function testRegistersValidPatient(): void
    {
        $result = $this->service->registerPatient([
            'patient_number' => 'MSH-0001',
            'full_name' => 'Pat Patient',
            'date_of_birth' => '1990-05-20',
            'gender' => 'female',
            'phone' => '0712345678',
            'address' => 'Nairobi',
            'emergency_contact' => 'Kin 0700000000',
        ]);

        self::assertTrue($result['ok']);
        self::assertSame([], $result['errors']);
        self::assertIsInt($result['patient_id']);

        $row = $this->patients->findById((int) $result['patient_id']);
        self::assertSame('MSH-0001', $row['patient_number']);
        self::assertSame('Pat Patient', $row['full_name']);
        self::assertNull($row['user_id']);
    }

    public function testRejectsInvalidPatientData(): void
    {
        $result = $this->service->registerPatient([
            'patient_number' => '',
            'full_name' => '',
            'date_of_birth' => 'not-a-date',
            'gender' => 'unknown',
        ]);

        self::assertFalse($result['ok']);
        self::assertContains('Patient number is required.', $result['errors']);
        self::assertContains('Full name is required.', $result['errors']);
        self::assertContains('Date of birth must use YYYY-MM-DD.', $result['errors']);
        self::assertContains('Gender must be male, female, or other.', $result['errors']);
    }

    public function testRegistersKenyanMobileNumbersInLocalAndInternationalFormats(): void
    {
        foreach (['0712345678', '254712345678', '+254712345678'] as $index => $phone) {
            $result = $this->service->registerPatient([
                'patient_number' => 'MSH-PHONE-' . $index,
                'full_name' => 'Phone Patient ' . $index,
                'date_of_birth' => '1990-01-01',
                'gender' => 'female',
                'phone' => $phone,
                'emergency_contact' => '+254733123456',
            ]);

            self::assertTrue($result['ok'], implode(', ', $result['errors']));
        }
    }

    public function testRejectsMalformedOrNonKenyanPhoneNumbers(): void
    {
        $result = $this->service->registerPatient([
            'patient_number' => 'MSH-PHONE-BAD',
            'full_name' => 'Invalid Phone Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
            'phone' => '12345',
            'emergency_contact' => '+15551234567',
        ]);

        self::assertFalse($result['ok']);
        self::assertContains('Phone must be a valid Kenyan mobile number.', $result['errors']);
        self::assertContains('Emergency contact must contain a valid Kenyan mobile number.', $result['errors']);
    }

    public function testRejectsDuplicatePatientNumber(): void
    {
        $this->registerFixturePatient('MSH-0002', 'First Patient');

        $result = $this->service->registerPatient([
            'patient_number' => 'MSH-0002',
            'full_name' => 'Second Patient',
            'date_of_birth' => '1985-01-01',
            'gender' => 'male',
        ]);

        self::assertFalse($result['ok']);
        self::assertContains('A patient with this patient number already exists.', $result['errors']);
    }

    public function testRegistersPatientLinkedToPatientUser(): void
    {
        $userId = $this->users->create(
            'Linked User',
            'linked.patient@example.com',
            password_hash('Str0ng!Pass1', PASSWORD_DEFAULT),
            'patient'
        );

        $result = $this->service->registerPatient([
            'user_id' => (string) $userId,
            'patient_number' => 'MSH-0003',
            'full_name' => 'Linked Patient',
            'date_of_birth' => '2000-02-02',
            'gender' => 'other',
        ]);

        self::assertTrue($result['ok']);
        $row = $this->patients->findById((int) $result['patient_id']);
        self::assertSame($userId, (int) $row['user_id']);
    }

    public function testRejectsLinkToNonPatientUser(): void
    {
        $doctorId = $this->users->create(
            'Dora Doctor',
            'dora@example.com',
            password_hash('Str0ng!Pass1', PASSWORD_DEFAULT),
            'doctor'
        );

        $result = $this->service->registerPatient([
            'user_id' => (string) $doctorId,
            'patient_number' => 'MSH-0004',
            'full_name' => 'Bad Link',
            'date_of_birth' => '2000-02-02',
            'gender' => 'female',
        ]);

        self::assertFalse($result['ok']);
        self::assertContains('Linked account must be an existing patient user.', $result['errors']);
    }

    public function testAssignsAndUnassignsPatientToClinicalStaff(): void
    {
        $patientId = $this->registerFixturePatient('MSH-0005', 'Assigned Patient');
        $nurseId = $this->users->create('Nora Nurse', 'nora@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'nurse');
        $adminId = $this->users->create('Ada Admin', 'ada@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'admin');

        $assigned = $this->service->assignPatient($patientId, $nurseId, $adminId);

        self::assertTrue($assigned['ok']);
        self::assertTrue($this->patients->isAssigned($patientId, $nurseId));

        $unassigned = $this->service->unassignPatient($patientId, $nurseId);

        self::assertTrue($unassigned['ok']);
        self::assertFalse($this->patients->isAssigned($patientId, $nurseId));
    }

    public function testRejectsAssignmentToNonClinicalStaff(): void
    {
        $patientId = $this->registerFixturePatient('MSH-0006', 'Queue Patient');
        $labId = $this->users->create('Lee Lab', 'lee@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'lab');
        $adminId = $this->users->create('Ada Admin', 'ada2@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'admin');

        $result = $this->service->assignPatient($patientId, $labId, $adminId);

        self::assertFalse($result['ok']);
        self::assertContains('Patients may only be assigned to nurses or doctors.', $result['errors']);
    }

    public function testAssignedNurseCanRoutePatientToDoctor(): void
    {
        $patientId = $this->registerFixturePatient('MSH-0009', 'Routed Patient');
        $adminId = $this->users->create('Ada Admin', 'ada4@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'admin');
        $nurseId = $this->users->create('Nora Nurse', 'nora4@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'nurse');
        $doctorId = $this->users->create('Dora Doctor', 'dora4@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'doctor');
        $this->service->assignPatient($patientId, $nurseId, $adminId);

        $result = $this->service->assignPatient($patientId, $doctorId, $nurseId);

        self::assertTrue($result['ok']);
        self::assertTrue($this->patients->isAssigned($patientId, $doctorId));
    }

    public function testSearchFindsByNameNumberOrPhone(): void
    {
        $this->registerFixturePatient('MSH-1000', 'Alice One', '0711111111');
        $this->registerFixturePatient('MSH-2000', 'Benson Two', '0722222222');

        self::assertCount(1, $this->patients->search('Alice'));
        self::assertCount(1, $this->patients->search('2000'));
        self::assertCount(1, $this->patients->search('0722'));
    }

    public function testAccessRulesRespectOwnerAssignmentAndAdminDemographics(): void
    {
        $patientUserId = $this->users->create('Owner', 'owner@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'patient');
        $patientId = $this->registerFixturePatient('MSH-0007', 'Owner Patient', null, $patientUserId);
        $otherPatientId = $this->registerFixturePatient('MSH-0008', 'Other Patient');
        $doctorId = $this->users->create('Dora Doctor', 'dora3@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'doctor');
        $adminId = $this->users->create('Ada Admin', 'ada3@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'admin');
        $this->service->assignPatient($patientId, $doctorId, $adminId);

        self::assertTrue($this->service->canViewPatient(['user_id' => $patientUserId, 'role' => 'patient'], $patientId));
        self::assertFalse($this->service->canViewPatient(['user_id' => $patientUserId, 'role' => 'patient'], $otherPatientId));
        self::assertTrue($this->service->canViewPatient(['user_id' => $doctorId, 'role' => 'doctor'], $patientId));
        self::assertFalse($this->service->canViewPatient(['user_id' => $doctorId, 'role' => 'doctor'], $otherPatientId));
        self::assertTrue($this->service->canViewPatient(['user_id' => $adminId, 'role' => 'admin'], $otherPatientId));
    }

    private function registerFixturePatient(
        string $number,
        string $name,
        ?string $phone = null,
        ?int $userId = null
    ): int {
        $result = $this->service->registerPatient([
            'user_id' => $userId !== null ? (string) $userId : '',
            'patient_number' => $number,
            'full_name' => $name,
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
            'phone' => $phone ?? '',
        ]);

        self::assertTrue($result['ok'], implode(', ', $result['errors']));
        return (int) $result['patient_id'];
    }
}
