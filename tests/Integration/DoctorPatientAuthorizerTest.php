<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\DoctorPatientAuthorizer;
use MediShield\Auth\UserRepository;
use MediShield\Patient\PatientRepository;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use MediShield\Visit\VisitRepository;
use PHPUnit\Framework\TestCase;

final class DoctorPatientAuthorizerTest extends TestCase
{
    private \PDO $pdo;
    private UserRepository $users;
    private PatientRepository $patients;
    private VisitRepository $visits;
    private DoctorPatientAuthorizer $authorizer;
    private int $adminId;
    private int $receptionistId;
    private int $doctorId;
    private int $otherDoctorId;

    protected function setUp(): void
    {
        $this->pdo = TestSchema::pdo();
        $clock = new Clock(
            static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
        );
        $this->users = new UserRepository($this->pdo, $clock);
        $this->patients = new PatientRepository($this->pdo, $clock);
        $this->visits = new VisitRepository($this->pdo, $clock);
        $this->authorizer = new DoctorPatientAuthorizer($this->pdo);
        $this->adminId = $this->users->create('Admin', 'authorizer-admin@example.com', 'hash', 'admin');
        $this->receptionistId = $this->users->create(
            'Reception',
            'authorizer-reception@example.com',
            'hash',
            'receptionist'
        );
        $this->doctorId = $this->users->create('Doctor', 'authorizer-doctor@example.com', 'hash', 'doctor');
        $this->otherDoctorId = $this->users->create(
            'Other Doctor',
            'authorizer-other@example.com',
            'hash',
            'doctor'
        );
    }

    public function testCanAccess_WithActiveAssignmentAndOwnedActiveVisit_ReturnsTrue(): void
    {
        $patientId = $this->patient('Allowed Patient');
        $visitId = $this->visit($patientId, $this->doctorId);
        $this->patients->assign($patientId, $this->doctorId, $this->adminId);

        self::assertTrue($this->authorizer->canAccess($this->doctorId, $patientId, $visitId));
        $this->pdo->beginTransaction();
        self::assertTrue($this->authorizer->canAccess($this->doctorId, $patientId, $visitId, true));
        $this->pdo->rollBack();
    }

    public function testCanAccess_WithOnlyOneSideOfPolicy_ReturnsFalse(): void
    {
        $visitOnlyPatientId = $this->patient('Visit Only Patient');
        $visitOnlyId = $this->visit($visitOnlyPatientId, $this->doctorId);

        $assignmentOnlyPatientId = $this->patient('Assignment Only Patient');
        $assignmentOnlyVisitId = $this->visits->create(
            $assignmentOnlyPatientId,
            $this->receptionistId,
            'cash',
            null
        );
        $this->patients->assign($assignmentOnlyPatientId, $this->doctorId, $this->adminId);

        self::assertFalse($this->authorizer->canAccess($this->doctorId, $visitOnlyPatientId, $visitOnlyId));
        self::assertFalse(
            $this->authorizer->canAccess($this->doctorId, $assignmentOnlyPatientId, $assignmentOnlyVisitId)
        );
        self::assertFalse($this->authorizer->canAccess($this->doctorId, $assignmentOnlyPatientId, 999999));
    }

    public function testCanAccess_WithAnotherDoctorsVisitOrPatientMismatch_ReturnsFalse(): void
    {
        $patientId = $this->patient('Owned By Other Doctor');
        $otherPatientId = $this->patient('Mismatched Patient');
        $visitId = $this->visit($patientId, $this->otherDoctorId);
        $this->patients->assign($patientId, $this->doctorId, $this->adminId);
        $this->patients->assign($otherPatientId, $this->doctorId, $this->adminId);

        self::assertFalse($this->authorizer->canAccess($this->doctorId, $patientId, $visitId));
        self::assertFalse($this->authorizer->canAccess($this->doctorId, $otherPatientId, $visitId));
    }

    public function testCanAccess_WithInactiveAssignmentOrInactiveVisit_ReturnsFalse(): void
    {
        $patientId = $this->patient('Inactive Authorization Patient');
        $visitId = $this->visit($patientId, $this->doctorId);
        $this->patients->assign($patientId, $this->doctorId, $this->adminId);
        $this->patients->unassign($patientId, $this->doctorId);

        self::assertFalse($this->authorizer->canAccess($this->doctorId, $patientId, $visitId));

        $this->patients->assign($patientId, $this->doctorId, $this->adminId);
        foreach (['triage', 'with_nurse', 'lab', 'pharmacy', 'completed'] as $status) {
            $this->visits->updateState($visitId, $status);
            self::assertFalse(
                $this->authorizer->canAccess($this->doctorId, $patientId, $visitId),
                'Status ' . $status . ' must not authorize doctor access.'
            );
        }

        $this->visits->updateState($visitId, 'with_doctor', null, $this->doctorId);
        $stmt = $this->pdo->prepare('UPDATE visits SET active_doctor_id = NULL WHERE visit_id = :visit_id');
        $stmt->execute([':visit_id' => $visitId]);
        self::assertFalse($this->authorizer->canAccess($this->doctorId, $patientId, $visitId));
    }

    public function testAuthorizedVisits_AfterAssignmentRevocation_RemovesAccessImmediately(): void
    {
        $patientId = $this->patient('Revoked Patient');
        $visitId = $this->visit($patientId, $this->doctorId);
        $this->patients->assign($patientId, $this->doctorId, $this->adminId);

        $authorized = $this->authorizer->authorizedVisits($this->doctorId);
        self::assertSame([$visitId], array_map(
            static fn (array $visit): int => (int) $visit['visit_id'],
            $authorized
        ));

        $this->patients->unassign($patientId, $this->doctorId);

        self::assertFalse($this->authorizer->canAccess($this->doctorId, $patientId, $visitId));
        self::assertSame([], $this->authorizer->authorizedVisits($this->doctorId));
    }

    private function patient(string $name): int
    {
        return $this->patients->create([
            'user_id' => null,
            'patient_number' => 'MSH-' . strtoupper(bin2hex(random_bytes(8))),
            'full_name' => $name,
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
            'phone' => null,
            'address' => null,
            'emergency_contact' => null,
        ]);
    }

    private function visit(int $patientId, int $doctorId): int
    {
        $visitId = $this->visits->create($patientId, $this->receptionistId, 'cash', null);
        $this->visits->updateState($visitId, 'with_doctor', null, $doctorId);
        return $visitId;
    }
}
