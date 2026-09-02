<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\DoctorPatientAuthorizer;
use MediShield\Auth\UserRepository;
use MediShield\Patient\PatientRepository;
use MediShield\Patient\PatientService;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use MediShield\Visit\VisitRepository;
use MediShield\Visit\VisitService;
use PHPUnit\Framework\TestCase;

final class VisitWorkflowTest extends TestCase
{
    public function testReceptionCreatesTriageVisitAndNurseRoutesItToAvailableDoctor(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $authorizer = new DoctorPatientAuthorizer($pdo);
        $patientService = new PatientService($patients, $users);
        $visits = new VisitRepository($pdo, $clock);
        $service = new VisitService($visits, $patients, $users, $authorizer);

        $receptionistId = $users->create('Rae Reception', 'rae@example.com', 'hash', 'receptionist');
        $nurseId = $users->create('Nora Nurse', 'nora@example.com', 'hash', 'nurse');
        $availableDoctorId = $users->create('Ava Available', 'ava@example.com', 'hash', 'doctor');
        $busyDoctorId = $users->create('Ben Busy', 'ben@example.com', 'hash', 'doctor');
        $patientId = (int) $patientService->registerPatient([
            'patient_number' => 'MSH-VISIT-1',
            'full_name' => 'Visit Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ])['patient_id'];

        $first = $service->createVisit($patientId, $receptionistId, 'insurance', 'AAR Insurance');
        self::assertTrue($first['ok']);
        self::assertSame('triage', $visits->findById((int) $first['visit_id'])['status']);

        $busyPatientId = (int) $patientService->registerPatient([
            'patient_number' => 'MSH-VISIT-2',
            'full_name' => 'Busy Patient',
            'date_of_birth' => '1991-01-01',
            'gender' => 'male',
        ])['patient_id'];
        $busyVisit = $service->createVisit($busyPatientId, $receptionistId, 'cash', null);
        $service->moveToNurse((int) $busyVisit['visit_id'], $nurseId);
        $service->assignDoctor((int) $busyVisit['visit_id'], $nurseId, $busyDoctorId);

        self::assertSame([$availableDoctorId], array_column($service->availableDoctors(), 'user_id'));

        $service->moveToNurse((int) $first['visit_id'], $nurseId);
        $assigned = $service->assignDoctor((int) $first['visit_id'], $nurseId, $availableDoctorId);

        self::assertTrue($assigned['ok']);
        self::assertSame('with_doctor', $visits->findById((int) $first['visit_id'])['status']);
        self::assertSame($availableDoctorId, (int) $visits->findById((int) $first['visit_id'])['doctor_id']);
        self::assertSame('Visit Patient', $service->doctorVisits($availableDoctorId)[0]['full_name']);

        $patients->unassign($patientId, $availableDoctorId);
        $routing = $service->routeFromDoctor(
            (int) $first['visit_id'],
            $patientId,
            $availableDoctorId,
            'lab'
        );
        self::assertFalse($routing['ok']);
        self::assertSame('with_doctor', $visits->findById((int) $first['visit_id'])['status']);
    }

    public function testReceptionRejectsAnInvalidPaymentOption(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $authorizer = new DoctorPatientAuthorizer($pdo);
        $patientService = new PatientService($patients, $users);
        $service = new VisitService(
            new VisitRepository($pdo, $clock),
            $patients,
            $users,
            $authorizer
        );

        $receptionistId = $users->create('Rae Reception', 'rae2@example.com', 'hash', 'receptionist');
        $patientId = (int) $patientService->registerPatient([
            'patient_number' => 'MSH-VISIT-3',
            'full_name' => 'Payment Patient',
            'date_of_birth' => '1992-01-01',
            'gender' => 'other',
        ])['patient_id'];

        $result = $service->createVisit($patientId, $receptionistId, 'card', null);

        self::assertFalse($result['ok']);
        self::assertContains('Payment method must be cash or insurance.', $result['errors']);
    }

    public function testOrderCompletion_KeepsEncounterInValidStatesUntilAllLinkedOrdersAreDone(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $authorizer = new DoctorPatientAuthorizer($pdo);
        $patientService = new PatientService($patients, $users);
        $visits = new VisitRepository($pdo, $clock);
        $service = new VisitService($visits, $patients, $users, $authorizer);
        $receptionistId = $users->create('Reception', 'encounter-reception@example.com', 'hash', 'receptionist');
        $nurseId = $users->create('Nurse', 'encounter-nurse@example.com', 'hash', 'nurse');
        $doctorId = $users->create('Doctor', 'encounter-doctor@example.com', 'hash', 'doctor');
        $patientId = (int) $patientService->registerPatient([
            'patient_number' => 'MSH-ORDER-STATE',
            'full_name' => 'Order State Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ])['patient_id'];
        $visit = $service->createVisit($patientId, $receptionistId, 'cash', null);
        $visitId = (int) $visit['visit_id'];
        $service->moveToNurse($visitId, $nurseId);
        $service->assignDoctor($visitId, $nurseId, $doctorId);
        $service->routeFromDoctor($visitId, $patientId, $doctorId, 'lab');
        self::assertSame([$doctorId], array_column($service->availableDoctors(), 'user_id'));

        $service->returnFromLab($visitId, true, true);
        self::assertSame('lab', $visits->findById($visitId)['status']);

        $service->returnFromLab($visitId, false, true);
        self::assertSame('pharmacy', $visits->findById($visitId)['status']);
        self::assertSame([$doctorId], array_column($service->availableDoctors(), 'user_id'));

        $service->completePharmacyVisit($visitId, true);
        self::assertSame('pharmacy', $visits->findById($visitId)['status']);

        $service->completePharmacyVisit($visitId, false);
        self::assertSame('completed', $visits->findById($visitId)['status']);
    }

    public function testAssignDoctor_WhenAssignmentWriteFails_RollsBackVisitOwnership(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(
            static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
        );
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $authorizer = new DoctorPatientAuthorizer($pdo);
        $patientService = new PatientService($patients, $users);
        $visits = new VisitRepository($pdo, $clock);
        $service = new VisitService($visits, $patients, $users, $authorizer);
        $receptionistId = $users->create('Reception', 'atomic-reception@example.com', 'hash', 'receptionist');
        $nurseId = $users->create('Nurse', 'atomic-nurse@example.com', 'hash', 'nurse');
        $doctorId = $users->create('Doctor', 'atomic-doctor@example.com', 'hash', 'doctor');
        $patientId = (int) $patientService->registerPatient([
            'full_name' => 'Atomic Routing Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ])['patient_id'];
        $visitId = (int) $service->createVisit($patientId, $receptionistId, 'cash', null)['visit_id'];
        self::assertTrue($service->moveToNurse($visitId, $nurseId)['ok']);
        $pdo->exec(
            'CREATE TRIGGER reject_doctor_assignment
             BEFORE INSERT ON patient_assignments
             WHEN NEW.staff_user_id = ' . $doctorId . "
             BEGIN
                 SELECT RAISE(ABORT, 'simulated assignment failure');
             END"
        );

        $result = $service->assignDoctor($visitId, $nurseId, $doctorId);

        self::assertFalse($result['ok']);
        self::assertSame('with_nurse', $visits->findById($visitId)['status']);
        self::assertNull($visits->findById($visitId)['doctor_id']);
        self::assertNull($visits->findById($visitId)['active_doctor_id']);
        self::assertFalse($patients->isAssigned($patientId, $doctorId));
    }

    public function testAssignDoctor_WithinOuterTransaction_DoesNotNestAndRollsBackBothWrites(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(
            static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
        );
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $authorizer = new DoctorPatientAuthorizer($pdo);
        $patientService = new PatientService($patients, $users);
        $visits = new VisitRepository($pdo, $clock);
        $service = new VisitService($visits, $patients, $users, $authorizer);
        $receptionistId = $users->create('Reception', 'outer-reception@example.com', 'hash', 'receptionist');
        $nurseId = $users->create('Nurse', 'outer-nurse@example.com', 'hash', 'nurse');
        $doctorId = $users->create('Doctor', 'outer-doctor@example.com', 'hash', 'doctor');
        $patientId = (int) $patientService->registerPatient([
            'full_name' => 'Outer Transaction Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ])['patient_id'];
        $visitId = (int) $service->createVisit($patientId, $receptionistId, 'cash', null)['visit_id'];
        self::assertTrue($service->moveToNurse($visitId, $nurseId)['ok']);

        $pdo->beginTransaction();
        $result = $service->assignDoctor($visitId, $nurseId, $doctorId);

        self::assertTrue($result['ok']);
        self::assertSame('with_doctor', $visits->findById($visitId)['status']);
        self::assertTrue($patients->isAssigned($patientId, $doctorId));
        $pdo->rollBack();

        $rolledBack = $visits->findById($visitId);
        self::assertSame('with_nurse', $rolledBack['status']);
        self::assertNull($rolledBack['doctor_id']);
        self::assertNull($rolledBack['active_doctor_id']);
        self::assertFalse($patients->isAssigned($patientId, $doctorId));
    }

    public function testRevokeDoctorAssignment_WithOwnedActiveVisit_RestoresNurseQueueAndDoctorCapacity(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(
            static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
        );
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $authorizer = new DoctorPatientAuthorizer($pdo);
        $patientService = new PatientService($patients, $users);
        $visits = new VisitRepository($pdo, $clock);
        $service = new VisitService($visits, $patients, $users, $authorizer);
        $receptionistId = $users->create(
            'Reception',
            'revoke-reception@example.com',
            'hash',
            'receptionist'
        );
        $nurseId = $users->create('Nurse', 'revoke-nurse@example.com', 'hash', 'nurse');
        $doctorId = $users->create('Doctor', 'revoke-doctor@example.com', 'hash', 'doctor');
        $patientId = (int) $patientService->registerPatient([
            'full_name' => 'Revocation Recovery Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ])['patient_id'];
        $visitId = (int) $service->createVisit($patientId, $receptionistId, 'cash', null)['visit_id'];
        self::assertTrue($service->moveToNurse($visitId, $nurseId)['ok']);
        self::assertTrue($service->assignDoctor($visitId, $nurseId, $doctorId)['ok']);
        self::assertTrue($authorizer->canAccess($doctorId, $patientId, $visitId));
        self::assertNotContains($doctorId, array_column($service->availableDoctors(), 'user_id'));

        $result = $service->revokeDoctorAssignment($patientId, $doctorId);

        self::assertTrue($result['ok']);
        self::assertFalse($patients->isAssigned($patientId, $doctorId));
        $recoveredVisit = $visits->findById($visitId);
        self::assertSame('with_nurse', $recoveredVisit['status']);
        self::assertSame($nurseId, (int) $recoveredVisit['nurse_id']);
        self::assertSame($doctorId, (int) $recoveredVisit['doctor_id']);
        self::assertNull($recoveredVisit['active_doctor_id']);
        self::assertContains($doctorId, array_column($service->availableDoctors(), 'user_id'));
        self::assertFalse($authorizer->canAccess($doctorId, $patientId, $visitId));
        self::assertSame([], $authorizer->authorizedVisits($doctorId));
    }

    public function testRevokeDoctorAssignment_WhenAssignmentWriteFails_RollsBackVisitRecovery(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(
            static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
        );
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $authorizer = new DoctorPatientAuthorizer($pdo);
        $patientService = new PatientService($patients, $users);
        $visits = new VisitRepository($pdo, $clock);
        $service = new VisitService($visits, $patients, $users, $authorizer);
        $receptionistId = $users->create(
            'Reception',
            'rollback-reception@example.com',
            'hash',
            'receptionist'
        );
        $nurseId = $users->create('Nurse', 'rollback-nurse@example.com', 'hash', 'nurse');
        $doctorId = $users->create('Doctor', 'rollback-doctor@example.com', 'hash', 'doctor');
        $patientId = (int) $patientService->registerPatient([
            'full_name' => 'Revocation Rollback Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ])['patient_id'];
        $visitId = (int) $service->createVisit($patientId, $receptionistId, 'cash', null)['visit_id'];
        self::assertTrue($service->moveToNurse($visitId, $nurseId)['ok']);
        self::assertTrue($service->assignDoctor($visitId, $nurseId, $doctorId)['ok']);
        $pdo->exec(
            'CREATE TRIGGER reject_doctor_unassignment
             BEFORE UPDATE OF active ON patient_assignments
             WHEN OLD.staff_user_id = ' . $doctorId . " AND NEW.active = 0
             BEGIN
                 SELECT RAISE(ABORT, 'simulated unassignment failure');
             END"
        );

        $result = $service->revokeDoctorAssignment($patientId, $doctorId);

        self::assertFalse($result['ok']);
        self::assertSame(['Unable to remove assignment. Please try again.'], $result['errors']);
        self::assertTrue($patients->isAssigned($patientId, $doctorId));
        $unchangedVisit = $visits->findById($visitId);
        self::assertSame('with_doctor', $unchangedVisit['status']);
        self::assertSame($nurseId, (int) $unchangedVisit['nurse_id']);
        self::assertSame($doctorId, (int) $unchangedVisit['doctor_id']);
        self::assertSame($doctorId, (int) $unchangedVisit['active_doctor_id']);
        self::assertTrue($authorizer->canAccess($doctorId, $patientId, $visitId));
        self::assertNotContains($doctorId, array_column($service->availableDoctors(), 'user_id'));
    }

    public function testPatientServiceUnassignPatient_ForNurse_LeavesDoctorVisitUnchanged(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(
            static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'))
        );
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $authorizer = new DoctorPatientAuthorizer($pdo);
        $patientService = new PatientService($patients, $users);
        $visits = new VisitRepository($pdo, $clock);
        $visitService = new VisitService($visits, $patients, $users, $authorizer);
        $receptionistId = $users->create(
            'Reception',
            'nurse-unassign-reception@example.com',
            'hash',
            'receptionist'
        );
        $nurseId = $users->create('Nurse', 'nurse-unassign@example.com', 'hash', 'nurse');
        $doctorId = $users->create('Doctor', 'nurse-unassign-doctor@example.com', 'hash', 'doctor');
        $patientId = (int) $patientService->registerPatient([
            'full_name' => 'Nurse Unassignment Patient',
            'date_of_birth' => '1990-01-01',
            'gender' => 'female',
        ])['patient_id'];
        $visitId = (int) $visitService->createVisit(
            $patientId,
            $receptionistId,
            'cash',
            null
        )['visit_id'];
        self::assertTrue($visitService->moveToNurse($visitId, $nurseId)['ok']);
        self::assertTrue($visitService->assignDoctor($visitId, $nurseId, $doctorId)['ok']);

        $wrongRevocationPath = $visitService->revokeDoctorAssignment($patientId, $nurseId);
        self::assertFalse($wrongRevocationPath['ok']);
        self::assertSame(['Assigned doctor not found.'], $wrongRevocationPath['errors']);
        self::assertTrue($patients->isAssigned($patientId, $nurseId));

        $result = $patientService->unassignPatient($patientId, $nurseId);

        self::assertTrue($result['ok']);
        self::assertFalse($patients->isAssigned($patientId, $nurseId));
        $unchangedVisit = $visits->findById($visitId);
        self::assertSame('with_doctor', $unchangedVisit['status']);
        self::assertSame($nurseId, (int) $unchangedVisit['nurse_id']);
        self::assertSame($doctorId, (int) $unchangedVisit['doctor_id']);
        self::assertSame($doctorId, (int) $unchangedVisit['active_doctor_id']);
        self::assertTrue($authorizer->canAccess($doctorId, $patientId, $visitId));
    }
}
