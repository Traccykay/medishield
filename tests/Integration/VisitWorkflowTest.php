<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

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
        $patientService = new PatientService($patients, $users);
        $visits = new VisitRepository($pdo, $clock);
        $service = new VisitService($visits, $patients, $users);

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
    }

    public function testReceptionRejectsAnInvalidPaymentOption(): void
    {
        $pdo = TestSchema::pdo();
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $users = new UserRepository($pdo, $clock);
        $patients = new PatientRepository($pdo, $clock);
        $patientService = new PatientService($patients, $users);
        $service = new VisitService(new VisitRepository($pdo, $clock), $patients, $users);

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
}
