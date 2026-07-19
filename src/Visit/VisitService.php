<?php

declare(strict_types=1);

namespace MediShield\Visit;

use MediShield\Auth\Rbac;
use MediShield\Auth\UserRepository;
use MediShield\Patient\PatientRepository;
use PDOException;

/**
 * Enforces the arrival-to-discharge workflow. A visit is administrative metadata,
 * so reception can operate the queue without receiving clinical-record access.
 */
final class VisitService
{
    public const INSURERS = ['AAR Insurance', 'Jubilee Insurance', 'NHIF/SHIF', 'Britam'];

    public function __construct(
        private VisitRepository $visits,
        private PatientRepository $patients,
        private UserRepository $users
    ) {
    }

    /** @return array{ok:bool,errors:string[],visit_id:?int} */
    public function createVisit(int $patientId, int $receptionistId, string $paymentMethod, ?string $insurer): array
    {
        $errors = [];
        $paymentMethod = trim($paymentMethod);
        $insurer = $this->nullableText($insurer);

        if ($this->patients->findById($patientId) === null) {
            $errors[] = 'Patient not found.';
        }
        $receptionist = $this->users->findById($receptionistId);
        if ($receptionist === null || (string) $receptionist['role'] !== Rbac::ROLE_RECEPTIONIST) {
            $errors[] = 'Receptionist not found.';
        }
        if (!in_array($paymentMethod, ['cash', 'insurance'], true)) {
            $errors[] = 'Payment method must be cash or insurance.';
        } elseif ($paymentMethod === 'insurance' && !in_array($insurer, self::INSURERS, true)) {
            $errors[] = 'Select a supported insurance provider.';
        }
        if ($paymentMethod === 'cash') {
            $insurer = null;
        }
        if ($this->visits->openVisitForPatient($patientId) !== null) {
            $errors[] = 'Patient already has an open visit.';
        }
        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'visit_id' => null];
        }

        return [
            'ok' => true,
            'errors' => [],
            'visit_id' => $this->visits->create($patientId, $receptionistId, $paymentMethod, $insurer),
        ];
    }

    /** @return array{ok:bool,errors:string[]} */
    public function moveToNurse(int $visitId, int $nurseId): array
    {
        $visit = $this->visits->findById($visitId);
        if ($visit === null || (string) $visit['status'] !== 'triage') {
            return ['ok' => false, 'errors' => ['Visit is not waiting for triage.']];
        }
        $nurse = $this->users->findById($nurseId);
        if ($nurse === null || (string) $nurse['role'] !== Rbac::ROLE_NURSE) {
            return ['ok' => false, 'errors' => ['Nurse not found.']];
        }
        $this->patients->assign((int) $visit['patient_id'], $nurseId, $nurseId);
        $this->visits->updateState($visitId, 'with_nurse', $nurseId);
        return ['ok' => true, 'errors' => []];
    }

    /** @return array{ok:bool,errors:string[]} */
    public function assignDoctor(int $visitId, int $nurseId, int $doctorId): array
    {
        $visit = $this->visits->findById($visitId);
        if ($visit === null || (string) $visit['status'] !== 'with_nurse' || (int) $visit['nurse_id'] !== $nurseId) {
            return ['ok' => false, 'errors' => ['Visit is not assigned to you for doctor routing.']];
        }
        if (!in_array($doctorId, array_map(static fn (array $doctor): int => (int) $doctor['user_id'], $this->availableDoctors()), true)) {
            return ['ok' => false, 'errors' => ['Selected doctor is not available.']];
        }
        try {
            if (!$this->visits->assignAvailableDoctor($visitId, $nurseId, $doctorId)) {
                return ['ok' => false, 'errors' => ['Visit is no longer waiting for doctor routing.']];
            }
        } catch (PDOException) {
            return ['ok' => false, 'errors' => ['Selected doctor is not available.']];
        }
        $this->patients->assign((int) $visit['patient_id'], $doctorId, $nurseId);
        return ['ok' => true, 'errors' => []];
    }

    /** @return array{ok:bool,errors:string[]} */
    public function routeFromDoctor(int $visitId, int $doctorId, string $destination): array
    {
        $visit = $this->visits->findById($visitId);
        if ($visit === null || (string) $visit['status'] !== 'with_doctor' || (int) $visit['doctor_id'] !== $doctorId) {
            return ['ok' => false, 'errors' => ['Visit is not assigned to you for routing.']];
        }
        if (!in_array($destination, ['lab', 'pharmacy'], true)) {
            return ['ok' => false, 'errors' => ['Invalid visit destination.']];
        }
        $this->visits->updateState($visitId, $destination);
        return ['ok' => true, 'errors' => []];
    }

    public function completePharmacyVisit(int $patientId): void
    {
        $visit = $this->visits->openVisitForPatient($patientId);
        if ($visit !== null && (string) $visit['status'] === 'pharmacy') {
            $this->visits->updateState((int) $visit['visit_id'], 'completed');
        }
    }

    /** Return a completed lab visit to its assigned doctor for result review. */
    public function returnFromLab(int $patientId): void
    {
        $visit = $this->visits->openVisitForPatient($patientId);
        if ($visit !== null && (string) $visit['status'] === 'lab' && $visit['doctor_id'] !== null) {
            $this->visits->updateState((int) $visit['visit_id'], 'with_doctor');
        }
    }

    /** @return array<int,array<string,mixed>> */
    public function triageQueue(): array
    {
        return $this->visits->visitsByStatus('triage');
    }

    /** @return array<int,array<string,mixed>> */
    public function nurseVisits(int $nurseId): array
    {
        return $this->visits->visitsByStatus('with_nurse', $nurseId, 'nurse_id');
    }

    /** @return array<int,array<string,mixed>> */
    public function doctorVisits(int $doctorId): array
    {
        return $this->visits->visitsByStatus('with_doctor', $doctorId, 'doctor_id');
    }

    /** @return array<int,array<string,mixed>> */
    public function availableDoctors(): array
    {
        return $this->visits->availableDoctors();
    }

    private function nullableText(?string $value): ?string
    {
        $value = trim((string) $value);
        return $value === '' ? null : $value;
    }
}
