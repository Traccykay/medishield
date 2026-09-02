<?php

declare(strict_types=1);

namespace MediShield\Visit;

use MediShield\Auth\DoctorPatientAuthorizer;
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
        private UserRepository $users,
        private DoctorPatientAuthorizer $doctorAuthorizer
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
            $assigned = $this->visits->transactional(function () use ($visitId, $nurseId, $doctorId): bool {
                $patientId = $this->visits->reserveAvailableDoctor($visitId, $nurseId, $doctorId);
                if ($patientId === null) {
                    return false;
                }

                $this->patients->assign($patientId, $doctorId, $nurseId);
                return true;
            });
            if (!$assigned) {
                return ['ok' => false, 'errors' => ['Visit is no longer waiting for doctor routing.']];
            }
        } catch (PDOException) {
            return ['ok' => false, 'errors' => ['Selected doctor is not available.']];
        }
        return ['ok' => true, 'errors' => []];
    }

    /**
     * Revoke doctor access and recover an active consultation in one transaction.
     *
     * @return array{ok:bool,errors:string[]}
     */
    public function revokeDoctorAssignment(int $patientId, int $doctorId): array
    {
        if ($this->patients->findById($patientId) === null) {
            return ['ok' => false, 'errors' => ['Patient not found.']];
        }

        $doctor = $this->users->findById($doctorId);
        if ($doctor === null || (string) $doctor['role'] !== Rbac::ROLE_DOCTOR) {
            return ['ok' => false, 'errors' => ['Assigned doctor not found.']];
        }

        try {
            $this->visits->transactional(function () use ($patientId, $doctorId): void {
                $this->visits->returnDoctorVisitToNurseQueue($patientId, $doctorId);
                $this->patients->unassign($patientId, $doctorId);
            });
        } catch (PDOException) {
            return ['ok' => false, 'errors' => ['Unable to remove assignment. Please try again.']];
        }

        return ['ok' => true, 'errors' => []];
    }

    /** @return array{ok:bool,errors:string[]} */
    public function routeFromDoctor(int $visitId, int $patientId, int $doctorId, string $destination): array
    {
        if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId)) {
            return ['ok' => false, 'errors' => ['Visit is not assigned to you for routing.']];
        }
        if (!in_array($destination, ['lab', 'pharmacy'], true)) {
            return ['ok' => false, 'errors' => ['Invalid visit destination.']];
        }
        $updated = $this->visits->transactional(function () use (
            $visitId,
            $patientId,
            $doctorId,
            $destination
        ): bool {
            if (!$this->doctorAuthorizer->canAccess($doctorId, $patientId, $visitId, true)) {
                return false;
            }
            $this->visits->updateState($visitId, $destination);
            return true;
        });
        if (!$updated) {
            return ['ok' => false, 'errors' => ['Visit is not assigned to you for routing.']];
        }
        return ['ok' => true, 'errors' => []];
    }

    /**
     * Complete only the encounter whose final prescription was dispensed. A
     * multi-medication consultation stays in the pharmacy queue until every
     * linked prescription leaves the pending queue.
     */
    public function completePharmacyVisit(int $visitId, bool $hasPendingPrescriptions): void
    {
        $visit = $this->visits->findById($visitId);
        if ($visit !== null && (string) $visit['status'] === 'pharmacy' && !$hasPendingPrescriptions) {
            $this->visits->updateState($visitId, 'completed');
        }
    }

    /**
     * Retain the lab state while another test is pending. Once complete, route
     * selected medication orders to pharmacy; otherwise return the patient to
     * their doctor to review all results.
     */
    public function returnFromLab(int $visitId, bool $hasPendingLabRequests, bool $hasPendingPrescriptions): void
    {
        $visit = $this->visits->findById($visitId);
        if ($visit === null || (string) $visit['status'] !== 'lab' || $visit['doctor_id'] === null || $hasPendingLabRequests) {
            return;
        }
        $this->visits->updateState($visitId, $hasPendingPrescriptions ? 'pharmacy' : 'with_doctor');
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
        return $this->doctorAuthorizer->authorizedVisits($doctorId);
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
