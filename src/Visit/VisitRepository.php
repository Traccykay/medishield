<?php

declare(strict_types=1);

namespace MediShield\Visit;

use MediShield\Support\Clock;
use PDO;

/**
 * Persistence layer for the non-clinical patient journey. Clinical details remain
 * in the Clinical module; this repository only stores queue and payment metadata.
 */
final class VisitRepository
{
    public function __construct(private PDO $pdo, private Clock $clock)
    {
    }

    public function create(int $patientId, int $receptionistId, string $paymentMethod, ?string $insurer): int
    {
        $now = $this->clock->nowString();
        $stmt = $this->pdo->prepare(
            'INSERT INTO visits
                (patient_id, receptionist_id, nurse_id, doctor_id, active_doctor_id, payment_method, insurer, status, created_at, updated_at)
             VALUES
                (:patient_id, :receptionist_id, NULL, NULL, NULL, :payment_method, :insurer, :status, :created_at, :updated_at)'
        );
        $stmt->execute([
            ':patient_id' => $patientId,
            ':receptionist_id' => $receptionistId,
            ':payment_method' => $paymentMethod,
            ':insurer' => $insurer,
            ':status' => 'triage',
            ':created_at' => $now,
            ':updated_at' => $now,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    public function findById(int $visitId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT v.*, p.patient_number, p.full_name AS patient_name
               FROM visits v
               JOIN patients p ON p.patient_id = v.patient_id
              WHERE v.visit_id = :id LIMIT 1'
        );
        $stmt->execute([':id' => $visitId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function openVisitForPatient(int $patientId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM visits
              WHERE patient_id = :patient_id AND status <> :completed
              ORDER BY visit_id DESC LIMIT 1'
        );
        $stmt->execute([':patient_id' => $patientId, ':completed' => 'completed']);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function updateState(int $visitId, string $status, ?int $nurseId = null, ?int $doctorId = null): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE visits
                SET status = :new_status,
                    nurse_id = COALESCE(:nurse_id, nurse_id),
                    doctor_id = COALESCE(:new_doctor_id, doctor_id),
                    active_doctor_id = CASE
                        WHEN :active_status = :with_doctor_status THEN COALESCE(:active_doctor_id, doctor_id)
                        ELSE NULL
                    END,
                    updated_at = :updated_at
              WHERE visit_id = :visit_id'
        );
        $stmt->execute([
            ':new_status' => $status,
            ':active_status' => $status,
            ':with_doctor_status' => 'with_doctor',
            ':nurse_id' => $nurseId,
            ':new_doctor_id' => $doctorId,
            ':active_doctor_id' => $doctorId,
            ':updated_at' => $this->clock->nowString(),
            ':visit_id' => $visitId,
        ]);
    }

    /**
     * Conditionally reserve an eligible visit for an available doctor.
     *
     * The caller owns the transaction and writes the corresponding patient
     * assignment after this visit-first lock/update. The unique active-doctor
     * key remains the final guard against concurrent reservations.
     */
    public function reserveAvailableDoctor(int $visitId, int $nurseId, int $doctorId): ?int
    {
        if (!$this->pdo->inTransaction()) {
            throw new \LogicException('Doctor reservation requires an active transaction.');
        }

        $lock = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? ' FOR UPDATE' : '';
        $visitStmt = $this->pdo->prepare(
            'SELECT patient_id, nurse_id, status
               FROM visits
              WHERE visit_id = :visit_id' . $lock
        );
        $visitStmt->execute([':visit_id' => $visitId]);
        $visit = $visitStmt->fetch();
        if (
            $visit === false
            || (string) $visit['status'] !== 'with_nurse'
            || (int) $visit['nurse_id'] !== $nurseId
        ) {
            return null;
        }

        $updateVisit = $this->pdo->prepare(
            'UPDATE visits
                SET status = :status, doctor_id = :doctor_id,
                    active_doctor_id = :active_doctor_id, updated_at = :updated_at
              WHERE visit_id = :visit_id AND nurse_id = :nurse_id AND status = :waiting_status'
        );
        $updateVisit->execute([
            ':status' => 'with_doctor',
            ':doctor_id' => $doctorId,
            ':active_doctor_id' => $doctorId,
            ':updated_at' => $this->clock->nowString(),
            ':visit_id' => $visitId,
            ':nurse_id' => $nurseId,
            ':waiting_status' => 'with_nurse',
        ]);

        return $updateVisit->rowCount() === 1 ? (int) $visit['patient_id'] : null;
    }

    /**
     * Return the doctor's current patient visit to its existing nurse.
     *
     * The caller owns the transaction and deactivates the corresponding
     * assignment only after this visit-first lock/update succeeds.
     */
    public function returnDoctorVisitToNurseQueue(int $patientId, int $doctorId): bool
    {
        if (!$this->pdo->inTransaction()) {
            throw new \LogicException('Doctor revocation requires an active transaction.');
        }

        $lock = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? ' FOR UPDATE' : '';
        $visitStmt = $this->pdo->prepare(
            'SELECT visit_id
               FROM visits
              WHERE patient_id = :patient_id
                AND status = :doctor_status
                AND active_doctor_id = :doctor_id
              ORDER BY visit_id DESC
              LIMIT 1' . $lock
        );
        $visitStmt->execute([
            ':patient_id' => $patientId,
            ':doctor_status' => 'with_doctor',
            ':doctor_id' => $doctorId,
        ]);
        $visitId = $visitStmt->fetchColumn();
        if ($visitId === false) {
            return false;
        }

        $updateVisit = $this->pdo->prepare(
            'UPDATE visits
                SET status = :nurse_status,
                    active_doctor_id = NULL,
                    updated_at = :updated_at
              WHERE visit_id = :visit_id
                AND patient_id = :patient_id
                AND status = :doctor_status
                AND active_doctor_id = :doctor_id'
        );
        $updateVisit->execute([
            ':nurse_status' => 'with_nurse',
            ':updated_at' => $this->clock->nowString(),
            ':visit_id' => $visitId,
            ':patient_id' => $patientId,
            ':doctor_status' => 'with_doctor',
            ':doctor_id' => $doctorId,
        ]);

        return $updateVisit->rowCount() === 1;
    }

    public function transactional(callable $operation): mixed
    {
        if ($this->pdo->inTransaction()) {
            return $operation();
        }

        $this->pdo->beginTransaction();
        try {
            $result = $operation();
            $this->pdo->commit();
            return $result;
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /** @return array<int,array<string,mixed>> */
    public function visitsByStatus(string $status, ?int $staffId = null, ?string $staffColumn = null): array
    {
        $where = ['v.status = :status'];
        $params = [':status' => $status];
        if ($staffId !== null && in_array($staffColumn, ['nurse_id', 'doctor_id'], true)) {
            $where[] = 'v.' . $staffColumn . ' = :staff_id';
            $params[':staff_id'] = $staffId;
        }

        $stmt = $this->pdo->prepare(
            'SELECT v.*, p.patient_number, p.full_name, p.full_name AS patient_name, p.date_of_birth
               FROM visits v
               JOIN patients p ON p.patient_id = v.patient_id
              WHERE ' . implode(' AND ', $where) . '
              ORDER BY v.created_at ASC, v.visit_id ASC'
        );
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /** @return array<int,array<string,mixed>> */
    public function availableDoctors(): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT u.user_id, u.full_name, u.email
               FROM users u
               LEFT JOIN visits v ON v.active_doctor_id = u.user_id
              WHERE u.role = :role AND u.status = :active_status AND v.visit_id IS NULL
              ORDER BY u.full_name'
        );
        $stmt->execute([
            ':role' => 'doctor',
            ':active_status' => 'active',
        ]);
        return $stmt->fetchAll();
    }
}
