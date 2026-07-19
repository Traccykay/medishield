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
                SET status = :status,
                    nurse_id = COALESCE(:nurse_id, nurse_id),
                    doctor_id = COALESCE(:doctor_id, doctor_id),
                    active_doctor_id = CASE WHEN :status = :busy_status THEN COALESCE(:doctor_id, doctor_id) ELSE NULL END,
                    updated_at = :updated_at
              WHERE visit_id = :visit_id'
        );
        $stmt->execute([
            ':status' => $status,
            ':busy_status' => 'with_doctor',
            ':nurse_id' => $nurseId,
            ':doctor_id' => $doctorId,
            ':updated_at' => $this->clock->nowString(),
            ':visit_id' => $visitId,
        ]);
    }

    /** Atomically reserve a doctor; the unique active_doctor_id key prevents races. */
    public function assignAvailableDoctor(int $visitId, int $nurseId, int $doctorId): bool
    {
        $stmt = $this->pdo->prepare(
            'UPDATE visits
                SET status = :status, doctor_id = :doctor_id, active_doctor_id = :doctor_id, updated_at = :updated_at
              WHERE visit_id = :visit_id AND nurse_id = :nurse_id AND status = :waiting_status'
        );
        $stmt->execute([
            ':status' => 'with_doctor',
            ':doctor_id' => $doctorId,
            ':updated_at' => $this->clock->nowString(),
            ':visit_id' => $visitId,
            ':nurse_id' => $nurseId,
            ':waiting_status' => 'with_nurse',
        ]);
        return $stmt->rowCount() === 1;
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
            'SELECT v.*, p.patient_number, p.full_name AS patient_name, p.date_of_birth
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
               LEFT JOIN visits v ON v.doctor_id = u.user_id AND v.status = :busy_status
              WHERE u.role = :role AND u.status = :active_status AND v.visit_id IS NULL
              ORDER BY u.full_name'
        );
        $stmt->execute([
            ':busy_status' => 'with_doctor',
            ':role' => 'doctor',
            ':active_status' => 'active',
        ]);
        return $stmt->fetchAll();
    }
}
