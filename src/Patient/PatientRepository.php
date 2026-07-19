<?php

declare(strict_types=1);

namespace MediShield\Patient;

use MediShield\Support\Clock;
use PDO;

/**
 * Persistence layer for `patients` and `patient_assignments`.
 *
 * The repository deliberately uses portable SQL so the same code runs on
 * MySQL/MariaDB in XAMPP and SQLite in tests. Higher-level validation and access
 * rules belong in PatientService; this class only stores and retrieves rows with
 * prepared statements.
 */
final class PatientRepository
{
    public function __construct(
        private PDO $pdo,
        private Clock $clock
    ) {
    }

    /**
     * Insert a patient demographic record and return its new patient_id.
     *
     * @param array{user_id:?int,patient_number:string,full_name:string,date_of_birth:string,gender:string,phone:?string,address:?string,emergency_contact:?string} $data
     */
    public function create(array $data): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO patients
                (user_id, patient_number, full_name, date_of_birth, gender,
                 phone, address, emergency_contact, created_at)
             VALUES
                (:user_id, :patient_number, :full_name, :date_of_birth, :gender,
                 :phone, :address, :emergency_contact, :created_at)'
        );
        $stmt->execute([
            ':user_id' => $data['user_id'],
            ':patient_number' => $data['patient_number'],
            ':full_name' => $data['full_name'],
            ':date_of_birth' => $data['date_of_birth'],
            ':gender' => $data['gender'],
            ':phone' => $data['phone'],
            ':address' => $data['address'],
            ':emergency_contact' => $data['emergency_contact'],
            ':created_at' => $this->clock->nowString(),
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /** Find a patient by primary key. */
    public function findById(int $patientId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM patients WHERE patient_id = :id LIMIT 1');
        $stmt->execute([':id' => $patientId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Find the patient record linked to a patient login account, if one exists. */
    public function findByUserId(int $userId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM patients WHERE user_id = :user_id LIMIT 1');
        $stmt->execute([':user_id' => $userId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function patientNumberExists(string $patientNumber): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM patients WHERE patient_number = :number LIMIT 1');
        $stmt->execute([':number' => $patientNumber]);
        return $stmt->fetchColumn() !== false;
    }

    public function userLinkExists(int $userId): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM patients WHERE user_id = :user_id LIMIT 1');
        $stmt->execute([':user_id' => $userId]);
        return $stmt->fetchColumn() !== false;
    }

    /**
     * Search by patient number, full name, or phone. The LIKE pattern is bound,
     * not interpolated, preserving SQL-injection protection.
     *
     * @return array<int,array<string,mixed>>
     */
    public function search(string $term, int $limit = 50): array
    {
        $term = trim($term);
        $limit = max(1, min($limit, 100));

        if ($term === '') {
            $stmt = $this->pdo->prepare(
                'SELECT * FROM patients ORDER BY patient_id DESC LIMIT :limit'
            );
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll();
        }

        $stmt = $this->pdo->prepare(
            'SELECT * FROM patients
              WHERE patient_number LIKE :term
                 OR full_name LIKE :term
                 OR phone LIKE :term
              ORDER BY patient_id DESC
              LIMIT :limit'
        );
        $stmt->bindValue(':term', '%' . $term . '%');
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Return active patient assignments, joined to staff users for display.
     *
     * @return array<int,array<string,mixed>>
     */
    public function assignmentsForPatient(int $patientId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT pa.assignment_id, pa.patient_id, pa.staff_user_id, pa.assigned_by,
                    pa.active, pa.created_at, u.full_name, u.email, u.role
               FROM patient_assignments pa
               JOIN users u ON u.user_id = pa.staff_user_id
              WHERE pa.patient_id = :patient_id AND pa.active = 1
              ORDER BY u.role, u.full_name'
        );
        $stmt->execute([':patient_id' => $patientId]);
        return $stmt->fetchAll();
    }

    /**
     * List all active nurse/doctor assignments for a staff member.
     *
     * @return array<int,array<string,mixed>>
     */
    public function assignedPatientsForStaff(int $staffUserId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT p.*
               FROM patient_assignments pa
               JOIN patients p ON p.patient_id = pa.patient_id
              WHERE pa.staff_user_id = :staff_user_id AND pa.active = 1
              ORDER BY p.full_name'
        );
        $stmt->execute([':staff_user_id' => $staffUserId]);
        return $stmt->fetchAll();
    }

    public function isAssigned(int $patientId, int $staffUserId): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM patient_assignments
              WHERE patient_id = :patient_id
                AND staff_user_id = :staff_user_id
                AND active = 1
              LIMIT 1'
        );
        $stmt->execute([
            ':patient_id' => $patientId,
            ':staff_user_id' => $staffUserId,
        ]);
        return $stmt->fetchColumn() !== false;
    }

    /**
     * Create or reactivate an assignment. The production schema has a unique key on
     * patient/staff, so reactivation uses an update first and falls back to insert.
     */
    public function assign(int $patientId, int $staffUserId, int $assignedBy): void
    {
        $update = $this->pdo->prepare(
            'UPDATE patient_assignments
                SET active = 1, assigned_by = :assigned_by, created_at = :created_at
              WHERE patient_id = :patient_id AND staff_user_id = :staff_user_id'
        );
        $update->execute([
            ':assigned_by' => $assignedBy,
            ':created_at' => $this->clock->nowString(),
            ':patient_id' => $patientId,
            ':staff_user_id' => $staffUserId,
        ]);

        if ($update->rowCount() > 0) {
            return;
        }

        $insert = $this->pdo->prepare(
            'INSERT INTO patient_assignments
                (patient_id, staff_user_id, assigned_by, active, created_at)
             VALUES
                (:patient_id, :staff_user_id, :assigned_by, 1, :created_at)'
        );
        $insert->execute([
            ':patient_id' => $patientId,
            ':staff_user_id' => $staffUserId,
            ':assigned_by' => $assignedBy,
            ':created_at' => $this->clock->nowString(),
        ]);
    }

    public function unassign(int $patientId, int $staffUserId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE patient_assignments
                SET active = 0
              WHERE patient_id = :patient_id AND staff_user_id = :staff_user_id'
        );
        $stmt->execute([
            ':patient_id' => $patientId,
            ':staff_user_id' => $staffUserId,
        ]);
    }
}
