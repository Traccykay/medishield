<?php

declare(strict_types=1);

namespace MediShield\Auth;

use PDO;

/**
 * Central database-backed policy for doctor access to a patient encounter.
 *
 * Both the active patient assignment and the currently owned `with_doctor`
 * visit must match in the same query. The list and point-query forms therefore
 * cannot drift into assignment-only or visit-only interpretations.
 */
final class DoctorPatientAuthorizer
{
    private const ACTIVE_JOIN = <<<'SQL'
         FROM visits v
         INNER JOIN patient_assignments pa
                 ON pa.patient_id = v.patient_id
                AND pa.staff_user_id = :assignment_doctor_id
                AND pa.active = 1
        SQL;

    private const ACTIVE_PREDICATE = <<<'SQL'
         WHERE v.status = :visit_status
           AND v.doctor_id = :visit_doctor_id
           AND v.active_doctor_id = :active_doctor_id
        SQL;

    public function __construct(private PDO $pdo)
    {
    }

    /**
     * Check one exact doctor/patient/visit tuple.
     *
     * When `$forUpdate` is true, callers must already be inside a transaction.
     * MySQL then locks the matching visit and assignment rows through the joined
     * query. SQLite omits unsupported lock syntax while the surrounding
     * transaction keeps the check and write in one database unit.
     */
    public function canAccess(
        int $doctorId,
        int $patientId,
        int $visitId,
        bool $forUpdate = false
    ): bool {
        if ($doctorId < 1 || $patientId < 1 || $visitId < 1) {
            return false;
        }

        $lock = $forUpdate && $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql'
            ? ' FOR UPDATE'
            : '';
        $stmt = $this->pdo->prepare(
            'SELECT v.visit_id'
            . self::ACTIVE_JOIN
            . self::ACTIVE_PREDICATE
            . ' AND v.patient_id = :patient_id'
            . ' AND v.visit_id = :visit_id'
            . ' LIMIT 1'
            . $lock
        );
        $stmt->execute($this->parameters($doctorId) + [
            ':patient_id' => $patientId,
            ':visit_id' => $visitId,
        ]);

        return $stmt->fetchColumn() !== false;
    }

    /**
     * Return only non-clinical demographics needed by doctor lists and links.
     *
     * @return array<int,array<string,mixed>>
     */
    public function authorizedVisits(int $doctorId): array
    {
        if ($doctorId < 1) {
            return [];
        }

        $stmt = $this->pdo->prepare(
            'SELECT v.visit_id, v.patient_id, v.status, p.patient_number, p.full_name,
                    p.date_of_birth, p.gender, p.phone'
            . self::ACTIVE_JOIN
            . ' INNER JOIN patients p ON p.patient_id = v.patient_id'
            . self::ACTIVE_PREDICATE
            . ' ORDER BY v.created_at ASC, v.visit_id ASC'
        );
        $stmt->execute($this->parameters($doctorId));
        return $stmt->fetchAll();
    }

    /** @return array<string,int|string> */
    private function parameters(int $doctorId): array
    {
        return [
            ':assignment_doctor_id' => $doctorId,
            ':visit_status' => 'with_doctor',
            ':visit_doctor_id' => $doctorId,
            ':active_doctor_id' => $doctorId,
        ];
    }
}
