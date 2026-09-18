<?php

declare(strict_types=1);

namespace MediShield\Reporting;

use PDO;

/**
 * Produces aggregate, role-scoped activity counts without returning names,
 * diagnoses, results, medication text, or other clinical contents.
 */
final class ActivityReportRepository
{
    public function __construct(private PDO $pdo)
    {
    }

    /** @return array<string,int> */
    public function forUser(int $userId, string $role): array
    {
        return match ($role) {
            'receptionist' => [
                'Visits registered' => $this->count('SELECT COUNT(*) FROM visits WHERE receptionist_id = :id', $userId),
                'Payments recorded' => $this->count('SELECT COUNT(*) FROM billing_bills WHERE recorded_by = :id', $userId),
            ],
            'nurse' => [
                'Vital-sign records completed' => $this->count('SELECT COUNT(*) FROM vitals WHERE nurse_id = :id', $userId),
                'Distinct patients supported' => $this->count('SELECT COUNT(DISTINCT patient_id) FROM vitals WHERE nurse_id = :id', $userId),
            ],
            'doctor' => [
                'Consultations documented' => $this->count('SELECT COUNT(*) FROM medical_records WHERE doctor_id = :id', $userId),
                'Distinct patients seen' => $this->count('SELECT COUNT(DISTINCT patient_id) FROM medical_records WHERE doctor_id = :id', $userId),
                'Lab requests ordered' => $this->count('SELECT COUNT(*) FROM lab_requests WHERE doctor_id = :id', $userId),
                'Prescriptions issued' => $this->count('SELECT COUNT(*) FROM prescriptions WHERE doctor_id = :id', $userId),
            ],
            'lab' => [
                'Lab tests completed' => $this->count('SELECT COUNT(*) FROM lab_results WHERE lab_technician_id = :id', $userId),
                'Distinct patients tested' => $this->count('SELECT COUNT(DISTINCT patient_id) FROM lab_results WHERE lab_technician_id = :id', $userId),
            ],
            'pharmacist' => [
                'Dispensing decisions completed' => $this->count('SELECT COUNT(*) FROM dispensing_records WHERE pharmacist_id = :id', $userId),
                'Medications dispensed' => $this->count("SELECT COUNT(*) FROM dispensing_records WHERE pharmacist_id = :id AND status = 'dispensed'", $userId),
            ],
            'patient' => $this->patientMetrics($userId),
            'admin' => [
                'Security actions performed' => $this->count('SELECT COUNT(*) FROM audit_logs WHERE user_id = :id', $userId),
                'Payments supervised' => $this->count('SELECT COUNT(*) FROM billing_bills WHERE recorded_by = :id', $userId),
            ],
            default => [],
        };
    }

    /** @return array<string,int> */
    public function forUserBetween(int $userId, string $role, string $start, string $end): array
    {
        $metric = fn (string $table, string $actor, string $label, string $extra = ''): array => [
            $label => $this->countBetween($table, $actor, $userId, $start, $end, $extra),
        ];
        return match ($role) {
            'receptionist' => $metric('visits', 'receptionist_id', 'Visits registered')
                + $metric('billing_bills', 'recorded_by', 'Payments recorded'),
            'nurse' => $metric('vitals', 'nurse_id', 'Vital-sign records completed')
                + ['Distinct patients supported' => $this->distinctBetween('vitals', 'nurse_id', $userId, $start, $end)],
            'doctor' => $metric('medical_records', 'doctor_id', 'Consultations documented')
                + ['Distinct patients seen' => $this->distinctBetween('medical_records', 'doctor_id', $userId, $start, $end)]
                + $metric('lab_requests', 'doctor_id', 'Lab requests ordered')
                + $metric('prescriptions', 'doctor_id', 'Prescriptions issued'),
            'lab' => $metric('lab_results', 'lab_technician_id', 'Lab tests completed')
                + ['Distinct patients tested' => $this->distinctBetween('lab_results', 'lab_technician_id', $userId, $start, $end)],
            'pharmacist' => $metric('dispensing_records', 'pharmacist_id', 'Dispensing decisions completed')
                + $metric('dispensing_records', 'pharmacist_id', 'Medications dispensed', "status = 'dispensed'"),
            'admin' => $metric('audit_logs', 'user_id', 'Security actions performed')
                + $metric('billing_bills', 'recorded_by', 'Payments supervised'),
            'patient' => $this->patientMetricsBetween($userId, $start, $end),
            default => [],
        };
    }

    /** @return array<string,int> */
    private function patientMetricsBetween(int $userId, string $start, string $end): array
    {
        $patientId = $this->pdo->prepare('SELECT patient_id FROM patients WHERE user_id = :id');
        $patientId->execute([':id' => $userId]);
        $id = (int) $patientId->fetchColumn();
        return [
            'Visits received' => $this->countBetween('visits', 'patient_id', $id, $start, $end),
            'Lab tests completed' => $this->countBetween('lab_results', 'patient_id', $id, $start, $end),
            'Prescriptions received' => $this->countBetween('prescriptions', 'patient_id', $id, $start, $end),
        ];
    }

    private function countBetween(string $table, string $actorColumn, int $id, string $start, string $end, string $extra = ''): int
    {
        $allowedTables = ['visits','billing_bills','vitals','medical_records','lab_requests','prescriptions','lab_results','dispensing_records','audit_logs'];
        $allowedColumns = ['receptionist_id','recorded_by','nurse_id','doctor_id','lab_technician_id','pharmacist_id','user_id','patient_id'];
        if (!in_array($table, $allowedTables, true) || !in_array($actorColumn, $allowedColumns, true)) {
            throw new \InvalidArgumentException('Unsupported report source.');
        }
        $sql = "SELECT COUNT(*) FROM $table WHERE $actorColumn = :id AND created_at >= :start AND created_at < :end";
        if ($extra !== '') {
            $sql .= ' AND ' . $extra;
        }
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':id' => $id, ':start' => $start, ':end' => $end]);
        return (int) $stmt->fetchColumn();
    }

    private function distinctBetween(string $table, string $actorColumn, int $id, string $start, string $end): int
    {
        if (!in_array($table, ['vitals','medical_records','lab_results'], true)) {
            throw new \InvalidArgumentException('Unsupported distinct report source.');
        }
        $stmt = $this->pdo->prepare("SELECT COUNT(DISTINCT patient_id) FROM $table WHERE $actorColumn = :id AND created_at >= :start AND created_at < :end");
        $stmt->execute([':id' => $id, ':start' => $start, ':end' => $end]);
        return (int) $stmt->fetchColumn();
    }

    /** @return array<string,int> */
    private function patientMetrics(int $userId): array
    {
        return [
            'Visits received' => $this->patientCount('visits', $userId),
            'Lab tests completed' => $this->patientCount('lab_results', $userId),
            'Prescriptions received' => $this->patientCount('prescriptions', $userId),
        ];
    }

    private function patientCount(string $table, int $userId): int
    {
        $allowed = ['visits', 'lab_results', 'prescriptions'];
        if (!in_array($table, $allowed, true)) {
            throw new \InvalidArgumentException('Unsupported patient activity table.');
        }
        return $this->count(
            'SELECT COUNT(*) FROM ' . $table . ' activity
              JOIN patients p ON p.patient_id = activity.patient_id
             WHERE p.user_id = :id',
            $userId
        );
    }

    private function count(string $sql, int $userId): int
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':id' => $userId]);
        return (int) $stmt->fetchColumn();
    }
}
