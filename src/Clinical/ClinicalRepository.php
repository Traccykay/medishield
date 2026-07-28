<?php

declare(strict_types=1);

namespace MediShield\Clinical;

use MediShield\Support\Clock;
use PDO;

/**
 * PDO persistence for vitals, diagnoses, lab queues, prescriptions, and
 * dispensing. The service layer owns validation/encryption; this layer stores
 * only the resulting AES-GCM payloads and keeps SQL parameterized and portable
 * for MySQL/MariaDB plus SQLite tests.
 */
final class ClinicalRepository
{
    public function __construct(private PDO $pdo, private Clock $clock)
    {
    }

    public function createVitals(array $data): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO vitals
                (patient_id, nurse_id, temperature_encrypted, systolic_encrypted, diastolic_encrypted,
                 pulse_encrypted, weight_encrypted, symptoms_encrypted, created_at)
             VALUES
                (:patient_id, :nurse_id, :temperature_encrypted, :systolic_encrypted, :diastolic_encrypted,
                 :pulse_encrypted, :weight_encrypted, :symptoms_encrypted, :created_at)'
        );
        $stmt->execute([
            ':patient_id' => $data['patient_id'],
            ':nurse_id' => $data['nurse_id'],
            ':temperature_encrypted' => $data['temperature_encrypted'],
            ':systolic_encrypted' => $data['systolic_encrypted'],
            ':diastolic_encrypted' => $data['diastolic_encrypted'],
            ':pulse_encrypted' => $data['pulse_encrypted'],
            ':weight_encrypted' => $data['weight_encrypted'],
            ':symptoms_encrypted' => $data['symptoms_encrypted'],
            ':created_at' => $this->clock->nowString(),
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    public function vitalsForPatient(int $patientId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT v.*, u.full_name AS nurse_name
               FROM vitals v
               JOIN users u ON u.user_id = v.nurse_id
              WHERE v.patient_id = :patient_id
              ORDER BY v.created_at DESC, v.vitals_id DESC'
        );
        $stmt->execute([':patient_id' => $patientId]);
        return $stmt->fetchAll();
    }

    public function recentVitalsByNurse(int $nurseId, int $limit = 10): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT v.*, p.patient_number, p.full_name AS patient_name
               FROM vitals v
               JOIN patients p ON p.patient_id = v.patient_id
              WHERE v.nurse_id = :nurse_id
              ORDER BY v.created_at DESC, v.vitals_id DESC
              LIMIT :limit'
        );
        $stmt->bindValue(':nurse_id', $nurseId, PDO::PARAM_INT);
        $stmt->bindValue(':limit', max(1, min($limit, 50)), PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function createMedicalRecord(int $visitId, int $patientId, int $doctorId, string $diagnosis, ?string $treatment): int
    {
        $now = $this->clock->nowString();
        $stmt = $this->pdo->prepare(
            'INSERT INTO medical_records
                (visit_id, patient_id, doctor_id, diagnosis_encrypted, treatment_encrypted, created_at, updated_at)
             VALUES
                (:visit_id, :patient_id, :doctor_id, :diagnosis, :treatment, :created_at, :updated_at)'
        );
        $stmt->execute([
            ':visit_id' => $visitId,
            ':patient_id' => $patientId,
            ':doctor_id' => $doctorId,
            ':diagnosis' => $diagnosis,
            ':treatment' => $treatment,
            ':created_at' => $now,
            ':updated_at' => $now,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    public function recordsForPatient(int $patientId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT mr.*, u.full_name AS doctor_name
               FROM medical_records mr
               JOIN users u ON u.user_id = mr.doctor_id
              WHERE mr.patient_id = :patient_id
              ORDER BY mr.created_at DESC, mr.record_id DESC'
        );
        $stmt->execute([':patient_id' => $patientId]);
        return $stmt->fetchAll();
    }

    public function findRecord(int $recordId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM medical_records WHERE record_id = :id LIMIT 1');
        $stmt->execute([':id' => $recordId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function createLabRequest(
        int $visitId,
        int $patientId,
        int $recordId,
        int $doctorId,
        string $testName,
        ?string $reason,
        int $catalogPriceKes
    ): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO lab_requests
                (visit_id, patient_id, record_id, doctor_id, test_name, reason, catalog_price_kes, status, created_at)
             VALUES
                (:visit_id, :patient_id, :record_id, :doctor_id, :test_name, :reason, :catalog_price_kes, :status, :created_at)'
        );
        $stmt->execute([
            ':visit_id' => $visitId,
            ':patient_id' => $patientId,
            ':record_id' => $recordId,
            ':doctor_id' => $doctorId,
            ':test_name' => $testName,
            ':reason' => $reason,
            ':catalog_price_kes' => $catalogPriceKes,
            ':status' => 'pending',
            ':created_at' => $this->clock->nowString(),
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    public function labRequests(string $status = 'pending', ?int $doctorId = null, ?int $patientId = null): array
    {
        $where = ['lr.status = :status'];
        $params = [':status' => $status];
        if ($doctorId !== null) {
            $where[] = 'lr.doctor_id = :doctor_id';
            $params[':doctor_id'] = $doctorId;
        }
        if ($patientId !== null) {
            $where[] = 'lr.patient_id = :patient_id';
            $params[':patient_id'] = $patientId;
        }
        $stmt = $this->pdo->prepare(
            'SELECT lr.*, p.patient_number, p.full_name AS patient_name, p.date_of_birth, p.gender,
                    u.full_name AS doctor_name
               FROM lab_requests lr
               JOIN patients p ON p.patient_id = lr.patient_id
               JOIN users u ON u.user_id = lr.doctor_id
              WHERE ' . implode(' AND ', $where) . '
              ORDER BY lr.created_at DESC, lr.lab_request_id DESC'
        );
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public function findLabRequest(int $labRequestId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT lr.*, p.patient_number, p.full_name AS patient_name, p.date_of_birth, p.gender
               FROM lab_requests lr
               JOIN patients p ON p.patient_id = lr.patient_id
              WHERE lr.lab_request_id = :id LIMIT 1'
        );
        $stmt->execute([':id' => $labRequestId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function hasPendingLabRequestsForVisit(int $visitId): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM lab_requests WHERE visit_id = :visit_id AND status = :status LIMIT 1'
        );
        $stmt->execute([':visit_id' => $visitId, ':status' => 'pending']);
        return $stmt->fetchColumn() !== false;
    }

    public function createLabResult(int $labRequestId, int $patientId, int $labTechId, string $encryptedResult): int
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare(
                'INSERT INTO lab_results
                    (lab_request_id, patient_id, lab_technician_id, result_encrypted, created_at)
                 VALUES
                    (:lab_request_id, :patient_id, :lab_technician_id, :result_encrypted, :created_at)'
            );
            $stmt->execute([
                ':lab_request_id' => $labRequestId,
                ':patient_id' => $patientId,
                ':lab_technician_id' => $labTechId,
                ':result_encrypted' => $encryptedResult,
                ':created_at' => $this->clock->nowString(),
            ]);
            $resultId = (int) $this->pdo->lastInsertId();

            $update = $this->pdo->prepare(
                'UPDATE lab_requests SET status = :status WHERE lab_request_id = :id'
            );
            $update->execute([':status' => 'completed', ':id' => $labRequestId]);
            $this->pdo->commit();
            return $resultId;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    public function labResultsForPatient(int $patientId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT res.*, lr.test_name, lr.reason, u.full_name AS lab_name
               FROM lab_results res
               JOIN lab_requests lr ON lr.lab_request_id = res.lab_request_id
               JOIN users u ON u.user_id = res.lab_technician_id
              WHERE res.patient_id = :patient_id
              ORDER BY res.created_at DESC, res.lab_result_id DESC'
        );
        $stmt->execute([':patient_id' => $patientId]);
        return $stmt->fetchAll();
    }

    public function createPrescription(
        int $visitId,
        int $patientId,
        int $recordId,
        int $doctorId,
        string $medication,
        string $dosage,
        ?string $instructions,
        int $catalogPriceKes
    ): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO prescriptions
                (visit_id, patient_id, record_id, doctor_id, medication_encrypted, dosage_encrypted,
                 instructions_encrypted, catalog_price_kes, status, created_at)
             VALUES
                (:visit_id, :patient_id, :record_id, :doctor_id, :medication, :dosage,
                 :instructions, :catalog_price_kes, :status, :created_at)'
        );
        $stmt->execute([
            ':visit_id' => $visitId,
            ':patient_id' => $patientId,
            ':record_id' => $recordId,
            ':doctor_id' => $doctorId,
            ':medication' => $medication,
            ':dosage' => $dosage,
            ':instructions' => $instructions,
            ':catalog_price_kes' => $catalogPriceKes,
            ':status' => 'pending',
            ':created_at' => $this->clock->nowString(),
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Persist one consultation as an all-or-nothing unit: a clinical record and
     * each selected lab or medication order cannot be split by a failed write.
     *
     * @param array<int,array{test_name:string,reason:?string,catalog_price_kes:int}> $labs
     * @param array<int,array{medication:string,dosage:string,instructions:?string,catalog_price_kes:int}> $prescriptions
     * @return array{record_id:int,lab_request_ids:int[],prescription_ids:int[]}
     */
    public function createConsultation(
        int $visitId,
        int $patientId,
        int $doctorId,
        string $diagnosis,
        ?string $treatment,
        array $labs,
        array $prescriptions
    ): array {
        $this->pdo->beginTransaction();
        try {
            $recordId = $this->createMedicalRecord($visitId, $patientId, $doctorId, $diagnosis, $treatment);
            $labRequestIds = [];
            foreach ($labs as $lab) {
                $labRequestIds[] = $this->createLabRequest(
                    $visitId,
                    $patientId,
                    $recordId,
                    $doctorId,
                    $lab['test_name'],
                    $lab['reason'],
                    $lab['catalog_price_kes']
                );
            }
            $prescriptionIds = [];
            foreach ($prescriptions as $prescription) {
                $prescriptionIds[] = $this->createPrescription(
                    $visitId,
                    $patientId,
                    $recordId,
                    $doctorId,
                    $prescription['medication'],
                    $prescription['dosage'],
                    $prescription['instructions'],
                    $prescription['catalog_price_kes']
                );
            }
            $this->pdo->commit();

            return [
                'record_id' => $recordId,
                'lab_request_ids' => $labRequestIds,
                'prescription_ids' => $prescriptionIds,
            ];
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    public function prescriptions(string $status = 'pending', ?int $doctorId = null, ?int $patientId = null): array
    {
        $where = ['rx.status = :status'];
        $params = [':status' => $status];
        if ($doctorId !== null) {
            $where[] = 'rx.doctor_id = :doctor_id';
            $params[':doctor_id'] = $doctorId;
        }
        if ($patientId !== null) {
            $where[] = 'rx.patient_id = :patient_id';
            $params[':patient_id'] = $patientId;
        }
        $stmt = $this->pdo->prepare(
            'SELECT rx.*, p.patient_number, p.full_name AS patient_name, p.date_of_birth, p.gender,
                    u.full_name AS doctor_name
               FROM prescriptions rx
               JOIN patients p ON p.patient_id = rx.patient_id
               JOIN users u ON u.user_id = rx.doctor_id
              WHERE ' . implode(' AND ', $where) . '
              ORDER BY rx.created_at DESC, rx.prescription_id DESC'
        );
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /**
     * Return every prescription issued for one patient, regardless of its current
     * queue status. The caller must complete object-level authorization before
     * requesting this clinical history.
     */
    public function prescriptionsForPatient(int $patientId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT rx.*, p.patient_number, p.full_name AS patient_name, p.date_of_birth, p.gender,
                    u.full_name AS doctor_name
               FROM prescriptions rx
               JOIN patients p ON p.patient_id = rx.patient_id
               JOIN users u ON u.user_id = rx.doctor_id
              WHERE rx.patient_id = :patient_id
              ORDER BY rx.created_at DESC, rx.prescription_id DESC'
        );
        $stmt->execute([':patient_id' => $patientId]);
        return $stmt->fetchAll();
    }

    public function findPrescription(int $prescriptionId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT rx.*, p.patient_number, p.full_name AS patient_name, p.date_of_birth, p.gender
               FROM prescriptions rx
               JOIN patients p ON p.patient_id = rx.patient_id
              WHERE rx.prescription_id = :id LIMIT 1'
        );
        $stmt->execute([':id' => $prescriptionId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Return only prescriptions whose linked encounter is actively assigned to
     * pharmacy. A refused item returns its entire encounter to the doctor, so
     * sibling pending items must not remain actionable in the pharmacy queue.
     *
     * @return array<int,array<string,mixed>>
     */
    public function pharmacyPrescriptions(): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT rx.*, p.patient_number, p.full_name AS patient_name, p.date_of_birth, p.gender,
                    u.full_name AS doctor_name
               FROM prescriptions rx
               JOIN visits v ON v.visit_id = rx.visit_id
               JOIN patients p ON p.patient_id = rx.patient_id
               JOIN users u ON u.user_id = rx.doctor_id
              WHERE rx.status = :prescription_status AND v.status = :visit_status
              ORDER BY rx.created_at DESC, rx.prescription_id DESC'
        );
        $stmt->execute([':prescription_status' => 'pending', ':visit_status' => 'pharmacy']);
        return $stmt->fetchAll();
    }

    public function hasPendingPrescriptionsForVisit(int $visitId): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM prescriptions WHERE visit_id = :visit_id AND status = :status LIMIT 1'
        );
        $stmt->execute([':visit_id' => $visitId, ':status' => 'pending']);
        return $stmt->fetchColumn() !== false;
    }

    public function isActivePharmacist(int $userId): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM users WHERE user_id = :user_id AND role = :role AND status = :status LIMIT 1'
        );
        $stmt->execute([':user_id' => $userId, ':role' => 'pharmacist', ':status' => 'active']);
        return $stmt->fetchColumn() !== false;
    }

    /**
     * Atomically resolve one pending pharmacy order. The encounter-state change
     * is in the same transaction as the dispensing record, so a refusal can
     * never be committed while leaving its patient in the pharmacy queue.
     */
    public function recordPharmacyOutcome(int $prescriptionId, int $pharmacistId, string $status, ?string $remarks): ?int
    {
        $this->pdo->beginTransaction();
        try {
            $lock = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? ' FOR UPDATE' : '';
            $prescriptionStmt = $this->pdo->prepare(
                'SELECT prescription_id, visit_id, patient_id, status
                   FROM prescriptions
                  WHERE prescription_id = :id' . $lock
            );
            $prescriptionStmt->execute([':id' => $prescriptionId]);
            $prescription = $prescriptionStmt->fetch();
            if ($prescription === false || (string) $prescription['status'] !== 'pending' || (int) $prescription['visit_id'] <= 0) {
                $this->pdo->rollBack();
                return null;
            }

            $visitStmt = $this->pdo->prepare(
                'SELECT visit_id, doctor_id, status FROM visits WHERE visit_id = :id' . $lock
            );
            $visitStmt->execute([':id' => (int) $prescription['visit_id']]);
            $visit = $visitStmt->fetch();
            if ($visit === false || (string) $visit['status'] !== 'pharmacy' || $visit['doctor_id'] === null) {
                $this->pdo->rollBack();
                return null;
            }

            $updatePrescription = $this->pdo->prepare(
                'UPDATE prescriptions
                    SET status = :status
                  WHERE prescription_id = :id AND status = :pending_status'
            );
            $updatePrescription->execute([
                ':status' => $status,
                ':id' => $prescriptionId,
                ':pending_status' => 'pending',
            ]);
            if ($updatePrescription->rowCount() !== 1) {
                $this->pdo->rollBack();
                return null;
            }

            $stmt = $this->pdo->prepare(
                'INSERT INTO dispensing_records
                    (prescription_id, patient_id, pharmacist_id, status, remarks, created_at)
                 VALUES
                    (:prescription_id, :patient_id, :pharmacist_id, :status, :remarks, :created_at)'
            );
            $stmt->execute([
                ':prescription_id' => $prescriptionId,
                ':patient_id' => (int) $prescription['patient_id'],
                ':pharmacist_id' => $pharmacistId,
                ':status' => $status,
                ':remarks' => $remarks,
                ':created_at' => $this->clock->nowString(),
            ]);
            $dispensingId = (int) $this->pdo->lastInsertId();

            if ($status === 'refused') {
                $visitUpdate = $this->pdo->prepare(
                    'UPDATE visits
                        SET status = :status, active_doctor_id = doctor_id, updated_at = :updated_at
                      WHERE visit_id = :visit_id AND status = :pharmacy_status AND doctor_id = :doctor_id'
                );
                $visitUpdate->execute([
                    ':status' => 'with_doctor',
                    ':updated_at' => $this->clock->nowString(),
                    ':visit_id' => (int) $visit['visit_id'],
                    ':pharmacy_status' => 'pharmacy',
                    ':doctor_id' => (int) $visit['doctor_id'],
                ]);
                if ($visitUpdate->rowCount() !== 1) {
                    $this->pdo->rollBack();
                    return null;
                }
            } elseif (!$this->hasPendingPrescriptionsForVisit((int) $visit['visit_id'])) {
                $visitUpdate = $this->pdo->prepare(
                    'UPDATE visits
                        SET status = :status, active_doctor_id = NULL, updated_at = :updated_at
                      WHERE visit_id = :visit_id AND status = :pharmacy_status'
                );
                $visitUpdate->execute([
                    ':status' => 'completed',
                    ':updated_at' => $this->clock->nowString(),
                    ':visit_id' => (int) $visit['visit_id'],
                    ':pharmacy_status' => 'pharmacy',
                ]);
                if ($visitUpdate->rowCount() !== 1) {
                    $this->pdo->rollBack();
                    return null;
                }
            }

            $this->pdo->commit();
            return $dispensingId;
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    public function dispensingForPatient(int $patientId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT dr.*, u.full_name AS pharmacist_name
               FROM dispensing_records dr
               JOIN users u ON u.user_id = dr.pharmacist_id
              WHERE dr.patient_id = :patient_id
              ORDER BY dr.created_at DESC, dr.dispensing_id DESC'
        );
        $stmt->execute([':patient_id' => $patientId]);
        return $stmt->fetchAll();
    }

    /**
     * Return pharmacy outcomes for a single encounter. The caller must first
     * enforce that the current doctor owns the linked visit before decrypting
     * or rendering these clinical details.
     *
     * @return array<int,array<string,mixed>>
     */
    public function pharmacyOutcomesForVisit(int $visitId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT dr.*, rx.medication_encrypted, rx.dosage_encrypted, rx.instructions_encrypted
               FROM dispensing_records dr
               JOIN prescriptions rx ON rx.prescription_id = dr.prescription_id
              WHERE rx.visit_id = :visit_id
              ORDER BY dr.created_at DESC, dr.dispensing_id DESC'
        );
        $stmt->execute([':visit_id' => $visitId]);
        return $stmt->fetchAll();
    }
}
