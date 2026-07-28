<?php

declare(strict_types=1);

namespace MediShield\Billing;

use MediShield\Support\Clock;
use PDO;

/**
 * Stores visit-linked financial records. Charge descriptions and unit prices are
 * copied into each row so later catalogue changes cannot alter a billed amount.
 */
final class BillingRepository
{
    public function __construct(private PDO $pdo, private Clock $clock)
    {
    }

    public function billForVisit(int $visitId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT b.*, v.patient_id, v.receptionist_id, v.payment_method AS visit_payment_method,
                    v.insurer AS visit_insurer, p.patient_number, p.full_name AS patient_name
               FROM billing_bills b
               JOIN visits v ON v.visit_id = b.visit_id
               JOIN patients p ON p.patient_id = b.patient_id
              WHERE b.visit_id = :visit_id
              LIMIT 1'
        );
        $stmt->execute([':visit_id' => $visitId]);
        $bill = $stmt->fetch();

        if ($bill === false) {
            return null;
        }

        $bill['charges'] = $this->chargesForBill((int) $bill['bill_id']);
        $bill['total_amount'] = array_sum(array_map(
            static fn (array $charge): int => (int) $charge['line_total'],
            $bill['charges']
        ));
        return $bill;
    }

    public function createBill(int $visitId, int $patientId, string $method, ?string $insurer): int
    {
        $now = $this->clock->nowString();
        $stmt = $this->pdo->prepare(
            'INSERT INTO billing_bills
                (visit_id, patient_id, payment_method, insurer, payment_status, payment_reference,
                 receipt_number, recorded_by, paid_at, created_at, updated_at)
             VALUES
                (:visit_id, :patient_id, :payment_method, :insurer, :payment_status, NULL,
                 NULL, NULL, NULL, :created_at, :updated_at)'
        );
        $stmt->execute([
            ':visit_id' => $visitId,
            ':patient_id' => $patientId,
            ':payment_method' => $method,
            ':insurer' => $insurer,
            ':payment_status' => 'unpaid',
            ':created_at' => $now,
            ':updated_at' => $now,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    public function addCharge(
        int $billId,
        string $type,
        string $description,
        int $unitPrice,
        int $quantity
    ): int {
        $stmt = $this->pdo->prepare(
            'INSERT INTO billing_charges
                (bill_id, charge_type, description_snapshot, unit_price_snapshot, quantity, line_total, created_at)
             VALUES
                (:bill_id, :charge_type, :description_snapshot, :unit_price_snapshot, :quantity, :line_total, :created_at)'
        );
        $stmt->execute([
            ':bill_id' => $billId,
            ':charge_type' => $type,
            ':description_snapshot' => $description,
            ':unit_price_snapshot' => $unitPrice,
            ':quantity' => $quantity,
            ':line_total' => $unitPrice * $quantity,
            ':created_at' => $this->clock->nowString(),
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    public function recordPayment(
        int $billId,
        string $status,
        ?string $reference,
        ?string $receiptNumber,
        int $recordedBy
    ): bool {
        $stmt = $this->pdo->prepare(
            'UPDATE billing_bills
                SET payment_status = :payment_status,
                    payment_reference = :payment_reference,
                    receipt_number = :receipt_number,
                    recorded_by = :recorded_by,
                    paid_at = :paid_at,
                    updated_at = :updated_at
              WHERE bill_id = :bill_id
                AND payment_status <> :paid_status'
        );
        $now = $this->clock->nowString();
        $stmt->execute([
            ':payment_status' => $status,
            ':payment_reference' => $reference,
            ':receipt_number' => $receiptNumber,
            ':recorded_by' => $recordedBy,
            ':paid_at' => $status === 'paid' ? $now : null,
            ':updated_at' => $now,
            ':bill_id' => $billId,
            ':paid_status' => 'paid',
        ]);
        return $stmt->rowCount() === 1;
    }

    /** @return array<int,array<string,mixed>> */
    public function visitsForStaff(?int $receptionistId = null): array
    {
        $where = '';
        $params = [];
        if ($receptionistId !== null) {
            $where = 'WHERE v.receptionist_id = :receptionist_id';
            $params[':receptionist_id'] = $receptionistId;
        }

        $stmt = $this->pdo->prepare(
            'SELECT v.visit_id, v.patient_id, v.receptionist_id, v.payment_method, v.insurer, v.status,
                    p.patient_number, p.full_name AS patient_name, b.bill_id, b.payment_status,
                    COALESCE((SELECT SUM(c.line_total) FROM billing_charges c WHERE c.bill_id = b.bill_id), 0) AS total_amount
               FROM visits v
               JOIN patients p ON p.patient_id = v.patient_id
               LEFT JOIN billing_bills b ON b.visit_id = v.visit_id
               ' . $where . '
              ORDER BY v.created_at DESC, v.visit_id DESC'
        );
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /** @return array<int,array<string,mixed>> */
    public function billsForPatient(int $patientId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT b.visit_id
               FROM billing_bills b
              WHERE b.patient_id = :patient_id
              ORDER BY b.created_at DESC, b.bill_id DESC'
        );
        $stmt->execute([':patient_id' => $patientId]);
        $bills = [];
        foreach ($stmt->fetchAll() as $row) {
            $bill = $this->billForVisit((int) $row['visit_id']);
            if ($bill !== null) {
                $bills[] = $bill;
            }
        }
        return $bills;
    }

    private function chargesForBill(int $billId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT charge_id, bill_id, charge_type, description_snapshot, unit_price_snapshot, quantity, line_total, created_at
               FROM billing_charges
              WHERE bill_id = :bill_id
              ORDER BY charge_id ASC'
        );
        $stmt->execute([':bill_id' => $billId]);
        return $stmt->fetchAll();
    }
}
