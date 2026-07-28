<?php

declare(strict_types=1);

namespace MediShield\Billing;

use MediShield\Auth\Rbac;
use MediShield\Clinical\ClinicalCatalog;
use MediShield\Patient\PatientRepository;
use MediShield\Visit\VisitRepository;

/**
 * Applies billing permissions and validation before immutable monetary snapshots
 * are stored. Prices always come from ClinicalCatalog, never from an HTTP form.
 */
final class BillingService
{
    public function __construct(
        private BillingRepository $billing,
        private VisitRepository $visits,
        private PatientRepository $patients
    ) {
    }

    /** @return array{ok:bool,errors:string[],charge_id:?int} */
    public function addCatalogCharge(int $visitId, array $actor, string $type, string $selection, mixed $quantity): array
    {
        $visit = $this->staffVisit($visitId, $actor);
        if ($visit === null) {
            return ['ok' => false, 'errors' => ['Billing record was not found.'], 'charge_id' => null];
        }

        $type = trim($type);
        $selection = trim($selection);
        $price = match ($type) {
            'service' => ClinicalCatalog::priceForTest($selection),
            'medication' => ClinicalCatalog::priceForMedication($selection),
            default => null,
        };
        $parsedQuantity = filter_var($quantity, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 100]]);
        if ($price === null || $parsedQuantity === false) {
            return ['ok' => false, 'errors' => ['Select a valid catalogue item and quantity.'], 'charge_id' => null];
        }

        $bill = $this->billing->billForVisit($visitId);
        if ($bill !== null && (string) $bill['payment_status'] === 'paid') {
            return ['ok' => false, 'errors' => ['Paid bills cannot be changed.'], 'charge_id' => null];
        }
        if ($bill === null) {
            $billId = $this->billing->createBill(
                $visitId,
                (int) $visit['patient_id'],
                (string) $visit['payment_method'],
                $visit['insurer'] === null ? null : (string) $visit['insurer']
            );
        } else {
            $billId = (int) $bill['bill_id'];
        }

        return [
            'ok' => true,
            'errors' => [],
            'charge_id' => $this->billing->addCharge($billId, $type, $selection, $price, (int) $parsedQuantity),
        ];
    }

    /** @return array{ok:bool,errors:string[]} */
    public function recordPayment(
        int $visitId,
        array $actor,
        string $method,
        string $status,
        ?string $reference,
        ?string $receiptNumber
    ): array {
        $visit = $this->staffVisit($visitId, $actor);
        $bill = $visit === null ? null : $this->billing->billForVisit($visitId);
        if ($visit === null || $bill === null) {
            return ['ok' => false, 'errors' => ['Billing record was not found.']];
        }
        if ((string) $bill['payment_status'] === 'paid') {
            return ['ok' => false, 'errors' => ['This bill is already paid.']];
        }
        if ($bill['charges'] === []) {
            return ['ok' => false, 'errors' => ['Add at least one charge before recording payment.']];
        }

        $method = trim($method);
        $status = trim($status);
        $reference = $this->nullableText($reference);
        $receiptNumber = $this->nullableText($receiptNumber);
        $errors = [];
        if ($method !== (string) $bill['payment_method']) {
            $errors[] = 'Payment method does not match the visit.';
        }
        if ($method === 'cash') {
            if ($status !== 'paid') {
                $errors[] = 'Cash payments must be recorded as paid.';
            }
        } elseif ($method === 'insurance') {
            if (!in_array($status, ['pending_insurance', 'paid'], true)) {
                $errors[] = 'Insurance payments must be pending or paid.';
            }
            if ($reference === null) {
                $errors[] = 'Insurance claim reference is required.';
            }
        } else {
            $errors[] = 'Invalid payment method.';
        }
        if ($status === 'paid' && $receiptNumber === null) {
            $errors[] = 'Receipt number is required for a paid bill.';
        }
        if (($reference !== null && mb_strlen($reference) > 100) || ($receiptNumber !== null && mb_strlen($receiptNumber) > 100)) {
            $errors[] = 'Payment reference and receipt number must be 100 characters or fewer.';
        }
        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors];
        }

        return $this->billing->recordPayment(
            (int) $bill['bill_id'],
            $status,
            $reference,
            $receiptNumber,
            (int) $actor['user_id']
        )
            ? ['ok' => true, 'errors' => []]
            : ['ok' => false, 'errors' => ['This bill is already paid.']];
    }

    public function billForStaffVisit(int $visitId, array $actor): ?array
    {
        return $this->staffVisit($visitId, $actor) === null ? null : $this->billing->billForVisit($visitId);
    }

    public function visitForStaff(int $visitId, array $actor): ?array
    {
        return $this->staffVisit($visitId, $actor);
    }

    public function billForPatientUser(int $visitId, int $patientUserId): ?array
    {
        $patient = $this->patients->findByUserId($patientUserId);
        $bill = $this->billing->billForVisit($visitId);
        if ($patient === null || $bill === null || (int) $bill['patient_id'] !== (int) $patient['patient_id']) {
            return null;
        }
        return $bill;
    }

    /** @return array<int,array<string,mixed>> */
    public function visitsForStaff(array $actor): array
    {
        return match ((string) ($actor['role'] ?? '')) {
            Rbac::ROLE_ADMIN => $this->billing->visitsForStaff(),
            Rbac::ROLE_RECEPTIONIST => $this->billing->visitsForStaff((int) $actor['user_id']),
            default => [],
        };
    }

    /** @return array<int,array<string,mixed>> */
    public function billsForPatientUser(int $patientUserId): array
    {
        $patient = $this->patients->findByUserId($patientUserId);
        return $patient === null ? [] : $this->billing->billsForPatient((int) $patient['patient_id']);
    }

    private function staffVisit(int $visitId, array $actor): ?array
    {
        $visit = $this->visits->findById($visitId);
        $role = (string) ($actor['role'] ?? '');
        if ($visit === null || !in_array($role, [Rbac::ROLE_ADMIN, Rbac::ROLE_RECEPTIONIST], true)) {
            return null;
        }
        if ($role === Rbac::ROLE_RECEPTIONIST && (int) $visit['receptionist_id'] !== (int) ($actor['user_id'] ?? 0)) {
            return null;
        }
        return $visit;
    }

    private function nullableText(?string $value): ?string
    {
        $value = trim((string) $value);
        return $value === '' ? null : $value;
    }
}
