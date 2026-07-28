<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Billing\BillingRepository;
use MediShield\Billing\BillingService;
use MediShield\Patient\PatientRepository;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use MediShield\Visit\VisitRepository;
use PHPUnit\Framework\TestCase;

final class BillingServiceTest extends TestCase
{
    private \PDO $pdo;
    private BillingService $billing;
    private VisitRepository $visits;
    private int $visitId;
    private int $receptionistId;
    private int $otherReceptionistId;
    private int $patientUserId;
    private int $otherPatientUserId;

    protected function setUp(): void
    {
        $this->pdo = TestSchema::pdo();
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $this->visits = new VisitRepository($this->pdo, $clock);
        $patients = new PatientRepository($this->pdo, $clock);
        $this->billing = new BillingService(new BillingRepository($this->pdo, $clock), $this->visits, $patients);

        $this->receptionistId = $this->createUser('Reception One', 'reception.one@example.com', 'receptionist');
        $this->otherReceptionistId = $this->createUser('Reception Two', 'reception.two@example.com', 'receptionist');
        $this->patientUserId = $this->createUser('Billing Patient', 'patient@example.com', 'patient');
        $this->otherPatientUserId = $this->createUser('Other Patient', 'other.patient@example.com', 'patient');
        $patientId = $this->createPatient($this->patientUserId, 'MSH-BILLING-ONE', 'Billing Patient');
        $this->createPatient($this->otherPatientUserId, 'MSH-BILLING-TWO', 'Other Patient');
        $this->visitId = $this->visits->create($patientId, $this->receptionistId, 'cash', null);
    }

    public function testAddCatalogCharges_WithValidStaffSelection_PersistsSnapshotsAndCalculatesTotal(): void
    {
        $staff = $this->staff($this->receptionistId, 'receptionist');

        $service = $this->billing->addCatalogCharge($this->visitId, $staff, 'service', 'Blood glucose', '2');
        $medication = $this->billing->addCatalogCharge($this->visitId, $staff, 'medication', 'Paracetamol 500 mg', '1');
        $bill = $this->billing->billForStaffVisit($this->visitId, $staff);

        self::assertTrue($service['ok']);
        self::assertTrue($medication['ok']);
        self::assertIsArray($bill);
        self::assertSame(950, (int) $bill['total_amount']);
        self::assertSame('Blood glucose', $bill['charges'][0]['description_snapshot']);
        self::assertSame(400, (int) $bill['charges'][0]['unit_price_snapshot']);
        self::assertSame(2, (int) $bill['charges'][0]['quantity']);
        self::assertSame(800, (int) $bill['charges'][0]['line_total']);
        self::assertSame(150, (int) $bill['charges'][1]['unit_price_snapshot']);
    }

    public function testRecordPayment_WithCashReferenceAndReceipt_FinalizesBill(): void
    {
        $staff = $this->staff($this->receptionistId, 'receptionist');
        $this->billing->addCatalogCharge($this->visitId, $staff, 'service', 'Blood glucose', '1');

        $result = $this->billing->recordPayment(
            $this->visitId,
            $staff,
            'cash',
            'paid',
            'CASH-001',
            'RCT-001'
        );
        $bill = $this->billing->billForStaffVisit($this->visitId, $staff);

        self::assertTrue($result['ok']);
        self::assertSame('paid', $bill['payment_status']);
        self::assertSame('cash', $bill['payment_method']);
        self::assertSame('CASH-001', $bill['payment_reference']);
        self::assertSame('RCT-001', $bill['receipt_number']);
        self::assertNotNull($bill['paid_at']);
    }

    public function testRecordPayment_WithInsuranceClaim_TracksPendingAndPaidStates(): void
    {
        $staff = $this->staff($this->receptionistId, 'receptionist');
        $insuranceVisitId = $this->visits->create(
            (int) $this->pdo->query("SELECT patient_id FROM patients WHERE patient_number = 'MSH-BILLING-ONE'")->fetchColumn(),
            $this->receptionistId,
            'insurance',
            'AAR Insurance'
        );
        $this->billing->addCatalogCharge($insuranceVisitId, $staff, 'service', 'Blood glucose', '1');

        $missingClaim = $this->billing->recordPayment($insuranceVisitId, $staff, 'insurance', 'pending_insurance', null, null);
        $pending = $this->billing->recordPayment($insuranceVisitId, $staff, 'insurance', 'pending_insurance', 'CLAIM-001', null);
        $paid = $this->billing->recordPayment($insuranceVisitId, $staff, 'insurance', 'paid', 'CLAIM-001', 'RCT-INS-001');
        $bill = $this->billing->billForStaffVisit($insuranceVisitId, $staff);

        self::assertFalse($missingClaim['ok']);
        self::assertTrue($pending['ok']);
        self::assertTrue($paid['ok']);
        self::assertSame('paid', $bill['payment_status']);
        self::assertSame('CLAIM-001', $bill['payment_reference']);
        self::assertSame('RCT-INS-001', $bill['receipt_number']);
    }

    public function testAddCatalogCharge_WithUnknownSelectionOrUnauthorizedStaff_RejectsWithoutWriting(): void
    {
        $staff = $this->staff($this->receptionistId, 'receptionist');

        $unknown = $this->billing->addCatalogCharge($this->visitId, $staff, 'service', 'Injected charge', '1');
        $unauthorized = $this->billing->addCatalogCharge(
            $this->visitId,
            $this->staff($this->otherReceptionistId, 'receptionist'),
            'service',
            'Blood glucose',
            '1'
        );

        self::assertFalse($unknown['ok']);
        self::assertFalse($unauthorized['ok']);
        self::assertNull($this->billing->billForStaffVisit($this->visitId, $staff));
    }

    public function testBillingViews_WithOtherPatientOrAfterPayment_DenyDisclosureAndMutation(): void
    {
        $staff = $this->staff($this->receptionistId, 'receptionist');
        $this->billing->addCatalogCharge($this->visitId, $staff, 'medication', 'Paracetamol 500 mg', '1');
        $this->billing->recordPayment($this->visitId, $staff, 'cash', 'paid', 'CASH-002', 'RCT-002');

        $otherPatientBill = $this->billing->billForPatientUser($this->visitId, $this->otherPatientUserId);
        $secondPayment = $this->billing->recordPayment($this->visitId, $staff, 'cash', 'paid', 'CASH-003', 'RCT-003');
        $newCharge = $this->billing->addCatalogCharge($this->visitId, $staff, 'medication', 'Paracetamol 500 mg', '1');

        self::assertNull($otherPatientBill);
        self::assertFalse($secondPayment['ok']);
        self::assertFalse($newCharge['ok']);
        self::assertSame(150, (int) $this->billing->billForPatientUser($this->visitId, $this->patientUserId)['total_amount']);
    }

    /** @return array{user_id:int,role:string} */
    private function staff(int $userId, string $role): array
    {
        return ['user_id' => $userId, 'role' => $role];
    }

    private function createUser(string $name, string $email, string $role): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (full_name, email, password_hash, role, status, created_at, updated_at)
             VALUES (:name, :email, :hash, :role, :status, :created_at, :updated_at)'
        );
        $stmt->execute([
            ':name' => $name,
            ':email' => $email,
            ':hash' => 'hash',
            ':role' => $role,
            ':status' => 'active',
            ':created_at' => '2026-01-01 12:00:00',
            ':updated_at' => '2026-01-01 12:00:00',
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    private function createPatient(int $userId, string $number, string $name): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO patients (user_id, patient_number, full_name, date_of_birth, gender, created_at)
             VALUES (:user_id, :number, :name, :date_of_birth, :gender, :created_at)'
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':number' => $number,
            ':name' => $name,
            ':date_of_birth' => '1990-01-01',
            ':gender' => 'female',
            ':created_at' => '2026-01-01 12:00:00',
        ]);
        return (int) $this->pdo->lastInsertId();
    }
}
