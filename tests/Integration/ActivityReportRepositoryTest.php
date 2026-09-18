<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Reporting\ActivityReportRepository;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

final class ActivityReportRepositoryTest extends TestCase
{
    public function testDoctorReportCountsActivityWithoutReturningPatientOrClinicalFields(): void
    {
        $pdo = TestSchema::pdo();
        $pdo->exec(
            "INSERT INTO medical_records
                (visit_id, patient_id, doctor_id, diagnosis_encrypted, treatment_encrypted, created_at, updated_at)
             VALUES (1, 10, 7, 'cipher-one', NULL, '2026-01-01', '2026-01-01'),
                    (2, 10, 7, 'cipher-two', NULL, '2026-01-02', '2026-01-02'),
                    (3, 11, 7, 'cipher-three', NULL, '2026-01-03', '2026-01-03')"
        );
        $pdo->exec(
            "INSERT INTO lab_requests
                (visit_id, patient_id, record_id, doctor_id, test_name, reason, catalog_price_kes, status, created_at)
             VALUES (1, 10, 1, 7, 'CBC', NULL, 100, 'completed', '2026-01-01')"
        );
        $pdo->exec(
            "INSERT INTO prescriptions
                (visit_id, patient_id, record_id, doctor_id, medication_encrypted, dosage_encrypted,
                 instructions_encrypted, catalog_price_kes, status, created_at)
             VALUES (1, 10, 1, 7, 'cipher-med', 'cipher-dose', NULL, 100, 'dispensed', '2026-01-01')"
        );

        $report = (new ActivityReportRepository($pdo))->forUser(7, 'doctor');

        self::assertSame(3, $report['Consultations documented']);
        self::assertSame(2, $report['Distinct patients seen']);
        self::assertSame(1, $report['Lab requests ordered']);
        self::assertSame(1, $report['Prescriptions issued']);
        self::assertArrayNotHasKey('patient_name', $report);
        self::assertArrayNotHasKey('diagnosis', $report);
    }

    public function testDoctorReportAppliesExclusiveUtcRange(): void
    {
        $pdo = TestSchema::pdo();
        $pdo->exec("INSERT INTO medical_records (visit_id, patient_id, doctor_id, diagnosis_encrypted, created_at, updated_at) VALUES (1, 10, 7, 'a', '2026-09-16 10:00:00', '2026-09-16 10:00:00'), (2, 11, 7, 'b', '2026-09-17 10:00:00', '2026-09-17 10:00:00')");
        $report = (new ActivityReportRepository($pdo))->forUserBetween(7, 'doctor', '2026-09-17 00:00:00', '2026-09-18 00:00:00');
        self::assertSame(1, $report['Consultations documented']);
        self::assertSame(1, $report['Distinct patients seen']);
    }
}
