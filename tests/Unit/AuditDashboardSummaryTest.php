<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Audit\AuditDashboardSummary;
use MediShield\Audit\AuditVerificationEventPolicy;
use PHPUnit\Framework\TestCase;

final class AuditDashboardSummaryTest extends TestCase
{
    public function testEmptyRecentWindowHasZeroSecurityCounters(): void
    {
        self::assertSame(
            ['failed_events' => 0, 'anomalies' => 0],
            AuditDashboardSummary::fromRows([])
        );
    }

    public function testOperationalUnknownEvidenceDoesNotIncreaseSecurityCounters(): void
    {
        $missingAnchor = AuditVerificationEventPolicy::classify([
            'state' => 'UNKNOWN',
            'reason' => 'EXTERNAL_ANCHOR_MISSING',
        ]);

        $summary = AuditDashboardSummary::fromRows([$missingAnchor]);

        self::assertSame(['failed_events' => 0, 'anomalies' => 0], $summary);
    }

    public function testIntegrityFailureIncreasesFailedAndAnomalyCounters(): void
    {
        $integrityFailure = AuditVerificationEventPolicy::classify([
            'state' => 'FAIL',
            'reason' => 'ROW_HASH_INVALID',
        ]);

        $summary = AuditDashboardSummary::fromRows([$integrityFailure]);

        self::assertSame(['failed_events' => 1, 'anomalies' => 1], $summary);
    }
}
