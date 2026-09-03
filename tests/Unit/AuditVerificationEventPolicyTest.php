<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Audit\AuditVerificationEventPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AuditVerificationEventPolicyTest extends TestCase
{
    public function testVerifiedChainIsSuccessfulNormalEvidence(): void
    {
        $classification = AuditVerificationEventPolicy::classify([
            'state' => 'PASS',
            'reason' => 'ANCHORED_CHAIN_VALID',
        ]);

        self::assertSame('SUCCESS', $classification['status']);
        self::assertSame('NORMAL', $classification['anomaly_flag']);
        self::assertTrue($classification['should_record']);
    }

    #[DataProvider('operationalUnknownReasons')]
    public function testOperationalUnknownIsSuccessfulNormalEvidence(
        string $reason,
        bool $shouldRecord
    ): void {
        $classification = AuditVerificationEventPolicy::classify([
            'state' => 'UNKNOWN',
            'reason' => $reason,
        ]);

        self::assertSame('SUCCESS', $classification['status']);
        self::assertSame('NORMAL', $classification['anomaly_flag']);
        self::assertSame($shouldRecord, $classification['should_record']);
    }

    public static function operationalUnknownReasons(): array
    {
        return [
            'missing external anchor' => ['EXTERNAL_ANCHOR_MISSING', true],
            'valid unanchored database suffix' => ['UNANCHORED_DATABASE_SUFFIX', false],
        ];
    }

    public function testPositiveIntegrityFailureIsFailedHighRiskEvidence(): void
    {
        $classification = AuditVerificationEventPolicy::classify([
            'state' => 'FAIL',
            'reason' => 'ROW_HASH_INVALID',
        ]);

        self::assertSame('FAILED', $classification['status']);
        self::assertSame('HIGH_RISK', $classification['anomaly_flag']);
        self::assertTrue($classification['should_record']);
    }

    #[DataProvider('verificationErrorReasons')]
    public function testIndeterminateVerificationErrorIsFailedSuspiciousEvidence(string $reason): void
    {
        $classification = AuditVerificationEventPolicy::classify([
            'state' => 'UNKNOWN',
            'reason' => $reason,
        ]);

        self::assertSame('FAILED', $classification['status']);
        self::assertSame('SUSPICIOUS', $classification['anomaly_flag']);
        self::assertTrue($classification['should_record']);
    }

    public static function verificationErrorReasons(): array
    {
        return [
            'database verification error' => ['VERIFICATION_ERROR'],
            'snapshot unavailable' => ['CONSISTENT_SNAPSHOT_UNAVAILABLE'],
            'anchor read error' => ['ANCHOR_READ_ERROR'],
            'anchor key mismatch' => ['ANCHOR_KEY_MISMATCH'],
        ];
    }
}
