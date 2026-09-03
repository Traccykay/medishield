<?php

declare(strict_types=1);

namespace MediShield\Audit;

/**
 * Maps integrity outcomes to the audit vocabulary without treating an expected
 * anchor-freshness limitation as a security attack. A suffix assessment is not
 * recorded because the resulting row would immediately extend that same suffix.
 */
final class AuditVerificationEventPolicy
{
    private const OPERATIONAL_UNKNOWN_REASONS = [
        'EXTERNAL_ANCHOR_MISSING',
        'UNANCHORED_DATABASE_SUFFIX',
    ];

    /**
     * @param array<string,mixed> $verification
     * @return array{status:string,anomaly_flag:string,should_record:bool}
     */
    public static function classify(array $verification): array
    {
        $state = (string) ($verification['state'] ?? 'UNKNOWN');
        $reason = (string) ($verification['reason'] ?? 'VERIFICATION_ERROR');

        if ($state === 'PASS') {
            return self::result('SUCCESS', 'NORMAL');
        }
        if ($state === 'FAIL') {
            return self::result('FAILED', 'HIGH_RISK');
        }
        if (in_array($reason, self::OPERATIONAL_UNKNOWN_REASONS, true)) {
            return self::result(
                'SUCCESS',
                'NORMAL',
                $reason !== 'UNANCHORED_DATABASE_SUFFIX'
            );
        }

        return self::result('FAILED', 'SUSPICIOUS');
    }

    /**
     * @return array{status:string,anomaly_flag:string,should_record:bool}
     */
    private static function result(
        string $status,
        string $anomalyFlag,
        bool $shouldRecord = true
    ): array {
        return [
            'status' => $status,
            'anomaly_flag' => $anomalyFlag,
            'should_record' => $shouldRecord,
        ];
    }
}
