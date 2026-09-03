<?php

declare(strict_types=1);

namespace MediShield\Audit;

/**
 * Computes dashboard security counters from the already verified recent window.
 * Keeping this rule outside the route makes status/anomaly semantics testable.
 */
final class AuditDashboardSummary
{
    /**
     * @param list<array<string,mixed>> $rows
     * @return array{failed_events:int,anomalies:int}
     */
    public static function fromRows(array $rows): array
    {
        $failedEvents = 0;
        $anomalies = 0;
        foreach ($rows as $row) {
            if (($row['status'] ?? '') === 'FAILED') {
                $failedEvents++;
            }
            if (($row['anomaly_flag'] ?? 'NORMAL') !== 'NORMAL') {
                $anomalies++;
            }
        }

        return [
            'failed_events' => $failedEvents,
            'anomalies' => $anomalies,
        ];
    }
}
