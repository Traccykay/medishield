<?php

declare(strict_types=1);

namespace MediShield\Reporting;

use DateTimeImmutable;
use DateTimeZone;

/** Validates report presets and returns an exclusive UTC date range. */
final class ReportPeriod
{
    /** @return array{preset:string,start:string,end:string,label:string} */
    public static function resolve(string $preset, string $from, string $to, DateTimeImmutable $today): array
    {
        $utc = new DateTimeZone('UTC');
        $today = $today->setTimezone($utc)->setTime(0, 0);
        if ($preset === 'custom') {
            $start = DateTimeImmutable::createFromFormat('!Y-m-d', $from, $utc);
            $last = DateTimeImmutable::createFromFormat('!Y-m-d', $to, $utc);
            if ($start !== false && $last !== false && $start <= $last && $last <= $today) {
                return ['preset' => 'custom', 'start' => $start->format('Y-m-d H:i:s'), 'end' => $last->modify('+1 day')->format('Y-m-d H:i:s'), 'label' => $from . ' to ' . $to];
            }
        }
        [$key, $start, $label] = match ($preset) {
            'week' => ['week', $today->modify('monday this week'), 'This week'],
            'month' => ['month', $today->modify('first day of this month'), 'This month'],
            default => ['today', $today, 'Today'],
        };
        return ['preset' => $key, 'start' => $start->format('Y-m-d H:i:s'), 'end' => $today->modify('+1 day')->format('Y-m-d H:i:s'), 'label' => $label];
    }
}
