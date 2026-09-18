<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use DateTimeImmutable;
use MediShield\Reporting\ReportPeriod;
use PHPUnit\Framework\TestCase;

final class ReportPeriodTest extends TestCase
{
    public function testResolvesPresetAndExclusiveEnd(): void
    {
        $period = ReportPeriod::resolve('week', '', '', new DateTimeImmutable('2026-09-17 15:00:00 UTC'));
        self::assertSame('2026-09-14 00:00:00', $period['start']);
        self::assertSame('2026-09-18 00:00:00', $period['end']);
    }

    public function testRejectsFutureCustomRange(): void
    {
        $period = ReportPeriod::resolve('custom', '2026-09-01', '2026-09-20', new DateTimeImmutable('2026-09-17 UTC'));
        self::assertSame('today', $period['preset']);
    }
}
