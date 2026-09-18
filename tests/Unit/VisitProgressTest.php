<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Visit\VisitProgress;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class VisitProgressTest extends TestCase
{
    #[DataProvider('statuses')]
    public function testStagesMarkExactlyOneCurrentStep(string $status, string $current): void
    {
        $stages = VisitProgress::stages($status);
        $currentStages = array_values(array_filter($stages, static fn (array $stage): bool => $stage['state'] === 'current'));

        self::assertCount(1, $currentStages);
        self::assertSame($current, $currentStages[0]['key']);
    }

    public static function statuses(): iterable
    {
        yield ['triage', 'triage'];
        yield ['with_nurse', 'triage'];
        yield ['with_doctor', 'doctor'];
        yield ['lab', 'lab'];
        yield ['pharmacy', 'pharmacy'];
        yield ['completed', 'completed'];
    }

    public function testUnknownStatusFailsClosedToReception(): void
    {
        $stages = VisitProgress::stages('unexpected');
        self::assertSame('current', $stages[0]['state']);
        self::assertSame('upcoming', $stages[1]['state']);
    }
}
