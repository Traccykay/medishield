<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Support\Clock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClockTest extends TestCase
{
    public function testParseDatabaseTimestamp_WithCanonicalUtcValue_ReturnsExactInstant(): void
    {
        $parsed = Clock::parseDatabaseTimestamp('2026-09-02 18:03:11');

        self::assertNotNull($parsed);
        self::assertSame('2026-09-02 18:03:11', $parsed->format(Clock::DATABASE_TIMESTAMP_FORMAT));
        self::assertSame('UTC', $parsed->getTimezone()->getName());
    }

    #[DataProvider('invalidTimestampProvider')]
    public function testParseDatabaseTimestamp_WithMalformedValue_ReturnsNull(mixed $value): void
    {
        self::assertNull(Clock::parseDatabaseTimestamp($value));
    }

    public static function invalidTimestampProvider(): array
    {
        return [
            'missing' => [null],
            'empty' => [''],
            'impossible date PHP would normalize' => ['2026-02-30 12:00:00'],
            'non-padded value' => ['2026-9-2 1:02:03'],
            'timezone suffix' => ['2026-09-02 18:03:11Z'],
            'integer' => [1788372191],
        ];
    }
}
