<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Security\AttackPatternClassifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AttackPatternClassifierTest extends TestCase
{
    /** @return iterable<string,array{array<string,mixed>,?string}> */
    public static function payloadProvider(): iterable
    {
        yield 'sql tautology' => [[
            'email' => "admin@example.test' OR '1'='1' -- ",
        ], 'SQL_INJECTION_ATTEMPT'];
        yield 'sql union' => [['q' => 'x UNION SELECT password_hash FROM users'], 'SQL_INJECTION_ATTEMPT'];
        yield 'xss event handler' => [[
            'full_name' => '<img src=x onerror="alert(1)">',
        ], 'XSS_ATTEMPT'];
        yield 'xss script tag' => [['notes' => '<script>alert(1)</script>'], 'XSS_ATTEMPT'];
        yield 'normal clinical text' => [['notes' => 'Pain improved after 20 minutes.'], null];
        yield 'nested normal form' => [['medications' => ['Paracetamol', 'Amoxicillin']], null];
    }

    #[DataProvider('payloadProvider')]
    public function testClassifiesOnlyHighConfidenceAttackPatterns(array $payload, ?string $expected): void
    {
        self::assertSame($expected, AttackPatternClassifier::classify($payload));
    }
}
