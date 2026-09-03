<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Audit\AuditRetentionPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AuditRetentionPolicyTest extends TestCase
{
    public function testFromArguments_ValidOverrideAndBatch_ReturnsPolicy(): void
    {
        $policy = AuditRetentionPolicy::fromArguments(
            ['purge-audit-pii.php', '--days', '45', '--batch-size=100', '--dry-run'],
            [
                'pii_retention_days' => 90,
                'minimum_pii_retention_days' => 30,
                'retention_batch_size' => 250,
            ]
        );

        self::assertSame(45, $policy->retentionDays);
        self::assertSame(100, $policy->batchSize);
        self::assertTrue($policy->dryRun);
    }

    #[DataProvider('invalidArguments')]
    public function testFromArguments_InvalidOrUnsafeValue_Throws(array $arguments): void
    {
        $this->expectException(\InvalidArgumentException::class);
        AuditRetentionPolicy::fromArguments(
            ['purge-audit-pii.php', ...$arguments],
            [
                'pii_retention_days' => 90,
                'minimum_pii_retention_days' => 30,
                'retention_batch_size' => 250,
            ]
        );
    }

    public static function invalidArguments(): iterable
    {
        yield 'unknown option' => [['--unknown']];
        yield 'missing days' => [['--days']];
        yield 'non integer' => [['--days', 'thirty']];
        yield 'below floor' => [['--days=29']];
        yield 'duplicate days' => [['--days=45', '--days', '60']];
        yield 'zero batch' => [['--batch-size=0']];
        yield 'oversized batch' => [['--batch-size=1001']];
    }
}
