<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Audit\ReadAudit;
use PHPUnit\Framework\TestCase;

final class ReadAuditTest extends TestCase
{
    public function testRecordsOnlyUniqueIdentifiersAndActorWithoutClinicalContents(): void
    {
        $events = [];
        $audit = new ReadAudit(static function (array $event) use (&$events): bool {
            $events[] = $event;
            return true;
        });
        $audit->records(['user_id' => 7, 'role' => 'nurse', 'email' => 'private'], 'nurse.dashboard', [4, 4, 9]);
        self::assertCount(2, $events);
        self::assertSame(['4', '9'], array_column($events, 'affected_record_id'));
        self::assertSame(7, $events[0]['user_id']);
        self::assertArrayNotHasKey('email', $events[0]);
        self::assertSame('PATIENT_VIEW', $events[0]['action']);
    }

    public function testAuditFailureStopsTheRead(): void
    {
        $audit = new ReadAudit(static fn (array $event): bool => false);
        $this->expectException(\RuntimeException::class);
        $audit->records(['user_id' => 7, 'role' => 'nurse'], 'nurse.dashboard', [4]);
    }

    public function testEmptyCollectionStillRecordsAccessWithoutInventingAnIdentifier(): void
    {
        $events = [];
        $audit = new ReadAudit(static function (array $event) use (&$events): bool {
            $events[] = $event;
            return true;
        });
        $audit->records(['user_id' => 8, 'role' => 'patient'], 'billing', [], 'BILLING_VIEWED');
        self::assertCount(1, $events);
        self::assertNull($events[0]['affected_record_id']);
        self::assertSame('BILLING_VIEWED', $events[0]['action']);
    }
}
