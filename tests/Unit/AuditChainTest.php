<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Security\AuditChain;
use PHPUnit\Framework\TestCase;

/** Tests for the tamper-evident audit hash chain (spec §9.8). */
final class AuditChainTest extends TestCase
{
    private AuditChain $chain;

    /** A representative audit entry. */
    private array $entry = [
        'user_id'            => 7,
        'user_role'          => 'admin',
        'action'             => 'USER_CREATED',
        'module'             => 'User Management',
        'affected_record_id' => 42,
        'status'             => 'SUCCESS',
        'anomaly_flag'       => 'NORMAL',
        'created_at'         => '2026-01-01 12:00:00',
    ];

    protected function setUp(): void
    {
        $this->chain = AuditChain::fromHexKey(str_repeat('cd', 32));
    }

    public function testHashIsDeterministicForSameInput(): void
    {
        $h1 = $this->chain->computeHash($this->entry, AuditChain::GENESIS);
        $h2 = $this->chain->computeHash($this->entry, AuditChain::GENESIS);
        self::assertSame($h1, $h2);
        self::assertNotSame('', $h1);
    }

    public function testChangingAnyFieldChangesTheHash(): void
    {
        $base = $this->chain->computeHash($this->entry, AuditChain::GENESIS);

        $modified = $this->entry;
        $modified['action'] = 'USER_UPDATED';
        self::assertNotSame($base, $this->chain->computeHash($modified, AuditChain::GENESIS));
    }

    public function testDifferentPreviousHashChangesTheHash(): void
    {
        $a = $this->chain->computeHash($this->entry, AuditChain::GENESIS);
        $b = $this->chain->computeHash($this->entry, 'some-other-previous-hash');
        self::assertNotSame($a, $b);
    }

    public function testKeyMattersHmacNotPlainHash(): void
    {
        $other = AuditChain::fromHexKey(str_repeat('ef', 32));
        self::assertNotSame(
            $this->chain->computeHash($this->entry, AuditChain::GENESIS),
            $other->computeHash($this->entry, AuditChain::GENESIS)
        );
    }

    public function testNullIdsAreHandled(): void
    {
        $entry = $this->entry;
        $entry['user_id'] = null;
        $entry['affected_record_id'] = null;
        // Should not throw and should produce a stable hash.
        $h = $this->chain->computeHash($entry, AuditChain::GENESIS);
        self::assertSame($h, $this->chain->computeHash($entry, AuditChain::GENESIS));
    }

    public function testTwoLinkVerificationDetectsTampering(): void
    {
        // Build a 2-row chain.
        $row1 = $this->chain->computeHash($this->entry, AuditChain::GENESIS);

        $entry2 = $this->entry;
        $entry2['action'] = 'AUDIT_LOGS_VIEWED';
        $row2 = $this->chain->computeHash($entry2, $row1);

        // Re-verify with the original row1 -> row2 matches.
        self::assertSame($row2, $this->chain->computeHash($entry2, $row1));

        // If row1 were tampered, its recomputed hash differs, so row2's stored
        // previous_hash linkage would no longer recompute to row2.
        $tamperedEntry1 = $this->entry;
        $tamperedEntry1['status'] = 'FAILED';
        $tamperedRow1 = $this->chain->computeHash($tamperedEntry1, AuditChain::GENESIS);
        self::assertNotSame($row2, $this->chain->computeHash($entry2, $tamperedRow1));
    }
}
