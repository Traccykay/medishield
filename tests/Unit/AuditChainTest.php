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
        $this->chain = AuditChain::fromHexKey(str_repeat('cd', 32), 'audit-primary-2026');
    }

    public function testHashIsDeterministicForSameInput(): void
    {
        $h1 = $this->chain->computeHash($this->entry, AuditChain::GENESIS);
        $h2 = $this->chain->computeHash($this->entry, AuditChain::GENESIS);
        self::assertSame($h1, $h2);
        self::assertNotSame('', $h1);
    }

    public function testVersionOneHistoricalVectorRemainsStable(): void
    {
        self::assertSame(
            'mqHUqIvLaz4//EAWXcT8iRCQUoZ3wEZnwYI09e+NYwk=',
            $this->chain->computeHash($this->entry, AuditChain::GENESIS, AuditChain::FORMAT_V1)
        );
    }

    public function testVersionTwoLengthPrefixPreventsDelimiterAmbiguity(): void
    {
        $left = $this->versionTwoEntry();
        $left['user_role'] = 'admin|USER_CREATED';
        $left['action'] = 'x';
        $right = $this->versionTwoEntry();
        $right['user_role'] = 'admin';
        $right['action'] = 'USER_CREATED|x';

        self::assertNotSame(
            $this->chain->computeHash($left, AuditChain::GENESIS, AuditChain::FORMAT_V2),
            $this->chain->computeHash($right, AuditChain::GENESIS, AuditChain::FORMAT_V2)
        );
    }

    public function testVersionTwoCanonicalVectorRemainsStable(): void
    {
        self::assertSame(
            'cb6391c098c4c70ab8d68e5e5b4b02fbc86cbce02a76c5e14815d3772c66acd6',
            $this->chain->computeHash(
                $this->versionTwoEntry(),
                AuditChain::GENESIS,
                AuditChain::FORMAT_V2
            )
        );
    }

    public function testVersionTwoBindsSequenceKeyNetworkAndAgent(): void
    {
        $entry = $this->versionTwoEntry();
        $base = $this->chain->computeHash($entry, AuditChain::GENESIS, AuditChain::FORMAT_V2);

        foreach (['seq', 'key_id', 'ip_address', 'user_agent'] as $field) {
            $changed = $entry;
            $changed[$field] = $field === 'seq' ? 12 : (string) $entry[$field] . '-changed';
            self::assertNotSame(
                $base,
                $this->chain->computeHash($changed, AuditChain::GENESIS, AuditChain::FORMAT_V2),
                $field . ' must be chained.'
            );
        }
    }

    public function testVersionTwoDistinguishesNullFromEmptyString(): void
    {
        $null = $this->versionTwoEntry();
        $null['affected_record_id'] = null;
        $empty = $null;
        $empty['affected_record_id'] = '';

        self::assertNotSame(
            $this->chain->computeHash($null, AuditChain::GENESIS, AuditChain::FORMAT_V2),
            $this->chain->computeHash($empty, AuditChain::GENESIS, AuditChain::FORMAT_V2)
        );
    }

    public function testShortRawKeyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        self::assertInstanceOf(
            AuditChain::class,
            new AuditChain(str_repeat('x', 31), 'audit-primary-2026')
        );
    }

    public function testShortHexKeyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        AuditChain::fromHexKey(str_repeat('ab', 31), 'audit-primary-2026');
    }

    public function testHeadMacChangesWhenCommittedTipChanges(): void
    {
        $head = [
            'last_seq' => 4,
            'last_log_id' => 8,
            'head_hash' => str_repeat('a', 64),
            'key_id' => 'audit-primary-2026',
            'format_version' => AuditChain::FORMAT_V2,
            'key_check' => $this->chain->keyCheck(),
            'updated_at' => '2026-01-01 12:00:00',
        ];
        $base = $this->chain->computeHeadMac($head);
        $head['last_seq'] = 3;

        self::assertNotSame($base, $this->chain->computeHeadMac($head));

        $head['last_seq'] = 4;
        $head['updated_at'] = '2026-01-01 12:00:01';
        self::assertNotSame($base, $this->chain->computeHeadMac($head));
    }

    public function testHeadMacAuthenticatesKeyCheck(): void
    {
        $head = [
            'last_seq' => 4,
            'last_log_id' => 8,
            'head_hash' => str_repeat('a', 64),
            'key_id' => 'audit-primary-2026',
            'format_version' => AuditChain::FORMAT_V2,
            'key_check' => $this->chain->keyCheck(),
            'updated_at' => '2026-01-01 12:00:00',
        ];
        $base = $this->chain->computeHeadMac($head);
        $head['key_check'] = str_repeat('f', 64);

        self::assertNotSame($base, $this->chain->computeHeadMac($head));
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
        $other = AuditChain::fromHexKey(str_repeat('ef', 32), 'audit-primary-2026');
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

    private function versionTwoEntry(): array
    {
        return [
            ...$this->entry,
            'seq' => 11,
            'event_id' => '00112233445566778899aabbccddeeff',
            'key_id' => 'audit-primary-2026',
            'format_version' => AuditChain::FORMAT_V2,
            'ip_address' => '203.0.113.10',
            'user_agent' => 'MediShield test|agent',
        ];
    }
}
