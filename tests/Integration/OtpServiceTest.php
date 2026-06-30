<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\OtpRepository;
use MediShield\Auth\OtpService;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for the login second factor (OTP). Exercises OtpService on top
 * of the real OtpRepository SQL against in-memory SQLite.
 */
final class OtpServiceTest extends TestCase
{
    private \PDO $pdo;
    private \DateTimeImmutable $now;
    private OtpService $otp;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-03-01 09:00:00', new \DateTimeZone('UTC'));
        $clock     = new Clock(fn (): \DateTimeImmutable => $this->now);
        $this->pdo = TestSchema::pdo();
        $repo      = new OtpRepository($this->pdo, $clock);
        // length 6, ttl 10 min, max 3 attempts (small for testing).
        $this->otp = new OtpService($repo, $clock, 6, 10, 3);
    }

    public function testIssuedCodeVerifiesOnce(): void
    {
        $code = $this->otp->issue(42);

        self::assertSame(6, strlen($code));
        self::assertSame('ok', $this->otp->verify(42, $code));
        // A consumed code cannot be replayed.
        self::assertSame('none', $this->otp->verify(42, $code));
    }

    public function testWrongCodeIsInvalidThenLocksOutAfterMaxAttempts(): void
    {
        $this->otp->issue(7);

        self::assertSame('invalid', $this->otp->verify(7, 'WRONG1'));
        self::assertSame('invalid', $this->otp->verify(7, 'WRONG2'));
        // 3rd wrong attempt hits the max (3) => the code dies.
        self::assertSame('too_many', $this->otp->verify(7, 'WRONG3'));
        // Even the correct code is now refused — user must restart login.
        self::assertSame('too_many', $this->otp->verify(7, 'WRONG4'));
    }

    public function testCodeExpires(): void
    {
        $code = $this->otp->issue(99);

        // Jump 11 minutes (ttl is 10).
        $this->now = $this->now->add(new \DateInterval('PT11M'));

        self::assertSame('expired', $this->otp->verify(99, $code));
    }

    public function testIssuingNewCodeInvalidatesTheOldOne(): void
    {
        $first = $this->otp->issue(5);
        $second = $this->otp->issue(5); // supersedes the first

        // The old code value is now refused (checked against the current code).
        self::assertSame('invalid', $this->otp->verify(5, $first), 'Old code must be dead.');
        self::assertSame('ok', $this->otp->verify(5, $second));
    }

    public function testVerifyWithNoIssuedCodeReturnsNone(): void
    {
        self::assertSame('none', $this->otp->verify(1, 'ABCDEF'));
    }

    public function testCodesAreStoredHashedNotPlaintext(): void
    {
        $code = $this->otp->issue(3);

        $stored = $this->pdo->query('SELECT code_hash FROM otp_codes')->fetchColumn();
        self::assertNotSame($code, $stored, 'The plaintext code must never be stored.');
        self::assertTrue(password_verify($code, (string) $stored));
    }
}
