<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\AuthService;
use MediShield\Auth\UserRepository;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for the login + lockout policy (spec §9.1), exercising
 * AuthService against a real (SQLite) UserRepository with a fixed clock.
 */
final class AuthServiceTest extends TestCase
{
    private UserRepository $repo;
    private AuthService $auth;
    private Clock $clock;

    protected function setUp(): void
    {
        $this->clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $this->repo  = new UserRepository(TestSchema::pdo(), $this->clock);
        $this->auth  = new AuthService($this->repo, $this->clock); // defaults: 5 / 3 / 15min
    }

    /** Seed a user with a known password and return their id. */
    private function seedUser(string $email = 'doc@example.com', string $password = 'Str0ng!Pass1', string $status = 'active'): int
    {
        $id = $this->repo->create('Doc', $email, password_hash($password, PASSWORD_DEFAULT), 'doctor');
        if ($status !== 'active') {
            $this->repo->setStatus($id, $status);
        }
        return $id;
    }

    public function testSuccessfulLoginResetsFailedCount(): void
    {
        $id = $this->seedUser();
        $this->repo->incrementFailedLogin($id); // pretend one earlier failure

        $result = $this->auth->attemptLogin('doc@example.com', 'Str0ng!Pass1');

        self::assertSame('success', $result['status']);
        self::assertNotNull($result['user']);
        self::assertTrue($result['must_change']);
        self::assertSame(0, (int) $this->repo->findById($id)['failed_login_count']);
    }

    public function testUnknownEmailIsGenericInvalid(): void
    {
        $result = $this->auth->attemptLogin('ghost@example.com', 'whatever');
        self::assertSame('invalid', $result['status']);
        self::assertNull($result['user']);
    }

    public function testInactiveAccountCannotLogin(): void
    {
        $this->seedUser('inactive@example.com', 'Str0ng!Pass1', 'inactive');
        $result = $this->auth->attemptLogin('inactive@example.com', 'Str0ng!Pass1');
        self::assertSame('invalid', $result['status']);
    }

    public function testThreeFailuresFlagSuspicious(): void
    {
        $this->seedUser();
        $this->auth->attemptLogin('doc@example.com', 'wrong');
        $this->auth->attemptLogin('doc@example.com', 'wrong');
        $third = $this->auth->attemptLogin('doc@example.com', 'wrong');

        self::assertSame('invalid', $third['status']);
        self::assertSame('SUSPICIOUS', $third['anomaly']);
        self::assertSame(3, $third['failed_count']);
    }

    public function testFiveFailuresLockAccountHighRisk(): void
    {
        $id = $this->seedUser();
        for ($i = 0; $i < 4; $i++) {
            $this->auth->attemptLogin('doc@example.com', 'wrong');
        }
        $fifth = $this->auth->attemptLogin('doc@example.com', 'wrong');

        self::assertSame('locked', $fifth['status']);
        self::assertSame('HIGH_RISK', $fifth['anomaly']);
        // locked_until should be now + 15 minutes.
        self::assertSame('2026-01-01 12:15:00', $this->repo->findById($id)['locked_until']);
    }

    public function testLockedAccountIsRejectedEvenWithCorrectPassword(): void
    {
        $this->seedUser();
        for ($i = 0; $i < 5; $i++) {
            $this->auth->attemptLogin('doc@example.com', 'wrong');
        }
        // Correct password, but still inside the lock window (same fixed clock).
        $result = $this->auth->attemptLogin('doc@example.com', 'Str0ng!Pass1');
        self::assertSame('locked', $result['status']);
    }

    public function testLockExpiresAfterWindow(): void
    {
        // Use a movable clock so we can advance past the lock window.
        $now = new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC'));
        $movable = new Clock(function () use (&$now) { return $now; });
        $repo = new UserRepository(TestSchema::pdo(), $movable);
        $auth = new AuthService($repo, $movable);

        $repo->create('Doc', 'doc@example.com', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'doctor');
        for ($i = 0; $i < 5; $i++) {
            $auth->attemptLogin('doc@example.com', 'wrong');
        }
        self::assertSame('locked', $auth->attemptLogin('doc@example.com', 'Str0ng!Pass1')['status']);

        // Advance 16 minutes -> lock expired -> correct password now succeeds.
        $now = $now->add(new \DateInterval('PT16M'));
        self::assertSame('success', $auth->attemptLogin('doc@example.com', 'Str0ng!Pass1')['status']);
    }
}
