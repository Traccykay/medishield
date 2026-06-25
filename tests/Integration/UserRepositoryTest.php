<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\UserRepository;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for UserRepository against an in-memory SQLite database.
 * Verifies the actual SQL works (CRUD + lockout counters).
 */
final class UserRepositoryTest extends TestCase
{
    private UserRepository $repo;

    protected function setUp(): void
    {
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $this->repo = new UserRepository(TestSchema::pdo(), $clock);
    }

    public function testCreateAndFind(): void
    {
        $id = $this->repo->create('Jane Doe', 'jane@example.com', 'hash', 'doctor');
        self::assertGreaterThan(0, $id);

        $byEmail = $this->repo->findByEmail('jane@example.com');
        self::assertNotNull($byEmail);
        self::assertSame('Jane Doe', $byEmail['full_name']);
        self::assertSame('doctor', $byEmail['role']);
        self::assertSame('active', $byEmail['status']);
        self::assertSame(1, (int) $byEmail['must_change_password']);

        $byId = $this->repo->findById($id);
        self::assertNotNull($byId);
        self::assertSame('jane@example.com', $byId['email']);
    }

    public function testFindMissingReturnsNull(): void
    {
        self::assertNull($this->repo->findByEmail('nobody@example.com'));
        self::assertNull($this->repo->findById(999));
    }

    public function testEmailExists(): void
    {
        self::assertFalse($this->repo->emailExists('x@example.com'));
        $this->repo->create('X', 'x@example.com', 'hash', 'nurse');
        self::assertTrue($this->repo->emailExists('x@example.com'));
    }

    public function testIncrementAndResetFailedLogin(): void
    {
        $id = $this->repo->create('Lock Me', 'lock@example.com', 'hash', 'patient');

        self::assertSame(1, $this->repo->incrementFailedLogin($id));
        self::assertSame(2, $this->repo->incrementFailedLogin($id));

        $this->repo->resetFailedAndUnlock($id);
        self::assertSame(0, (int) $this->repo->findById($id)['failed_login_count']);
    }

    public function testLockUntilSetsTimestamp(): void
    {
        $id = $this->repo->create('Locked', 'locked@example.com', 'hash', 'patient');
        $this->repo->lockUntil($id, '2026-01-01 12:15:00');
        self::assertSame('2026-01-01 12:15:00', $this->repo->findById($id)['locked_until']);
    }

    public function testSetStatusAndListAll(): void
    {
        $id = $this->repo->create('A', 'a@example.com', 'hash', 'lab');
        $this->repo->create('B', 'b@example.com', 'hash', 'pharmacist');

        $this->repo->setStatus($id, 'inactive');
        self::assertSame('inactive', $this->repo->findById($id)['status']);

        self::assertCount(2, $this->repo->listAll());
    }
}
