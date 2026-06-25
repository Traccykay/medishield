<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\UserRepository;
use MediShield\Auth\UserService;
use MediShield\Security\PasswordPolicy;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for admin user creation / "registration" (spec §9.2).
 */
final class UserServiceTest extends TestCase
{
    private UserRepository $repo;
    private UserService $service;

    protected function setUp(): void
    {
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $this->repo = new UserRepository(TestSchema::pdo(), $clock);
        $this->service = new UserService($this->repo, new PasswordPolicy());
    }

    public function testCreatesAValidUser(): void
    {
        $result = $this->service->createUser('Nora Nurse', 'nora@example.com', 'Str0ng!Pass1', 'nurse');

        self::assertTrue($result['ok']);
        self::assertSame([], $result['errors']);
        self::assertIsInt($result['user_id']);

        $row = $this->repo->findByEmail('nora@example.com');
        self::assertNotNull($row);
        self::assertSame('nurse', $row['role']);
        self::assertSame(1, (int) $row['must_change_password']);
        // Stored value is a hash that verifies, not the plaintext.
        self::assertNotSame('Str0ng!Pass1', $row['password_hash']);
        self::assertTrue(password_verify('Str0ng!Pass1', $row['password_hash']));
    }

    public function testRejectsDuplicateEmail(): void
    {
        $this->service->createUser('First', 'dupe@example.com', 'Str0ng!Pass1', 'doctor');
        $result = $this->service->createUser('Second', 'dupe@example.com', 'Str0ng!Pass1', 'nurse');

        self::assertFalse($result['ok']);
        self::assertContains('An account with this email already exists.', $result['errors']);
    }

    public function testRejectsWeakPassword(): void
    {
        $result = $this->service->createUser('Weak', 'weak@example.com', 'weak', 'doctor');
        self::assertFalse($result['ok']);
        self::assertNotEmpty($result['errors']);
        self::assertNull($result['user_id']);
    }

    public function testRejectsInvalidRole(): void
    {
        $result = $this->service->createUser('Bad Role', 'badrole@example.com', 'Str0ng!Pass1', 'superuser');
        self::assertFalse($result['ok']);
        self::assertContains('A valid role must be selected.', $result['errors']);
    }

    public function testRejectsInvalidEmail(): void
    {
        $result = $this->service->createUser('Bad Email', 'not-an-email', 'Str0ng!Pass1', 'doctor');
        self::assertFalse($result['ok']);
        self::assertContains('A valid email address is required.', $result['errors']);
    }

    public function testRejectsEmptyFullName(): void
    {
        $result = $this->service->createUser('   ', 'blank@example.com', 'Str0ng!Pass1', 'doctor');
        self::assertFalse($result['ok']);
        self::assertContains('Full name is required.', $result['errors']);
    }
}
