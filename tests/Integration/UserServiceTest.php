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

    public function testChangePasswordSucceedsAndClearsMustChange(): void
    {
        $created = $this->service->createUser('Dora Doctor', 'dora@example.com', 'Old!Pass123', 'doctor');
        $userId  = (int) $created['user_id'];

        $result = $this->service->changePassword($userId, 'Old!Pass123', 'New!Pass456');

        self::assertTrue($result['ok']);
        self::assertSame([], $result['errors']);

        $row = $this->repo->findById($userId);
        self::assertSame(0, (int) $row['must_change_password']);
        self::assertTrue(password_verify('New!Pass456', $row['password_hash']));
        self::assertFalse(password_verify('Old!Pass123', $row['password_hash']));
    }

    public function testChangePasswordRejectsWrongCurrentPassword(): void
    {
        $created = $this->service->createUser('Dora Doctor', 'dora2@example.com', 'Old!Pass123', 'doctor');
        $userId  = (int) $created['user_id'];

        $result = $this->service->changePassword($userId, 'WrongCurrent1!', 'New!Pass456');

        self::assertFalse($result['ok']);
        self::assertContains('Your current password is incorrect.', $result['errors']);
        // Password must be unchanged.
        $row = $this->repo->findById($userId);
        self::assertTrue(password_verify('Old!Pass123', $row['password_hash']));
    }

    public function testChangePasswordRejectsSameAsCurrent(): void
    {
        $created = $this->service->createUser('Dora Doctor', 'dora3@example.com', 'Old!Pass123', 'doctor');
        $userId  = (int) $created['user_id'];

        $result = $this->service->changePassword($userId, 'Old!Pass123', 'Old!Pass123');

        self::assertFalse($result['ok']);
        self::assertContains('The new password must be different from the current password.', $result['errors']);
    }

    public function testChangePasswordRejectsWeakNewPassword(): void
    {
        $created = $this->service->createUser('Dora Doctor', 'dora4@example.com', 'Old!Pass123', 'doctor');
        $userId  = (int) $created['user_id'];

        $result = $this->service->changePassword($userId, 'Old!Pass123', 'weak');

        self::assertFalse($result['ok']);
        self::assertNotEmpty($result['errors']);
        // Password must be unchanged.
        $row = $this->repo->findById($userId);
        self::assertTrue(password_verify('Old!Pass123', $row['password_hash']));
    }

    public function testCreatePendingUserStartsInactiveWithNoUsablePassword(): void
    {
        $result = $this->service->createPendingUser('Pat Pending', 'pat@example.com', 'doctor');

        self::assertTrue($result['ok']);
        self::assertSame([], $result['errors']);
        self::assertIsInt($result['user_id']);

        $row = $this->repo->findByEmail('pat@example.com');
        self::assertNotNull($row);
        self::assertSame('inactive', $row['status']);
        self::assertSame(0, (int) $row['must_change_password']);
        // The sentinel must never be a hash that any password verifies against.
        self::assertSame(UserService::PENDING_PASSWORD_SENTINEL, $row['password_hash']);
        self::assertFalse(password_verify('anything', (string) $row['password_hash']));
    }

    public function testCreatePendingUserRejectsDuplicateEmail(): void
    {
        $this->service->createPendingUser('First', 'dupe-pending@example.com', 'doctor');
        $result = $this->service->createPendingUser('Second', 'dupe-pending@example.com', 'nurse');

        self::assertFalse($result['ok']);
        self::assertContains('An account with this email already exists.', $result['errors']);
        self::assertNull($result['user_id']);
    }

    public function testCreatePendingUserRejectsInvalidRoleAndEmail(): void
    {
        $badRole = $this->service->createPendingUser('Bad Role', 'okpending@example.com', 'superuser');
        self::assertFalse($badRole['ok']);
        self::assertContains('A valid role must be selected.', $badRole['errors']);

        $badEmail = $this->service->createPendingUser('Bad Email', 'not-an-email', 'doctor');
        self::assertFalse($badEmail['ok']);
        self::assertContains('A valid email address is required.', $badEmail['errors']);
    }
}
