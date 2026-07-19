<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\SessionValidator;
use MediShield\Auth\UserRepository;
use MediShield\Auth\UserService;
use MediShield\Security\PasswordPolicy;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for server-side validation of a preserved authenticated session.
 */
final class SessionValidatorTest extends TestCase
{
    private UserRepository $users;
    private UserService $userService;
    private SessionValidator $sessions;

    protected function setUp(): void
    {
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-07-19 12:00:00', new \DateTimeZone('UTC')));
        $this->users = new UserRepository(TestSchema::pdo(), $clock);
        $this->userService = new UserService($this->users, new PasswordPolicy());
        $this->sessions = new SessionValidator($this->users);
    }

    public function testAuthenticateSession_WithCurrentActiveAccount_ReturnsCanonicalUser(): void
    {
        $userId = $this->users->create(
            'Dora Doctor',
            'dora@example.com',
            password_hash('Old!Pass123', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $session = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));

        $authenticated = $this->sessions->authenticateSession($session);

        self::assertNotNull($authenticated);
        self::assertSame($userId, $authenticated['user_id']);
        self::assertSame('doctor', $authenticated['role']);
        self::assertFalse($authenticated['must_change']);
    }

    public function testAuthenticateSession_WithDeactivatedAccount_RejectsPreservedSession(): void
    {
        $userId = $this->users->create(
            'Dora Doctor',
            'dora@example.com',
            password_hash('Old!Pass123', PASSWORD_DEFAULT),
            'doctor'
        );
        $preservedSession = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));
        $this->users->setStatus($userId, 'inactive');

        self::assertNull(
            $this->sessions->authenticateSession($preservedSession),
            'A session created before deactivation must not retain access.'
        );
    }

    public function testAuthenticateSession_AfterPasswordChange_RejectsPreservedSession(): void
    {
        $created = $this->userService->createUser('Dora Doctor', 'dora@example.com', 'Old!Pass123', 'doctor', false);
        $userId = (int) $created['user_id'];
        $preservedSession = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));

        self::assertTrue($this->userService->changePassword($userId, 'Old!Pass123', 'New!Pass456')['ok']);

        self::assertNull(
            $this->sessions->authenticateSession($preservedSession),
            'A session created before a password change must not retain access.'
        );
    }

    public function testAuthenticateSession_AfterPasswordReset_RejectsPreservedSession(): void
    {
        $userId = $this->users->create(
            'Dora Doctor',
            'dora@example.com',
            password_hash('Old!Pass123', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $preservedSession = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));
        $this->users->activate($userId, password_hash('Reset!Pass456', PASSWORD_DEFAULT));

        self::assertNull(
            $this->sessions->authenticateSession($preservedSession),
            'A session created before a password reset must not retain access.'
        );
    }

    public function testAuthenticateSession_WithoutCredentialFingerprint_RejectsSession(): void
    {
        $userId = $this->users->create(
            'Dora Doctor',
            'dora@example.com',
            password_hash('Old!Pass123', PASSWORD_DEFAULT),
            'doctor'
        );

        self::assertNull($this->sessions->authenticateSession([
            'user_id' => $userId,
            'role' => 'doctor',
            'full_name' => 'Dora Doctor',
            'email' => 'dora@example.com',
            'must_change' => false,
        ]));
    }
}
