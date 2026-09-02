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
    private \DateTimeImmutable $now;
    private UserRepository $users;
    private UserService $userService;
    private SessionValidator $sessions;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-07-19 12:00:00', new \DateTimeZone('UTC'));
        $clock = new Clock(fn (): \DateTimeImmutable => $this->now);
        $this->users = new UserRepository(TestSchema::pdo(), $clock);
        $this->userService = new UserService($this->users, new PasswordPolicy());
        $this->sessions = new SessionValidator($this->users, $clock);
    }

    public function testAuthenticateSession_WithCurrentActiveAccount_ReturnsCanonicalUser(): void
    {
        $userId = $this->users->create(
            'Dora Doctor',
            'dora@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
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
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
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
        $created = $this->userService->createUser('Dora Doctor', 'dora@example.com', 'Old!Pass1234', 'doctor', false);
        $userId = (int) $created['user_id'];
        $preservedSession = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));

        self::assertTrue($this->userService->changePassword($userId, 'Old!Pass1234', 'New!Pass4567')['ok']);

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
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $preservedSession = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));
        $this->users->updatePassword($userId, password_hash('Reset!Pass456', PASSWORD_DEFAULT));

        self::assertNull(
            $this->sessions->authenticateSession($preservedSession),
            'A session created before a password reset must not retain access.'
        );
    }

    public function testAuthenticateSession_WithoutAuthVersion_RejectsSession(): void
    {
        $userId = $this->users->create(
            'Dora Doctor',
            'dora@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
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

    public function testCreateAuthenticatedSession_StoresEpochWithoutCredentialMaterial(): void
    {
        $userId = $this->users->create(
            'Epoch User',
            'session-epoch@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );

        $session = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));

        self::assertSame(1, $session['auth_version']);
        self::assertArrayNotHasKey('credential_fingerprint', $session);
        self::assertStringNotContainsString('Old!Pass1234', serialize($session));
    }

    public function testAuthenticateSession_AfterDeactivateReactivate_RejectsPreservedSession(): void
    {
        $userId = $this->users->create(
            'Dora Doctor',
            'cycle@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $preserved = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));

        $this->users->setStatus($userId, 'inactive');
        $this->users->setStatus($userId, 'active');

        self::assertNull($this->sessions->authenticateSession($preserved));
    }

    public function testAuthenticateSession_AfterRoleTransition_RejectsOldPrivilege(): void
    {
        $userId = $this->users->create(
            'Nora Nurse',
            'role@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'nurse',
            false
        );
        $preserved = $this->sessions->createAuthenticatedSession((array) $this->users->findById($userId));

        $this->users->setRole($userId, 'doctor');

        self::assertNull($this->sessions->authenticateSession($preserved));
    }

    public function testPendingLogin_WithCurrentAuthVersion_ReturnsAuthoritativeUser(): void
    {
        $userId = $this->users->create(
            'Dora Doctor',
            'pending@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $pending = $this->sessions->createPendingLogin((array) $this->users->findById($userId));

        $result = $this->sessions->validatePendingLogin($pending);

        self::assertSame('valid', $result['status']);
        self::assertSame($userId, $result['user']['user_id']);
    }

    public function testPendingLogin_AfterPasswordRoleOrStatusChange_IsRevoked(): void
    {
        foreach (['password', 'role', 'status-cycle'] as $change) {
            $email = $change . '@example.com';
            $userId = $this->users->create(
                'Pending Change',
                $email,
                password_hash('Old!Pass1234', PASSWORD_DEFAULT),
                'nurse',
                false
            );
            $pending = $this->sessions->createPendingLogin((array) $this->users->findById($userId));

            if ($change === 'password') {
                $this->users->updatePassword($userId, password_hash('New!Pass4567', PASSWORD_DEFAULT));
            } elseif ($change === 'role') {
                $this->users->setRole($userId, 'doctor');
            } else {
                $this->users->setStatus($userId, 'inactive');
                $this->users->setStatus($userId, 'active');
            }

            self::assertSame('revoked', $this->sessions->validatePendingLogin($pending)['status'], $change);
        }
    }

    public function testPendingLogin_WithExpiredOrMalformedStartedAt_FailsClosed(): void
    {
        $userId = $this->users->create(
            'Pending Age',
            'age@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $pending = $this->sessions->createPendingLogin((array) $this->users->findById($userId));

        $this->now = $this->now->add(new \DateInterval('PT11M'));
        self::assertSame('expired', $this->sessions->validatePendingLogin($pending)['status']);

        foreach ([null, '', 'not-a-time', -1, $this->now->getTimestamp() + 1] as $startedAt) {
            $malformed = $pending;
            $malformed['started_at'] = $startedAt;
            self::assertSame('malformed', $this->sessions->validatePendingLogin($malformed)['status']);
        }

        unset($pending['started_at']);
        self::assertSame('malformed', $this->sessions->validatePendingLogin($pending)['status']);
    }

    public function testPendingLogin_AtExactMaximumAge_IsExpired(): void
    {
        $userId = $this->users->create(
            'Pending Cutoff',
            'pending-cutoff@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $pending = $this->sessions->createPendingLogin((array) $this->users->findById($userId));
        $this->now = $this->now->add(new \DateInterval('PT10M'));

        self::assertSame('expired', $this->sessions->validatePendingLogin($pending)['status']);
    }

    public function testPendingLogin_AfterAccountLock_IsRevoked(): void
    {
        $userId = $this->users->create(
            'Locked Pending',
            'locked-pending@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $pending = $this->sessions->createPendingLogin((array) $this->users->findById($userId));
        $this->users->lockUntil($userId, $this->now->add(new \DateInterval('PT15M'))->format('Y-m-d H:i:s'));

        self::assertSame('revoked', $this->sessions->validatePendingLogin($pending)['status']);
    }

    public function testPendingLogin_WithNormalizedInvalidLockTimestamp_IsRevoked(): void
    {
        $userId = $this->users->create(
            'Malformed Lock',
            'pending-malformed-lock@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $pending = $this->sessions->createPendingLogin((array) $this->users->findById($userId));
        $this->users->lockUntil($userId, '2026-02-30 12:15:00');

        self::assertSame('revoked', $this->sessions->validatePendingLogin($pending)['status']);
    }

    public function testAuthenticatedTiming_MissingMalformedFutureOrExpiredTimestamp_FailsClosed(): void
    {
        $timing = $this->sessions->createLoginTimestamps();
        self::assertSame('valid', $this->sessions->validateSessionTiming($timing));

        foreach ([
            [],
            ['login_at' => 'bad', 'last_activity' => $this->now->getTimestamp()],
            ['login_at' => $this->now->getTimestamp(), 'last_activity' => null],
            ['login_at' => $this->now->getTimestamp() + 1, 'last_activity' => $this->now->getTimestamp()],
            ['login_at' => $this->now->getTimestamp(), 'last_activity' => $this->now->getTimestamp() - 1],
        ] as $malformed) {
            self::assertSame('malformed', $this->sessions->validateSessionTiming($malformed));
        }

        $this->now = $this->now->add(new \DateInterval('PT21M'));
        self::assertSame('expired', $this->sessions->validateSessionTiming($timing));
    }

    public function testAuthenticatedTiming_AtIdleOrAbsoluteCutoff_IsExpired(): void
    {
        $timing = $this->sessions->createLoginTimestamps();
        $this->now = $this->now->add(new \DateInterval('PT20M'));
        self::assertSame('expired', $this->sessions->validateSessionTiming($timing));

        $this->now = new \DateTimeImmutable('2026-07-19 12:00:00', new \DateTimeZone('UTC'));
        $timing = $this->sessions->createLoginTimestamps();
        $timing['last_activity'] = $this->now
            ->add(new \DateInterval('PT7H59M'))
            ->getTimestamp();
        $this->now = $this->now->add(new \DateInterval('PT8H'));

        self::assertSame('expired', $this->sessions->validateSessionTiming($timing));
    }
}
