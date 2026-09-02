<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\ActivationRepository;
use MediShield\Auth\ActivationService;
use MediShield\Auth\UserRepository;
use MediShield\Auth\UserService;
use MediShield\Security\PasswordPolicy;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for the account-activation-link flow: a pending (inactive,
 * passwordless) account is activated when the user follows an emailed token link
 * and sets their own password.
 */
final class ActivationServiceTest extends TestCase
{
    private \PDO $pdo;
    private \DateTimeImmutable $now;
    private UserRepository $users;
    private UserService $userService;
    private ActivationRepository $repository;
    private ActivationService $activation;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-03-01 09:00:00', new \DateTimeZone('UTC'));
        $clock     = new Clock(fn (): \DateTimeImmutable => $this->now);
        $this->pdo = TestSchema::pdo();

        $this->users       = new UserRepository($this->pdo, $clock);
        $this->userService = new UserService($this->users, new PasswordPolicy());
        $this->repository  = new ActivationRepository($this->pdo, $clock);
        $this->activation  = new ActivationService($this->repository, $this->users, new PasswordPolicy(), $clock, 48);
    }

    /** Helper: create a pending user and return its id. */
    private function makePending(string $email = 'pending@example.com'): int
    {
        $res = $this->userService->createPendingUser('Pending Person', $email, 'doctor');
        return (int) $res['user_id'];
    }

    public function testIssueStoresHashNotPlaintextToken(): void
    {
        $userId = $this->makePending();
        $token  = $this->activation->issueFor($userId);

        $stored = $this->pdo->query('SELECT token_hash FROM account_activations')->fetchColumn();
        self::assertNotSame($token, $stored, 'Plaintext token must never be stored.');
        self::assertSame(hash('sha256', $token), $stored);
    }

    public function testValidateAcceptsAFreshToken(): void
    {
        $userId = $this->makePending();
        $token  = $this->activation->issueFor($userId);

        $result = $this->activation->validate($token);
        self::assertTrue($result['ok']);
        self::assertSame($userId, $result['user_id']);
    }

    public function testActivateSetsPasswordAndActivatesAccount(): void
    {
        $userId = $this->makePending();
        $token  = $this->activation->issueFor($userId);

        $result = $this->activation->activate($token, 'Str0ng!Pass1', 'Str0ng!Pass1');

        self::assertTrue($result['ok']);
        self::assertSame($userId, $result['user_id']);

        $row = $this->users->findById($userId);
        self::assertSame('active', $row['status']);
        self::assertSame(0, (int) $row['must_change_password']);
        self::assertTrue(password_verify('Str0ng!Pass1', (string) $row['password_hash']));
    }

    public function testActiveAccountResetConsumesLinkAndAdvancesAuthVersion(): void
    {
        $userId = $this->users->create(
            'Reset Person',
            'reset@example.com',
            password_hash('Old!Pass1234', PASSWORD_DEFAULT),
            'doctor',
            false
        );
        $token = $this->activation->issueFor($userId);

        $result = $this->activation->activate($token, 'New!Pass4567', 'New!Pass4567');

        self::assertTrue($result['ok']);
        $row = $this->users->findById($userId);
        self::assertTrue(password_verify('New!Pass4567', (string) $row['password_hash']));
        self::assertFalse(password_verify('Old!Pass1234', (string) $row['password_hash']));
        self::assertSame(2, (int) $row['auth_version']);
        self::assertFalse($this->activation->validate($token)['ok']);
    }

    public function testActivationLinkIsSingleUse(): void
    {
        $userId = $this->makePending();
        $token  = $this->activation->issueFor($userId);

        self::assertTrue($this->activation->activate($token, 'Str0ng!Pass1', 'Str0ng!Pass1')['ok']);

        // Re-using the same link must fail.
        $second = $this->activation->activate($token, 'An0ther!Pass2', 'An0ther!Pass2');
        self::assertFalse($second['ok']);
        // And the token no longer validates.
        self::assertFalse($this->activation->validate($token)['ok']);
    }

    public function testConsumeIsConditionalSoOnlyOneRedeemerCanClaimTheToken(): void
    {
        $userId = $this->makePending();
        $this->activation->issueFor($userId);
        $activationId = (int) $this->pdo->query(
            'SELECT activation_id FROM account_activations'
        )->fetchColumn();

        self::assertTrue($this->repository->markUsed($activationId));
        self::assertFalse($this->repository->markUsed($activationId));
    }

    public function testActivateRejectsMismatchedConfirmation(): void
    {
        $userId = $this->makePending();
        $token  = $this->activation->issueFor($userId);

        $result = $this->activation->activate($token, 'Str0ng!Pass1', 'Different!Pass2');
        self::assertFalse($result['ok']);
        self::assertContains('The two passwords do not match.', $result['errors']);

        // Account must remain inactive when activation fails.
        $row = $this->users->findById($userId);
        self::assertSame('inactive', $row['status']);
    }

    public function testActivateRejectsWeakPassword(): void
    {
        $userId = $this->makePending();
        $token  = $this->activation->issueFor($userId);

        $result = $this->activation->activate($token, 'weak', 'weak');
        self::assertFalse($result['ok']);
        self::assertNotEmpty($result['errors']);

        $row = $this->users->findById($userId);
        self::assertSame('inactive', $row['status']);
    }

    public function testExpiredTokenIsRejected(): void
    {
        $userId = $this->makePending();
        $token  = $this->activation->issueFor($userId);

        // Jump 49 hours (ttl is 48).
        $this->now = $this->now->add(new \DateInterval('PT49H'));

        self::assertSame('expired', $this->activation->validate($token)['reason']);
        $result = $this->activation->activate($token, 'Str0ng!Pass1', 'Str0ng!Pass1');
        self::assertFalse($result['ok']);
    }

    public function testTokenExpiresAtTheExactCutoff(): void
    {
        $userId = $this->makePending('cutoff@example.com');
        $token = $this->activation->issueFor($userId);
        $this->now = $this->now->add(new \DateInterval('PT48H'));

        self::assertSame('expired', $this->activation->validate($token)['reason']);
        self::assertFalse($this->activation->activate($token, 'Strong!Pass12', 'Strong!Pass12')['ok']);
    }

    public function testMalformedExpiryFailsClosed(): void
    {
        $userId = $this->makePending('malformed-expiry@example.com');
        $token = $this->activation->issueFor($userId);
        $this->pdo->prepare(
            'UPDATE account_activations
                SET expires_at = :expires_at
              WHERE user_id = :user_id'
        )->execute([
            ':expires_at' => '2026-02-30 09:00:00',
            ':user_id' => $userId,
        ]);

        self::assertSame('expired', $this->activation->validate($token)['reason']);
        self::assertFalse($this->activation->activate($token, 'Strong!Pass12', 'Strong!Pass12')['ok']);
    }

    public function testIssuingNewTokenInvalidatesOldOne(): void
    {
        $userId = $this->makePending();
        $first  = $this->activation->issueFor($userId);
        $second = $this->activation->issueFor($userId);

        self::assertFalse($this->activation->validate($first)['ok'], 'Old token must be dead.');
        self::assertTrue($this->activation->validate($second)['ok']);
    }

    public function testDeactivation_InvalidatesOutstandingActivationLinkAndPreservesInactiveStatus(): void
    {
        $userId = $this->makePending('deactivated@example.com');
        $token = $this->activation->issueFor($userId);

        $this->users->setStatus($userId, 'inactive');

        self::assertFalse(
            $this->activation->validate($token)['ok'],
            'An administrator deactivation must revoke an unused activation link.'
        );
        self::assertFalse(
            $this->users->activatePendingAccount($userId, password_hash('Str0ng!Pass1', PASSWORD_DEFAULT)),
            'A token already read by a concurrent request must not reactivate a deactivated pending account.'
        );
        self::assertFalse($this->activation->activate($token, 'Str0ng!Pass1', 'Str0ng!Pass1')['ok']);
        self::assertSame('inactive', $this->users->findById($userId)['status']);
    }

    public function testUnknownTokenIsInvalid(): void
    {
        self::assertSame('invalid', $this->activation->validate('deadbeef')['reason']);
    }

    public function testActivationRollsBackPasswordAndTokenWhenOtpInvalidationFails(): void
    {
        $userId = $this->makePending('rollback@example.com');
        $token = $this->activation->issueFor($userId);
        $this->pdo->prepare(
            'INSERT INTO otp_codes
                (user_id, code_hash, attempts, expires_at, used_at, created_at)
             VALUES (:user_id, :code_hash, 0, :expires_at, NULL, :created_at)'
        )->execute([
            ':user_id' => $userId,
            ':code_hash' => password_hash('ABC234', PASSWORD_DEFAULT),
            ':expires_at' => '2026-03-01 09:10:00',
            ':created_at' => '2026-03-01 09:00:00',
        ]);
        $this->pdo->exec(
            "CREATE TRIGGER fail_otp_invalidation
             BEFORE UPDATE OF used_at ON otp_codes
             BEGIN
                 SELECT RAISE(ABORT, 'forced otp invalidation failure');
             END"
        );

        try {
            $this->activation->activate($token, 'Strong!Pass12', 'Strong!Pass12');
            self::fail('Activation must surface a transactional OTP invalidation failure.');
        } catch (\PDOException) {
        }

        $user = $this->users->findById($userId);
        self::assertSame('inactive', $user['status']);
        self::assertSame(UserService::PENDING_PASSWORD_SENTINEL, $user['password_hash']);
        self::assertTrue($this->activation->validate($token)['ok']);
    }
}
