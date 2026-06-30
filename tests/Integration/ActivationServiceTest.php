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
    private ActivationService $activation;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-03-01 09:00:00', new \DateTimeZone('UTC'));
        $clock     = new Clock(fn (): \DateTimeImmutable => $this->now);
        $this->pdo = TestSchema::pdo();

        $this->users       = new UserRepository($this->pdo, $clock);
        $this->userService = new UserService($this->users, new PasswordPolicy());
        $repo              = new ActivationRepository($this->pdo, $clock);
        $this->activation  = new ActivationService($repo, $this->users, new PasswordPolicy(), $clock, 48);
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

    public function testIssuingNewTokenInvalidatesOldOne(): void
    {
        $userId = $this->makePending();
        $first  = $this->activation->issueFor($userId);
        $second = $this->activation->issueFor($userId);

        self::assertFalse($this->activation->validate($first)['ok'], 'Old token must be dead.');
        self::assertTrue($this->activation->validate($second)['ok']);
    }

    public function testUnknownTokenIsInvalid(): void
    {
        self::assertSame('invalid', $this->activation->validate('deadbeef')['reason']);
    }
}
