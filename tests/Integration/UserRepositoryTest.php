<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\UserRepository;
use MediShield\Auth\UserService;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for UserRepository against an in-memory SQLite database.
 * Verifies the actual SQL works (CRUD + lockout counters).
 */
final class UserRepositoryTest extends TestCase
{
    private \PDO $pdo;
    private UserRepository $repo;

    protected function setUp(): void
    {
        $clock = new Clock(static fn () => new \DateTimeImmutable('2026-01-01 12:00:00', new \DateTimeZone('UTC')));
        $this->pdo = TestSchema::pdo();
        $this->repo = new UserRepository($this->pdo, $clock);
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
        self::assertSame(1, (int) $byEmail['auth_version']);

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

    public function testPasswordChangeIncrementsAuthVersionAndInvalidatesOutstandingOtp(): void
    {
        $id = $this->repo->create('Credential Epoch', 'epoch@example.com', 'old-hash', 'doctor');
        $this->insertOtp($id);

        $this->repo->updatePassword($id, 'new-hash');

        self::assertSame(2, (int) $this->repo->findById($id)['auth_version']);
        self::assertNotNull($this->pdo->query('SELECT used_at FROM otp_codes')->fetchColumn());
    }

    public function testDeactivateReactivateNeverRevivesOldAuthVersionAndInvalidatesOtp(): void
    {
        $id = $this->repo->create('Status Epoch', 'status@example.com', 'hash', 'nurse');
        $this->insertOtp($id);

        $this->repo->setStatus($id, 'inactive');
        $this->repo->setStatus($id, 'active');

        $user = $this->repo->findById($id);
        self::assertSame('active', $user['status']);
        self::assertSame(3, (int) $user['auth_version']);
        self::assertNotNull($this->pdo->query('SELECT used_at FROM otp_codes')->fetchColumn());
    }

    public function testRoleTransitionIncrementsAuthVersionAndInvalidatesOtp(): void
    {
        $id = $this->repo->create('Role Epoch', 'role@example.com', 'hash', 'nurse');
        $this->insertOtp($id);

        $this->repo->setRole($id, 'doctor');

        $user = $this->repo->findById($id);
        self::assertSame('doctor', $user['role']);
        self::assertSame(2, (int) $user['auth_version']);
        self::assertNotNull($this->pdo->query('SELECT used_at FROM otp_codes')->fetchColumn());
    }

    public function testActivationAndResetIncrementAuthVersionAndInvalidateOtp(): void
    {
        $pendingId = $this->repo->create(
            'Pending Epoch',
            'pending-epoch@example.com',
            UserService::PENDING_PASSWORD_SENTINEL,
            'doctor',
            false,
            'inactive'
        );
        $this->insertOtp($pendingId);

        self::assertTrue($this->repo->activatePendingAccount($pendingId, 'activated-hash'));
        self::assertSame(2, (int) $this->repo->findById($pendingId)['auth_version']);
        self::assertNotNull($this->pdo->query('SELECT used_at FROM otp_codes')->fetchColumn());

        $this->insertOtp($pendingId);
        self::assertTrue($this->repo->resetActiveAccountPassword($pendingId, 'reset-hash'));
        self::assertSame(3, (int) $this->repo->findById($pendingId)['auth_version']);
        $activeOtpCount = $this->pdo->query(
            'SELECT COUNT(*) FROM otp_codes WHERE used_at IS NULL'
        )->fetchColumn();
        self::assertSame(0, (int) $activeOtpCount);
    }

    public function testCredentialMutationRollsBackWhenOtpInvalidationFails(): void
    {
        $id = $this->repo->create('Atomic Epoch', 'atomic@example.com', 'old-hash', 'doctor');
        $this->insertOtp($id);
        $this->pdo->exec(
            "CREATE TRIGGER fail_credential_otp_invalidation
             BEFORE UPDATE OF used_at ON otp_codes
             BEGIN
                 SELECT RAISE(ABORT, 'forced otp invalidation failure');
             END"
        );

        try {
            $this->repo->updatePassword($id, 'new-hash');
            self::fail('The credential mutation must not commit without OTP invalidation.');
        } catch (\PDOException) {
        }

        $user = $this->repo->findById($id);
        self::assertSame('old-hash', $user['password_hash']);
        self::assertSame(1, (int) $user['auth_version']);
        self::assertNull($this->pdo->query('SELECT used_at FROM otp_codes')->fetchColumn());
    }

    public function testStatusMutationAndActivationRevocationRollBackWhenOtpInvalidationFails(): void
    {
        $id = $this->repo->create('Atomic Status', 'atomic-status@example.com', 'hash', 'doctor');
        $this->insertOtp($id);
        $this->pdo->prepare(
            'INSERT INTO account_activations
                (user_id, token_hash, expires_at, used_at, created_at)
             VALUES (:user_id, :token_hash, :expires_at, NULL, :created_at)'
        )->execute([
            ':user_id' => $id,
            ':token_hash' => hash('sha256', 'status-reset-token'),
            ':expires_at' => '2026-01-03 12:00:00',
            ':created_at' => '2026-01-01 12:00:00',
        ]);
        $this->createOtpInvalidationFailureTrigger('fail_status_otp_invalidation');

        try {
            $this->repo->setStatus($id, 'inactive');
            self::fail('Status and activation revocation must not commit without OTP invalidation.');
        } catch (\PDOException) {
        }

        $user = $this->repo->findById($id);
        self::assertSame('active', $user['status']);
        self::assertSame(1, (int) $user['auth_version']);
        self::assertNull($this->pdo->query('SELECT used_at FROM otp_codes')->fetchColumn());
        self::assertNull($this->pdo->query('SELECT used_at FROM account_activations')->fetchColumn());
    }

    public function testRoleMutationRollsBackWhenOtpInvalidationFails(): void
    {
        $id = $this->repo->create('Atomic Role', 'atomic-role@example.com', 'hash', 'nurse');
        $this->insertOtp($id);
        $this->createOtpInvalidationFailureTrigger('fail_role_otp_invalidation');

        try {
            $this->repo->setRole($id, 'doctor');
            self::fail('Role mutation must not commit without OTP invalidation.');
        } catch (\PDOException) {
        }

        $user = $this->repo->findById($id);
        self::assertSame('nurse', $user['role']);
        self::assertSame(1, (int) $user['auth_version']);
        self::assertNull($this->pdo->query('SELECT used_at FROM otp_codes')->fetchColumn());
    }

    private function insertOtp(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO otp_codes
                (user_id, code_hash, attempts, expires_at, used_at, created_at)
             VALUES (:user_id, :code_hash, 0, :expires_at, NULL, :created_at)'
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':code_hash' => password_hash('ABC234', PASSWORD_DEFAULT),
            ':expires_at' => '2026-01-01 12:10:00',
            ':created_at' => '2026-01-01 12:00:00',
        ]);
    }

    private function createOtpInvalidationFailureTrigger(string $name): void
    {
        $allowedNames = [
            'fail_status_otp_invalidation',
            'fail_role_otp_invalidation',
        ];
        if (!in_array($name, $allowedNames, true)) {
            throw new \InvalidArgumentException('Unsupported test trigger name.');
        }

        $this->pdo->exec(
            "CREATE TRIGGER {$name}
             BEFORE UPDATE OF used_at ON otp_codes
             BEGIN
                 SELECT RAISE(ABORT, 'forced otp invalidation failure');
             END"
        );
    }
}
