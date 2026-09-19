<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\ActivationRepository;
use MediShield\Auth\ActivationService;
use MediShield\Auth\InitialAdminProvisioner;
use MediShield\Auth\UserRepository;
use MediShield\Auth\UserService;
use MediShield\Security\PasswordPolicy;
use MediShield\Support\Clock;
use MediShield\Tests\Support\FakeMailer;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

final class InitialAdminProvisionerTest extends TestCase
{
    private \PDO $pdo;
    private UserRepository $users;
    private ActivationService $activations;
    private FakeMailer $mailer;
    private InitialAdminProvisioner $provisioner;

    protected function setUp(): void
    {
        $clock = new Clock(
            static fn (): \DateTimeImmutable => new \DateTimeImmutable(
                '2026-09-02 14:00:00',
                new \DateTimeZone('UTC')
            )
        );
        $this->pdo = TestSchema::pdo();
        $this->users = new UserRepository($this->pdo, $clock);
        $userService = new UserService($this->users, new PasswordPolicy());
        $this->activations = new ActivationService(
            new ActivationRepository($this->pdo, $clock),
            $this->users,
            new PasswordPolicy(),
            $clock,
            24
        );
        $this->mailer = new FakeMailer();
        $this->provisioner = new InitialAdminProvisioner(
            $this->pdo,
            $this->users,
            $userService,
            $this->activations,
            $this->mailer,
            'https://medishield.example',
            24
        );
    }

    public function testProvision_NoExistingAdmin_CreatesInactiveAdminAndDeliversActivation(): void
    {
        $result = $this->provisioner->provision('Initial Administrator', 'initial.admin@example.com');

        self::assertTrue($result['ok']);
        self::assertTrue($result['created']);
        self::assertIsInt($result['user_id']);
        self::assertArrayNotHasKey('token', $result);
        self::assertArrayNotHasKey('password', $result);

        $admin = $this->users->findByEmail('initial.admin@example.com');
        self::assertNotNull($admin);
        self::assertSame('admin', $admin['role']);
        self::assertSame('inactive', $admin['status']);
        self::assertSame(UserService::PENDING_ACTIVATION_SENTINEL, $admin['password_hash']);
        self::assertFalse(password_verify('anything', (string) $admin['password_hash']));

        self::assertCount(1, $this->mailer->sent);
        $message = $this->mailer->last();
        self::assertNotNull($message);
        self::assertSame('initial.admin@example.com', $message['to']);
        self::assertStringNotContainsString('password', strtolower($message['subject']));

        self::assertMatchesRegularExpression(
            '/activate\.php\?token=([a-f0-9]{64})/',
            $message['body']
        );
        self::assertStringContainsString('expires in 24 hours', $message['body']);
        preg_match('/activate\.php\?token=([a-f0-9]{64})/', $message['body'], $matches);
        self::assertTrue($this->activations->validate($matches[1])['ok']);
    }

    public function testProvision_ReplayedAfterSuccess_IsNoOp(): void
    {
        $first = $this->provisioner->provision('Initial Administrator', 'initial.admin@example.com');
        $second = $this->provisioner->provision('Initial Administrator', 'initial.admin@example.com');

        self::assertTrue($first['created']);
        self::assertTrue($second['ok']);
        self::assertFalse($second['created']);
        self::assertNull($second['user_id']);
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
        self::assertSame(
            1,
            (int) $this->pdo->query('SELECT COUNT(*) FROM account_activations')->fetchColumn()
        );
        self::assertCount(1, $this->mailer->sent);
    }

    public function testProvision_WhenAdminAlreadyExists_PreservesExistingRowAndSendsNothing(): void
    {
        $existingHash = password_hash('Existing!Pass2026', PASSWORD_DEFAULT);
        $existingId = $this->users->create(
            'Existing Administrator',
            'existing.admin@example.com',
            $existingHash,
            'admin',
            false,
            'active'
        );

        $result = $this->provisioner->provision('Different Administrator', 'different@example.com');

        self::assertTrue($result['ok']);
        self::assertFalse($result['created']);
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM account_activations')->fetchColumn());
        self::assertCount(0, $this->mailer->sent);

        $existing = $this->users->findById($existingId);
        self::assertNotNull($existing);
        self::assertSame('Existing Administrator', $existing['full_name']);
        self::assertSame('active', $existing['status']);
        self::assertSame($existingHash, $existing['password_hash']);
    }

    public function testProvision_WithInjectionShapedEmail_RejectsWithoutMutation(): void
    {
        $result = $this->provisioner->provision(
            'Initial Administrator',
            "admin@example.com' OR 1=1 --"
        );

        self::assertFalse($result['ok']);
        self::assertFalse($result['created']);
        self::assertContains('A valid email address is required.', $result['errors']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM account_activations')->fetchColumn());
        self::assertCount(0, $this->mailer->sent);
    }

    public function testProvision_WhenDeliveryFails_RollsBackAdminAndActivation(): void
    {
        $this->mailer->shouldSucceed = false;

        $result = $this->provisioner->provision('Initial Administrator', 'initial.admin@example.com');

        self::assertFalse($result['ok']);
        self::assertFalse($result['created']);
        self::assertContains('The activation link could not be delivered.', $result['errors']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM account_activations')->fetchColumn());
    }
}
