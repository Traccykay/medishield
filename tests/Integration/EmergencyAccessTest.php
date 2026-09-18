<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\EmergencyAccess;
use MediShield\Auth\UserRepository;
use MediShield\Patient\PatientRepository;
use MediShield\Security\Crypto;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

final class EmergencyAccessTest extends TestCase
{
    private \PDO $pdo;
    private Clock $clock;
    private \DateTimeImmutable $now;
    private EmergencyAccess $service;
    private array $doctor;
    private array $admin;
    private int $patientId;
    private array $events = [];
    private bool $auditAvailable = true;

    protected function setUp(): void
    {
        $this->pdo = TestSchema::pdo();
        $this->now = new \DateTimeImmutable('2026-09-16 10:00:00', new \DateTimeZone('UTC'));
        $this->clock = new Clock(fn () => $this->now);
        $users = new UserRepository($this->pdo, $this->clock);
        $doctorId = $users->create('Doctor', 'emergency-doctor@example.test', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'doctor', false);
        $adminId = $users->create('Admin', 'emergency-admin@example.test', 'hash', 'admin', false);
        $this->doctor = ['user_id' => $doctorId, 'role' => 'doctor', 'auth_version' => 1];
        $this->admin = ['user_id' => $adminId, 'role' => 'admin', 'auth_version' => 1];
        $this->patientId = (new PatientRepository($this->pdo, $this->clock))->create([
            'user_id' => null, 'patient_number' => 'MSH-1234567890123456',
            'full_name' => 'Emergency Patient', 'date_of_birth' => '1990-01-01',
            'gender' => 'female', 'phone' => null, 'address' => null, 'emergency_contact' => null,
        ]);
        $this->service = new EmergencyAccess($this->pdo, $this->clock, new Crypto(str_repeat('a', 32)), str_repeat('b', 64),
            function (array $event): bool {
                $this->events[] = $event;
                return $this->auditAvailable;
            });
    }

    private function grant(string $password = 'Str0ng!Pass1', string $reason = 'Immediate clinical assessment needed'): ?int
    {
        return $this->service->request($this->doctor, $this->patientId, $password, $reason, 'session-one', '127.0.0.1');
    }

    public function testGrantIsPatientDoctorSessionBoundAndExpiresAtExactBoundary(): void
    {
        $grant = $this->grant();
        self::assertIsInt($grant);
        self::assertTrue($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-one'));
        self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId + 1, 'session-one'));
        self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-two'));
        self::assertFalse($this->service->canRead($this->admin, $grant, $this->patientId, 'session-one'));
        self::assertFalse($this->service->canRead($this->doctor + ['extra' => 1], $grant + 1, $this->patientId, 'session-one'));
        $this->now = $this->now->modify('+15 minutes');
        self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-one'));
    }

    public function testReasonEncryptedAndNeverInAuditEvents(): void
    {
        $grant = $this->grant();
        $stored = $this->pdo->query('SELECT reason_encrypted FROM emergency_access_grants')->fetchColumn();
        self::assertNotSame('Immediate clinical assessment needed', $stored);
        self::assertStringNotContainsString('Immediate clinical', json_encode($this->events));
        self::assertSame('Immediate clinical assessment needed', $this->service->reviewDetail($this->admin, $grant)['reason']);
        self::assertSame(1, $this->service->pendingReviewCount($this->admin));
    }

    public function testWrongPasswordAndMissingReasonDoNotGrantAccess(): void
    {
        self::assertNull($this->grant('wrong'));
        self::assertNull($this->grant('Str0ng!Pass1', ''));
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM emergency_access_grants')->fetchColumn());
    }

    public function testAuditFailureLeavesGrantUnusable(): void
    {
        $this->auditAvailable = false;
        try {
            $this->grant();
            self::fail('Audit outage must block grant activation');
        } catch (\RuntimeException $e) {
            self::assertFalse($this->service->canRead($this->doctor, 1, $this->patientId, 'session-one'));
        }
    }

    public function testDisabledAccountAndCredentialEpochRevokeExistingGrant(): void
    {
        $grant = $this->grant();
        $this->pdo->prepare('UPDATE users SET status = :status WHERE user_id = :id')
            ->execute([':status' => 'inactive', ':id' => $this->doctor['user_id']]);
        self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-one'));
        self::assertNull($this->grant());
        $this->pdo->prepare('UPDATE users SET status = :status, auth_version = 2 WHERE user_id = :id')
            ->execute([':status' => 'active', ':id' => $this->doctor['user_id']]);
        self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-one'));
        $this->doctor['auth_version'] = 2;
        self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-one'));
    }

    public function testAdministratorReviewAndRevocationPreserveHistory(): void
    {
        $grant = $this->grant();
        $this->service->review($this->admin, $grant, true);
        self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-one'));
        self::assertSame(0, $this->service->pendingReviewCount($this->admin));
        self::assertCount(1, $this->service->reviewQueue($this->admin));
        $row = $this->pdo->query('SELECT * FROM emergency_access_grants')->fetch();
        self::assertSame($this->admin['user_id'], (int) $row['reviewed_by']);
        self::assertNotNull($row['revoked_at']);
    }

    public function testDoctorCannotReviewGrants(): void
    {
        $grant = $this->grant();
        $this->expectException(\RuntimeException::class);
        $this->service->review($this->doctor, $grant, true);
    }

    public function testOtherDoctorAndChangedRoleCannotUseGrant(): void
    {
        $grant = $this->grant();
        $id = (new UserRepository($this->pdo, $this->clock))->create('Other', 'other@example.test', 'hash', 'doctor', false);
        self::assertFalse($this->service->canRead(['user_id' => $id, 'role' => 'doctor', 'auth_version' => 1], $grant, $this->patientId, 'session-one'));
        $this->pdo->prepare('UPDATE users SET role = :role WHERE user_id = :id')
            ->execute([':role' => 'nurse', ':id' => $this->doctor['user_id']]);
        self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-one'));
    }

    public function testReadAuditOutageBlocksDisclosureAndRevokeStillTakesEffect(): void
    {
        $grant = $this->grant();
        $this->auditAvailable = false;
        try {
            $this->service->authorizeRead($this->doctor, $grant, $this->patientId, 'session-one');
            self::fail('Read must fail on audit outage');
        } catch (\RuntimeException $e) {
            self::assertTrue(true);
        }
        try {
            $this->service->review($this->admin, $grant, true);
        } catch (\RuntimeException $e) {
            self::assertFalse($this->service->canRead($this->doctor, $grant, $this->patientId, 'session-one'));
        }
        self::assertSame(1, $this->service->pendingReviewCount($this->admin));
    }

    public function testPasswordAttemptsAreBoundedAcrossSessionsAndIpChanges(): void
    {
        for ($i = 0; $i < 5; $i++) {
            self::assertNull($this->service->request($this->doctor, $this->patientId, 'wrong', 'Urgent care access', 'session-' . $i, '127.0.0.' . $i));
        }
        self::assertNull($this->grant());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM emergency_access_grants')->fetchColumn());
    }

    public function testGrantDoesNotChangeOrdinaryDoctorAuthorizationOrAssignments(): void
    {
        $this->grant();
        $authorizer = new \MediShield\Auth\DoctorPatientAuthorizer($this->pdo);
        self::assertFalse($authorizer->canAccess($this->doctor['user_id'], $this->patientId, 1));
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM patient_assignments')->fetchColumn());
    }

    public function testReviewOfMissingGrantDoesNotClaimSuccess(): void
    {
        try {
            $this->service->review($this->admin, 999, true);
            self::fail('Missing grant review must fail');
        } catch (\RuntimeException $e) {
            self::assertSame([], $this->events);
        }
    }

    public function testRevocationDuringAuditPreventsActivationAndRead(): void
    {
        $service = new EmergencyAccess($this->pdo, $this->clock, new Crypto(str_repeat('a', 32)), str_repeat('b', 64),
            function (array $event): bool {
                $stmt = $this->pdo->prepare('UPDATE emergency_access_grants SET revoked_at = :now WHERE grant_id = :id');
                $stmt->execute([':now' => $this->clock->nowString(), ':id' => $event['affected_record_id']]);
                return true;
            });
        self::assertNull($service->request($this->doctor, $this->patientId, 'Str0ng!Pass1', 'Urgent clinical assessment', 'session-one', '127.0.0.1'));
        $grant = $this->grant();
        self::assertTrue($this->service->authorizeRead($this->doctor, $grant, $this->patientId, 'session-one'));
        self::assertSame('EMERGENCY_ACCESS_VIEWED', $this->events[count($this->events) - 1]['action']);
        self::assertFalse($service->authorizeRead($this->doctor, $grant, $this->patientId, 'session-one'));
    }
}
