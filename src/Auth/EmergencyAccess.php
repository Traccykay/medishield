<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Audit\ReadAudit;
use MediShield\Security\Crypto;
use MediShield\Security\RequestThrottle;
use MediShield\Support\Clock;
use PDO;

/**
 * Explicit emergency exception for a separate read-only chart, never ordinary
 * encounter writes. Grants begin unusable, are audited, then activated. Failure
 * or a crash between these steps leaves an unusable grant for admin review.
 */
final class EmergencyAccess
{
    public const DURATION_MINUTES = 15;
    private UserRepository $users;
    private SessionValidator $sessions;
    private RequestThrottle $throttle;
    private ReadAudit $audit;

    public function __construct(
        private PDO $pdo,
        private Clock $clock,
        private Crypto $crypto,
        string $throttleKey,
        \Closure $append
    ) {
        $this->users = new UserRepository($pdo, $clock);
        $this->sessions = new SessionValidator($this->users, $clock);
        $this->throttle = new RequestThrottle($pdo, $clock, $throttleKey);
        $this->audit = new ReadAudit($append);
    }

    /** Reauthenticate the current actor, without changing their MFA/session state. */
    public function request(
        array $actor,
        int $patientId,
        string $password,
        string $reason,
        string $sessionBinding,
        string $clientIp
    ): ?int {
        $current = $this->current($actor, 'doctor');
        $reason = trim($reason);
        if ($current === null || $sessionBinding === '') {
            return null;
        }
        $withinUserBudget = $this->throttle->allow('emergency-user', (string) $current['user_id'], 5, 900);
        $withinIpBudget = $this->throttle->allow('emergency-ip', $clientIp, 20, 900);
        if (!$withinUserBudget || !$withinIpBudget || strlen($password) > 4096
            || mb_strlen($reason) < 10 || mb_strlen($reason) > 1000) {
            $this->event($actor, 'EMERGENCY_ACCESS_DENIED', null, 'BLOCKED');
            return null;
        }
        $auth = (new AuthService($this->users, $this->clock))->attemptLogin($current['email'], $password);
        if ($auth['status'] !== 'success' || $auth['must_change']
            || (int) $auth['user']['user_id'] !== (int) $current['user_id']
            || (int) $auth['user']['auth_version'] !== (int) $current['auth_version']) {
            $this->event($actor, 'EMERGENCY_ACCESS_DENIED', null, 'BLOCKED');
            return null;
        }
        $patient = $this->pdo->prepare('SELECT patient_id FROM patients WHERE patient_id = :patient_id');
        $patient->execute([':patient_id' => $patientId]);
        if ($patient->fetchColumn() === false) {
            $this->event($actor, 'EMERGENCY_ACCESS_DENIED', null, 'BLOCKED');
            return null;
        }
        $insert = $this->pdo->prepare(
            'INSERT INTO emergency_access_grants
             (doctor_id, patient_id, auth_version, session_hash, reason_encrypted, created_at, expires_at)
             VALUES (:doctor_id, :patient_id, :auth_version, :session_hash, :reason, :created, :expires)'
        );
        $insert->execute([
            ':doctor_id' => $current['user_id'], ':patient_id' => $patientId,
            ':auth_version' => $current['auth_version'], ':session_hash' => hash('sha256', $sessionBinding),
            ':reason' => $this->crypto->encrypt($reason), ':created' => $this->clock->nowString(),
            ':expires' => $this->clock->plusMinutesString(self::DURATION_MINUTES),
        ]);
        $id = (int) $this->pdo->lastInsertId();
        // No caller transaction: AuditLogger must commit its own hash-chain append.
        $this->event($actor, 'EMERGENCY_ACCESS_GRANTED', $id);
        if ($this->current($actor, 'doctor') === null) {
            return null;
        }
        $activate = $this->pdo->prepare(
            'UPDATE emergency_access_grants SET authorized_at = :now
              WHERE grant_id = :id AND authorized_at IS NULL AND revoked_at IS NULL
                AND expires_at > :cutoff AND EXISTS (
                    SELECT 1 FROM users u WHERE u.user_id = emergency_access_grants.doctor_id
                      AND u.auth_version = emergency_access_grants.auth_version
                      AND u.role = :role AND u.status = :status AND u.must_change_password = 0
                      AND (u.locked_until IS NULL OR u.locked_until <= :lock_cutoff)
                )'
        );
        $activate->execute([':now' => $this->clock->nowString(), ':id' => $id,
            ':cutoff' => $this->clock->nowString(), ':role' => 'doctor', ':status' => 'active',
            ':lock_cutoff' => $this->clock->nowString()]);
        return $activate->rowCount() === 1 ? $id : null;
    }

    public function canRead(array $actor, int $grantId, int $patientId, string $sessionBinding): bool
    {
        if ($this->current($actor, 'doctor') === null || $sessionBinding === '') {
            return false;
        }
        $stmt = $this->pdo->prepare(
            'SELECT grant_id FROM emergency_access_grants
              WHERE grant_id = :grant_id AND doctor_id = :doctor_id AND patient_id = :patient_id
                AND auth_version = :auth_version AND session_hash = :session_hash
                AND authorized_at IS NOT NULL AND revoked_at IS NULL
                AND created_at <= :now AND expires_at > :cutoff'
        );
        $stmt->execute([':grant_id' => $grantId, ':doctor_id' => $actor['user_id'], ':patient_id' => $patientId,
            ':auth_version' => $actor['auth_version'], ':session_hash' => hash('sha256', $sessionBinding),
            ':now' => $this->clock->nowString(), ':cutoff' => $this->clock->nowString()]);
        return $stmt->fetchColumn() !== false;
    }

    /** Call before loading/rendering the emergency chart. Every read is flagged for review. */
    public function authorizeRead(array $actor, int $grantId, int $patientId, string $sessionBinding): bool
    {
        if (!$this->canRead($actor, $grantId, $patientId, $sessionBinding)) {
            $this->event($actor, 'EMERGENCY_ACCESS_DENIED', null, 'BLOCKED');
            return false;
        }
        $this->event($actor, 'EMERGENCY_ACCESS_VIEWED', $grantId);
        // Account or grant revocation may have occurred while appending the audit.
        return $this->canRead($actor, $grantId, $patientId, $sessionBinding);
    }

    /** Admin lists contain identifiers and state, not patient names or free-text reasons. */
    public function reviewQueue(array $admin, int $beforeId = PHP_INT_MAX): array
    {
        $this->requireAdmin($admin);
        $this->audit->records($admin, 'emergency.review_queue', [], 'AUDIT_LOGS_VIEWED');
        $stmt = $this->pdo->prepare(
            'SELECT grant_id, doctor_id, patient_id, created_at, expires_at, authorized_at,
                    revoked_at, reviewed_at, reviewed_by
               FROM emergency_access_grants WHERE grant_id < :before_id ORDER BY grant_id DESC LIMIT 50'
        );
        $stmt->execute([':before_id' => $beforeId]);
        return $stmt->fetchAll();
    }

    public function pendingReviewCount(array $admin): int
    {
        $this->requireAdmin($admin);
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM emergency_access_grants WHERE reviewed_at IS NULL');
        $stmt->execute();
        return (int) $stmt->fetchColumn();
    }

    public function reviewDetail(array $admin, int $grantId): ?array
    {
        $this->requireAdmin($admin);
        $this->audit->records($admin, 'emergency.review_detail', [$grantId], 'AUDIT_LOGS_VIEWED');
        $stmt = $this->pdo->prepare('SELECT * FROM emergency_access_grants WHERE grant_id = :id');
        $stmt->execute([':id' => $grantId]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $row['reason'] = $this->crypto->decrypt($row['reason_encrypted']);
        unset($row['reason_encrypted'], $row['session_hash']);
        return $row;
    }

    /** Review never activates a grant. Revocation survives an audit outage. */
    public function review(array $admin, int $grantId, bool $revoke): void
    {
        $this->requireAdmin($admin);
        $exists = $this->pdo->prepare('SELECT grant_id FROM emergency_access_grants WHERE grant_id = :id');
        $exists->execute([':id' => $grantId]);
        if ($exists->fetchColumn() === false) {
            throw new \RuntimeException('Emergency review record unavailable.');
        }
        if ($revoke) {
            $stmt = $this->pdo->prepare(
                'UPDATE emergency_access_grants SET revoked_at = :now WHERE grant_id = :id AND revoked_at IS NULL'
            );
            $stmt->execute([':now' => $this->clock->nowString(), ':id' => $grantId]);
            $this->event($admin, 'EMERGENCY_ACCESS_REVOKED', $grantId);
        }
        $this->event($admin, 'EMERGENCY_ACCESS_REVIEWED', $grantId);
        $stmt = $this->pdo->prepare(
            'UPDATE emergency_access_grants SET reviewed_at = :now, reviewed_by = :admin_id
              WHERE grant_id = :id AND reviewed_at IS NULL'
        );
        $stmt->execute([':now' => $this->clock->nowString(), ':admin_id' => $admin['user_id'], ':id' => $grantId]);
    }

    private function current(array $actor, string $role): ?array
    {
        $current = $this->sessions->authenticateSession($actor);
        if ($current === null || $current['role'] !== $role || $current['must_change']) {
            return null;
        }
        $row = $this->users->findById((int) $current['user_id']);
        if ($row['locked_until'] !== null && (string) $row['locked_until'] > $this->clock->nowString()) {
            return null;
        }
        return $current;
    }

    private function requireAdmin(array $admin): void
    {
        if ($this->current($admin, 'admin') === null) {
            throw new \RuntimeException('Emergency review access denied.');
        }
    }

    private function event(array $actor, string $action, ?int $grantId, string $status = 'SUCCESS'): void
    {
        $this->audit->event([
            'user_id' => (int) $actor['user_id'], 'user_role' => (string) $actor['role'],
            'action' => $action, 'module' => 'emergency',
            'affected_record_id' => $grantId === null ? null : (string) $grantId,
            'status' => $status, 'anomaly_flag' => 'HIGH_RISK',
        ]);
    }
}
