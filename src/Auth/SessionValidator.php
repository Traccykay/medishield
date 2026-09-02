<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Support\Clock;

/**
 * Validates the server-side authentication payload before every protected request.
 *
 * PHP session identifiers remain valid until their lifetime expires, so a session
 * payload alone cannot reflect account mutations. A persisted monotonic
 * `auth_version` is copied into pending and authenticated sessions, then compared
 * with the authoritative user row on every protected request. Password, status,
 * and role changes advance that epoch, so old sessions can never become valid
 * again after a deactivate/reactivate cycle.
 */
final class SessionValidator
{
    private Clock $clock;

    public function __construct(
        private UserRepository $users,
        ?Clock $clock = null,
        private int $pendingMaxAgeSeconds = 600
    ) {
        $this->clock = $clock ?? new Clock();
    }

    /**
     * Create the minimal, server-side authentication payload for a verified user.
     *
     * @param array<string,mixed> $user A current users-table row.
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool,auth_version:int}
     */
    public function createAuthenticatedSession(array $user): array
    {
        return [
            'user_id'      => (int) $user['user_id'],
            'role'         => (string) $user['role'],
            'full_name'    => (string) $user['full_name'],
            'email'        => (string) $user['email'],
            'must_change'  => (bool) ($user['must_change_password'] ?? false),
            'auth_version' => (int) $user['auth_version'],
        ];
    }

    /**
     * Create the minimal pre-MFA payload. The password verifier and OTP never
     * enter the session.
     *
     * @param array<string,mixed> $user
     * @return array{user_id:int,role:string,auth_version:int,started_at:int}
     */
    public function createPendingLogin(array $user): array
    {
        return [
            'user_id' => (int) $user['user_id'],
            'role' => (string) $user['role'],
            'auth_version' => (int) $user['auth_version'],
            'started_at' => $this->clock->now()->getTimestamp(),
        ];
    }

    /**
     * Authenticate a preserved PHP session against the authoritative user row.
     *
     * @param array<string,mixed> $sessionAuth The auth payload saved at login.
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool,auth_version:int}|null
     */
    public function authenticateSession(array $sessionAuth): ?array
    {
        $userId = $this->positiveSessionInt($sessionAuth['user_id'] ?? null);
        $authVersion = $this->positiveSessionInt($sessionAuth['auth_version'] ?? null);
        $role = $sessionAuth['role'] ?? null;
        if ($userId === null || $authVersion === null || !is_string($role) || $role === '') {
            return null;
        }
        $user = $this->users->findById($userId);
        if ($user === null || (string) $user['status'] !== 'active') {
            return null;
        }
        if (
            (int) $user['auth_version'] !== $authVersion
            || !hash_equals((string) $user['role'], $role)
        ) {
            return null;
        }

        return $this->createAuthenticatedSession($user);
    }

    /**
     * Revalidate the first factor immediately before OTP redemption.
     *
     * @param array<string,mixed> $pending
     * @return array{status:string,user:?array}
     */
    public function validatePendingLogin(array $pending): array
    {
        $userId = $this->positiveSessionInt($pending['user_id'] ?? null);
        $authVersion = $this->positiveSessionInt($pending['auth_version'] ?? null);
        $startedAt = $this->positiveSessionInt($pending['started_at'] ?? null);
        $role = $pending['role'] ?? null;
        $now = $this->clock->now()->getTimestamp();

        if (
            $userId === null
            || $authVersion === null
            || $startedAt === null
            || !is_string($role)
            || $role === ''
            || $startedAt > $now
        ) {
            return ['status' => 'malformed', 'user' => null];
        }
        if (($now - $startedAt) >= max(1, $this->pendingMaxAgeSeconds)) {
            return ['status' => 'expired', 'user' => null];
        }

        $user = $this->users->findById($userId);
        if (
            $user === null
            || (string) $user['status'] !== 'active'
            || (int) $user['auth_version'] !== $authVersion
            || !hash_equals((string) $user['role'], $role)
            || $this->isLocked($user)
        ) {
            return ['status' => 'revoked', 'user' => null];
        }

        return ['status' => 'valid', 'user' => $user];
    }

    /** @return array{login_at:int,last_activity:int} */
    public function createLoginTimestamps(): array
    {
        $now = $this->clock->now()->getTimestamp();
        return ['login_at' => $now, 'last_activity' => $now];
    }

    /**
     * @param array<string,mixed> $timing
     */
    public function validateSessionTiming(
        array $timing,
        int $idleTimeoutSeconds = 1200,
        int $absoluteTimeoutSeconds = 28800
    ): string {
        $loginAt = $this->positiveSessionInt($timing['login_at'] ?? null);
        $lastActivity = $this->positiveSessionInt($timing['last_activity'] ?? null);
        $now = $this->clock->now()->getTimestamp();
        if (
            $loginAt === null
            || $lastActivity === null
            || $loginAt > $now
            || $lastActivity > $now
            || $lastActivity < $loginAt
        ) {
            return 'malformed';
        }

        if (
            ($now - $lastActivity) >= max(1, $idleTimeoutSeconds)
            || ($now - $loginAt) >= max(1, $absoluteTimeoutSeconds)
        ) {
            return 'expired';
        }

        return 'valid';
    }

    private function positiveSessionInt(mixed $value): ?int
    {
        return is_int($value) && $value > 0 ? $value : null;
    }

    /** Invalid lock timestamps fail closed. */
    private function isLocked(array $user): bool
    {
        $until = $user['locked_until'] ?? null;
        if ($until === null || $until === '') {
            return false;
        }

        $lockedUntil = Clock::parseDatabaseTimestamp($until);
        return $lockedUntil === null || $lockedUntil > $this->clock->now();
    }
}
