<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Support\Clock;

/**
 * AuthService
 * -----------
 * Orchestrates a login attempt and the brute-force lockout policy (spec §9.1).
 *
 * It deliberately returns a small result array describing WHAT happened and lets
 * the calling page handle the side effects (creating the session, writing the
 * audit log, redirecting). That separation is what makes the security-critical
 * logic unit-testable without a web server.
 *
 * Lockout policy (configurable, defaults from spec):
 *   - SUSPICIOUS anomaly flagged at {@see $suspiciousAt} (default 3) failures.
 *   - Account locked for {@see $lockMinutes} (default 15) after {@see $maxAttempts}
 *     (default 5) consecutive failures; that event is HIGH_RISK.
 *   - A correct password resets the counter and clears the lock.
 *
 * Anti-enumeration: when the email is unknown we still run a dummy password_verify
 * so the response time is similar to a real account, and the page always shows the
 * single generic message "Invalid login credentials."
 *
 * Result shape:
 *   [
 *     'status'  => 'success' | 'invalid' | 'locked',
 *     'user'    => array|null,            // the user row on success
 *     'anomaly' => 'NORMAL' | 'SUSPICIOUS' | 'HIGH_RISK',
 *     'failed_count' => int,              // current failed count (0 on success)
 *     'must_change'  => bool,             // force password change at first login
 *   ]
 */
final class AuthService
{
    private string $dummyHash;

    public function __construct(
        private UserRepository $users,
        private Clock $clock,
        private int $maxAttempts = 5,
        private int $suspiciousAt = 3,
        private int $lockMinutes = 15
    ) {
        // Precompute a throwaway hash once, for timing-equalisation on unknown emails.
        $this->dummyHash = password_hash('not-a-real-password', PASSWORD_DEFAULT);
    }

    /**
     * Attempt to authenticate.
     *
     * @return array{status:string,user:?array,anomaly:string,failed_count:int,must_change:bool}
     */
    public function attemptLogin(string $email, string $password): array
    {
        $user = $this->users->findByEmail($email);

        // Unknown email: spend similar time, then fail generically.
        if ($user === null) {
            password_verify($password, $this->dummyHash);
            return $this->result('invalid');
        }

        // Inactive accounts cannot log in; reveal nothing specific.
        if (($user['status'] ?? 'active') !== 'active') {
            return $this->result('invalid');
        }

        // Currently locked? Reject without even checking the password.
        if ($this->isLocked($user)) {
            return $this->result('locked');
        }

        // Correct password -> success.
        if (password_verify($password, (string) $user['password_hash'])) {
            $this->users->resetFailedAndUnlock((int) $user['user_id']);
            return [
                'status'       => 'success',
                'user'         => $user,
                'anomaly'      => 'NORMAL',
                'failed_count' => 0,
                'must_change'  => (bool) ($user['must_change_password'] ?? false),
            ];
        }

        // Wrong password -> increment counter and apply lockout policy.
        $count = $this->users->incrementFailedLogin((int) $user['user_id']);

        if ($count >= $this->maxAttempts) {
            $this->users->lockUntil(
                (int) $user['user_id'],
                $this->clock->plusMinutesString($this->lockMinutes)
            );
            return $this->result('locked', 'HIGH_RISK', $count);
        }

        if ($count >= $this->suspiciousAt) {
            return $this->result('invalid', 'SUSPICIOUS', $count);
        }

        return $this->result('invalid', 'NORMAL', $count);
    }

    /** Is the account's lock still in the future relative to the injected clock? */
    private function isLocked(array $user): bool
    {
        $until = $user['locked_until'] ?? null;
        if ($until === null || $until === '') {
            return false;
        }
        try {
            $lockedUntil = new \DateTimeImmutable((string) $until, new \DateTimeZone('UTC'));
        } catch (\Exception) {
            return false;
        }
        return $lockedUntil > $this->clock->now();
    }

    /** Build a non-success result array. */
    private function result(string $status, string $anomaly = 'NORMAL', int $failedCount = 0): array
    {
        return [
            'status'       => $status,
            'user'         => null,
            'anomaly'      => $anomaly,
            'failed_count' => $failedCount,
            'must_change'  => false,
        ];
    }
}
