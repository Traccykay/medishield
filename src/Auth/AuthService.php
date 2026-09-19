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
 * Anti-enumeration: every failure returns the same external status. Unknown,
 * inactive, and locked accounts still perform one password verification against
 * either the account hash or a dummy hash so the account state is not disclosed
 * by the response message or by an avoidable fast path.
 *
 * Forensic attribution: a FAILED attempt against a real account still records WHICH
 * account was targeted (target_user_id / target_user_role) so an administrator can
 * follow up on a possible credential compromise. This is safe because the audit log
 * is admin-only and never shown to the person logging in — the user-facing response
 * stays generic. An unknown email has no account to attribute, so the target is null.
 *
 * Result shape:
 *   [
 *     'status'  => 'success' | 'invalid',
 *     'internal_status' => 'authenticated' | 'unknown_account' |
     *                          'inactive_account' | 'wrong_password' | 'locked_account' |
     *                          'locked_account_confirmed',
 *     'audit_action' => 'LOGIN_SUCCESS' | 'LOGIN_FAILED' | 'ACCOUNT_LOCKED',
 *     'user'    => array|null,            // the authenticated user row, success only
 *     'anomaly' => 'NORMAL' | 'SUSPICIOUS' | 'HIGH_RISK',
 *     'failed_count' => int,              // current failed count (0 on success)
 *     'must_change'  => bool,             // force password change at first login
 *     'account_unlocked' => bool,         // an expired lock was cleared
 *     'target_user_id'   => int|null,     // the account a FAILED attempt was against
 *     'target_user_role' => string|null,  // that account's role (for audit triage)
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
     * @return array{status:string,internal_status:string,audit_action:string,user:?array,anomaly:string,failed_count:int,must_change:bool,target_user_id:?int,target_user_role:?string}
     */
    public function attemptLogin(string $email, string $password): array
    {
        $user = $this->users->findByEmail($email);

        // Unknown email: spend similar time, then fail generically. There is no
        // account to attribute the attempt to.
        if ($user === null) {
            password_verify($password, $this->dummyHash);
            return $this->result('unknown_account');
        }

        // These denial paths still do password-verification work. A pending account
        // has a non-hash sentinel, so use the dummy verifier rather than exposing a
        // substantially cheaper path.
        if (($user['status'] ?? 'active') !== 'active') {
            password_verify($password, $this->verificationHash($user));
            return $this->result(
                'inactive_account',
                'NORMAL',
                (int) ($user['failed_login_count'] ?? 0),
                $user
            );
        }

        if ($this->isLocked($user)) {
            $passwordMatches = password_verify($password, $this->verificationHash($user));
            return $this->result(
                $passwordMatches ? 'locked_account_confirmed' : 'locked_account',
                'NORMAL',
                (int) ($user['failed_login_count'] ?? 0),
                $user
            );
        }

        $accountUnlocked = $this->hasExpiredLock($user);

        // Correct password -> first factor accepted. LOGIN_SUCCESS is emitted by
        // verify_otp.php only after the second factor completes.
        if (password_verify($password, (string) $user['password_hash'])) {
            $this->users->resetFailedAndUnlock((int) $user['user_id']);
            return [
                'status'           => 'success',
                'internal_status'  => 'authenticated',
                'audit_action'     => 'LOGIN_SUCCESS',
                'user'             => $user,
                'anomaly'          => 'NORMAL',
                'failed_count'     => 0,
                'must_change'      => (bool) ($user['must_change_password'] ?? false),
                'account_unlocked' => $accountUnlocked,
                'target_user_id'   => (int) $user['user_id'],
                'target_user_role' => (string) $user['role'],
            ];
        }

        // Wrong password -> increment counter and apply lockout policy.
        $count = $this->users->incrementFailedLogin((int) $user['user_id']);

        if ($count >= $this->maxAttempts) {
            $this->users->lockUntil(
                (int) $user['user_id'],
                $this->clock->plusMinutesString($this->lockMinutes)
            );
            return $this->result('locked_account', 'HIGH_RISK', $count, $user, 'ACCOUNT_LOCKED');
        }

        if ($count >= $this->suspiciousAt) {
            return $this->result('wrong_password', 'SUSPICIOUS', $count, $user);
        }

        return $this->result('wrong_password', 'NORMAL', $count, $user);
    }

    /** Is the account's lock still in the future relative to the injected clock? */
    private function isLocked(array $user): bool
    {
        $until = $user['locked_until'] ?? null;
        if ($until === null || $until === '') {
            return false;
        }

        $lockedUntil = Clock::parseDatabaseTimestamp($until);
        return $lockedUntil === null || $lockedUntil > $this->clock->now();
    }

    private function hasExpiredLock(array $user): bool
    {
        $until = $user['locked_until'] ?? null;
        if (!is_string($until) || $until === '') {
            return false;
        }

        $lockedUntil = Clock::parseDatabaseTimestamp($until);
        return $lockedUntil !== null && $lockedUntil <= $this->clock->now();
    }

    /** Return a valid verifier for one unit of password checking work. */
    private function verificationHash(array $user): string
    {
        $hash = (string) ($user['password_hash'] ?? '');
        $info = password_get_info($hash);
        return ($info['algoName'] ?? 'unknown') === 'unknown' ? $this->dummyHash : $hash;
    }

    /**
     * Build a non-success result array.
     *
     * @param array<string,mixed>|null $user The targeted account, when one exists,
     *                                        so a FAILED attempt can be attributed
     *                                        to it in the (admin-only) audit log.
     */
    private function result(
        string $internalStatus,
        string $anomaly = 'NORMAL',
        int $failedCount = 0,
        ?array $user = null,
        string $auditAction = 'LOGIN_FAILED'
    ): array {
        return [
            'status'           => 'invalid',
            'internal_status'  => $internalStatus,
            'audit_action'     => $auditAction,
            'user'             => null,
            'anomaly'          => $anomaly,
            'failed_count'     => $failedCount,
            'must_change'      => false,
            'account_unlocked' => false,
            'target_user_id'   => $user !== null ? (int) $user['user_id'] : null,
            'target_user_role' => $user !== null ? (string) $user['role'] : null,
        ];
    }
}
