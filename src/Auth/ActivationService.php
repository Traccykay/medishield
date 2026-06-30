<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Security\PasswordPolicy;
use MediShield\Support\Clock;

/**
 * ActivationService
 * -----------------
 * Implements the ACCOUNT-ACTIVATION-LINK flow. When an admin creates a user
 * ({@see UserService::createPendingUser()}) the account has no usable password and
 * status 'inactive'. This service:
 *
 *   1. issueFor()  — mints a high-entropy token, stores only its SHA-256 hash with
 *                    an expiry, and returns the PLAINTEXT token for the emailed link.
 *   2. validate()  — checks a token from a link is known, unused and unexpired.
 *   3. activate()  — re-checks the token, enforces the password policy + confirm
 *                    match, then sets the chosen password and flips the account to
 *                    'active' (via {@see UserRepository::activate()}), consuming the
 *                    token so the link is single-use.
 *
 * Security rationale mirrors OtpService but the token is long-lived (hours) and
 * high-entropy, hence SHA-256 (deterministic lookup) rather than bcrypt. The caller
 * (a page) owns emailing the link and writing the audit entries.
 */
final class ActivationService
{
    public function __construct(
        private ActivationRepository $activations,
        private UserRepository $users,
        private PasswordPolicy $passwordPolicy,
        private Clock $clock,
        private int $ttlHours = 48
    ) {
    }

    /**
     * Mint, store (hashed) and return a fresh activation token for a user. Any
     * previously-issued unused token for this user is invalidated first so only one
     * link is ever live. The caller emails the returned plaintext token and audits
     * ACTIVATION_SENT.
     */
    public function issueFor(int $userId): string
    {
        $this->activations->invalidateAllForUser($userId);

        $token = bin2hex(random_bytes(32)); // 64 hex chars, ~256 bits of entropy
        $expiresAt = $this->clock->now()
            ->add(new \DateInterval('PT' . max(1, $this->ttlHours) . 'H'))
            ->format('Y-m-d H:i:s');

        $this->activations->create($userId, $this->hashToken($token), $expiresAt);

        return $token;
    }

    /**
     * Check a token from an activation link without consuming it (used to decide
     * whether to render the "set your password" form).
     *
     * @return array{ok:bool, user_id:?int, reason:?string}
     *   reason is 'invalid' (unknown/used) or 'expired' when ok is false.
     */
    public function validate(string $token): array
    {
        $row = $this->activations->findActiveByHash($this->hashToken($token));
        if ($row === null) {
            return ['ok' => false, 'user_id' => null, 'reason' => 'invalid'];
        }
        if ($this->isExpired((string) $row['expires_at'])) {
            return ['ok' => false, 'user_id' => null, 'reason' => 'expired'];
        }
        return ['ok' => true, 'user_id' => (int) $row['user_id'], 'reason' => null];
    }

    /**
     * Activate the account behind a token by setting the user's chosen password.
     * Re-validates the token, enforces the password policy and confirm match, then
     * sets the password + status 'active' and burns the token (single use).
     *
     * @return array{ok:bool, errors:string[], user_id:?int}
     */
    public function activate(string $token, string $password, string $confirm): array
    {
        $row = $this->activations->findActiveByHash($this->hashToken($token));
        if ($row === null) {
            return ['ok' => false, 'errors' => ['This activation link is invalid or has already been used.'], 'user_id' => null];
        }
        if ($this->isExpired((string) $row['expires_at'])) {
            return ['ok' => false, 'errors' => ['This activation link has expired. Please ask an administrator to resend it.'], 'user_id' => null];
        }

        $userId = (int) $row['user_id'];
        $user   = $this->users->findById($userId);
        if ($user === null) {
            return ['ok' => false, 'errors' => ['The account for this link no longer exists.'], 'user_id' => null];
        }

        $errors = [];
        foreach ($this->passwordPolicy->validate($password, (string) $user['email']) as $passwordError) {
            $errors[] = $passwordError;
        }
        if ($password !== $confirm) {
            $errors[] = 'The two passwords do not match.';
        }

        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'user_id' => $userId];
        }

        $this->users->activate($userId, password_hash($password, PASSWORD_DEFAULT));
        $this->activations->markUsed((int) $row['activation_id']);

        return ['ok' => true, 'errors' => [], 'user_id' => $userId];
    }

    /** SHA-256 of the high-entropy token — safe deterministic lookup key. */
    private function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    private function isExpired(string $expiresAt): bool
    {
        try {
            $exp = new \DateTimeImmutable($expiresAt, new \DateTimeZone('UTC'));
        } catch (\Exception) {
            return true; // unparseable expiry => treat as expired (fail safe)
        }
        return $this->clock->now() > $exp;
    }
}
