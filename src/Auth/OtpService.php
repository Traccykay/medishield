<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Support\Clock;

/**
 * OtpService
 * ----------
 * Implements the login SECOND FACTOR (2FA). After a correct email+password
 * (handled by {@see AuthService}), the user must also enter a short-lived
 * one-time passcode (OTP) emailed to them. Only then are they fully logged in.
 *
 * Design (security rationale):
 *   - The code is 6 characters from an UNAMBIGUOUS alphabet (no 0/O, 1/I) so it is
 *     easy to retype, generated with a cryptographically-secure RNG (random_int).
 *   - Only a bcrypt HASH of the code is stored (password_hash), so a database leak
 *     never reveals a usable code. Verification uses password_verify (constant
 *     time for a given hash).
 *   - Each code EXPIRES after a few minutes ({@see $ttlMinutes}) — replay window
 *     is small.
 *   - Wrong tries are counted; after {@see $maxAttempts} the code is dead and the
 *     user must restart login. This stops brute-forcing the small code space.
 *   - Issuing a new code invalidates older ones, so only one code is ever live.
 *
 * This class deliberately returns a small status string and lets the calling page
 * handle session/audit/redirect side effects — the same testable split used by
 * AuthService.
 */
final class OtpService
{
    /** Alphabet excludes easily-confused characters (0/O, 1/I/L). */
    private const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

    public function __construct(
        private OtpRepository $otps,
        private Clock $clock,
        private int $length = 6,
        private int $ttlMinutes = 10,
        private int $maxAttempts = 5
    ) {
    }

    /**
     * Generate, store (hashed), and return a fresh code for a user. The caller is
     * responsible for emailing the returned plaintext code and auditing OTP_SENT.
     * Any previously-issued unused code for this user is invalidated first.
     */
    public function issue(int $userId): string
    {
        $this->otps->invalidateAllForUser($userId);

        $code = $this->generateCode();
        $hash = password_hash($code, PASSWORD_DEFAULT);
        $expiresAt = $this->clock->now()
            ->add(new \DateInterval('PT' . max(1, $this->ttlMinutes) . 'M'))
            ->format('Y-m-d H:i:s');

        $this->otps->create($userId, $hash, $expiresAt);

        return $code;
    }

    /**
     * Verify a submitted code for a user.
     *
     * @return string One of:
     *   'ok'        — code correct; it has been consumed, caller may complete login.
     *   'invalid'   — wrong code; attempt counted, user may retry.
     *   'expired'   — newest code has passed its expiry.
     *   'too_many'  — attempt limit reached; the code is dead, restart login.
     *   'none'      — there is no active code (e.g. session/code mismatch).
     */
    public function verify(int $userId, string $code): string
    {
        $row = $this->otps->latestActiveForUser($userId);
        if ($row === null) {
            return 'none';
        }

        // Expiry takes priority — an expired code is never accepted.
        if ($this->isExpired((string) $row['expires_at'])) {
            return 'expired';
        }

        // Already burned through the attempt budget?
        if ((int) $row['attempts'] >= $this->maxAttempts) {
            return 'too_many';
        }

        if (password_verify($code, (string) $row['code_hash'])) {
            $this->otps->markUsed((int) $row['otp_id']);
            return 'ok';
        }

        $newCount = $this->otps->incrementAttempts((int) $row['otp_id']);
        return $newCount >= $this->maxAttempts ? 'too_many' : 'invalid';
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

    /** Build a random code of the configured length from the unambiguous alphabet. */
    private function generateCode(): string
    {
        $alphabetLen = strlen(self::ALPHABET);
        $code = '';
        for ($i = 0; $i < max(1, $this->length); $i++) {
            $code .= self::ALPHABET[random_int(0, $alphabetLen - 1)];
        }
        return $code;
    }
}
