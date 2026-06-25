<?php

declare(strict_types=1);

namespace MediShield\Security;

/**
 * PasswordPolicy
 * --------------
 * Enforces MediShield's password rules (spec §9.1) at the point a password is
 * created or reset. This is pure validation logic — no hashing, no storage — so
 * it is fully unit-tested.
 *
 * Rules:
 *   - At least {@see MIN_LENGTH} characters.
 *   - Contains at least one uppercase letter, one lowercase letter, one digit,
 *     and one symbol (non-alphanumeric).
 *   - Must NOT equal the local-part of the user's email (case-insensitive),
 *     to stop trivially guessable "name = password" choices.
 *
 * Hashing of an accepted password is the caller's job (see {@see UserService}),
 * using PHP's password_hash(). Passwords are never encrypted, only hashed.
 */
final class PasswordPolicy
{
    /** Minimum acceptable password length. */
    public const MIN_LENGTH = 10;

    /**
     * Validate a candidate password.
     *
     * @param string $password The plaintext password to check.
     * @param string $email    The user's email; its local-part is disallowed as a password.
     * @return string[]         A list of human-readable error messages. Empty array == valid.
     */
    public function validate(string $password, string $email = ''): array
    {
        $errors = [];

        if (mb_strlen($password) < self::MIN_LENGTH) {
            $errors[] = 'Password must be at least ' . self::MIN_LENGTH . ' characters long.';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter.';
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter.';
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one digit.';
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one symbol.';
        }

        $localPart = $email !== '' ? strstr($email, '@', true) : '';
        if ($localPart !== false && $localPart !== '' && strcasecmp($password, $localPart) === 0) {
            $errors[] = 'Password must not match the email name.';
        }

        return $errors;
    }

    /** Convenience boolean check: true when the password satisfies every rule. */
    public function isValid(string $password, string $email = ''): bool
    {
        return $this->validate($password, $email) === [];
    }
}
