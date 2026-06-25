<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Security\PasswordPolicy;

/**
 * UserService
 * -----------
 * Application logic for creating users (the "registration" performed by an admin,
 * spec §9.2). Public self-registration does NOT exist in MediShield — only an
 * administrator (e.g. the seeded superadmin) creates accounts and assigns roles.
 *
 * This service validates input, enforces the password policy, guarantees email
 * uniqueness, hashes the password, and persists via {@see UserRepository}. It
 * returns a structured result so the page can render field errors cleanly.
 *
 * Newly created accounts start with must_change_password = true, forcing the user
 * to choose their own password on first login.
 *
 * Result shape:
 *   ['ok' => bool, 'errors' => string[], 'user_id' => int|null]
 */
final class UserService
{
    public function __construct(
        private UserRepository $users,
        private PasswordPolicy $passwordPolicy
    ) {
    }

    /**
     * Validate and create a user.
     *
     * @return array{ok:bool, errors:string[], user_id:?int}
     */
    public function createUser(
        string $fullName,
        string $email,
        string $password,
        string $role,
        bool $mustChangePassword = true
    ): array {
        $fullName = trim($fullName);
        $email    = trim($email);
        $errors   = [];

        if ($fullName === '') {
            $errors[] = 'Full name is required.';
        }

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'A valid email address is required.';
        }

        if (!Rbac::isValidRole($role)) {
            $errors[] = 'A valid role must be selected.';
        }

        // Password rules (length, character classes, not-equal-to-email).
        foreach ($this->passwordPolicy->validate($password, $email) as $passwordError) {
            $errors[] = $passwordError;
        }

        // Only check uniqueness once the email itself is well-formed.
        if (filter_var($email, FILTER_VALIDATE_EMAIL) !== false && $this->users->emailExists($email)) {
            $errors[] = 'An account with this email already exists.';
        }

        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'user_id' => null];
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $userId = $this->users->create($fullName, $email, $hash, $role, $mustChangePassword);

        return ['ok' => true, 'errors' => [], 'user_id' => $userId];
    }
}
