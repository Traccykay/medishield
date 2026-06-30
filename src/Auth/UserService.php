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
    /**
     * Sentinel stored in password_hash for accounts created via the activation-link
     * flow. It is NOT a valid bcrypt hash, so password_verify() against it always
     * returns false — a pending account therefore cannot be logged into until the
     * user follows the emailed link and {@see UserRepository::activate()} replaces
     * this sentinel with a real hash.
     */
    public const PENDING_PASSWORD_SENTINEL = 'PENDING_ACTIVATION';

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

    /**
     * Create a PENDING user with no usable password (account-activation-link flow,
     * spec §9.2 / Deliverable). Unlike {@see createUser()} the admin does NOT set a
     * password here — instead the account is stored with status 'inactive' and a
     * sentinel password hash. The caller then issues an activation token (see
     * ActivationService) and emails the user a link to choose their own password,
     * which activates the account.
     *
     * Validates name/email/role and email uniqueness exactly like createUser() but
     * deliberately skips the password policy (there is no password yet).
     *
     * @return array{ok:bool, errors:string[], user_id:?int}
     */
    public function createPendingUser(
        string $fullName,
        string $email,
        string $role
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

        if (filter_var($email, FILTER_VALIDATE_EMAIL) !== false && $this->users->emailExists($email)) {
            $errors[] = 'An account with this email already exists.';
        }

        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors, 'user_id' => null];
        }

        // No usable password and inactive until the user activates via the link.
        $userId = $this->users->create(
            $fullName,
            $email,
            self::PENDING_PASSWORD_SENTINEL,
            $role,
            false,        // must_change_password — activation sets the password instead
            'inactive'
        );

        return ['ok' => true, 'errors' => [], 'user_id' => $userId];
    }

    /**
     * Change an existing user's password. Verifies the current password, enforces
     * the password policy on the new one (including "must differ from current"),
     * then persists the new hash and clears the must_change_password flag.
     *
     * Looks the user up by id so the caller (a page) never has to trust a hash or
     * email coming from the request.
     *
     * @return array{ok:bool, errors:string[]}
     */
    public function changePassword(
        int $userId,
        string $currentPassword,
        string $newPassword
    ): array {
        $user = $this->users->findById($userId);
        if ($user === null) {
            return ['ok' => false, 'errors' => ['Account not found.']];
        }

        $errors = [];

        // The user must prove they know the current password before changing it.
        if (!password_verify($currentPassword, (string) $user['password_hash'])) {
            $errors[] = 'Your current password is incorrect.';
        }

        // Enforce strength rules (length, character classes, not-equal-to-email).
        foreach ($this->passwordPolicy->validate($newPassword, (string) $user['email']) as $passwordError) {
            $errors[] = $passwordError;
        }

        // A password change must actually change the password.
        if ($newPassword !== '' && password_verify($newPassword, (string) $user['password_hash'])) {
            $errors[] = 'The new password must be different from the current password.';
        }

        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors];
        }

        $this->users->updatePassword($userId, password_hash($newPassword, PASSWORD_DEFAULT));

        return ['ok' => true, 'errors' => []];
    }
}
