<?php

declare(strict_types=1);

namespace MediShield\Auth;

/**
 * Validates the server-side authentication payload before every protected request.
 *
 * PHP session identifiers remain valid until their lifetime expires, so a session
 * payload alone cannot reflect an administrator's account deactivation or a later
 * password replacement. This validator compares a per-login fingerprint of the
 * stored password verifier with the current database value and confirms that the
 * account remains active. It therefore fails closed for legacy or malformed
 * session payloads and revokes all preserved sessions after either event.
 */
final class SessionValidator
{
    public function __construct(private UserRepository $users)
    {
    }

    /**
     * Create the minimal, server-side authentication payload for a verified user.
     *
     * The fingerprint is derived from—not equal to—the password verifier. It is
     * only stored in PHP's server-side session and changes whenever the password
     * verifier changes.
     *
     * @param array<string,mixed> $user A current users-table row.
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool,credential_fingerprint:string}
     */
    public function createAuthenticatedSession(array $user): array
    {
        return [
            'user_id'                => (int) $user['user_id'],
            'role'                   => (string) $user['role'],
            'full_name'              => (string) $user['full_name'],
            'email'                  => (string) $user['email'],
            'must_change'            => (bool) ($user['must_change_password'] ?? false),
            'credential_fingerprint' => hash('sha256', (string) $user['password_hash']),
        ];
    }

    /**
     * Authenticate a preserved PHP session against the authoritative user row.
     *
     * @param array<string,mixed> $sessionAuth The auth payload saved at login.
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool,credential_fingerprint:string}|null
     */
    public function authenticateSession(array $sessionAuth): ?array
    {
        $userId = $sessionAuth['user_id'] ?? null;
        $fingerprint = $sessionAuth['credential_fingerprint'] ?? null;
        if (!is_int($userId) && !ctype_digit((string) $userId)) {
            return null;
        }
        if ((int) $userId <= 0 || !is_string($fingerprint) || $fingerprint === '') {
            return null;
        }

        $user = $this->users->findById((int) $userId);
        if ($user === null || (string) $user['status'] !== 'active') {
            return null;
        }

        $currentAuth = $this->createAuthenticatedSession($user);
        if (!hash_equals($currentAuth['credential_fingerprint'], $fingerprint)) {
            return null;
        }

        return $currentAuth;
    }
}
