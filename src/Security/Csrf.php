<?php

declare(strict_types=1);

namespace MediShield\Security;

/**
 * Csrf
 * ----
 * Generates and verifies CSRF (Cross-Site Request Forgery) tokens for forms that
 * create, update, or submit data (spec §17).
 *
 * The token lives in the user's session. To keep this class unit-testable it does
 * NOT touch PHP's global session directly; instead callers pass the session array
 * (typically `$_SESSION`) by reference. In a page this looks like:
 *
 *     $token = Csrf::token($_SESSION);          // put in a hidden form field
 *     ...
 *     if (!Csrf::check($_SESSION, $_POST['csrf_token'] ?? null)) { reject(); }
 *
 * Verification uses hash_equals() for a timing-safe comparison.
 */
final class Csrf
{
    /** Session array key under which the token is stored. */
    public const SESSION_KEY = 'csrf_token';

    /** Conventional hidden form field / POST key name. */
    public const FIELD = 'csrf_token';

    /**
     * Return the session's CSRF token, generating and storing one if absent.
     *
     * @param array<string,mixed> $session Session storage, passed by reference (e.g. $_SESSION).
     */
    public static function token(array &$session): string
    {
        if (empty($session[self::SESSION_KEY]) || !is_string($session[self::SESSION_KEY])) {
            $session[self::SESSION_KEY] = bin2hex(random_bytes(32));
        }
        return $session[self::SESSION_KEY];
    }

    /**
     * Timing-safe check that a submitted token matches the session token.
     *
     * @param array<string,mixed> $session   Session storage (e.g. $_SESSION).
     * @param string|null         $submitted Token received from the form POST.
     */
    public static function check(array $session, ?string $submitted): bool
    {
        $stored = $session[self::SESSION_KEY] ?? null;
        if (!is_string($stored) || $stored === '' || !is_string($submitted) || $submitted === '') {
            return false;
        }
        return hash_equals($stored, $submitted);
    }
}
