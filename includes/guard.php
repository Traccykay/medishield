<?php

declare(strict_types=1);

/**
 * guard.php
 * ---------
 * Server-side authentication & authorization helpers used by every protected
 * page. Per the golden security rules, "hidden UI is not authorization" — every
 * page must call one of these guards BEFORE rendering or mutating anything.
 *
 * Responsibilities:
 *   - Track the logged-in user in the session (set at login, read on each request).
 *   - Prevent session fixation by regenerating the session id at login.
 *   - Enforce idle and absolute session timeouts (spec §16).
 *   - Force a password change when must_change_password is set (first login).
 *   - Gate pages by role / URL-area via Rbac, auditing BLOCKED attempts.
 *
 * Depends on bootstrap.php (must be included first): it provides the session,
 * config, audit helper (ms_audit_log) and Rbac via the autoloader.
 */

use MediShield\Auth\Rbac;

require_once __DIR__ . '/bootstrap.php';

/* ---------------------------------------------------------------------------
 * Session <-> user mapping
 * ------------------------------------------------------------------------- */

if (!function_exists('current_user')) {
    /**
     * The currently authenticated user as a small associative array, or null when
     * nobody is logged in. Only non-sensitive identity fields are kept in session.
     *
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool}|null
     */
    function current_user(): ?array
    {
        if (empty($_SESSION['auth']) || !is_array($_SESSION['auth'])) {
            return null;
        }
        return $_SESSION['auth'];
    }
}

if (!function_exists('is_logged_in')) {
    function is_logged_in(): bool
    {
        return current_user() !== null;
    }
}

if (!function_exists('login_user')) {
    /**
     * Establish an authenticated session for a freshly verified user row.
     * Regenerates the session id (anti-fixation) and records timestamps used by
     * the idle / absolute timeout checks.
     *
     * @param array<string,mixed> $user A users-table row (from the repository).
     */
    function login_user(array $user): void
    {
        // New privilege level => new session id, discarding the pre-login one.
        session_regenerate_id(true);

        $now = time();
        $_SESSION['auth'] = [
            'user_id'     => (int) $user['user_id'],
            'role'        => (string) $user['role'],
            'full_name'   => (string) $user['full_name'],
            'email'       => (string) $user['email'],
            'must_change' => (bool) ($user['must_change_password'] ?? false),
        ];
        $_SESSION['login_at']      = $now;  // for absolute timeout
        $_SESSION['last_activity'] = $now;  // for idle timeout
    }
}

if (!function_exists('logout_user')) {
    /** Fully tear down the session (used by logout and on timeout). */
    function logout_user(): void
    {
        $_SESSION = [];

        // Expire the session cookie in the browser as well.
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                [
                    'expires'  => time() - 42000,
                    'path'     => $params['path'],
                    'domain'   => $params['domain'],
                    'secure'   => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => $params['samesite'] ?? 'Strict',
                ]
            );
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }
}

/* ---------------------------------------------------------------------------
 * Timeout enforcement
 * ------------------------------------------------------------------------- */

if (!function_exists('enforce_timeouts')) {
    /**
     * Log the user out and redirect to the login page if either the idle window
     * or the absolute session lifetime has been exceeded. No-op for guests.
     */
    function enforce_timeouts(): void
    {
        if (!is_logged_in()) {
            return;
        }

        $cfg      = ms_config()['session'];
        $idleMax  = (int) ($cfg['idle_timeout_seconds'] ?? 1200);
        $absMax   = (int) ($cfg['absolute_timeout_seconds'] ?? 28800);
        $now      = time();
        $lastSeen = (int) ($_SESSION['last_activity'] ?? $now);
        $loginAt  = (int) ($_SESSION['login_at'] ?? $now);

        $idleExpired = ($now - $lastSeen) > $idleMax;
        $absExpired  = ($now - $loginAt) > $absMax;

        if ($idleExpired || $absExpired) {
            logout_user();
            redirect('/login.php?timeout=1');
        }

        $_SESSION['last_activity'] = $now;
    }
}

/* ---------------------------------------------------------------------------
 * Page guards
 * ------------------------------------------------------------------------- */

if (!function_exists('require_login')) {
    /**
     * Ensure a user is authenticated (else redirect to login) and that the session
     * has not timed out. If the account is flagged must_change_password, force a
     * redirect to the change-password page — unless $allowPasswordChange is true
     * (which the change-password page itself passes, to avoid a redirect loop).
     *
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool}
     */
    function require_login(bool $allowPasswordChange = false): array
    {
        if (!is_logged_in()) {
            redirect('/login.php');
        }

        enforce_timeouts();

        $user = current_user();
        if ($user === null) {        // timeout may have cleared the session
            redirect('/login.php');
        }

        if ($user['must_change'] && !$allowPasswordChange) {
            redirect('/change_password.php');
        }

        return $user;
    }
}

if (!function_exists('require_role')) {
    /**
     * Require an authenticated user whose role is exactly $role. On mismatch,
     * audit the blocked attempt and show the 403 page. Returns the user on success.
     *
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool}
     */
    function require_role(string $role): array
    {
        $user = require_login();

        if ($user['role'] !== $role) {
            deny_access($user, "role:$role");
        }

        return $user;
    }
}

if (!function_exists('require_area')) {
    /**
     * Require that the user's role may access the given URL area (e.g. 'admin'),
     * using the central Rbac map. Audits and blocks on failure.
     *
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool}
     */
    function require_area(string $area): array
    {
        $user = require_login();

        if (!Rbac::canAccessArea($user['role'], $area)) {
            deny_access($user, "area:$area");
        }

        return $user;
    }
}

if (!function_exists('deny_access')) {
    /**
     * Record an UNAUTHORIZED_ACCESS audit event (status BLOCKED) and render the
     * 403 page, then stop. Centralised so every denial is logged identically.
     *
     * @param array<string,mixed> $user The authenticated user who was denied.
     */
    function deny_access(array $user, string $target): never
    {
        ms_audit_log([
            'user_id'      => (int) $user['user_id'],
            'user_role'    => (string) $user['role'],
            'action'       => 'UNAUTHORIZED_ACCESS',
            'module'       => 'auth',
            'status'       => 'BLOCKED',
            'anomaly_flag' => 'SUSPICIOUS',
        ]);

        http_response_code(403);
        redirect('/unauthorized.php');
    }
}

if (!function_exists('landing_path_for')) {
    /**
     * Where to send a user after login. In Deliverable 1 only the admin area is
     * built, so admins go to their dashboard and every other role lands on the
     * generic placeholder dashboard. Later deliverables will switch this to
     * Rbac::dashboardPath() as each role's workspace is implemented.
     */
    function landing_path_for(string $role): string
    {
        return $role === Rbac::ROLE_ADMIN ? '/admin/dashboard.php' : '/dashboard.php';
    }
}
