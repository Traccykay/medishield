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
use MediShield\Security\Csrf;

require_once __DIR__ . '/bootstrap.php';

/* ---------------------------------------------------------------------------
 * Session <-> user mapping
 * ------------------------------------------------------------------------- */

if (!function_exists('current_user')) {
    /**
     * The currently authenticated user as a small associative array, or null when
     * nobody is logged in. Only non-sensitive identity fields are kept in session.
     *
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool,auth_version:int}|null
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

        $_SESSION['auth'] = ms_session_validator()->createAuthenticatedSession($user);
        foreach (ms_session_validator()->createLoginTimestamps() as $key => $value) {
            $_SESSION[$key] = $value;
        }
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

if (!function_exists('audit_forced_logout')) {
    /**
     * Record a timeout or server-side revocation without copying arbitrary session
     * values into the forensic log.
     *
     * @param array<string,mixed> $auth
     */
    function audit_forced_logout(array $auth, string $status, string $anomaly = 'NORMAL'): void
    {
        $candidateId = $auth['user_id'] ?? null;
        $userId = is_int($candidateId) && $candidateId > 0 ? $candidateId : null;
        $candidateRole = $auth['role'] ?? null;
        $role = is_string($candidateRole) && Rbac::isValidRole($candidateRole)
            ? $candidateRole
            : 'guest';

        ms_audit_log([
            'user_id' => $userId,
            'user_role' => $role,
            'action' => 'LOGOUT',
            'module' => 'auth',
            'status' => $status,
            'anomaly_flag' => $anomaly,
        ]);
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
        $timingStatus = ms_session_validator()->validateSessionTiming(
            [
                'login_at' => $_SESSION['login_at'] ?? null,
                'last_activity' => $_SESSION['last_activity'] ?? null,
            ],
            $idleMax,
            $absMax
        );
        if ($timingStatus !== 'valid') {
            audit_forced_logout(
                current_user() ?? [],
                $timingStatus === 'expired' ? 'SUCCESS' : 'BLOCKED',
                $timingStatus === 'malformed' ? 'SUSPICIOUS' : 'NORMAL'
            );
            logout_user();
            redirect('/login.php?timeout=1');
        }

        $_SESSION['last_activity'] = time();
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
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool,auth_version:int}
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

        $user = ms_session_validator()->authenticateSession($user);
        if ($user === null) {
            // A status or password change in another browser invalidates this
            // preserved session before any protected page can act on it.
            audit_forced_logout(current_user() ?? [], 'BLOCKED');
            logout_user();
            redirect('/login.php');
        }
        $_SESSION['auth'] = $user;

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

if (!function_exists('require_nav')) {
    /**
     * Require that the user's role may access the given sidebar nav key (e.g.
     * 'reports', 'payments'). This is the SERVER-SIDE enforcement behind a sidebar
     * link — the sidebar only hides links, so each page that a nav item points to
     * must call this so a user cannot reach it by typing the URL. Audits and blocks
     * on failure.
     *
     * @return array{user_id:int,role:string,full_name:string,email:string,must_change:bool}
     */
    function require_nav(string $navKey): array
    {
        $user = require_login();

        if (!Rbac::canAccessNav($user['role'], $navKey)) {
            deny_access($user, "nav:$navKey");
        }

        return $user;
    }
}

if (!function_exists('request_positive_int')) {
    /**
     * Parse an untrusted request identifier without coercing arrays or partial
     * numeric strings into valid object IDs.
     */
    function request_positive_int(mixed $value): int
    {
        if (!is_int($value) && !is_string($value)) {
            return 0;
        }

        $filtered = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        return $filtered === false ? 0 : (int) $filtered;
    }
}

if (!function_exists('request_string')) {
    /** Return a form scalar as text; arrays and objects are invalid input. */
    function request_string(mixed $value): string
    {
        return is_string($value) || is_int($value) || is_float($value)
            ? (string) $value
            : '';
    }
}

if (!function_exists('request_post_guard')) {
    /**
     * Enforce the request method and validate CSRF before a controller parses
     * request fields, looks up an object, or invokes domain work.
     *
     * Mixed GET/form pages receive false for GET and true for a verified POST.
     * Action-only controllers pass $postOnly=true so every non-POST method is
     * rejected with 405. CSRF failures always terminate with the same generic
     * 403 response after exactly one best-effort audit attempt.
     */
    function request_post_guard(string $module, bool $postOnly = false): bool
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        $method = is_string($method) ? strtoupper($method) : '';

        if ($method === 'GET' && !$postOnly) {
            return false;
        }

        if ($method !== 'POST') {
            if (!headers_sent()) {
                header('Allow: POST');
            }
            http_response_code(405);
            exit('Request method not allowed.');
        }

        if (Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
            return true;
        }

        $allowedModules = [
            'admin',
            'auth',
            'billing',
            'doctor',
            'lab',
            'nurse',
            'patients',
            'pharmacy',
            'reception',
            'triage',
        ];
        $auditModule = in_array($module, $allowedModules, true) ? $module : 'auth';

        $actor = current_user();
        $candidateId = is_array($actor) ? ($actor['user_id'] ?? null) : null;
        $candidateRole = is_array($actor) ? ($actor['role'] ?? null) : null;
        $role = is_string($candidateRole) && Rbac::isValidRole($candidateRole)
            ? $candidateRole
            : 'guest';
        $userId = $role !== 'guest' && is_int($candidateId) && $candidateId > 0
            ? $candidateId
            : null;

        try {
            ms_audit_log([
                'user_id' => $userId,
                'user_role' => $role,
                'action' => 'CSRF_REJECTED',
                'module' => $auditModule,
                'status' => 'BLOCKED',
                'anomaly_flag' => 'SUSPICIOUS',
            ]);
        } catch (\Throwable $exception) {
            // The rejection must remain fail-closed even if an alternate audit
            // adapter violates ms_audit_log()'s no-throw contract.
            error_log('[request-guard] CSRF audit failed: ' . $exception->getMessage());
        }

        http_response_code(403);
        exit('Request could not be processed.');
    }
}

if (!function_exists('require_doctor_patient_access')) {
    /**
     * Enforce the complete doctor object-level policy before any patient or
     * clinical record is retrieved by a route.
     *
     * @param array<string,mixed> $user
     */
    function require_doctor_patient_access(
        array $user,
        int $patientId,
        int $visitId,
        string $target
    ): void {
        if (
            (string) ($user['role'] ?? '') !== Rbac::ROLE_DOCTOR
            || !ms_doctor_authorizer()->canAccess((int) $user['user_id'], $patientId, $visitId)
        ) {
            deny_access($user, $target, $patientId);
        }
    }
}

if (!function_exists('deny_access')) {
    /**
     * Record an UNAUTHORIZED_ACCESS audit event (status BLOCKED) and render the
     * 403 page, then stop. Centralised so every denial is logged identically.
     *
     * @param array<string,mixed> $user The authenticated user who was denied.
     */
    function deny_access(array $user, string $target, ?int $patientId = null): never
    {
        $targetModule = explode(':', $target, 2)[0];
        $module = in_array($targetModule, [
            'admin',
            'auth',
            'billing',
            'doctor',
            'lab',
            'nurse',
            'patients',
            'pharmacy',
            'reception',
        ], true) ? $targetModule : 'auth';

        ms_audit_log([
            'user_id'      => (int) $user['user_id'],
            'user_role'    => (string) $user['role'],
            'action'       => 'UNAUTHORIZED_ACCESS',
            'module'       => $module,
            'affected_record_id' => $patientId !== null && $patientId > 0
                ? (string) $patientId
                : null,
            'status'       => 'BLOCKED',
            'anomaly_flag' => 'HIGH_RISK',
        ]);

        http_response_code(403);
        redirect('/unauthorized.php');
    }
}

if (!function_exists('landing_path_for')) {
    function landing_path_for(string $role): string
    {
        return Rbac::dashboardPath($role);
    }
}
