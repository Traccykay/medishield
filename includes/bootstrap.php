<?php

declare(strict_types=1);

/**
 * bootstrap.php
 * -------------
 * Single entry point that every public page includes FIRST. It wires the whole
 * application together so individual pages stay thin and consistent:
 *
 *   1. Loads the Composer autoloader (PSR-4 "MediShield\\" => src/).
 *   2. Loads configuration (config/config.php, falling back to the committed
 *      config.sample.php so the app still boots before setup-db.ps1 has run).
 *   3. Forces UTC and installs an error handler that logs to logs/app_errors.log
 *      instead of leaking stack traces to the browser.
 *   4. Hardens and starts the PHP session (HttpOnly, SameSite=Strict, Secure on
 *      HTTPS) BEFORE any output — this must happen before session_start().
 *   5. Sends the security headers (see headers.php).
 *   6. Exposes a tiny lazy "service container" (ms_db, ms_auth, ms_user_service,
 *      ms_audit, ms_crypto, ...) plus view helpers (e(), redirect(), ms_audit_log()).
 *
 * Pages should never instantiate repositories/services directly; they ask the
 * container, so construction stays in one audited place.
 */

use MediShield\Audit\AuditLogger;
use MediShield\Auth\ActivationRepository;
use MediShield\Auth\ActivationService;
use MediShield\Auth\AuthService;
use MediShield\Auth\OtpRepository;
use MediShield\Auth\OtpService;
use MediShield\Auth\Rbac;
use MediShield\Auth\SessionValidator;
use MediShield\Auth\UserRepository;
use MediShield\Auth\UserService;
use MediShield\Clinical\ClinicalRepository;
use MediShield\Clinical\ClinicalService;
use MediShield\Database\Connection;
use MediShield\Mail\LogMailer;
use MediShield\Mail\Mailer;
use MediShield\Mail\SmtpMailer;
use MediShield\Patient\PatientRepository;
use MediShield\Patient\PatientService;
use MediShield\Security\AuditChain;
use MediShield\Security\Crypto;
use MediShield\Security\PasswordPolicy;
use MediShield\Support\Clock;
use MediShield\Visit\VisitRepository;
use MediShield\Visit\VisitService;

require_once __DIR__ . '/../vendor/autoload.php';

/* ---------------------------------------------------------------------------
 * 1. Configuration
 * ------------------------------------------------------------------------- */

if (!function_exists('ms_config')) {
    /**
     * Return the application configuration array (loaded once).
     * Prefers config/config.php; falls back to the committed sample template.
     */
    function ms_config(): array
    {
        static $config = null;
        if ($config !== null) {
            return $config;
        }

        $real   = __DIR__ . '/../config/config.php';
        $sample = __DIR__ . '/../config/config.sample.php';
        $config = require (is_file($real) ? $real : $sample);

        $testDatabase = getenv('MEDISHIELD_DB_NAME');
        if (is_string($testDatabase) && $testDatabase !== '') {
            $config['db']['name'] = $testDatabase;
        }
        $testMailDir = getenv('MEDISHIELD_MAIL_DUMP_DIR');
        if (is_string($testMailDir) && $testMailDir !== '') {
            $config['mail']['dump_dir'] = $testMailDir;
        }

        return $config;
    }
}

/* ---------------------------------------------------------------------------
 * 2. Timezone + error handling (no stack traces to the browser)
 * ------------------------------------------------------------------------- */

date_default_timezone_set('UTC');

(static function (): void {
    $logFile = ms_config()['error_log'] ?? (__DIR__ . '/../logs/app_errors.log');
    $logDir  = dirname($logFile);
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0775, true);
    }

    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    ini_set('error_log', $logFile);

    set_exception_handler(static function (\Throwable $e) use ($logFile): void {
        error_log('[uncaught] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
        http_response_code(500);
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
        }
        echo '<!doctype html><meta charset="utf-8"><title>Error</title>'
           . '<p>An unexpected error occurred. The incident has been logged.</p>';
    });
})();

/* ---------------------------------------------------------------------------
 * 3. Session hardening + start (must precede any output)
 * ------------------------------------------------------------------------- */

(static function (): void {
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $cfg   = ms_config();
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $https,        // Secure only when actually on HTTPS
        'httponly' => true,          // JS cannot read the session cookie
        'samesite' => 'Strict',      // mitigates CSRF on top-level navigations
    ]);

    session_name($cfg['session']['cookie_name'] ?? 'MEDISHIELD_SID');
    session_start();
})();

require_once __DIR__ . '/headers.php';
ms_send_security_headers();

/* ---------------------------------------------------------------------------
 * 4. Lazy service container
 * ------------------------------------------------------------------------- */

if (!function_exists('ms_clock')) {
    function ms_clock(): Clock
    {
        static $clock = null;
        return $clock ??= new Clock();
    }
}

if (!function_exists('ms_db')) {
    function ms_db(): \PDO
    {
        static $pdo = null;
        return $pdo ??= Connection::fromConfig(ms_config());
    }
}

if (!function_exists('ms_crypto')) {
    function ms_crypto(): Crypto
    {
        static $crypto = null;
        return $crypto ??= Crypto::fromHexKey(ms_config()['encryption_key_hex']);
    }
}

if (!function_exists('ms_user_repo')) {
    function ms_user_repo(): UserRepository
    {
        static $repo = null;
        return $repo ??= new UserRepository(ms_db(), ms_clock());
    }
}

if (!function_exists('ms_auth')) {
    function ms_auth(): AuthService
    {
        static $auth = null;
        if ($auth === null) {
            $cfg  = ms_config()['auth'];
            $auth = new AuthService(
                ms_user_repo(),
                ms_clock(),
                (int) $cfg['max_failed_attempts'],
                (int) $cfg['suspicious_at'],
                (int) $cfg['lock_minutes']
            );
        }
        return $auth;
    }
}

if (!function_exists('ms_user_service')) {
    function ms_user_service(): UserService
    {
        static $svc = null;
        return $svc ??= new UserService(ms_user_repo(), new PasswordPolicy());
    }
}

if (!function_exists('ms_session_validator')) {
    function ms_session_validator(): SessionValidator
    {
        static $validator = null;
        return $validator ??= new SessionValidator(ms_user_repo());
    }
}

if (!function_exists('ms_audit')) {
    function ms_audit(): AuditLogger
    {
        static $logger = null;
        if ($logger === null) {
            $chain  = AuditChain::fromHexKey(ms_config()['audit_hmac_key_hex']);
            $logger = new AuditLogger(ms_db(), $chain, ms_clock());
        }
        return $logger;
    }
}

if (!function_exists('ms_mailer')) {
    /**
     * The configured mail transport. 'log' (default) writes each message to
     * logs/mail/ for local development; 'smtp' sends real email via PHPMailer.
     * SmtpMailer is only constructed when actually selected, so PHPMailer is not
     * required to be installed for the default dev flow.
     */
    function ms_mailer(): Mailer
    {
        static $mailer = null;
        if ($mailer === null) {
            $cfg       = ms_config()['mail'] ?? [];
            $transport = $cfg['transport'] ?? 'log';

            if ($transport === 'smtp') {
                $mailer = new SmtpMailer(
                    (array) ($cfg['smtp'] ?? []),
                    (string) ($cfg['from_email'] ?? 'no-reply@medishield.local'),
                    (string) ($cfg['from_name'] ?? 'MediShield')
                );
            } else {
                $mailer = new LogMailer(
                    (string) ($cfg['dump_dir'] ?? (__DIR__ . '/../logs/mail')),
                    ms_clock()
                );
            }
        }
        return $mailer;
    }
}

if (!function_exists('ms_otp_service')) {
    function ms_otp_service(): OtpService
    {
        static $svc = null;
        if ($svc === null) {
            $cfg = ms_config()['otp'] ?? [];
            $svc = new OtpService(
                new OtpRepository(ms_db(), ms_clock()),
                ms_clock(),
                (int) ($cfg['length'] ?? 6),
                (int) ($cfg['ttl_minutes'] ?? 10),
                (int) ($cfg['max_attempts'] ?? 5)
            );
        }
        return $svc;
    }
}

if (!function_exists('ms_activation_service')) {
    function ms_activation_service(): ActivationService
    {
        static $svc = null;
        if ($svc === null) {
            $cfg = ms_config()['activation'] ?? [];
            $svc = new ActivationService(
                new ActivationRepository(ms_db(), ms_clock()),
                ms_user_repo(),
                new PasswordPolicy(),
                ms_clock(),
                (int) ($cfg['ttl_hours'] ?? 48)
            );
        }
        return $svc;
    }
}

if (!function_exists('ms_patient_repo')) {
    function ms_patient_repo(): PatientRepository
    {
        static $repo = null;
        return $repo ??= new PatientRepository(ms_db(), ms_clock());
    }
}

if (!function_exists('ms_patient_service')) {
    function ms_patient_service(): PatientService
    {
        static $svc = null;
        return $svc ??= new PatientService(ms_patient_repo(), ms_user_repo());
    }
}

if (!function_exists('ms_clinical_repo')) {
    function ms_clinical_repo(): ClinicalRepository
    {
        static $repo = null;
        return $repo ??= new ClinicalRepository(ms_db(), ms_clock());
    }
}

if (!function_exists('ms_clinical_service')) {
    function ms_clinical_service(): ClinicalService
    {
        static $svc = null;
        return $svc ??= new ClinicalService(ms_clinical_repo(), ms_patient_repo(), ms_crypto());
    }

    if (!function_exists('ms_visit_repo')) {
        function ms_visit_repo(): VisitRepository
        {
            static $repo = null;
            return $repo ??= new VisitRepository(ms_db(), ms_clock());
        }
    }

    if (!function_exists('ms_visit_service')) {
        function ms_visit_service(): VisitService
        {
            static $svc = null;
            return $svc ??= new VisitService(ms_visit_repo(), ms_patient_repo(), ms_user_repo());
        }
    }
}

/* ---------------------------------------------------------------------------
 * 5. View / request helpers
 * ------------------------------------------------------------------------- */

if (!function_exists('e')) {
    /** HTML-escape a value for safe output (XSS defence). Use on EVERY echo. */
    function e(?string $value): string
    {
        return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

if (!function_exists('redirect')) {
    /** Send a Location redirect (app-relative path) and stop. */
    function redirect(string $path): never
    {
        // App-relative paths ("/login.php") are rewritten to include the base path
        // so redirects work whether the app is served from the web root or from a
        // sub-folder such as http://localhost/medishield/public/.
        $target = (isset($path[0]) && $path[0] === '/') ? ms_url($path) : $path;
        if (!headers_sent()) {
            header('Location: ' . $target);
        }
        exit;
    }
}

if (!function_exists('ms_base')) {
    /**
     * The URL path prefix the application is served from, without a trailing slash.
     *
     * - Served from the web root (DocumentRoot = public/)  => ''        (empty)
     * - Copied into htdocs as htdocs/medishield            => '/medishield/public'
     *
     * Computed once by diffing the real public/ directory against the request's
     * DOCUMENT_ROOT, so every internal link keeps working no matter where the
     * project is dropped — the #1 cause of "CSS won't load / links 404" reports.
     */
    function ms_base(): string
    {
        static $base = null;
        if ($base !== null) {
            return $base;
        }

        $docRoot   = isset($_SERVER['DOCUMENT_ROOT']) ? realpath($_SERVER['DOCUMENT_ROOT']) : false;
        $publicDir = realpath(__DIR__ . '/../public');

        if ($docRoot === false || $publicDir === false) {
            return $base = '';
        }

        $docRoot   = str_replace('\\', '/', $docRoot);
        $publicDir = str_replace('\\', '/', $publicDir);

        // If public/ lives under the document root, the leftover is our base path.
        $base = str_starts_with($publicDir, $docRoot)
            ? rtrim(substr($publicDir, strlen($docRoot)), '/')
            : '';

        return $base;
    }
}

if (!function_exists('ms_url')) {
    /** Build an app-absolute URL for a "/path", honouring the base path. */
    function ms_url(string $path): string
    {
        if ($path === '' || $path[0] !== '/') {
            return $path; // already relative/absolute; leave it alone
        }
        return ms_base() . $path;
    }
}

if (!function_exists('ms_client_ip')) {
    function ms_client_ip(): string
    {
        return (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    }
}

if (!function_exists('ms_user_agent')) {
    function ms_user_agent(): ?string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
        return $ua !== null ? substr((string) $ua, 0, 255) : null;
    }
}

if (!function_exists('ms_audit_log')) {
    /**
     * Convenience wrapper that appends an audit entry, automatically attaching the
     * request IP / user-agent. Auditing must never crash the page, so any failure
     * is logged and swallowed.
     */
    function ms_audit_log(array $event): void
    {
        try {
            $event += [
                'ip_address' => ms_client_ip(),
                'user_agent' => ms_user_agent(),
            ];
            ms_audit()->log($event);
        } catch (\Throwable $e) {
            error_log('[audit] failed to write entry: ' . $e->getMessage());
        }
    }
}

if (!function_exists('ms_dashboard_for')) {
    /** Resolve the landing dashboard path for a role (admin gets the admin area). */
    function ms_dashboard_for(string $role): string
    {
        return Rbac::dashboardPath($role);
    }
}
