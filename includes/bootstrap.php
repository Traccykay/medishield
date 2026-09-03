<?php

declare(strict_types=1);

require_once __DIR__ . '/error_boundary.php';

/**
 * bootstrap.php
 * -------------
 * Single entry point that every public page includes FIRST. It wires the whole
 * application together so individual pages stay thin and consistent:
 *
 *   1. Installs the dependency-free error boundary before failure-prone work.
 *   2. Loads the Composer autoloader (PSR-4 "MediShield\\" => src/).
 *   3. Loads the generated configuration (config/config.php).
 *   4. Forces UTC and routes diagnostics to logs/app_errors.log.
 *   5. Rejects unsafe production mail/base-URL configuration before any state,
 *      database, audit, credential, or mail operation can occur.
 *   6. Hardens and starts the PHP session (HttpOnly, SameSite=Strict, Secure on
 *      HTTPS) BEFORE any output — this must happen before session_start().
 *   7. Sends the security headers (see headers.php).
 *   8. Exposes a tiny lazy "service container" (ms_db, ms_auth, ms_user_service,
 *      ms_audit, ms_crypto, ...) plus view helpers (e(), redirect(), ms_audit_log()).
 *
 * Pages should never instantiate repositories/services directly; they ask the
 * container, so construction stays in one audited place.
 */

use MediShield\Audit\AuditLogger;
use MediShield\Audit\AuditAnchorStore;
use MediShield\Billing\BillingRepository;
use MediShield\Billing\BillingService;
use MediShield\Auth\ActivationRepository;
use MediShield\Auth\ActivationService;
use MediShield\Auth\AuthService;
use MediShield\Auth\DoctorPatientAuthorizer;
use MediShield\Auth\OtpRepository;
use MediShield\Auth\OtpService;
use MediShield\Auth\Rbac;
use MediShield\Auth\SessionValidator;
use MediShield\Auth\UserRepository;
use MediShield\Auth\UserService;
use MediShield\Clinical\ClinicalRepository;
use MediShield\Clinical\ClinicalService;
use MediShield\Database\Connection;
use MediShield\Mail\Mailer;
use MediShield\Mail\MailerFactory;
use MediShield\Patient\PatientRepository;
use MediShield\Patient\PatientService;
use MediShield\Security\AuditChain;
use MediShield\Security\Crypto;
use MediShield\Security\PasswordPolicy;
use MediShield\Security\RequestThrottle;
use MediShield\Security\TransportSecurity;
use MediShield\Support\BootstrapConfigValidator;
use MediShield\Support\Clock;
use MediShield\Visit\VisitRepository;
use MediShield\Visit\VisitService;

require_once __DIR__ . '/../vendor/autoload.php';

/* ---------------------------------------------------------------------------
 * 1. Configuration
 * ------------------------------------------------------------------------- */

if (!function_exists('ms_config')) {
    /**
     * Return the generated application configuration array (loaded once).
     */
    function ms_config(): array
    {
        static $config = null;
        if ($config !== null) {
            return $config;
        }

        $real   = __DIR__ . '/../config/config.php';
        if (!is_file($real)) {
            throw new \RuntimeException('Application configuration is missing. Run scripts\setup-db.ps1 before starting MediShield.');
        }
        $config = require $real;

        $testDatabase = getenv('MEDISHIELD_DB_NAME');
        if (is_string($testDatabase) && $testDatabase !== '') {
            $config['db']['name'] = $testDatabase;
        }
        $testMailDir = getenv('MEDISHIELD_MAIL_DUMP_DIR');
        if (is_string($testMailDir) && $testMailDir !== '') {
            $config['mail']['dump_dir'] = $testMailDir;
        }
        $testAnchorPath = getenv('MEDISHIELD_AUDIT_ANCHOR_PATH');
        if (is_string($testAnchorPath) && $testAnchorPath !== '') {
            $config['audit_anchor_path'] = $testAnchorPath;
        }

        return $config;
    }
}

/* ---------------------------------------------------------------------------
 * 2. Timezone + configured diagnostic destination
 * ------------------------------------------------------------------------- */

date_default_timezone_set('UTC');
$configuredErrorLog = ms_config()['error_log'] ?? (__DIR__ . '/../logs/app_errors.log');
ms_error_boundary_set_log_file((string) $configuredErrorLog);
BootstrapConfigValidator::validate(ms_config());

/* ---------------------------------------------------------------------------
 * 3. Session hardening + start (must precede any output)
 * ------------------------------------------------------------------------- */

(static function (): void {
    if (session_status() === PHP_SESSION_ACTIVE) {
        if (
            (int) ini_get('session.use_strict_mode') !== 1
            || (int) ini_get('session.use_only_cookies') !== 1
        ) {
            throw new \RuntimeException('An insecure session was started before application bootstrap.');
        }
        return;
    }

    $cfg   = ms_config();
    $https = TransportSecurity::isHttps(
        $_SERVER,
        (array) ($cfg['transport']['trusted_proxy_ips'] ?? [])
    );
    if (($cfg['environment'] ?? 'development') === 'production' && !$https) {
        http_response_code(403);
        exit('HTTPS is required.');
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    if (
        (int) ini_get('session.use_strict_mode') !== 1
        || (int) ini_get('session.use_only_cookies') !== 1
    ) {
        throw new \RuntimeException('Required session security settings could not be applied.');
    }

    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $https,        // Secure only when actually on HTTPS
        'httponly' => true,          // JS cannot read the session cookie
        'samesite' => 'Strict',      // mitigates CSRF on top-level navigations
    ]);

    session_name($cfg['session']['cookie_name'] ?? 'MEDISHIELD_SID');
    if (!session_start()) {
        throw new \RuntimeException('The secure session could not be started.');
    }
})();

require_once __DIR__ . '/headers.php';
ms_send_security_headers(TransportSecurity::isHttps(
    $_SERVER,
    (array) (ms_config()['transport']['trusted_proxy_ips'] ?? [])
));

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
        return $validator ??= new SessionValidator(
            ms_user_repo(),
            ms_clock(),
            (int) (ms_config()['session']['pending_login_timeout_seconds'] ?? 600)
        );
    }
}

if (!function_exists('ms_audit')) {
    function ms_audit(): AuditLogger
    {
        static $logger = null;
        if ($logger === null) {
            $chain  = AuditChain::fromHexKey(
                (string) ms_config()['audit_hmac_key_hex'],
                (string) ms_config()['audit_key_id']
            );
            $logger = new AuditLogger(ms_db(), $chain, ms_clock());
        }

        return $logger;
    }
}

if (!function_exists('ms_audit_anchors')) {
    function ms_audit_anchors(): AuditAnchorStore
    {
        static $anchors = null;
        return $anchors ??= AuditAnchorStore::fromHexKey(
            (string) ms_config()['audit_anchor_path'],
            (string) ms_config()['audit_anchor_hmac_key_hex'],
            (string) ms_config()['audit_anchor_key_id'],
            ms_clock()
        );
    }
}

if (!function_exists('ms_request_throttle')) {
    function ms_request_throttle(): RequestThrottle
    {
        static $throttle = null;
        return $throttle ??= new RequestThrottle(
            ms_db(),
            ms_clock(),
            (string) ms_config()['request_throttle_hmac_key_hex']
        );
    }
}

if (!function_exists('ms_is_https_request')) {
    function ms_is_https_request(): bool
    {
        return TransportSecurity::isHttps(
            $_SERVER,
            (array) (ms_config()['transport']['trusted_proxy_ips'] ?? [])
        );
    }
}

if (!function_exists('ms_mailer')) {
    /**
     * The explicitly configured mail transport. Log delivery is restricted to
     * non-production environments; unknown or missing transports fail closed.
     */
    function ms_mailer(): Mailer
    {
        static $mailer = null;
        return $mailer ??= MailerFactory::fromConfig(ms_config(), ms_clock());
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

if (!function_exists('ms_doctor_authorizer')) {
    function ms_doctor_authorizer(): DoctorPatientAuthorizer
    {
        static $authorizer = null;
        return $authorizer ??= new DoctorPatientAuthorizer(ms_db());
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
        return $svc ??= new ClinicalService(
            ms_clinical_repo(),
            ms_patient_repo(),
            ms_crypto(),
            ms_doctor_authorizer()
        );
    }
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
        return $svc ??= new VisitService(
            ms_visit_repo(),
            ms_patient_repo(),
            ms_user_repo(),
            ms_doctor_authorizer()
        );
    }
}

if (!function_exists('ms_billing_repo')) {
    function ms_billing_repo(): BillingRepository
    {
        static $repo = null;
        return $repo ??= new BillingRepository(ms_db(), ms_clock());
    }
}

if (!function_exists('ms_billing_service')) {
    function ms_billing_service(): BillingService
    {
        static $svc = null;
        return $svc ??= new BillingService(ms_billing_repo(), ms_visit_repo(), ms_patient_repo());
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
     * Append after the domain operation has committed. A failed forensic write
     * cannot roll back an already-committed clinical/business transaction, but it
     * returns false and emits a PHI-free structured diagnostic instead of silently
     * claiming success.
     */
    function ms_audit_log(array $event): bool
    {
        try {
            $event += [
                'ip_address' => ms_client_ip(),
                'user_agent' => ms_user_agent(),
            ];
            ms_audit()->log($event);
            return true;
        } catch (\Throwable $e) {
            error_log(json_encode([
                'event' => 'AUDIT_APPEND_FAILED',
                'severity' => 'ERROR',
                'action' => is_string($event['action'] ?? null) ? $event['action'] : 'UNKNOWN',
                'module' => is_string($event['module'] ?? null) ? $event['module'] : 'unknown',
                'error_type' => $e::class,
            ], JSON_UNESCAPED_SLASHES));
            return false;
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
