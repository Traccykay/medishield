<?php
/**
 * config.sample.php
 * -----------------
 * Template configuration for MediShield. This file IS committed to git.
 *
 * The real configuration (config/config.php) is created from this template by
 * scripts\setup-db.ps1 and is git-ignored, because it will eventually hold the
 * encryption key and audit HMAC key.
 *
 * For the XAMPP localhost demo the database defaults below match a stock XAMPP
 * install (MySQL root user, empty password). Change them for any real deployment.
 *
 * SECURITY NOTE:
 *   - ENCRYPTION_KEY  : 32 raw bytes (provided here as 64 hex chars) used for
 *                        AES-256-GCM encryption of sensitive clinical fields.
 *   - AUDIT_HMAC_KEY  : a DISTINCT 32-byte key used to HMAC-chain the audit log.
 *   Generate fresh keys with:  php -r "echo bin2hex(random_bytes(32));"
 *   Never reuse the sample keys below in any environment that holds real data.
 */

declare(strict_types=1);

return [
    // --- Database connection (XAMPP defaults) ---
    'db' => [
        'host'    => '127.0.0.1',
        'port'    => 3306,
        'name'    => 'medishield_db',
        'user'    => 'root',
        'pass'    => '',
        'charset' => 'utf8mb4',
    ],

    // --- Cryptographic keys (REPLACE in real deployments) ---
    // 64 hex chars = 32 bytes. These are sample/dev keys only.
    'encryption_key_hex' => '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    'audit_hmac_key_hex' => 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100',

    // --- Session / security policy ---
    'session' => [
        'idle_timeout_seconds'     => 1200,   // 20 minutes of inactivity
        'absolute_timeout_seconds' => 28800,  // 8 hours since login
        'cookie_name'              => 'MEDISHIELD_SID',
    ],

    // --- Authentication policy ---
    'auth' => [
        'max_failed_attempts' => 5,   // lock account after this many failures
        'suspicious_at'       => 3,   // flag SUSPICIOUS at this many failures
        'lock_minutes'        => 15,  // lockout duration
    ],

    // --- Audit log retention ---
    // attempted_identifier (the email typed on a failed login) is PII. It is kept
    // for follow-up on possible credential compromise, then scrubbed (set NULL) by
    // scripts/purge-audit-pii.php once it is older than this many days. The audit
    // ROW and its hash chain are never deleted — only the personal identifier is
    // removed (data minimisation).
    'audit' => [
        'pii_retention_days' => 90,
    ],

    // --- Email (used for OTP codes and account-activation links) ---
    // 'transport' selects how mail is delivered:
    //   'log'  : DEV default — no real email is sent. Each message is written as a
    //            file under dump_dir (logs/mail/) so you can read the OTP/activation
    //            link locally without an SMTP server.
    //   'smtp' : PRODUCTION — send via the SMTP settings below using PHPMailer.
    // NEVER hardcode a real mailbox password here; supply it via the environment or
    // an untracked config/config.php in real deployments.
    'mail' => [
        'transport'    => 'log',
        'from_email'   => 'no-reply@medishield.local',
        'from_name'    => 'MediShield',
        // Base URL the app is reached at, used to build absolute activation links.
        // Include the /public path if served from a sub-folder under XAMPP.
        'app_base_url' => 'http://localhost/medishield/public',
        'dump_dir'     => __DIR__ . '/../logs/mail',
        'smtp' => [
            'host'       => 'smtp.gmail.com',
            'port'       => 587,
            'encryption' => 'tls',          // 'tls' or 'ssl'
            'username'   => '',             // e.g. medishield.mailer@gmail.com
            'password'   => '',             // Gmail App Password — set via env/secret
            'timeout'    => 15,
        ],
    ],

    // --- One-time passcode (login second factor / 2FA) ---
    'otp' => [
        'length'       => 6,    // characters in the emailed code
        'ttl_minutes'  => 10,   // how long a code stays valid
        'max_attempts' => 5,    // wrong tries before the code is killed
    ],

    // --- Account activation links ---
    'activation' => [
        'ttl_hours' => 48,      // how long an activation link stays valid
    ],

    // --- Paths ---
    'error_log' => __DIR__ . '/../logs/app_errors.log',
];
