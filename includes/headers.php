<?php

declare(strict_types=1);

/**
 * headers.php
 * -----------
 * Sends the HTTP security headers MediShield applies to every response
 * (spec §19). Centralising them here means no page can forget them.
 *
 * Headers set:
 *   - X-Frame-Options / CSP frame-ancestors : clickjacking protection.
 *   - X-Content-Type-Options                : stop MIME-type sniffing.
 *   - Referrer-Policy                       : limit referrer leakage.
 *   - Content-Security-Policy               : restrict resource origins.
 *   - Permissions-Policy                    : disable unneeded device APIs.
 *   - Strict-Transport-Security             : only when served over HTTPS.
 *
 * Session cookie hardening (HttpOnly, SameSite, Secure) is configured separately
 * in bootstrap.php, because it must happen before session_start().
 */

if (!function_exists('ms_send_security_headers')) {
    function ms_send_security_headers(): void
    {
        // Avoid "headers already sent" noise if output started (e.g. in tests).
        if (headers_sent()) {
            return;
        }

        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer-when-downgrade');
        header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'");
        header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
        header_remove('X-Powered-By');

        // Only advertise HSTS when actually on HTTPS (localhost demo runs on HTTP).
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        if ($https) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }
}
