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
 *   - Cross-Origin-* policies               : isolate same-origin responses.
 *   - Strict-Transport-Security             : only when served over HTTPS.
 *
 * Session cookie hardening (HttpOnly, SameSite, Secure) is configured separately
 * in bootstrap.php, because it must happen before session_start().
 */

if (!function_exists('ms_send_security_headers')) {
    function ms_send_security_headers(bool $isHttps = false): void
    {
        // Avoid "headers already sent" noise if output started (e.g. in tests).
        if (headers_sent()) {
            return;
        }

        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer-when-downgrade');
        header("Content-Security-Policy: default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'");
        header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
        header('Cross-Origin-Embedder-Policy: require-corp');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header_remove('X-Powered-By');

        // Only advertise HSTS when actually on HTTPS (localhost demo runs on HTTP).
        if ($isHttps) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }
}

if (!function_exists('ms_send_no_store_headers')) {
    /** Prevent browsers and intermediaries from retaining authentication responses. */
    function ms_send_no_store_headers(): void
    {
        if (headers_sent()) {
            return;
        }

        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
    }
}
