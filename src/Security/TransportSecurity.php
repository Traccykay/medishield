<?php

declare(strict_types=1);

namespace MediShield\Security;

/**
 * Determines whether a request arrived over HTTPS without trusting client-sent
 * forwarding headers. A reverse proxy can assert HTTPS only when its immediate
 * address is explicitly configured as trusted.
 */
final class TransportSecurity
{
    /**
     * @param array<string,mixed> $server
     * @param string[] $trustedProxyIps
     */
    public static function isHttps(array $server, array $trustedProxyIps = []): bool
    {
        $https = strtolower((string) ($server['HTTPS'] ?? ''));
        if ($https === 'on' || $https === '1') {
            return true;
        }

        $remoteAddress = (string) ($server['REMOTE_ADDR'] ?? '');
        if (!in_array($remoteAddress, $trustedProxyIps, true)) {
            return false;
        }

        // Reject lists such as "http, https": a proxy must supply one unambiguous
        // value for the immediately preceding trusted hop.
        return strtolower(trim((string) ($server['HTTP_X_FORWARDED_PROTO'] ?? ''))) === 'https';
    }
}
