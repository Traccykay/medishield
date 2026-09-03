<?php

declare(strict_types=1);

namespace MediShield\Support;

/**
 * Validates configuration that must be safe before request processing starts.
 *
 * This check deliberately runs before sessions and every lazy service. Authentication
 * flows persist credentials before sending them, so rejecting an unsafe production
 * mail boundary only when the mailer is constructed would be too late.
 */
final class BootstrapConfigValidator
{
    public const FAILURE_MESSAGE = 'Application bootstrap configuration validation failed.';

    /**
     * @param array<string,mixed> $config
     */
    public static function validate(array $config): void
    {
        if (!self::hasSafeCryptographicConfiguration($config)) {
            self::fail();
        }

        $mail = $config['mail'] ?? null;
        if (!is_array($mail)) {
            self::fail();
        }

        $transport = $mail['transport'] ?? null;
        if ($transport !== 'log' && $transport !== 'smtp') {
            self::fail();
        }

        $environment = $config['environment'] ?? 'development';
        if ($environment !== 'production') {
            return;
        }

        if (
            $transport !== 'smtp'
            || !self::isHttpsBaseUrl($mail['app_base_url'] ?? null)
            || !self::hasValidProductionSmtpSettings($mail)
        ) {
            self::fail();
        }
    }

    /**
     * @param array<string,mixed> $config
     */
    private static function hasSafeCryptographicConfiguration(array $config): bool
    {
        $keyFields = [
            'encryption_key_hex',
            'audit_hmac_key_hex',
            'audit_anchor_hmac_key_hex',
            'request_throttle_hmac_key_hex',
        ];
        $keys = [];
        foreach ($keyFields as $field) {
            $value = $config[$field] ?? null;
            if (
                !is_string($value)
                || strlen($value) < 64
                || strlen($value) % 2 !== 0
                || preg_match('/^[0-9a-fA-F]+$/D', $value) !== 1
            ) {
                return false;
            }
            $keys[] = strtolower($value);
        }
        if (count(array_unique($keys)) !== count($keys)) {
            return false;
        }

        foreach (['audit_key_id', 'audit_anchor_key_id'] as $field) {
            $value = $config[$field] ?? null;
            if (
                !is_string($value)
                || preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $value) !== 1
            ) {
                return false;
            }
        }

        $anchorPath = $config['audit_anchor_path'] ?? null;
        if (!is_string($anchorPath) || $anchorPath === '') {
            return false;
        }
        $normalized = self::normalizeAbsolutePath($anchorPath);
        $publicRoot = self::normalizeAbsolutePath(dirname(__DIR__, 2) . '/public');
        if ($normalized === null || $publicRoot === null) {
            return false;
        }

        return $normalized !== $publicRoot
            && !str_starts_with($normalized, $publicRoot . '/');
    }

    private static function normalizeAbsolutePath(string $path): ?string
    {
        if ($path === '' || str_contains($path, "\0")) {
            return null;
        }
        $path = str_replace('\\', '/', $path);
        if (preg_match('/^[A-Za-z]:\//D', $path) === 1) {
            $prefix = strtolower(substr($path, 0, 2));
            $path = substr($path, 3);
        } elseif (str_starts_with($path, '/')) {
            $prefix = '';
            $path = ltrim($path, '/');
        } else {
            return null;
        }

        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                if ($segments === []) {
                    return null;
                }
                array_pop($segments);
                continue;
            }
            $segments[] = strtolower($segment);
        }
        return $prefix . '/' . implode('/', $segments);
    }

    private static function isHttpsBaseUrl(mixed $value): bool
    {
        if (!is_string($value) || $value === '' || trim($value) !== $value) {
            return false;
        }

        if (filter_var($value, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        $parts = parse_url($value);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && is_string($parts['host'] ?? null)
            && $parts['host'] !== ''
            && !isset($parts['user'])
            && !isset($parts['pass'])
            && !isset($parts['query'])
            && !isset($parts['fragment']);
    }

    /**
     * @param array<string,mixed> $mail
     */
    private static function hasValidProductionSmtpSettings(array $mail): bool
    {
        $smtp = $mail['smtp'] ?? null;
        if (!is_array($smtp)) {
            return false;
        }

        $fromEmail = $mail['from_email'] ?? null;
        $fromName = $mail['from_name'] ?? null;
        $host = $smtp['host'] ?? null;
        $username = $smtp['username'] ?? null;
        $password = $smtp['password'] ?? null;
        $encryption = $smtp['encryption'] ?? null;

        return is_string($fromEmail)
            && trim($fromEmail) === $fromEmail
            && filter_var($fromEmail, FILTER_VALIDATE_EMAIL) !== false
            && self::isNonEmptySingleLine($fromName)
            && self::isNonWhitespaceToken($host)
            && self::isValidInteger($smtp['port'] ?? null, 1, 65535)
            && ($encryption === 'tls' || $encryption === 'ssl')
            && self::isNonWhitespaceToken($username)
            && is_string($password)
            && trim($password) !== ''
            && self::isValidInteger($smtp['timeout'] ?? null, 1, 300);
    }

    private static function isNonEmptySingleLine(mixed $value): bool
    {
        return is_string($value)
            && $value !== ''
            && trim($value) === $value
            && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
    }

    private static function isNonWhitespaceToken(mixed $value): bool
    {
        return self::isNonEmptySingleLine($value)
            && preg_match('/\s/', $value) !== 1;
    }

    private static function isValidInteger(mixed $value, int $minimum, int $maximum): bool
    {
        if (
            !is_int($value)
            && (!is_string($value) || preg_match('/^[0-9]+$/D', $value) !== 1)
        ) {
            return false;
        }

        return filter_var(
            $value,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => $minimum, 'max_range' => $maximum]]
        ) !== false;
    }

    private static function fail(): never
    {
        throw new \RuntimeException(self::FAILURE_MESSAGE);
    }
}
