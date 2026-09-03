<?php

declare(strict_types=1);

namespace MediShield\Support;

use InvalidArgumentException;

/**
 * Validates and builds local application paths for links and redirects.
 */
final class LocalUrl
{
    public static function build(string $target, string $basePath = ''): string
    {
        if (
            $target === ''
            || preg_match('/[\x00-\x1F\x7F]/', $target) === 1
            || preg_match('/%(?![0-9A-Fa-f]{2})/', $target) === 1
            || str_contains($target, '\\')
        ) {
            throw new InvalidArgumentException('Application URL target is malformed.');
        }

        $parts = parse_url($target);
        $path = is_array($parts) ? ($parts['path'] ?? null) : null;
        if (
            !is_array($parts)
            || !is_string($path)
            || $path === ''
            || $path[0] !== '/'
            || str_starts_with($path, '//')
            || isset($parts['scheme'])
            || isset($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['port'])
            || preg_match('/%(?:2f|5c)/i', $path) === 1
        ) {
            throw new InvalidArgumentException('Application URL target must be a local absolute path.');
        }

        $decodedPath = rawurldecode($path);
        if (
            str_contains($decodedPath, '%')
            || str_contains($decodedPath, '\\')
            || preg_match('/[\x00-\x1F\x7F]/', $decodedPath) === 1
        ) {
            throw new InvalidArgumentException('Application URL target is malformed.');
        }
        foreach (explode('/', ltrim($decodedPath, '/')) as $segment) {
            if ($segment === '.' || $segment === '..') {
                throw new InvalidArgumentException('Application URL target must not contain dot segments.');
            }
        }

        if (
            $basePath !== ''
            && (
                $basePath[0] !== '/'
                || str_starts_with($basePath, '//')
                || str_ends_with($basePath, '/')
                || preg_match('/[\x00-\x1F\x7F\\\\]/', $basePath) === 1
            )
        ) {
            throw new InvalidArgumentException('Application base path is malformed.');
        }

        return $basePath . $target;
    }

    public static function assertRedirectStatus(int $status): int
    {
        if (!in_array($status, [301, 302, 303, 307, 308], true)) {
            throw new InvalidArgumentException('Unsupported redirect status.');
        }

        return $status;
    }
}
