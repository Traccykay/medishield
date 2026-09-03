<?php

declare(strict_types=1);

/**
 * Router for PHP's development server.
 *
 * PHP's built-in server otherwise serves any file below the document root and
 * performs permissive script fallback. This front controller therefore executes
 * only enumerated routes and serves only enumerated static assets.
 */

use MediShield\Security\PublicRuntimePolicy;

require_once __DIR__ . '/../includes/error_boundary.php';
require_once __DIR__ . '/../includes/headers.php';
require_once __DIR__ . '/../src/Security/PublicRuntimePolicy.php';

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$decision = PublicRuntimePolicy::decide(is_string($requestUri) ? $requestUri : '/');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$method = is_string($method) ? strtoupper($method) : '';

if ($decision['kind'] === 'route') {
    $route = __DIR__ . DIRECTORY_SEPARATOR
        . str_replace('/', DIRECTORY_SEPARATOR, $decision['path']);
    if (!is_file($route)) {
        ms_runtime_error(404, 'Not found.');
    }

    require $route;
    return true;
}

if ($decision['kind'] === 'asset') {
    if (!in_array($method, ['GET', 'HEAD'], true)) {
        header('Allow: GET, HEAD', true);
        ms_runtime_error(405, 'Method not allowed.');
    }

    $asset = realpath(
        __DIR__ . DIRECTORY_SEPARATOR
        . str_replace('/', DIRECTORY_SEPARATOR, $decision['path'])
    );
    $assetsRoot = realpath(__DIR__ . DIRECTORY_SEPARATOR . 'assets');
    if (
        $asset === false
        || $assetsRoot === false
        || !is_file($asset)
        || !str_starts_with($asset, $assetsRoot . DIRECTORY_SEPARATOR)
    ) {
        ms_runtime_error(404, 'Not found.');
    }

    ms_send_security_headers();
    header('Content-Type: ' . $decision['mime'], true);
    header('Cache-Control: public, max-age=3600', true);
    header('Content-Length: ' . (string) filesize($asset), true);
    if ($method === 'GET') {
        readfile($asset);
    }
    return true;
}

ms_runtime_error(
    $decision['status'],
    $decision['kind'] === 'forbidden' ? 'Forbidden.' : 'Not found.'
);

/**
 * Emit a deterministic router-owned error without exposing filesystem details.
 */
function ms_runtime_error(int $status, string $message): never
{
    ms_send_security_headers();
    ms_send_no_store_headers();
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8', true);
    echo $message . "\n";
    exit;
}
