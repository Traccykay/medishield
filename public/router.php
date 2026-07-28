<?php

declare(strict_types=1);

/**
 * Router for PHP's development server.
 *
 * The built-in server serves static files without loading PHP, which would skip
 * the security headers enforced by Apache in production. Serve only assets here
 * so local browser and ZAP checks exercise the same response policy.
 */

$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$relativePath = ltrim(rawurldecode(is_string($requestPath) ? $requestPath : '/'), '/\\');
$assetsRoot = realpath(__DIR__ . DIRECTORY_SEPARATOR . 'assets');
$candidate = realpath(__DIR__ . DIRECTORY_SEPARATOR . $relativePath);

if (
    $assetsRoot !== false
    && $candidate !== false
    && is_file($candidate)
    && str_starts_with($candidate, $assetsRoot . DIRECTORY_SEPARATOR)
) {
    require_once __DIR__ . '/../includes/headers.php';
    ms_send_security_headers();

    $mimeType = (new finfo(FILEINFO_MIME_TYPE))->file($candidate);
    if (is_string($mimeType) && $mimeType !== '') {
        header('Content-Type: ' . $mimeType);
    }

    readfile($candidate);
    return true;
}

return false;
