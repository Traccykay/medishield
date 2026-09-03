<?php

declare(strict_types=1);

/**
 * Dependency-free error boundary installed before Composer and configuration.
 *
 * Keep this file limited to PHP core functions: it must remain usable when the
 * autoloader, application configuration, or database initialization fails.
 */

ini_set('zend.exception_ignore_args', '1');

if (!defined('MEDISHIELD_ERROR_BOUNDARY_LOADED')) {
    define('MEDISHIELD_ERROR_BOUNDARY_LOADED', true);

    $fallbackLog = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'logs'
        . DIRECTORY_SEPARATOR . 'app_errors.log';
    $configuredLog = getenv('MEDISHIELD_ERROR_LOG');
    $initialLog = is_string($configuredLog) && $configuredLog !== ''
        ? $configuredLog
        : $fallbackLog;

    $GLOBALS['medishield_error_boundary'] = [
        'buffer_level' => ob_get_level(),
        'handled' => false,
    ];

    ini_set('display_errors', '0');
    ini_set('display_startup_errors', '0');
    ini_set('log_errors', '1');
    ini_set('expose_php', '0');
    error_reporting(E_ALL);

    if (!function_exists('ms_error_boundary_set_log_file')) {
        function ms_error_boundary_set_log_file(string $logFile): void
        {
            if ($logFile === '') {
                return;
            }

            $logDirectory = dirname($logFile);
            if (!is_dir($logDirectory) && !mkdir($logDirectory, 0775, true) && !is_dir($logDirectory)) {
                error_log('[error-boundary] Unable to create application log directory.');
                return;
            }

            ini_set('error_log', $logFile);
        }
    }

    if (!function_exists('ms_error_boundary_render_generic_response')) {
        function ms_error_boundary_render_generic_response(): void
        {
            $state = $GLOBALS['medishield_error_boundary'] ?? ['buffer_level' => 0];
            $baseLevel = (int) ($state['buffer_level'] ?? 0);
            while (ob_get_level() > $baseLevel) {
                ob_end_clean();
            }

            http_response_code(500);
            if (!headers_sent()) {
                header('Content-Type: text/html; charset=utf-8', true);
                header('X-Frame-Options: DENY', true);
                header('X-Content-Type-Options: nosniff', true);
                header('Referrer-Policy: no-referrer', true);
                header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'", true);
                header('Cache-Control: no-store, private, max-age=0, must-revalidate', true);
                header_remove('X-Powered-By');
            }

            echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                . '<title>Error</title></head><body>'
                . '<p>An unexpected error occurred. Please try again later.</p>'
                . '</body></html>';
        }
    }

    ms_error_boundary_set_log_file($initialLog);
    ob_start();

    set_exception_handler(static function (\Throwable $exception): void {
        $GLOBALS['medishield_error_boundary']['handled'] = true;
        error_log(sprintf(
            '[uncaught] %s: %s @ %s:%d%s%s',
            get_class($exception),
            $exception->getMessage(),
            $exception->getFile(),
            $exception->getLine(),
            PHP_EOL,
            $exception->getTraceAsString()
        ));
        ms_error_boundary_render_generic_response();
    });

    register_shutdown_function(static function (): void {
        if (($GLOBALS['medishield_error_boundary']['handled'] ?? false) === true) {
            return;
        }

        $error = error_get_last();
        if ($error === null || !in_array(
            $error['type'],
            [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR],
            true
        )) {
            return;
        }

        $GLOBALS['medishield_error_boundary']['handled'] = true;
        error_log(sprintf(
            '[fatal] %s @ %s:%d',
            $error['message'],
            $error['file'],
            $error['line']
        ));
        ms_error_boundary_render_generic_response();
    });
}
