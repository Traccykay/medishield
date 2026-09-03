<?php

declare(strict_types=1);

namespace MediShield\Security;

/**
 * Dependency-free allowlist for the PHP development server's public boundary.
 */
final class PublicRuntimePolicy
{
    /** @var list<string> */
    private const ROUTES = [
        'activate.php',
        'admin/assign_patient.php',
        'admin/audit.php',
        'admin/create_user.php',
        'admin/dashboard.php',
        'admin/reset_password.php',
        'admin/users.php',
        'change_password.php',
        'dashboard.php',
        'doctor/add_diagnosis.php',
        'doctor/dashboard.php',
        'doctor/history.php',
        'doctor/issue_prescription.php',
        'doctor/request_lab.php',
        'doctor/view_patient.php',
        'forgot_password.php',
        'index.php',
        'lab/dashboard.php',
        'lab/history.php',
        'lab/requests.php',
        'lab/upload_result.php',
        'login.php',
        'logout.php',
        'nurse/add_vitals.php',
        'nurse/assign_doctor.php',
        'nurse/dashboard.php',
        'nurse/triage.php',
        'nurse/view_vitals.php',
        'patient/dashboard.php',
        'patient/lab_results.php',
        'patient/prescriptions.php',
        'patient/profile.php',
        'patient/records.php',
        'patient_profile.php',
        'patients.php',
        'payments.php',
        'pharmacy/dashboard.php',
        'pharmacy/dispense.php',
        'pharmacy/history.php',
        'pharmacy/prescriptions.php',
        'reception/dashboard.php',
        'reception/intake.php',
        'register_patient.php',
        'reports.php',
        'unauthorized.php',
        'verify_otp.php',
    ];

    /** @var array<string,string> */
    private const STATIC_ASSETS = [
        'assets/css/style.css' => 'text/css; charset=utf-8',
    ];

    /** @var list<string> */
    private const FORBIDDEN_DIRECTORIES = [
        'config',
        'docs',
        'includes',
        'logs',
        'node_modules',
        'partials',
        'scripts',
        'sql',
        'src',
        'tests',
        'var',
        'vendor',
    ];

    /** @var list<string> */
    private const FORBIDDEN_EXTENSIONS = [
        'bak',
        'conf',
        'dist',
        'env',
        'ini',
        'json',
        'log',
        'map',
        'md',
        'old',
        'orig',
        'save',
        'sql',
        'swp',
        'tmp',
        'xml',
        'yaml',
        'yml',
    ];

    /**
     * @return array{kind:'route',status:200,path:string}
     *     |array{kind:'asset',status:200,path:string,mime:string}
     *     |array{kind:'forbidden',status:403}
     *     |array{kind:'not_found',status:404}
     */
    public static function decide(string $requestUri): array
    {
        if (
            preg_match('/[\x00-\x1F\x7F]/', $requestUri) === 1
            || preg_match('/%(?![0-9A-Fa-f]{2})/', $requestUri) === 1
        ) {
            return self::forbidden();
        }

        $rawPath = parse_url($requestUri, PHP_URL_PATH);
        if (!is_string($rawPath) || $rawPath === '' || $rawPath[0] !== '/') {
            return self::forbidden();
        }
        if (
            str_starts_with($rawPath, '//')
            || str_contains($rawPath, '\\')
            || preg_match('/%(?:2f|5c)/i', $rawPath) === 1
        ) {
            return self::forbidden();
        }

        $decodedPath = rawurldecode($rawPath);
        if (
            str_contains($decodedPath, '%')
            || str_contains($decodedPath, '\\')
            || preg_match('/[\x00-\x1F\x7F]/', $decodedPath) === 1
            || preg_match('#//+#', $decodedPath) === 1
        ) {
            return self::forbidden();
        }

        if ($decodedPath === '/') {
            return ['kind' => 'route', 'status' => 200, 'path' => 'index.php'];
        }

        $relativePath = ltrim($decodedPath, '/');
        if (str_ends_with($relativePath, '/')) {
            return ['kind' => 'not_found', 'status' => 404];
        }
        $segments = explode('/', $relativePath);
        foreach ($segments as $segment) {
            $normalizedSegment = strtolower($segment);
            if (
                $segment === ''
                || $segment === '.'
                || $segment === '..'
                || str_starts_with($segment, '.')
                || in_array($normalizedSegment, self::FORBIDDEN_DIRECTORIES, true)
            ) {
                return self::forbidden();
            }
        }

        $basename = strtolower((string) end($segments));
        $extension = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
        if (
            preg_match('/^readme(?:\..*)?$/i', $basename) === 1
            || $basename === 'router.php'
            || $basename === 'composer.json'
            || $basename === 'composer.lock'
            || $basename === 'package.json'
            || $basename === 'package-lock.json'
            || $basename === 'phpunit.xml'
            || str_ends_with($basename, '~')
            || in_array($extension, self::FORBIDDEN_EXTENSIONS, true)
        ) {
            return self::forbidden();
        }

        if (in_array($relativePath, self::ROUTES, true)) {
            return ['kind' => 'route', 'status' => 200, 'path' => $relativePath];
        }
        if (isset(self::STATIC_ASSETS[$relativePath])) {
            return [
                'kind' => 'asset',
                'status' => 200,
                'path' => $relativePath,
                'mime' => self::STATIC_ASSETS[$relativePath],
            ];
        }

        return ['kind' => 'not_found', 'status' => 404];
    }

    /** @return array{kind:'forbidden',status:403} */
    private static function forbidden(): array
    {
        return ['kind' => 'forbidden', 'status' => 403];
    }
}
