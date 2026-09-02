<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}

$GLOBALS['request_guard_probe'] = [
    'audit_events' => [],
    'audit_failed' => false,
    'mutated' => false,
];

function ms_audit_log(array $event): void
{
    $GLOBALS['request_guard_probe']['audit_events'][] = $event;
    if ($GLOBALS['request_guard_probe']['audit_failed']) {
        throw new RuntimeException('Injected audit storage failure.');
    }
}

$variant = (string) ($argv[1] ?? 'missing');
$authenticated = (string) ($argv[2] ?? 'guest') === 'authenticated';
$GLOBALS['request_guard_probe']['audit_failed'] = (string) ($argv[3] ?? 'audit-ok') === 'audit-fails';
$_SERVER['REQUEST_METHOD'] = match ($variant) {
    'get' => 'GET',
    'put' => 'PUT',
    default => 'POST',
};

require_once dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'guard.php';

$_SESSION = [];
$_SESSION[\MediShield\Security\Csrf::SESSION_KEY] = 'stored-token';
if ($authenticated) {
    $_SESSION['auth'] = [
        'user_id' => 42,
        'role' => 'admin',
        'full_name' => 'Request Guard Probe',
        'email' => 'probe@example.test',
        'must_change' => false,
        'auth_version' => 1,
    ];
}

$_POST = match ($variant) {
    'wrong' => ['csrf_token' => 'wrong-token'],
    'array' => ['csrf_token' => ['attacker-controlled']],
    default => [],
};

register_shutdown_function(static function (): void {
    echo "\nREQUEST_GUARD_PROBE:";
    echo json_encode([
        'status' => http_response_code(),
        'audit_events' => $GLOBALS['request_guard_probe']['audit_events'],
        'mutated' => $GLOBALS['request_guard_probe']['mutated'],
    ], JSON_THROW_ON_ERROR);
});

request_post_guard('patients', $variant === 'get');
$GLOBALS['request_guard_probe']['mutated'] = true;
