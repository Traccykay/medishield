<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}

use MediShield\Audit\AuditLogger;
use MediShield\Auth\ActivationRepository;
use MediShield\Auth\ActivationService;
use MediShield\Auth\InitialAdminProvisioner;
use MediShield\Auth\UserRepository;
use MediShield\Auth\UserService;
use MediShield\Database\Connection;
use MediShield\Mail\LogMailer;
use MediShield\Mail\SmtpMailer;
use MediShield\Security\AuditChain;
use MediShield\Security\PasswordPolicy;
use MediShield\Support\Clock;

/** @return never */
function refuse(string $message): never
{
    fwrite(STDERR, $message . PHP_EOL);
    exit(1);
}

$options = getopt('', [
    'name:',
    'email:',
    'confirm-database:',
    'confirm-initial-admin',
]);

if (!array_key_exists('confirm-initial-admin', $options)) {
    refuse('Refusing to provision without --confirm-initial-admin.');
}

foreach (['name', 'email', 'confirm-database'] as $requiredOption) {
    if (!isset($options[$requiredOption]) || !is_string($options[$requiredOption])) {
        refuse("Missing required --$requiredOption value.");
    }
}

require_once __DIR__ . '/../vendor/autoload.php';

$configPath = __DIR__ . '/../config/config.php';
if (!is_file($configPath)) {
    refuse('Application configuration is missing. Run scripts\\setup-db.ps1 first.');
}

/** @var array<string,mixed> $config */
$config = require $configPath;
$configuredDatabase = (string) ($config['db']['name'] ?? '');
$confirmedDatabase = (string) $options['confirm-database'];
if ($configuredDatabase === '' || !hash_equals($configuredDatabase, $confirmedDatabase)) {
    refuse('Refusing to provision because --confirm-database does not match config/config.php.');
}

$mailConfig = (array) ($config['mail'] ?? []);
$transport = (string) ($mailConfig['transport'] ?? 'log');
$baseUrl = (string) ($mailConfig['app_base_url'] ?? '');
$scheme = strtolower((string) parse_url($baseUrl, PHP_URL_SCHEME));
if (!filter_var($baseUrl, FILTER_VALIDATE_URL) || !in_array($scheme, ['http', 'https'], true)) {
    refuse('Refusing to provision without a valid HTTP(S) mail.app_base_url.');
}
if (($config['environment'] ?? 'development') === 'production') {
    if ($transport !== 'smtp') {
        refuse('Production initial-admin provisioning requires the SMTP mail transport.');
    }
    if ($scheme !== 'https') {
        refuse('Production initial-admin provisioning requires an HTTPS mail.app_base_url.');
    }
}

$errorLog = (string) ($config['error_log'] ?? (__DIR__ . '/../logs/app_errors.log'));
ini_set('log_errors', '1');
ini_set('error_log', $errorLog);

try {
    $clock = new Clock();
    $pdo = Connection::fromConfig($config);
    $users = new UserRepository($pdo, $clock);
    $activationConfig = (array) ($config['activation'] ?? []);
    $ttlHours = (int) ($activationConfig['ttl_hours'] ?? 48);
    $activations = new ActivationService(
        new ActivationRepository($pdo, $clock),
        $users,
        new PasswordPolicy(),
        $clock,
        $ttlHours
    );
    $mailer = $transport === 'smtp'
        ? new SmtpMailer(
            (array) ($mailConfig['smtp'] ?? []),
            (string) ($mailConfig['from_email'] ?? 'no-reply@medishield.local'),
            (string) ($mailConfig['from_name'] ?? 'MediShield')
        )
        : new LogMailer(
            (string) ($mailConfig['dump_dir'] ?? (__DIR__ . '/../logs/mail')),
            $clock
        );

    $provisioner = new InitialAdminProvisioner(
        $pdo,
        $users,
        new UserService($users, new PasswordPolicy()),
        $activations,
        $mailer,
        $baseUrl,
        $ttlHours
    );
    $result = $provisioner->provision((string) $options['name'], (string) $options['email']);
    if (!$result['ok']) {
        refuse(implode(' ', $result['errors']));
    }
    if (!$result['created']) {
        fwrite(STDOUT, 'No changes made: an administrator account already exists.' . PHP_EOL);
        exit(0);
    }

    try {
        $audit = new AuditLogger(
            $pdo,
            AuditChain::fromHexKey(
                (string) $config['audit_hmac_key_hex'],
                (string) ($config['audit_key_id'] ?? 'primary')
            ),
            $clock
        );
        foreach (['USER_CREATED', 'ACTIVATION_SENT'] as $action) {
            $audit->log([
                'user_id' => null,
                'user_role' => 'admin',
                'action' => $action,
                'module' => 'initial_admin_provisioning',
                'affected_record_id' => $result['user_id'],
                'ip_address' => '127.0.0.1',
                'user_agent' => 'MediShield CLI',
                'status' => 'SUCCESS',
            ]);
        }
    } catch (\Throwable $e) {
        error_log('[initial-admin] Provisioned account but failed to write audit entries: ' . $e->getMessage());
        fwrite(
            STDERR,
            'The inactive administrator and activation were created, but audit logging failed. '
            . 'No credential was printed; inspect the application error log.' . PHP_EOL
        );
        exit(2);
    }

    fwrite(
        STDOUT,
        'Inactive administrator created. The configured mail transport delivered an expiring '
        . 'single-use activation link; no password or token was printed.' . PHP_EOL
    );
} catch (\Throwable $e) {
    error_log('[initial-admin] Provisioning failed: ' . $e->getMessage());
    refuse('Initial administrator provisioning failed. Inspect the application error log.');
}
