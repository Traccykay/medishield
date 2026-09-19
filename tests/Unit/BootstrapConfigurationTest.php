<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Support\BootstrapConfigValidator;
use PHPUnit\Framework\TestCase;

final class BootstrapConfigurationTest extends TestCase
{
    private string $root;
    private string $workingDirectory;

    protected function setUp(): void
    {
        $this->root = dirname(__DIR__, 2);
        $this->workingDirectory = $this->root . DIRECTORY_SEPARATOR . 'test-results'
            . DIRECTORY_SEPARATOR . 'phpunit-bootstrap-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($this->workingDirectory, 0700, true));
    }

    protected function tearDown(): void
    {
        $mailDirectory = $this->workingDirectory . DIRECTORY_SEPARATOR . 'mail';
        foreach (glob($mailDirectory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            unlink($file);
        }
        if (is_dir($mailDirectory)) {
            rmdir($mailDirectory);
        }
        foreach (glob($this->workingDirectory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        if (is_dir($this->workingDirectory)) {
            rmdir($this->workingDirectory);
        }
    }

    public function testDefaultIdleTimeoutIsFiveMinutes(): void
    {
        $config = require $this->root . DIRECTORY_SEPARATOR . 'config'
            . DIRECTORY_SEPARATOR . 'config.sample.php';

        self::assertSame(300, $config['session']['idle_timeout_seconds']);
    }

    public function testBootstrap_ValidationRunsImmediatelyAfterConfiguredErrorLogAndBeforeSessionOrServices(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'bootstrap.php'
        );
        $errorLog = strpos($contents, 'ms_error_boundary_set_log_file((string) $configuredErrorLog)');
        $validation = strpos($contents, 'BootstrapConfigValidator::validate(ms_config())');
        $session = strpos($contents, 'session_status()');
        $database = strpos($contents, 'function ms_db');
        $audit = strpos($contents, 'function ms_audit');
        $mailer = strpos($contents, 'function ms_mailer');

        self::assertNotFalse($errorLog);
        self::assertNotFalse($validation);
        self::assertNotFalse($session);
        self::assertNotFalse($database);
        self::assertNotFalse($audit);
        self::assertNotFalse($mailer);
        self::assertLessThan($validation, $errorLog);
        self::assertLessThan($session, $validation);
        self::assertLessThan($database, $validation);
        self::assertLessThan($audit, $validation);
        self::assertLessThan($mailer, $validation);
    }

    public function testBootstrap_UnsafeProductionConfigurationStopsBeforeDatabaseCredentialOrMailSideEffects(): void
    {
        $config = $this->validConfig();
        $config['mail']['transport'] = 'log';
        $config['mail']['app_base_url'] = 'http://medishield.example.test/private-config-path';
        $config['mail']['smtp']['username'] = 'smtp-sensitive-identity@example.test';
        $config['mail']['smtp']['password'] = 'smtp-sensitive-password';

        $result = $this->runProbe($config, true, 'credential-flow');

        $this->assertGenericBoundaryOnly($result['output']);
        self::assertStringContainsString(BootstrapConfigValidator::FAILURE_MESSAGE, $result['log']);
        self::assertSame(1, substr_count($result['log'], BootstrapConfigValidator::FAILURE_MESSAGE));
        foreach ([
            'private-config-path',
            'smtp-sensitive-identity',
            'smtp-sensitive-password',
            $this->workingDirectory,
        ] as $sensitiveValue) {
            self::assertStringNotContainsString($sensitiveValue, $result['output']);
            self::assertStringNotContainsString($sensitiveValue, $result['log']);
        }
        $this->assertNoContinuationSideEffects();
    }

    public function testBootstrap_UnknownDevelopmentTransportStopsBeforeCredentialIssuance(): void
    {
        $config = $this->validConfig();
        $config['environment'] = 'development';
        $config['mail']['transport'] = 'unknown-sensitive-transport';

        $result = $this->runProbe($config, false, 'credential-flow');

        $this->assertGenericBoundaryOnly($result['output']);
        self::assertStringNotContainsString('unknown-sensitive-transport', $result['output']);
        $this->assertNoContinuationSideEffects();
    }

    public function testBootstrap_ProductionSmtpHttpsConfiguration_ReachesNextBootstrapStage(): void
    {
        $result = $this->runProbe($this->validConfig(), true, 'complete');

        self::assertStringContainsString('BOOTSTRAP_COMPLETE', $result['output']);
        self::assertStringNotContainsString('An unexpected error occurred', $result['output']);
        self::assertFileExists($this->workingDirectory . DIRECTORY_SEPARATOR . 'next-stage.marker');
        self::assertFileDoesNotExist($this->workingDirectory . DIRECTORY_SEPARATOR . 'database.marker');
        self::assertFileDoesNotExist($this->workingDirectory . DIRECTORY_SEPARATOR . 'token.marker');
    }

    public function testBootstrap_DevelopmentLogConfiguration_PreservesCredentialDeliveryWorkflow(): void
    {
        $config = $this->validConfig();
        $config['environment'] = 'development';
        $config['mail']['transport'] = 'log';
        $config['mail']['app_base_url'] = 'http://127.0.0.1:8000';

        $result = $this->runProbe($config, false, 'credential-flow');

        self::assertStringContainsString('CREDENTIAL_FLOW_COMPLETE', $result['output']);
        self::assertFileExists($this->workingDirectory . DIRECTORY_SEPARATOR . 'database.marker');
        self::assertFileExists($this->workingDirectory . DIRECTORY_SEPARATOR . 'token.marker');
        $messages = glob($this->workingDirectory . DIRECTORY_SEPARATOR . 'mail'
            . DIRECTORY_SEPARATOR . '*.txt') ?: [];
        self::assertCount(1, $messages);
        self::assertStringContainsString(
            'bootstrap-probe-credential',
            (string) file_get_contents($messages[0])
        );
    }

    /**
     * @param array<string,mixed> $config
     * @return array{output:string,log:string}
     */
    private function runProbe(array $config, bool $https, string $action): array
    {
        $config['error_log'] = $this->workingDirectory . DIRECTORY_SEPARATOR . 'app-errors.log';
        $config['mail']['dump_dir'] = $this->workingDirectory . DIRECTORY_SEPARATOR . 'mail';

        $environment = getenv();
        self::assertIsArray($environment);
        $environment['MEDISHIELD_BOOTSTRAP_PROBE_CONFIG'] = base64_encode(
            json_encode($config, JSON_THROW_ON_ERROR)
        );
        $environment['MEDISHIELD_BOOTSTRAP_PROBE_ACTION'] = $action;
        $environment['MEDISHIELD_BOOTSTRAP_PROBE_HTTPS'] = $https ? '1' : '0';
        $environment['MEDISHIELD_BOOTSTRAP_PROBE_DIRECTORY'] = $this->workingDirectory;
        $environment['MEDISHIELD_ERROR_LOG'] = $config['error_log'];

        $process = proc_open(
            [
                PHP_BINARY,
                $this->root . DIRECTORY_SEPARATOR . 'tests' . DIRECTORY_SEPARATOR
                    . 'Support' . DIRECTORY_SEPARATOR . 'bootstrap_config_probe.php',
            ],
            [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $this->root,
            $environment,
            ['bypass_shell' => true]
        );
        self::assertIsResource($process);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        $log = $this->workingDirectory . DIRECTORY_SEPARATOR . 'app-errors.log';

        return [
            'output' => (string) $stdout . (string) $stderr,
            'log' => is_file($log) ? (string) file_get_contents($log) : '',
        ];
    }

    private function assertGenericBoundaryOnly(string $output): void
    {
        self::assertStringContainsString(
            'An unexpected error occurred. Please try again later.',
            $output
        );
        self::assertStringNotContainsString(BootstrapConfigValidator::FAILURE_MESSAGE, $output);
        self::assertStringNotContainsString('RuntimeException', $output);
        self::assertStringNotContainsString('Stack trace', $output);
        self::assertStringNotContainsString('.php', $output);
        self::assertStringNotContainsString('smtp', $output);
        self::assertStringNotContainsString('token', $output);
        self::assertStringNotContainsString('credential', $output);
    }

    private function assertNoContinuationSideEffects(): void
    {
        self::assertFileDoesNotExist($this->workingDirectory . DIRECTORY_SEPARATOR . 'database.marker');
        self::assertFileDoesNotExist($this->workingDirectory . DIRECTORY_SEPARATOR . 'token.marker');
        self::assertDirectoryDoesNotExist($this->workingDirectory . DIRECTORY_SEPARATOR . 'mail');
    }

    /**
     * @return array<string,mixed>
     */
    private function validConfig(): array
    {
        return [
            'environment' => 'production',
            'encryption_key_hex' => str_repeat('11', 32),
            'audit_hmac_key_hex' => str_repeat('22', 32),
            'audit_key_id' => 'audit-primary-2026',
            'audit_anchor_hmac_key_hex' => str_repeat('33', 32),
            'audit_anchor_key_id' => 'anchor-primary-2026',
            'audit_anchor_path' => $this->workingDirectory . DIRECTORY_SEPARATOR
                . 'audit-chain-anchors.jsonl',
            'request_throttle_hmac_key_hex' => str_repeat('44', 32),
            'session' => [
                'cookie_name' => 'MEDISHIELD_PROBE_SID',
            ],
            'transport' => [
                'trusted_proxy_ips' => [],
            ],
            'mail' => [
                'transport' => 'smtp',
                'from_email' => 'no-reply@example.test',
                'from_name' => 'MediShield',
                'app_base_url' => 'https://medishield.example.test',
                'smtp' => [
                    'host' => 'smtp.example.test',
                    'port' => 587,
                    'encryption' => 'tls',
                    'username' => 'mailer@example.test',
                    'password' => 'bootstrap-probe-password',
                    'timeout' => 15,
                ],
            ],
        ];
    }
}
