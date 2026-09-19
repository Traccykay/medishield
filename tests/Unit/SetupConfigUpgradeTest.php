<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Regression tests for setup-time upgrades of the ignored application config.
 */
final class SetupConfigUpgradeTest extends TestCase
{
    private string $root;
    private string $samplePath;
    private string $setupConfigScript;

    protected function setUp(): void
    {
        $this->root = dirname(__DIR__, 2);
        $this->samplePath = $this->root . DIRECTORY_SEPARATOR . 'config'
            . DIRECTORY_SEPARATOR . 'config.sample.php';
        $this->setupConfigScript = $this->root . DIRECTORY_SEPARATOR . 'scripts'
            . DIRECTORY_SEPARATOR . 'setup-config.ps1';
    }

    public function testDisposableUpgrade_WithLegacyNormalConfig_PreservesPersistentDatabaseNamesAndSecrets(): void
    {
        $configPath = $this->newTestConfigPath();
        $legacySecrets = $this->knownSecrets();
        file_put_contents($configPath, $this->legacyConfigWithoutMaintenanceBlock($legacySecrets));

        try {
            $result = $this->runConfigUpgrade(
                $configPath,
                'medishield_ui_test',
                true
            );

            self::assertSame(0, $result['exitCode'], $result['stderr']);
            $config = require $configPath;
            self::assertIsArray($config);
            self::assertSame('medishield_db', $config['db']['name']);
            self::assertSame('medishield_db', $config['audit_maintenance_db']['name']);
            self::assertSame('legacy-web-password', $config['db']['pass']);
            self::assertSame(str_repeat('1', 64), $config['encryption_key_hex']);
            self::assertSame(str_repeat('2', 64), $config['audit_hmac_key_hex']);
            self::assertSame(str_repeat('3', 64), $config['audit_anchor_hmac_key_hex']);
            self::assertSame(str_repeat('4', 64), $config['request_throttle_hmac_key_hex']);
            self::assertMatchesRegularExpression(
                '/\A[0-9a-f]{64}\z/',
                $config['audit_maintenance_db']['pass']
            );
            self::assertStringNotContainsString(
                'medishield_ui_test',
                (string) file_get_contents($configPath)
            );
        } finally {
            @unlink($configPath);
            @unlink($configPath . '.pre-hardening.bak');
        }
    }

    public function testNormalUpgrade_WithMaintenanceDatabaseDrift_RepairsOnlyThatName(): void
    {
        $configPath = $this->newTestConfigPath();
        $driftedConfig = $this->configuredSample($this->knownSecrets());
        $driftedConfig = $this->replaceMaintenanceDatabaseName(
            $driftedConfig,
            'medishield_ui_test'
        );
        $expectedConfig = $this->replaceMaintenanceDatabaseName(
            $driftedConfig,
            'medishield_db'
        );
        file_put_contents($configPath, $driftedConfig);

        try {
            $result = $this->runConfigUpgrade($configPath, 'medishield_db', false);

            self::assertSame(0, $result['exitCode'], $result['stderr']);
            self::assertSame($expectedConfig, (string) file_get_contents($configPath));
        } finally {
            @unlink($configPath);
            @unlink($configPath . '.pre-hardening.bak');
        }
    }

    public function testFreshNormalSetup_WithSelectedDatabase_GeneratesAlignedConfiguration(): void
    {
        $configPath = $this->newTestConfigPath();

        try {
            $result = $this->runConfigUpgrade(
                $configPath,
                'medishield_phase5_fresh',
                false
            );

            self::assertSame(0, $result['exitCode'], $result['stderr']);
            $config = require $configPath;
            self::assertIsArray($config);
            self::assertSame('medishield_phase5_fresh', $config['db']['name']);
            self::assertSame(
                'medishield_phase5_fresh',
                $config['audit_maintenance_db']['name']
            );
            self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $config['db']['pass']);
            self::assertMatchesRegularExpression(
                '/\A[0-9a-f]{64}\z/',
                $config['audit_maintenance_db']['pass']
            );

            $keys = [
                $config['encryption_key_hex'],
                $config['audit_hmac_key_hex'],
                $config['audit_anchor_hmac_key_hex'],
                $config['request_throttle_hmac_key_hex'],
            ];
            self::assertCount(4, array_unique($keys));
            $contents = (string) file_get_contents($configPath);
            foreach (array_keys($this->knownSecrets()) as $placeholder) {
                self::assertStringNotContainsString($placeholder, $contents);
            }
        } finally {
            @unlink($configPath);
            @unlink($configPath . '.pre-hardening.bak');
        }
    }

    public function testFreshDisposableSetup_UsesSampleNormalDatabaseForPersistentConfiguration(): void
    {
        $configPath = $this->newTestConfigPath();

        try {
            $result = $this->runConfigUpgrade($configPath, 'medishield_ui_test', true);

            self::assertSame(0, $result['exitCode'], $result['stderr']);
            $config = require $configPath;
            self::assertIsArray($config);
            self::assertSame('medishield_db', $config['db']['name']);
            self::assertSame('medishield_db', $config['audit_maintenance_db']['name']);
            self::assertStringNotContainsString(
                'medishield_ui_test',
                (string) file_get_contents($configPath)
            );
        } finally {
            @unlink($configPath);
            @unlink($configPath . '.pre-hardening.bak');
        }
    }

    public function testConfigUpgrade_WithCommandShapedDatabaseName_RejectsWithoutWritingConfig(): void
    {
        $configPath = $this->newTestConfigPath();

        try {
            $result = $this->runConfigUpgrade(
                $configPath,
                "medishield_db'; Remove-Item config.php; '",
                false
            );

            self::assertNotSame(0, $result['exitCode']);
            self::assertStringContainsString(
                'contains unsupported characters',
                $result['stderr']
            );
            self::assertFileDoesNotExist($configPath);
        } finally {
            @unlink($configPath);
            @unlink($configPath . '.pre-hardening.bak');
        }
    }

    /**
     * @param array<string,string> $replacements
     */
    private function legacyConfigWithoutMaintenanceBlock(array $replacements): string
    {
        $sample = $this->configuredSample($replacements);
        $maintenanceStart = strpos($sample, '    // Used only by scripts/purge-audit-pii.php.');
        $cryptoStart = strpos($sample, '    // --- Cryptographic keys', (int) $maintenanceStart);

        self::assertNotFalse($maintenanceStart);
        self::assertNotFalse($cryptoStart);

        $legacy = substr($sample, 0, $maintenanceStart) . substr($sample, $cryptoStart);

        return $legacy;
    }

    /**
     * @param array<string,string> $replacements
     */
    public function testUpgrade_ReplacesOnlyThePreviousTwentyMinuteIdleDefault(): void
    {
        $configPath = $this->newTestConfigPath();
        $legacy = $this->configuredSample($this->knownSecrets());
        $legacy = str_replace(
            "'idle_timeout_seconds'     => 300,",
            "'idle_timeout_seconds'     => 1200,",
            $legacy
        );
        file_put_contents($configPath, $legacy);

        try {
            $result = $this->runConfigUpgrade($configPath, 'medishield_db', false);

            self::assertSame(0, $result['exitCode'], $result['stderr']);
            $config = require $configPath;
            self::assertSame(300, $config['session']['idle_timeout_seconds']);
        } finally {
            @unlink($configPath);
            @unlink($configPath . '.pre-hardening.bak');
        }
    }

    private function configuredSample(array $replacements): string
    {
        return str_replace(
            array_keys($replacements),
            array_values($replacements),
            (string) file_get_contents($this->samplePath)
        );
    }

    private function replaceMaintenanceDatabaseName(string $config, string $databaseName): string
    {
        $blockStart = strpos($config, "    'audit_maintenance_db' => [");
        self::assertNotFalse($blockStart);
        $nameStart = strpos($config, "        'name'    => '", $blockStart);
        self::assertNotFalse($nameStart);
        $valueStart = $nameStart + strlen("        'name'    => '");
        $valueEnd = strpos($config, "'", $valueStart);
        self::assertNotFalse($valueEnd);

        return substr($config, 0, $valueStart)
            . $databaseName
            . substr($config, $valueEnd);
    }

    /**
     * @return array<string,string>
     */
    private function knownSecrets(): array
    {
        return [
            '__DB_PASSWORD__' => 'legacy-web-password',
            '__AUDIT_MAINTENANCE_DB_PASSWORD__' => 'legacy-maintenance-password',
            '__ENCRYPTION_KEY__' => str_repeat('1', 64),
            '__AUDIT_HMAC_KEY__' => str_repeat('2', 64),
            '__AUDIT_ANCHOR_HMAC_KEY__' => str_repeat('3', 64),
            '__THROTTLE_HMAC_KEY__' => str_repeat('4', 64),
        ];
    }

    private function newTestConfigPath(): string
    {
        return $this->root . DIRECTORY_SEPARATOR . 'tests' . DIRECTORY_SEPARATOR
            . 'setup-config-' . bin2hex(random_bytes(8)) . '.php';
    }

    /**
     * @return array{exitCode:int,stdout:string,stderr:string}
     */
    private function runConfigUpgrade(
        string $configPath,
        string $selectedDatabase,
        bool $disposable
    ): array {
        $quote = static fn (string $value): string => str_replace("'", "''", $value);
        $disposableArgument = $disposable ? '$true' : '$false';
        $probe = sprintf(
            <<<'POWERSHELL'
$ErrorActionPreference = 'Stop'
. '%s'
Update-MediShieldApplicationConfig `
    -SamplePath '%s' `
    -DestinationPath '%s' `
    -SelectedDatabaseName '%s' `
    -DisposableUiSetup:%s | Out-Null
POWERSHELL,
            $quote($this->setupConfigScript),
            $quote($this->samplePath),
            $quote($configPath),
            $quote($selectedDatabase),
            $disposableArgument
        );

        $process = proc_open(
            [
                'powershell.exe',
                '-NoLogo',
                '-NoProfile',
                '-NonInteractive',
                '-ExecutionPolicy',
                'Bypass',
                '-Command',
                $probe,
            ],
            [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $this->root,
            null,
            ['bypass_shell' => true]
        );
        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [
            'exitCode' => proc_close($process),
            'stdout' => $stdout,
            'stderr' => $stderr,
        ];
    }
}
