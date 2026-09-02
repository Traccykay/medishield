<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Regression tests for the checked-in Apache and CLI execution boundaries.
 */
final class DeploymentBoundaryTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = dirname(__DIR__, 2);
    }

    public function testRepositoryRootHtaccess_AllowsOnlyPublicSubtree(): void
    {
        $path = $this->root . DIRECTORY_SEPARATOR . '.htaccess';

        self::assertFileExists($path);
        $contents = (string) file_get_contents($path);

        self::assertStringContainsString('Options -Indexes', $contents);
        self::assertStringContainsString('RewriteRule ^public(?:/|$) - [L]', $contents);
        self::assertStringContainsString('RewriteRule ^ - [F,L]', $contents);
    }

    public function testPublicHtaccess_BlocksIncludeOnlyAndDocumentationFiles(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . '.htaccess'
        );

        self::assertStringContainsString('RewriteRule ^partials(?:/|$) - [F,L,NC]', $contents);
        self::assertStringContainsString('README', $contents);
        self::assertStringContainsString('Require all denied', $contents);
    }

    public function testMaintenanceScripts_CheckCliBeforeAutoloadOrConfiguration(): void
    {
        $scripts = glob($this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . '*.php');
        self::assertIsArray($scripts);
        self::assertNotEmpty($scripts);

        foreach ($scripts as $script) {
            $contents = (string) file_get_contents($script);
            $guard = strpos($contents, "PHP_SAPI !== 'cli'");
            $autoload = strpos($contents, 'vendor/autoload.php');
            $configuration = strpos($contents, 'config/config.php');

            self::assertNotFalse($guard, basename($script) . ' must reject non-CLI execution.');
            if ($autoload !== false) {
                self::assertLessThan($autoload, $guard, basename($script) . ' must guard before autoloading.');
            }
            if ($configuration !== false) {
                self::assertLessThan($configuration, $guard, basename($script) . ' must guard before configuration.');
            }
        }
    }

    public function testUiDatabaseSetup_AllowsOnlyNamedDisposableDatabases(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . 'setup-ui-test-db.ps1'
        );

        self::assertStringContainsString(
            "'medishield_ui_test', 'medishield_ui_account_test'",
            $contents
        );
        self::assertStringContainsString('$DbName -notin $AllowedDatabases', $contents);
    }

    public function testBillingPartial_LivesOutsidePublicDocumentRoot(): void
    {
        self::assertFileDoesNotExist(
            $this->root . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'partials'
                . DIRECTORY_SEPARATOR . 'bill_charges.php'
        );
        self::assertFileExists(
            $this->root . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'partials'
                . DIRECTORY_SEPARATOR . 'bill_charges.php'
        );
    }

    public function testPhpConfigurator_EnforcesProductionSafeDiagnostics(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . 'configure-php-ini.ps1'
        );

        foreach ([
            "'display_errors'         = 'Off'",
            "'display_startup_errors' = 'Off'",
            "'log_errors'             = 'On'",
            "'error_reporting'        = 'E_ALL'",
            "'expose_php'             = 'Off'",
            "'zend.exception_ignore_args' = 'On'",
        ] as $setting) {
            self::assertStringContainsString($setting, $contents);
        }
        self::assertStringContainsString(
            "'zend.exception_ignore_args' = @('1', 'On')",
            $contents
        );
        self::assertStringContainsString('PHP INI verification failed', $contents);
    }

    public function testApacheConfigurator_HardensAndValidatesXamppConfiguration(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . 'configure-xampp-apache.ps1'
        );

        foreach ([
            'ServerTokens Prod',
            'ServerSignature Off',
            'LoadModule rewrite_module modules/mod_rewrite.so',
            'AllowOverride All',
            'httpd.exe -t',
            'medishield.local',
            'configure-php-ini.ps1',
        ] as $requirement) {
            self::assertStringContainsString($requirement, $contents);
        }
        self::assertStringContainsString('Test-ApacheRunning', $contents);
        self::assertStringContainsString(
            'Runtime verification failed; Apache, hosts, and process state were restored.',
            $contents
        );
    }
}
