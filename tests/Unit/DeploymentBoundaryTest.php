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
}
