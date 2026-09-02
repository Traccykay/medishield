<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
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
        self::assertStringContainsString('& $scriptPath -DbName $DbName', $contents);
    }

    public function testDatabaseSetup_PropagatesSelectedDatabaseToVitalsMigration(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . 'setup-db.ps1'
        );
        $databaseOverride = strpos($contents, '$env:MEDISHIELD_SETUP_DB_NAME = $DbName');
        $migrationInvocation = strpos($contents, '& php $vitalsMigrationPath');
        $databaseOverrideCleanup = strpos(
            $contents,
            'Remove-Item Env:MEDISHIELD_SETUP_DB_NAME'
        );

        self::assertNotFalse($databaseOverride);
        self::assertNotFalse($migrationInvocation);
        self::assertNotFalse($databaseOverrideCleanup);
        self::assertLessThan($migrationInvocation, $databaseOverride);
        self::assertGreaterThan($migrationInvocation, $databaseOverrideCleanup);
    }

    #[DataProvider('disposablePhpHelpers')]
    public function testDisposablePhpHelper_WithUntrustedDatabaseOverride_RefusesBeforeDatabaseAccess(
        string $script,
        string $environmentVariable
    ): void {
        $environment = getenv();
        self::assertIsArray($environment);
        $environment['MEDISHIELD_DB_NAME'] = 'medishield_arbitrary';
        $environment['MEDISHIELD_SETUP_DB_NAME'] = 'medishield_arbitrary';
        $environment['MEDISHIELD_SETUP_DB_USER'] = 'medishield_boundary_probe_invalid';
        $environment['MEDISHIELD_SETUP_DB_PASS'] = '';
        $environment[$environmentVariable] = 'medishield_arbitrary';

        $process = proc_open(
            [
                PHP_BINARY,
                $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . $script,
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
        $exitCode = proc_close($process);
        $output = (string) $stdout . (string) $stderr;

        self::assertNotSame(0, $exitCode, $script . ' must reject an untrusted database override.');
        self::assertStringContainsString(
            'isolated UI test database',
            $output,
            $script . ' must enforce the shared disposable-database boundary.'
        );
        self::assertStringNotContainsString(
            'SQLSTATE',
            $output,
            $script . ' must reject the override before attempting a database connection.'
        );
    }

    public function testApplicationSeed_DoesNotInstallUniversalAdministrator(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'sql' . DIRECTORY_SEPARATOR . 'seed.sql'
        );

        self::assertStringNotContainsString('INSERT IGNORE INTO users', $contents);
        self::assertStringNotContainsString('medishield.superadmin@gmail.com', $contents);
        self::assertStringNotContainsString('ChangeMe!2026', $contents);
        self::assertStringNotContainsString('$2y$', $contents);
    }

    public function testDatabaseSetup_DoesNotDiscloseUniversalCredential(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . 'setup-db.ps1'
        );

        self::assertStringNotContainsString('medishield.superadmin@gmail.com', $contents);
        self::assertStringNotContainsString('ChangeMe!2026', $contents);
        self::assertStringContainsString('provision-initial-admin.php', $contents);
    }

    public function testInitialAdminProvisioning_RequiresCliAndExplicitDatabaseConfirmation(): void
    {
        $path = $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR
            . 'provision-initial-admin.php';

        self::assertFileExists($path);
        $contents = (string) file_get_contents($path);
        $guard = strpos($contents, "PHP_SAPI !== 'cli'");
        $autoload = strpos($contents, 'vendor/autoload.php');
        $configuration = strpos($contents, 'config/config.php');

        self::assertNotFalse($guard);
        self::assertNotFalse($autoload);
        self::assertNotFalse($configuration);
        self::assertLessThan($autoload, $guard);
        self::assertLessThan($configuration, $guard);
        self::assertStringContainsString('confirm-initial-admin', $contents);
        self::assertStringContainsString('confirm-database', $contents);
    }

    public function testInitialAdminProvisioning_WithoutExplicitConfirmation_RefusesBeforeDatabaseAccess(): void
    {
        $path = $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR
            . 'provision-initial-admin.php';
        $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($path) . ' 2>&1';
        exec($command, $output, $exitCode);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString(
            'Refusing to provision without --confirm-initial-admin.',
            implode("\n", $output)
        );
    }

    public function testUiSeeder_OwnsDeterministicForcedPasswordFixture(): void
    {
        $seed = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR
            . 'seed-ui-test-users.php'
        );
        $browserTest = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'e2e' . DIRECTORY_SEPARATOR
            . 'account-self-service.spec.js'
        );

        self::assertStringContainsString('ui.forced-password-admin@medishield.test', $seed);
        self::assertStringContainsString('UiTest!2026A', $seed);
        self::assertStringContainsString('ui.forced-password-admin@medishield.test', $browserTest);
        self::assertStringNotContainsString('medishield.superadmin@gmail.com', $browserTest);
        self::assertStringNotContainsString('ChangeMe!2026', $browserTest);
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

    public function testBootstrap_EnforcesStrictCookieOnlySessionsBeforeStartingSession(): void
    {
        $contents = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'bootstrap.php'
        );

        $strictMode = strpos($contents, "ini_set('session.use_strict_mode', '1')");
        $cookieOnly = strpos($contents, "ini_set('session.use_only_cookies', '1')");
        $sessionStart = strpos($contents, 'if (!session_start())');

        self::assertNotFalse($strictMode);
        self::assertNotFalse($cookieOnly);
        self::assertNotFalse($sessionStart);
        self::assertLessThan($sessionStart, $strictMode);
        self::assertLessThan($sessionStart, $cookieOnly);
        self::assertStringContainsString("ini_get('session.use_strict_mode')", $contents);
        self::assertStringContainsString("ini_get('session.use_only_cookies')", $contents);
    }

    public function testSensitiveAuthenticationResponses_OptOutOfCaching(): void
    {
        $headers = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'headers.php'
        );
        self::assertStringContainsString(
            'Cache-Control: no-store, no-cache, must-revalidate, max-age=0',
            $headers
        );

        foreach ([
            'login.php',
            'verify_otp.php',
            'activate.php',
            'forgot_password.php',
            'change_password.php',
        ] as $page) {
            $contents = (string) file_get_contents(
                $this->root . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . $page
            );
            self::assertStringContainsString('ms_send_no_store_headers();', $contents, $page);
        }

        $adminReset = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR
            . 'admin' . DIRECTORY_SEPARATOR . 'reset_password.php'
        );
        self::assertStringContainsString('ms_send_no_store_headers();', $adminReset);
    }

    public function testStateChangingControllers_UseTheCentralRequestGuard(): void
    {
        $controllers = [
            'activate.php',
            'admin/assign_patient.php',
            'admin/create_user.php',
            'admin/reset_password.php',
            'admin/users.php',
            'change_password.php',
            'doctor/add_diagnosis.php',
            'doctor/issue_prescription.php',
            'doctor/request_lab.php',
            'forgot_password.php',
            'lab/upload_result.php',
            'login.php',
            'logout.php',
            'nurse/add_vitals.php',
            'nurse/assign_doctor.php',
            'nurse/triage.php',
            'payments.php',
            'pharmacy/dispense.php',
            'reception/intake.php',
            'register_patient.php',
            'verify_otp.php',
        ];

        foreach ($controllers as $controller) {
            $contents = (string) file_get_contents(
                $this->root . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR
                . str_replace('/', DIRECTORY_SEPARATOR, $controller)
            );

            self::assertStringContainsString(
                'request_post_guard(',
                $contents,
                $controller . ' must use the central method and CSRF guard.'
            );
            self::assertStringNotContainsString(
                'Csrf::check(',
                $contents,
                $controller . ' must not retain a route-local CSRF branch.'
            );
        }
    }

    public function testAuthVersionMigration_IsIdempotentOnMariaDbAndMySql(): void
    {
        $migration = (string) file_get_contents(
            $this->root . DIRECTORY_SEPARATOR . 'sql' . DIRECTORY_SEPARATOR . 'migrations'
                . DIRECTORY_SEPARATOR . '2026-09-02_add_auth_version.sql'
        );

        self::assertStringContainsString('information_schema.COLUMNS', $migration);
        self::assertStringContainsString('PREPARE', $migration);
        self::assertStringContainsString('ADD COLUMN auth_version', $migration);
        self::assertStringNotContainsString('ADD COLUMN IF NOT EXISTS auth_version', $migration);
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

    /** @return array<string,array{string,string}> */
    public static function disposablePhpHelpers(): array
    {
        return [
            'vitals encryption migration' => [
                'migrate-vitals-encryption.php',
                'MEDISHIELD_SETUP_DB_NAME',
            ],
            'UI account seed' => [
                'seed-ui-test-users.php',
                'MEDISHIELD_DB_NAME',
            ],
            'UI workflow seed' => [
                'seed-ui-dashboard-data.php',
                'MEDISHIELD_DB_NAME',
            ],
        ];
    }
}
