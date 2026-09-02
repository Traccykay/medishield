<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Subprocess tests prove bootstrap failures cannot leak diagnostic detail.
 */
final class ErrorBoundaryTest extends TestCase
{
    private string $root;
    private string $temporaryDirectory;

    protected function setUp(): void
    {
        $this->root = dirname(__DIR__, 2);
        $this->temporaryDirectory = sys_get_temp_dir()
            . DIRECTORY_SEPARATOR
            . 'medishield-error-boundary-'
            . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($this->temporaryDirectory, 0700, true));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->temporaryDirectory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->temporaryDirectory);
    }

    public function testEarlyBootstrapFailure_ReturnsOnlyGenericResponse(): void
    {
        $result = $this->runProbe(
            "require __DIR__ . '/missing/vendor/autoload.php';"
        );

        $this->assertGenericResponse($result['output']);
    }

    public function testDatabaseConfigurationFailure_HidesSensitiveDetailsAndLogsDiagnostics(): void
    {
        $sensitiveMessage = 'SQLSTATE[HY000] user medishield_app database medishield_db '
            . 'at C:\\xampp\\htdocs\\medishield\\src\\Database\\Connection.php';
        $result = $this->runProbe(
            'throw new PDOException(' . var_export($sensitiveMessage, true) . ');'
        );

        $this->assertGenericResponse($result['output']);
        foreach (['SQLSTATE', 'medishield_app', 'medishield_db', 'C:\\xampp', 'PDOException', 'Stack trace'] as $secret) {
            self::assertStringNotContainsStringIgnoringCase($secret, $result['output']);
        }

        self::assertStringContainsString('[uncaught]', $result['log']);
        self::assertStringContainsString('PDOException', $result['log']);
        self::assertStringContainsString('medishield_db', $result['log']);
    }

    public function testUncaughtException_WithSecretScalarArgument_LogsDiagnosticsWithoutSecret(): void
    {
        $secret = 'trace-secret-' . bin2hex(random_bytes(24));
        $result = $this->runProbe(
            <<<'PHP'
$ignoreArgs = strtolower((string) ini_get('zend.exception_ignore_args'));
if (!in_array($ignoreArgs, ['1', 'on'], true)) {
    throw new RuntimeException('Trace argument suppression is inactive.');
}
function medishield_trace_secret_probe(string $credential): void
{
    throw new RuntimeException('Trace argument diagnostic probe.');
}
medishield_trace_secret_probe(%s);
PHP,
            ['zend.exception_ignore_args' => '0'],
            [$secret]
        );

        $this->assertGenericResponse($result['output']);
        self::assertStringContainsString('[uncaught]', $result['log']);
        self::assertStringContainsString('RuntimeException: Trace argument diagnostic probe.', $result['log']);
        self::assertStringContainsString('medishield_trace_secret_probe', $result['log']);
        self::assertFalse(
            str_contains($result['log'], $secret),
            'Server diagnostics exposed a scalar stack-trace argument.'
        );
    }

    public function testBootstrap_LoadsErrorBoundaryBeforeComposerAndConfiguration(): void
    {
        $contents = (string) file_get_contents($this->root . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'bootstrap.php');
        $boundary = strpos($contents, "require_once __DIR__ . '/error_boundary.php'");
        $autoload = strpos($contents, 'vendor/autoload.php');
        $configuration = strpos($contents, 'function ms_config');

        self::assertNotFalse($boundary);
        self::assertNotFalse($autoload);
        self::assertNotFalse($configuration);
        self::assertLessThan($autoload, $boundary);
        self::assertLessThan($configuration, $boundary);
    }

    /**
     * @return array{output:string,log:string}
     */
    private function runProbe(string $statement, array $iniSettings = [], array $statementArguments = []): array
    {
        $script = $this->temporaryDirectory . DIRECTORY_SEPARATOR . 'probe.php';
        $log = $this->temporaryDirectory . DIRECTORY_SEPARATOR . 'app-errors.log';
        $boundary = $this->root . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'error_boundary.php';
        if ($statementArguments !== []) {
            $statement = sprintf(
                $statement,
                ...array_map(static fn (string $value): string => var_export($value, true), $statementArguments)
            );
        }
        file_put_contents(
            $script,
            "<?php\nrequire " . var_export($boundary, true) . ";\n{$statement}\n"
        );

        $descriptorSpec = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $environment = getenv();
        self::assertIsArray($environment);
        $environment['MEDISHIELD_ERROR_LOG'] = $log;
        $command = [PHP_BINARY];
        foreach ($iniSettings as $name => $value) {
            $command[] = '-d';
            $command[] = $name . '=' . $value;
        }
        $command[] = $script;
        $process = proc_open(
            $command,
            $descriptorSpec,
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

        return [
            'output' => (string) $stdout . (string) $stderr,
            'log' => is_file($log) ? (string) file_get_contents($log) : '',
        ];
    }

    private function assertGenericResponse(string $output): void
    {
        self::assertStringContainsString(
            'An unexpected error occurred. Please try again later.',
            $output
        );
        self::assertStringNotContainsString('missing/vendor/autoload.php', $output);
        self::assertStringNotContainsString('ErrorBoundaryTest.php', $output);
        self::assertStringNotContainsString('Stack trace', $output);
    }
}
