<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for the XAMPP Apache configuration transaction.
 */
final class ApacheConfiguratorTest extends TestCase
{
    private string $script;
    private string $contents;

    protected function setUp(): void
    {
        $this->script = dirname(__DIR__, 2)
            . DIRECTORY_SEPARATOR . 'scripts'
            . DIRECTORY_SEPARATOR . 'configure-xampp-apache.ps1';
        self::assertFileExists($this->script);

        $this->contents = (string) file_get_contents($this->script);
    }

    #[DataProvider('powerShellEngines')]
    public function testNativeCommandHelper_WithNativeStderrAndFailure_CapturesResultAndRestoresPreference(
        string $engine
    ): void {
        $probe = str_replace(
            '__SCRIPT__',
            str_replace("'", "''", $this->script),
            <<<'POWERSHELL'
. '__SCRIPT__'
$ErrorActionPreference = 'Stop'
$nativeExecutable = Join-Path $env:SystemRoot 'System32\where.exe'
$result = Invoke-NativeCommand -FilePath $nativeExecutable -ArgumentList @(
    'medishield-command-that-does-not-exist'
)
[pscustomobject]@{
    ExitCode = $result.ExitCode
    Output = $result.Output
    ErrorActionPreference = [string] $ErrorActionPreference
} | ConvertTo-Json -Compress
POWERSHELL
        );

        $result = $this->runPowerShell($engine, $probe);

        self::assertSame(0, $result['exitCode'], $result['stderr']);
        $payload = json_decode(trim($result['stdout']), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        self::assertSame(1, $payload['ExitCode']);
        self::assertNotSame('', trim($payload['Output']));
        self::assertSame('Stop', $payload['ErrorActionPreference']);
    }

    #[DataProvider('powerShellEngines')]
    public function testConfigurationGenerator_WithCustomPort_PreservesDefaultSiteAndListener(
        string $engine
    ): void {
        $probe = str_replace(
            '__SCRIPT__',
            str_replace("'", "''", $this->script),
            <<<'POWERSHELL'
. '__SCRIPT__'
$customPortHardening = New-ApacheHardeningBody -MainContent "Listen 80`r`n" -Port 8765
$existingPortHardening = New-ApacheHardeningBody -MainContent "Listen 127.0.0.1:8765`r`n" -Port 8765
$virtualHosts = New-ApacheVirtualHostsBody `
    -DefaultRoot 'C:\xampp\htdocs' `
    -PublicRoot 'C:\repo\medishield\public' `
    -ApplicationHostName 'medishield.local' `
    -Port 8765
$remoteVirtualHosts = New-ApacheVirtualHostsBody `
    -DefaultRoot 'C:\xampp\htdocs' `
    -PublicRoot 'C:\repo\medishield\public' `
    -ApplicationHostName 'medishield.local' `
    -Port 8765 `
    -AllowRemoteAccess
[pscustomobject]@{
    CustomPortHardening = $customPortHardening
    ExistingPortHardening = $existingPortHardening
    VirtualHosts = $virtualHosts
    RemoteVirtualHosts = $remoteVirtualHosts
} | ConvertTo-Json -Compress
POWERSHELL
        );

        $result = $this->runPowerShell($engine, $probe);
        self::assertSame(0, $result['exitCode'], $result['stderr']);
        $payload = json_decode(trim($result['stdout']), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        self::assertStringContainsString('Listen 8765', $payload['CustomPortHardening']);
        self::assertStringNotContainsString('Listen 8765', $payload['ExistingPortHardening']);
        self::assertSame(2, substr_count($payload['VirtualHosts'], '<VirtualHost *:8765>'));
        self::assertStringContainsString('DocumentRoot "C:/xampp/htdocs"', $payload['VirtualHosts']);
        self::assertStringContainsString(
            'DocumentRoot "C:/repo/medishield/public"',
            $payload['VirtualHosts']
        );
        self::assertStringContainsString('Options -Indexes -MultiViews', $payload['VirtualHosts']);
        self::assertStringContainsString('AcceptPathInfo Off', $payload['VirtualHosts']);
        self::assertStringContainsString('Require local', $payload['VirtualHosts']);
        self::assertStringNotContainsString('Require all granted', $payload['VirtualHosts']);
        self::assertStringContainsString(
            'Header always set Referrer-Policy "no-referrer"',
            $payload['VirtualHosts']
        );
        self::assertStringContainsString('Require all granted', $payload['RemoteVirtualHosts']);
        self::assertStringNotContainsString('Require local', $payload['RemoteVirtualHosts']);

        $defaultHost = strpos($payload['VirtualHosts'], 'ServerName localhost');
        $medishieldHost = strpos($payload['VirtualHosts'], 'ServerName medishield.local');
        self::assertNotFalse($defaultHost);
        self::assertNotFalse($medishieldHost);
        self::assertLessThan(
            $medishieldHost,
            $defaultHost,
            'The localhost vhost must be first so unmatched Host requests retain XAMPP behavior.'
        );
    }

    #[DataProvider('powerShellEngines')]
    public function testHttpProbe_WithDeniedResponse_InspectsPrimaryErrorBodyAndRepositoryPath(
        string $engine
    ): void {
        $errorDetailsBody = strpos(
            $this->contents,
            '$body = [string] $ErrorRecord.ErrorDetails.Message'
        );
        $responseFallback = strpos($this->contents, 'ReadAsStringAsync');

        self::assertNotFalse($errorDetailsBody);
        self::assertNotFalse($responseFallback);
        self::assertLessThan(
            $responseFallback,
            $errorDetailsBody,
            'PowerShell ErrorDetails.Message must be inspected before version-specific response fallbacks.'
        );
        self::assertStringContainsString('$bodyInspected', $this->contents);
        self::assertStringContainsString('$repositoryRoot', $this->forbiddenContentBlock());

        $probe = str_replace(
            '__SCRIPT__',
            str_replace("'", "''", $this->script),
            <<<'POWERSHELL'
. '__SCRIPT__'
$errorRecord = [System.Management.Automation.ErrorRecord]::new(
    [Exception]::new('exception fallback must not win'),
    'MediShield.HttpProbe',
    [System.Management.Automation.ErrorCategory]::InvalidResult,
    $null
)
$errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('forbidden response body')
$result = Get-HttpErrorBody -ErrorRecord $errorRecord
$result | ConvertTo-Json -Compress
POWERSHELL
        );
        $result = $this->runPowerShell($engine, $probe);

        self::assertSame(0, $result['exitCode'], $result['stderr']);
        $payload = json_decode(trim($result['stdout']), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        self::assertTrue($payload['Inspected']);
        self::assertSame('forbidden response body', $payload['Body']);
    }

    public function testApacheProcessTransaction_UsesNativeHelperForEveryHttpdInvocation(): void
    {
        self::assertDoesNotMatchRegularExpression('/&\s*\$httpd\b/', $this->contents);
        self::assertStringContainsString(
            "Invoke-NativeCommand -FilePath \$httpd -ArgumentList @('-t')",
            $this->contents
        );
        self::assertStringContainsString(
            "Invoke-NativeCommand -FilePath \$httpd -ArgumentList @('-k', 'restart')",
            $this->contents
        );
        self::assertStringContainsString(
            "Invoke-NativeCommand -FilePath \$httpd -ArgumentList @('-k', 'shutdown')",
            $this->contents
        );
        self::assertStringContainsString(
            'Runtime verification failed; Apache, hosts, and process state were restored.',
            $this->contents
        );
    }

    public function testRuntimeVerification_CoversExposureProtocolAndHeaderBoundary(): void
    {
        foreach ([
            '/README.md',
            '/.htaccess',
            '/router.php',
            '/assets/README.md',
            '/assets/css/style.css',
            '/assets/css/style.css.map',
            '/assets/css/',
            '/login.php.bak',
            '/manifest.json',
            '/runtime-probe-missing',
            "'TRACE'",
            "Host = 'unexpected.invalid'",
            'ExpectedContentType',
            'RequireSecurityHeaders',
            'AllowCaching',
        ] as $probe) {
            self::assertStringContainsString($probe, $this->contents);
        }

        self::assertStringContainsString(
            'returned non-unique or unexpected',
            $this->contents
        );
        self::assertStringContainsString(
            "'Referrer-Policy' = 'no-referrer'",
            $this->contents
        );
    }

    /**
     * @return iterable<string,array{string}>
     */
    public static function powerShellEngines(): iterable
    {
        yield 'Windows PowerShell 5.1' => ['powershell.exe'];
        yield 'PowerShell 7' => ['pwsh.exe'];
    }

    /**
     * @return array{exitCode:int,stdout:string,stderr:string}
     */
    private function runPowerShell(string $engine, string $probe): array
    {
        $executable = $this->findExecutable($engine);
        if ($executable === null && strcasecmp($engine, 'pwsh.exe') === 0) {
            self::markTestSkipped('Optional PowerShell 7 compatibility check requires pwsh.exe.');
        }
        self::assertNotNull($executable, "{$engine} is required for XAMPP automation tests.");

        $process = proc_open(
            [
                $executable,
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
            dirname(__DIR__, 2),
            null,
            ['bypass_shell' => true]
        );
        self::assertIsResource($process, "{$engine} must be installed for its compatibility regression.");

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

    private function findExecutable(string $executable): ?string
    {
        $path = getenv('PATH');
        if (!is_string($path)) {
            return null;
        }

        foreach (explode(PATH_SEPARATOR, $path) as $directory) {
            $candidate = rtrim($directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $executable;
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    private function forbiddenContentBlock(): string
    {
        $start = strpos($this->contents, '$forbidden = @(');
        self::assertNotFalse($start);

        $end = strpos($this->contents, ')', $start);
        self::assertNotFalse($end);

        return substr($this->contents, $start, $end - $start + 1);
    }
}
