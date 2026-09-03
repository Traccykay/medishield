<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Regression tests for dependency, workstation installer, and ZAP boundaries.
 */
final class ToolchainHardeningTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = dirname(__DIR__, 2);
    }

    public function testComposerLock_TargetsPhp81AndMaintainedPhpunit10(): void
    {
        $manifest = $this->readJson('composer.json');
        $lock = $this->readJson('composer.lock');

        self::assertSame('>=8.1', $manifest['require']['php'] ?? null);
        self::assertSame('^10.5', $manifest['require-dev']['phpunit/phpunit'] ?? null);
        self::assertSame('8.1.0', $manifest['config']['platform']['php'] ?? null);
        self::assertSame('8.1.0', $lock['platform-overrides']['php'] ?? null);

        $phpunit = $this->findComposerPackage($lock, 'phpunit/phpunit');
        self::assertMatchesRegularExpression('/^10\.5\.\d+$/', (string) ($phpunit['version'] ?? ''));
        self::assertSame('>=8.1', $phpunit['require']['php'] ?? null);
        self::assertNotNull($this->findComposerPackage($lock, 'phpmailer/phpmailer'));
    }

    public function testNpmLock_UsesExactPlaywrightAndOfficialSha512Artifacts(): void
    {
        $manifest = $this->readJson('package.json');
        $lock = $this->readJson('package-lock.json');

        self::assertSame('1.61.1', $manifest['devDependencies']['@playwright/test'] ?? null);
        self::assertSame(
            '1.61.1',
            $lock['packages']['']['devDependencies']['@playwright/test'] ?? null
        );

        foreach ($lock['packages'] as $path => $package) {
            if ($path === '') {
                continue;
            }

            self::assertStringStartsWith(
                'https://registry.npmjs.org/',
                (string) ($package['resolved'] ?? ''),
                "{$path} must resolve only from the approved npm registry."
            );
            self::assertStringStartsWith(
                'sha512-',
                (string) ($package['integrity'] ?? ''),
                "{$path} must use the strongest registry integrity supplied in the lock."
            );
        }
    }

    public function testDependencyAuditScript_UsesBothLockedEcosystemsAndSignatureVerification(): void
    {
        $contents = $this->readFile('scripts/audit-dependencies.ps1');

        foreach ([
            'composer validate --strict',
            'composer audit --locked',
            'composer prohibits php 8.1 --tree',
            'npm.cmd ci --ignore-scripts',
            'npm.cmd audit --package-lock-only --ignore-scripts',
            'npm.cmd audit signatures',
            'https://registry.npmjs.org/',
            '--strict-ssl=true',
        ] as $requirement) {
            self::assertStringContainsString($requirement, $contents);
        }
    }

    public function testUiRunner_AlwaysReconcilesAndUsesRepositoryLocalPlaywright(): void
    {
        $contents = $this->readFile('scripts/run-ui-tests.ps1');

        self::assertStringContainsString('npm.cmd ci --ignore-scripts', $contents);
        self::assertStringNotContainsString('node_modules/@playwright/test', $contents);
        self::assertStringNotContainsString('npx.cmd', $contents);
        self::assertStringContainsString('node_modules\.bin\playwright.cmd', $contents);
        self::assertStringContainsString('& $playwright install chromium', $contents);
        self::assertStringContainsString('& $playwright test', $contents);

        foreach ([
            'PLAYWRIGHT_DOWNLOAD_HOST',
            'PLAYWRIGHT_CHROMIUM_DOWNLOAD_HOST',
            'PLAYWRIGHT_FIREFOX_DOWNLOAD_HOST',
            'PLAYWRIGHT_WEBKIT_DOWNLOAD_HOST',
        ] as $override) {
            self::assertStringContainsString($override, $contents);
        }
    }

    public function testElevatedInstaller_HasNoRemoteBootstrapAndSeparatesProjectDependencies(): void
    {
        $contents = $this->readFile('scripts/install-dependencies.ps1');

        self::assertStringNotContainsString('Invoke-Expression', $contents);
        self::assertStringNotContainsString('DownloadString', $contents);
        self::assertStringNotContainsString('SetEnvironmentVariable', $contents);
        self::assertStringNotContainsString('config --global', $contents);
        self::assertStringContainsString('https://chocolatey.org/install', $contents);
        self::assertStringContainsString(
            "https://community.chocolatey.org/api/v2/",
            $contents
        );
        self::assertStringContainsString("XamppPackageVersion = '8.1.6'", $contents);
        self::assertStringContainsString('--version', $contents);
        self::assertStringContainsString('--source', $contents);
        self::assertStringContainsString('--no-plugins', $contents);
        self::assertStringContainsString('--no-scripts', $contents);
        self::assertStringContainsString('WaitForExit', $contents);
        self::assertStringContainsString(
            "C:\ProgramData\chocolatey\bin\choco.exe",
            $contents
        );
        self::assertStringContainsString('if ($MyInvocation.InvocationName -ne', $contents);

        $probe = <<<'POWERSHELL'
. '__INSTALLER__'
$results = [ordered]@{}
$results.ElevatedDefault = Resolve-InstallPhase `
    -IsAdministrator $true `
    -MachinePackages:$false `
    -ProjectDependencies:$false
$results.StandardDefault = Resolve-InstallPhase `
    -IsAdministrator $false `
    -MachinePackages:$false `
    -ProjectDependencies:$false
try {
    Resolve-InstallPhase `
        -IsAdministrator $true `
        -MachinePackages:$false `
        -ProjectDependencies:$true | Out-Null
    $results.ElevatedProjectRejected = $false
} catch {
    $results.ElevatedProjectRejected = $true
}
try {
    Resolve-InstallPhase `
        -IsAdministrator $false `
        -MachinePackages:$true `
        -ProjectDependencies:$false | Out-Null
    $results.StandardMachineRejected = $false
} catch {
    $results.StandardMachineRejected = $true
}
try {
    Assert-ApprovedPackageSource -Source 'http://community.chocolatey.org/api/v2/'
    $results.HttpSourceRejected = $false
} catch {
    $results.HttpSourceRejected = $true
}
$results | ConvertTo-Json -Compress
POWERSHELL;
        $result = $this->runPowerShell(str_replace(
            '__INSTALLER__',
            str_replace("'", "''", $this->path('scripts/install-dependencies.ps1')),
            $probe
        ));
        self::assertSame(0, $result['exitCode'], $result['stderr']);
        $payload = json_decode(trim($result['stdout']), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('MachinePackages', $payload['ElevatedDefault']);
        self::assertSame('ProjectDependencies', $payload['StandardDefault']);
        self::assertTrue($payload['ElevatedProjectRejected']);
        self::assertTrue($payload['StandardMachineRejected']);
        self::assertTrue($payload['HttpSourceRejected']);
    }

    public function testDockerHelper_RequiresReviewedPreinstallationAndUsesApplicationPaths(): void
    {
        $contents = $this->readFile('scripts/ensure-docker-desktop.ps1');

        self::assertStringNotContainsString('winget', strtolower($contents));
        self::assertStringNotContainsString('choco', strtolower($contents));
        self::assertStringContainsString('SkipInstall', $contents);
        self::assertStringContainsString('Docker Desktop must be preinstalled', $contents);
        self::assertStringContainsString(
            'C:\Program Files\Docker\Docker\Docker Desktop.exe',
            $contents
        );
        self::assertStringContainsString(
            'C:\Program Files\Docker\Docker\resources\bin\docker.exe',
            $contents
        );
        self::assertStringContainsString('if ($MyInvocation.InvocationName -ne', $contents);
    }

    public function testZapRunner_PinsImageAndHardensContainerLifecycle(): void
    {
        $contents = $this->readFile('scripts/run-zap-baseline.ps1');
        $digest = 'sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef';

        self::assertStringContainsString(
            "ghcr.io/zaproxy/zaproxy@$digest",
            $contents
        );
        self::assertStringNotContainsString('zaproxy/zap-stable', $contents);
        self::assertStringNotContainsString(':stable', $contents);

        foreach ([
            '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true',
            '--read-only',
            '--tmpfs',
            '/home/zap/.ZAP:rw,nosuid,nodev,size=1g,mode=1777',
            'target=/zap/zap.out',
            '--name',
            '--network',
            'zap-run-manifest.json',
            'ConvertTo-Json',
            'Assert-TcpPortAvailable',
            'Assert-MediShieldIdentityResponse',
            'Initialize-ZapReportDirectory',
            'Assert-ZapReports',
            'Invoke-BoundedDockerCleanup',
            '@(\'rm\', \'--force\', $containerName)',
            '@(\'network\', \'rm\', $networkName)',
            'if ($MyInvocation.InvocationName -ne',
            'exit $script:ZapExitCode',
        ] as $requirement) {
            self::assertStringContainsString($requirement, $contents);
        }
    }

    public function testZapHelpers_RejectOccupiedPortStaleArtifactsAndWrongIdentity(): void
    {
        $script = $this->readFile('scripts/run-zap-baseline.ps1');
        self::assertStringContainsString('if ($MyInvocation.InvocationName -ne', $script);

        $probe = <<<'POWERSHELL'
. '__ZAP__'
$root = '__ROOT__'
$testRoot = Join-Path $root ('test-results\zap-unit-' + [guid]::NewGuid().ToString('N'))
$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Loopback,
    0
)
$results = [ordered]@{}
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $testRoot 'zap-baseline.html') -Value 'stale'
    try {
        Initialize-ZapReportDirectory -ReportDirectory $testRoot
        $results.StaleRejected = $false
    } catch {
        $results.StaleRejected = $true
    }

    $listener.Start()
    $port = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    try {
        Assert-TcpPortAvailable -Port $port
        $results.OccupiedPortRejected = $false
    } catch {
        $results.OccupiedPortRejected = $true
    } finally {
        $listener.Stop()
    }

    $nonce = '0123456789abcdef0123456789abcdef'
    Assert-MediShieldIdentityResponse `
        -StatusCode 200 `
        -Body $nonce `
        -ResponseNonce $nonce `
        -ExpectedNonce $nonce
    $results.ValidIdentityAccepted = $true
    try {
        Assert-MediShieldIdentityResponse `
            -StatusCode 200 `
            -Body $nonce `
            -ResponseNonce 'wrong' `
            -ExpectedNonce $nonce
        $results.WrongIdentityRejected = $false
    } catch {
        $results.WrongIdentityRejected = $true
    }

    Remove-Item -LiteralPath (Join-Path $testRoot 'zap-baseline.html') -Force
    Set-Content -LiteralPath (Join-Path $testRoot 'zap-baseline.html') `
        -Value '<html><body>ok</body></html>'
    Set-Content -LiteralPath (Join-Path $testRoot 'zap-baseline.json') `
        -Value '{"site":[]}'
    Set-Content -LiteralPath (Join-Path $testRoot 'zap-baseline.xml') `
        -Value '<OWASPZAPReport />'
    Assert-ZapReports -ReportDirectory $testRoot
    $results.ValidReportsAccepted = $true

    Clear-Content -LiteralPath (Join-Path $testRoot 'zap-baseline.json')
    try {
        Assert-ZapReports -ReportDirectory $testRoot
        $results.EmptyReportRejected = $false
    } catch {
        $results.EmptyReportRejected = $true
    }
} finally {
    if ($listener.Server.IsBound) {
        $listener.Stop()
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
$results | ConvertTo-Json -Compress
POWERSHELL;
        $result = $this->runPowerShell(str_replace(
            ['__ZAP__', '__ROOT__'],
            [
                str_replace("'", "''", $this->path('scripts/run-zap-baseline.ps1')),
                str_replace("'", "''", $this->root),
            ],
            $probe
        ));

        self::assertSame(0, $result['exitCode'], $result['stderr']);
        $payload = json_decode(trim($result['stdout']), true, 512, JSON_THROW_ON_ERROR);
        self::assertTrue($payload['StaleRejected']);
        self::assertTrue($payload['OccupiedPortRejected']);
        self::assertTrue($payload['ValidIdentityAccepted']);
        self::assertTrue($payload['WrongIdentityRejected']);
        self::assertTrue($payload['ValidReportsAccepted']);
        self::assertTrue($payload['EmptyReportRejected']);
    }

    public function testBoundedProcessHelpers_ReturnNativeExitCodesAfterTimedWait(): void
    {
        foreach ([
            'scripts/install-dependencies.ps1',
            'scripts/run-zap-baseline.ps1',
        ] as $relativePath) {
            $probe = <<<'POWERSHELL'
. '__SCRIPT__'
$exitCode = Invoke-BoundedApplication `
    -FilePath $env:ComSpec `
    -ArgumentList @('/d', '/c', 'echo bounded-output & exit 23') `
    -WorkingDirectory '__ROOT__' `
    -TimeoutSeconds 10
$exitCode
POWERSHELL;
            $result = $this->runPowerShell(str_replace(
                ['__SCRIPT__', '__ROOT__'],
                [
                    str_replace("'", "''", $this->path($relativePath)),
                    str_replace("'", "''", $this->root),
                ],
                $probe
            ));

            self::assertSame(0, $result['exitCode'], $result['stderr']);
            self::assertSame(
                "bounded-output \r\n23",
                trim($result['stdout']),
                "{$relativePath} must preserve diagnostics and the native exit code."
            );
        }
    }

    public function testZapImageMetadata_AllowsMissingVersionButRequiresReviewedDigest(): void
    {
        $probe = <<<'POWERSHELL'
. '__ZAP__'
$image = [pscustomobject]@{
    RepoDigests = @($script:ZapImage)
    Id = 'sha256:local-image-id'
    Config = [pscustomobject]@{
        Labels = $null
        Env = @()
    }
}
$metadata = ConvertTo-ZapImageMetadata -Images @($image)
$results = [ordered]@{
    Version = $metadata.Version
    ImageId = $metadata.ImageId
}
$image.RepoDigests = @('ghcr.io/zaproxy/zaproxy@sha256:wrong')
try {
    ConvertTo-ZapImageMetadata -Images @($image) | Out-Null
    $results.WrongDigestRejected = $false
} catch {
    $results.WrongDigestRejected = $true
}
$results | ConvertTo-Json -Compress
POWERSHELL;
        $result = $this->runPowerShell(str_replace(
            '__ZAP__',
            str_replace(
                "'",
                "''",
                $this->path('scripts/run-zap-baseline.ps1')
            ),
            $probe
        ));

        self::assertSame(0, $result['exitCode'], $result['stderr']);
        $payload = json_decode(trim($result['stdout']), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('unavailable', $payload['Version']);
        self::assertSame('sha256:local-image-id', $payload['ImageId']);
        self::assertTrue($payload['WrongDigestRejected']);
    }

    public function testZapRunner_ForcedFailureCannotBeMaskedBySuccessStreamOutput(): void
    {
        $probe = <<<'POWERSHELL'
. '__ZAP__'
$runsRoot = Join-Path '__ROOT__' 'test-results\zap\runs'
$before = @(
    Get-ChildItem -LiteralPath $runsRoot -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName }
)
function Assert-TcpPortAvailable {
    throw 'forced pre-scan failure'
}
try {
    Invoke-ZapBaseline | Out-Host
    $exitCode = $script:ZapExitCode
} finally {
    Get-ChildItem -LiteralPath $runsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notin $before } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
}
exit $exitCode
POWERSHELL;
        $result = $this->runPowerShell(str_replace(
            ['__ZAP__', '__ROOT__'],
            [
                str_replace(
                    "'",
                    "''",
                    $this->path('scripts/run-zap-baseline.ps1')
                ),
                str_replace("'", "''", $this->root),
            ],
            $probe
        ));

        self::assertSame(1, $result['exitCode'], $result['stderr']);
        self::assertStringContainsString(
            'forced pre-scan failure',
            $result['stderr']
        );
    }

    /**
     * @param array<string,mixed> $lock
     * @return array<string,mixed>|null
     */
    private function findComposerPackage(array $lock, string $name): ?array
    {
        foreach (['packages', 'packages-dev'] as $group) {
            foreach ($lock[$group] ?? [] as $package) {
                if (($package['name'] ?? null) === $name) {
                    return $package;
                }
            }
        }

        return null;
    }

    /** @return array<string,mixed> */
    private function readJson(string $relativePath): array
    {
        $decoded = json_decode(
            $this->readFile($relativePath),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        self::assertIsArray($decoded);

        return $decoded;
    }

    private function readFile(string $relativePath): string
    {
        $path = $this->path($relativePath);
        self::assertFileExists($path);

        return (string) file_get_contents($path);
    }

    private function path(string $relativePath): string
    {
        return $this->root . DIRECTORY_SEPARATOR
            . str_replace('/', DIRECTORY_SEPARATOR, $relativePath);
    }

    /**
     * @return array{exitCode:int,stdout:string,stderr:string}
     */
    private function runPowerShell(string $probe): array
    {
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
