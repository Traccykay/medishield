<#
.SYNOPSIS
Runs a pinned OWASP ZAP passive baseline against a disposable MediShield instance.

.DESCRIPTION
Every run uses the reviewed immutable GHCR digest, a unique report directory,
container, and network. The runner rejects occupied ports, proves the local
server with a run nonce, applies a read-only/capability-free container boundary,
validates every report, records a JSON run manifest, and performs bounded exact
cleanup while preserving the primary ZAP exit code.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 10)]
    [int]$SpiderMinutes = 2,

    [ValidateRange(1024, 65535)]
    [int]$Port = 8766,

    [switch]$SkipDockerInstall
)

$ErrorActionPreference = 'Stop'
$script:ZapImage = 'ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef'
$script:ZapDigest = 'sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef'
$script:ZapExitCode = 1

function ConvertTo-ProcessArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-BoundedApplication {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $argumentLine = ($ArgumentList | ForEach-Object {
        ConvertTo-ProcessArgument -Value $_
    }) -join ' '
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $argumentLine
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Process '$FilePath' could not be started."
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) {
            Stop-Process -Id $process.Id -Force
        }

        $process.WaitForExit()
        $process.Refresh()
        [Console]::Out.Write($stdout.GetAwaiter().GetResult())
        [Console]::Error.Write($stderr.GetAwaiter().GetResult())
        if ($timedOut) {
            throw "Process '$FilePath' exceeded the $TimeoutSeconds second timeout."
        }

        return [int]$process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Invoke-BoundedDockerCleanup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DockerPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    return Invoke-BoundedApplication `
        -FilePath $DockerPath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -TimeoutSeconds 30
}

function Get-DockerCliPath {
    foreach ($candidate in @(
        'C:\Program Files\Docker\Docker\resources\bin\docker.exe',
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'),
        (Join-Path $env:LOCALAPPDATA 'Docker\resources\bin\docker.exe')
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw 'docker.exe was not found at an approved Docker Desktop application path.'
}

function Assert-TcpPortAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1024, 65535)]
        [int]$Port
    )

    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        $Port
    )
    try {
        $listener.Start()
    } catch {
        throw "TCP port $Port is already occupied; refusing to scan an unidentified server."
    } finally {
        if ($listener.Server.IsBound) {
            $listener.Stop()
        }
    }
}

function Assert-MediShieldIdentityResponse {
    param(
        [Parameter(Mandatory = $true)]
        [int]$StatusCode,

        [Parameter(Mandatory = $true)]
        [string]$Body,

        [Parameter(Mandatory = $true)]
        [string]$ResponseNonce,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedNonce
    )

    if (
        $StatusCode -ne 200 -or
        $Body.Trim() -cne $ExpectedNonce -or
        $ResponseNonce -cne $ExpectedNonce
    ) {
        throw 'The process listening on the scan port did not prove the expected run nonce.'
    }
}

function Wait-MediShieldIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$Nonce
    )

    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
            Assert-MediShieldIdentityResponse `
                -StatusCode $response.StatusCode `
                -Body ([string]$response.Content) `
                -ResponseNonce ([string]$response.Headers['X-MediShield-Test-Nonce']) `
                -ExpectedNonce $Nonce
            return
        } catch {
            if ($attempt -lt 30) {
                Start-Sleep -Seconds 1
            }
        }
    }

    throw "The disposable MediShield server did not prove its identity at '$Url'."
}

function Initialize-ZapReportDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportDirectory
    )

    if (Test-Path -LiteralPath $ReportDirectory) {
        $existing = @(Get-ChildItem -LiteralPath $ReportDirectory -Force)
        if ($existing.Count -gt 0) {
            throw "The ZAP report directory '$ReportDirectory' contains stale artifacts."
        }
        return
    }

    New-Item -ItemType Directory -Path $ReportDirectory | Out-Null
}

function Assert-ZapReports {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportDirectory
    )

    $paths = @{
        Html = Join-Path $ReportDirectory 'zap-baseline.html'
        Json = Join-Path $ReportDirectory 'zap-baseline.json'
        Xml = Join-Path $ReportDirectory 'zap-baseline.xml'
    }
    foreach ($entry in $paths.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "ZAP $($entry.Key) report is missing."
        }
        if ((Get-Item -LiteralPath $entry.Value).Length -le 0) {
            throw "ZAP $($entry.Key) report is empty."
        }
    }

    $html = Get-Content -LiteralPath $paths.Html -Raw
    if ($html -notmatch '(?is)<html(?:\s|>)') {
        throw 'ZAP HTML report is not parseable HTML.'
    }
    try {
        Get-Content -LiteralPath $paths.Json -Raw |
            ConvertFrom-Json -ErrorAction Stop | Out-Null
    } catch {
        throw 'ZAP JSON report is not parseable JSON.'
    }
    try {
        [xml](Get-Content -LiteralPath $paths.Xml -Raw) | Out-Null
    } catch {
        throw 'ZAP XML report is not parseable XML.'
    }
}

function Write-ZapRunManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$State
    )

    $pendingPath = "$ManifestPath.pending"
    $State | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $pendingPath -Encoding UTF8
    Move-Item -LiteralPath $pendingPath -Destination $ManifestPath -Force
}

function New-ZapIdentityRouter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Nonce,

        [Parameter(Mandatory = $true)]
        [string]$ApplicationRouter
    )

    $template = @'
<?php

declare(strict_types=1);

$nonce = '__NONCE__';
$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($requestPath === '/__medishield_zap_identity__') {
    $provided = is_string($_GET['nonce'] ?? null) ? $_GET['nonce'] : '';
    if (!hash_equals($nonce, $provided)) {
        http_response_code(404);
        return true;
    }
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-MediShield-Test-Nonce: ' . $nonce);
    echo $nonce;
    return true;
}

return require '__APPLICATION_ROUTER__';
'@
    $router = $ApplicationRouter.Replace('\', '/').Replace("'", "\'")
    $content = $template.
        Replace('__NONCE__', $Nonce).
        Replace('__APPLICATION_ROUTER__', $router)
    Set-Content -LiteralPath $Path -Value $content -Encoding ASCII
}

function Ensure-ZapImage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DockerPath,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $delays = @(0, 5, 15)
    foreach ($delay in $delays) {
        if ($delay -gt 0) {
            Start-Sleep -Seconds $delay
        }
        try {
            $exitCode = Invoke-BoundedApplication `
                -FilePath $DockerPath `
                -ArgumentList @('pull', $script:ZapImage) `
                -WorkingDirectory $WorkingDirectory `
                -TimeoutSeconds 300
            if ($exitCode -eq 0) {
                return
            }
        } catch {
            Write-Warning $_.Exception.Message
        }
    }

    throw "The reviewed ZAP digest could not be pulled after $($delays.Count) bounded attempts. No unpinned fallback is allowed."
}

function ConvertTo-ZapImageMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Images
    )

    $image = @($Images)[0]
    if ($null -eq $image) {
        throw 'Docker returned no metadata for the reviewed ZAP image.'
    }
    if (@($image.RepoDigests) -notcontains $script:ZapImage) {
        throw "The local ZAP image does not expose the reviewed digest $script:ZapDigest."
    }
    if ([string]::IsNullOrWhiteSpace([string]$image.Id)) {
        throw 'The reviewed ZAP image exposes no image ID.'
    }

    $version = $null
    if ($null -ne $image.Config.Labels) {
        $version = $image.Config.Labels.'org.opencontainers.image.version'
    }
    if ([string]::IsNullOrWhiteSpace([string]$version)) {
        foreach ($value in @($image.Config.Env)) {
            if ($value -like 'ZAP_VERSION=*') {
                $version = $value.Substring('ZAP_VERSION='.Length)
                break
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$version)) {
        $version = 'unavailable'
    }

    return [pscustomobject]@{
        Version = [string]$version
        ImageId = [string]$image.Id
    }
}

function Get-ZapImageMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DockerPath
    )

    $raw = & $DockerPath image inspect $script:ZapImage 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'The reviewed ZAP image could not be inspected after pull.'
    }

    return ConvertTo-ZapImageMetadata -Images @($raw | ConvertFrom-Json)
}

function Remove-LegacyZapReports {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZapRoot
    )

    foreach ($name in @(
        'zap-baseline.html',
        'zap-baseline.json',
        'zap-baseline.xml'
    )) {
        $path = Join-Path $ZapRoot $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Invoke-ZapBaseline {
    $root = Split-Path -Parent $PSScriptRoot
    $zapRoot = Join-Path $root 'test-results\zap'
    $runsRoot = Join-Path $zapRoot 'runs'
    New-Item -ItemType Directory -Force -Path $runsRoot | Out-Null
    Remove-LegacyZapReports -ZapRoot $zapRoot

    $runId = 'zap-{0}-{1}' -f (
        [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    ), ([guid]::NewGuid().ToString('N').Substring(0, 12))
    $runDirectory = Join-Path $runsRoot $runId
    if (Test-Path -LiteralPath $runDirectory) {
        throw "Generated ZAP run directory '$runDirectory' already exists."
    }
    New-Item -ItemType Directory -Path $runDirectory | Out-Null
    $reportDirectory = Join-Path $runDirectory 'reports'
    Initialize-ZapReportDirectory -ReportDirectory $reportDirectory

    $nonce = [guid]::NewGuid().ToString('N')
    $identityRouter = Join-Path $runDirectory 'identity-router.php'
    New-ZapIdentityRouter `
        -Path $identityRouter `
        -Nonce $nonce `
        -ApplicationRouter (Join-Path $root 'public\router.php')

    $containerName = "medishield-$runId"
    $networkName = "medishield-$runId"
    $localTarget = "http://127.0.0.1:$Port/login.php"
    $zapTarget = "http://host.docker.internal:$Port/login.php"
    $identityUrl = "http://127.0.0.1:$Port/__medishield_zap_identity__?nonce=$nonce"
    $manifestPath = Join-Path $runDirectory 'zap-run-manifest.json'
    $zapLogPath = Join-Path $runDirectory 'zap.out'
    New-Item -ItemType File -Path $zapLogPath | Out-Null
    $mount = "type=bind,source=$reportDirectory,target=/zap/wrk"
    $logMount = "type=bind,source=$zapLogPath,target=/zap/zap.out"
    $dockerArguments = @(
        'run',
        '--name',
        $containerName,
        '--network',
        $networkName,
        '--cap-drop=ALL',
        '--security-opt=no-new-privileges:true',
        '--read-only',
        '--user=zap',
        '--tmpfs',
        '/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777',
        '--tmpfs',
        '/home/zap/.ZAP:rw,nosuid,nodev,size=1g,mode=1777',
        '--add-host=host.docker.internal:host-gateway',
        '--mount',
        $mount,
        '--mount',
        $logMount,
        $script:ZapImage,
        'zap-baseline.py',
        '-t',
        $zapTarget,
        '-m',
        [string]$SpiderMinutes,
        '-r',
        'zap-baseline.html',
        '-J',
        'zap-baseline.json',
        '-x',
        'zap-baseline.xml',
        '-l',
        'WARN'
    )
    $state = [ordered]@{
        run_id = $runId
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        completed_at_utc = $null
        status = 'STARTED'
        image = $script:ZapImage
        digest = $script:ZapDigest
        version = $null
        image_id = $null
        target = $zapTarget
        local_target = $localTarget
        disposable_database = 'medishield_ui_test'
        command = @('docker.exe') + $dockerArguments
        command_exit_code = $null
        exit_code = $null
        reports_validated = $false
        cleanup = [ordered]@{
            container = 'not-started'
            network = 'not-created'
            server = 'not-started'
        }
        error = $null
    }
    Write-ZapRunManifest -ManifestPath $manifestPath -State $state

    $server = $null
    $dockerPath = $null
    $networkCreated = $false
    $containerAttempted = $false
    $primaryExitCode = 1
    $primaryFailure = $null
    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    $previousPath = $env:Path

    try {
        Assert-TcpPortAvailable -Port $Port

        $ensureDocker = Join-Path $PSScriptRoot 'ensure-docker-desktop.ps1'
        & $ensureDocker -SkipInstall:$SkipDockerInstall.IsPresent
        if ($LASTEXITCODE -ne 0) {
            throw "Docker Desktop readiness failed with exit code $LASTEXITCODE."
        }
        $dockerPath = Get-DockerCliPath
        $dockerDirectory = Split-Path -Parent $dockerPath
        $env:Path = "$dockerDirectory;$previousPath"

        Ensure-ZapImage -DockerPath $dockerPath -WorkingDirectory $root
        $metadata = Get-ZapImageMetadata -DockerPath $dockerPath
        $state.version = $metadata.Version
        $state.image_id = $metadata.ImageId
        $state.command[0] = $dockerPath
        Write-ZapRunManifest -ManifestPath $manifestPath -State $state

        & (Join-Path $PSScriptRoot 'ensure-mysql.ps1')
        if ($LASTEXITCODE -ne 0) {
            throw "Disposable database engine readiness failed with exit code $LASTEXITCODE."
        }
        & (Join-Path $PSScriptRoot 'setup-ui-test-db.ps1')
        if ($LASTEXITCODE -ne 0) {
            throw "Disposable database setup failed with exit code $LASTEXITCODE."
        }

        $php = Get-Command php.exe -ErrorAction SilentlyContinue
        if ($null -eq $php) {
            throw 'php.exe was not found for the disposable scan server.'
        }
        $previousDatabase = $env:MEDISHIELD_DB_NAME
        $previousMailDir = $env:MEDISHIELD_MAIL_DUMP_DIR
        $env:MEDISHIELD_DB_NAME = 'medishield_ui_test'
        $env:MEDISHIELD_MAIL_DUMP_DIR = Join-Path $runDirectory 'mail'
        try {
            $server = Start-Process `
                -FilePath $php.Source `
                -ArgumentList @(
                    '-S',
                    "127.0.0.1:$Port",
                    '-t',
                    (Join-Path $root 'public'),
                    $identityRouter
                ) `
                -WorkingDirectory $root `
                -PassThru `
                -WindowStyle Hidden
            $state.cleanup.server = 'running'
        } finally {
            $env:MEDISHIELD_DB_NAME = $previousDatabase
            $env:MEDISHIELD_MAIL_DUMP_DIR = $previousMailDir
        }
        Wait-MediShieldIdentity -Url $identityUrl -Nonce $nonce

        $networkExit = Invoke-BoundedApplication `
            -FilePath $dockerPath `
            -ArgumentList @(
                'network',
                'create',
                '--driver',
                'bridge',
                '--label',
                "medishield.zap.run=$runId",
                $networkName
            ) `
            -WorkingDirectory $root `
            -TimeoutSeconds 30
        if ($networkExit -ne 0) {
            throw "Docker network creation failed with exit code $networkExit."
        }
        $networkCreated = $true
        $state.cleanup.network = 'created'

        $containerAttempted = $true
        $zapExitCode = Invoke-BoundedApplication `
            -FilePath $dockerPath `
            -ArgumentList $dockerArguments `
            -WorkingDirectory $root `
            -TimeoutSeconds (($SpiderMinutes * 60) + 300)
        $state.command_exit_code = $zapExitCode
        $primaryExitCode = $zapExitCode

        try {
            Assert-ZapReports -ReportDirectory $reportDirectory
            $state.reports_validated = $true
        } catch {
            $primaryFailure = $_.Exception.Message
            if ($primaryExitCode -eq 0) {
                $primaryExitCode = 1
            }
        }
        if ($zapExitCode -ne 0 -and $null -eq $primaryFailure) {
            $primaryFailure = "ZAP baseline returned exit code $zapExitCode."
        }
    } catch {
        if ($null -eq $primaryFailure) {
            $primaryFailure = $_.Exception.Message
        }
        if ($null -eq $state.command_exit_code) {
            $state.command_exit_code = 1
        }
        $primaryExitCode = 1
    } finally {
        $env:Path = $previousPath

        if ($null -ne $server) {
            try {
                if (-not $server.HasExited) {
                    Stop-Process -Id $server.Id -Force
                    $server.WaitForExit(10000) | Out-Null
                }
                $state.cleanup.server = 'removed'
            } catch {
                $cleanupErrors.Add("Server cleanup failed: $($_.Exception.Message)")
            }
        }

        if ($containerAttempted -and $null -ne $dockerPath) {
            try {
                $containerExit = Invoke-BoundedDockerCleanup `
                    -DockerPath $dockerPath `
                    -Arguments @('rm', '--force', $containerName) `
                    -WorkingDirectory $root
                if ($containerExit -ne 0) {
                    throw "docker rm returned exit code $containerExit."
                }
                $state.cleanup.container = 'removed'
            } catch {
                $cleanupErrors.Add("Container cleanup failed: $($_.Exception.Message)")
            }
        }

        if ($networkCreated -and $null -ne $dockerPath) {
            try {
                $networkExit = Invoke-BoundedDockerCleanup `
                    -DockerPath $dockerPath `
                    -Arguments @('network', 'rm', $networkName) `
                    -WorkingDirectory $root
                if ($networkExit -ne 0) {
                    throw "docker network rm returned exit code $networkExit."
                }
                $state.cleanup.network = 'removed'
            } catch {
                $cleanupErrors.Add("Network cleanup failed: $($_.Exception.Message)")
            }
        }

        if (Test-Path -LiteralPath $identityRouter) {
            Remove-Item -LiteralPath $identityRouter -Force
        }

        if ($cleanupErrors.Count -gt 0) {
            $state.cleanup.errors = @($cleanupErrors)
            if ($primaryExitCode -eq 0) {
                $primaryExitCode = 1
                $primaryFailure = 'ZAP completed, but exact cleanup failed.'
            }
        }
        $state.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        $state.exit_code = $primaryExitCode
        $state.status = if ($primaryExitCode -eq 0) { 'PASSED' } else { 'FAILED' }
        $state.error = $primaryFailure
        Write-ZapRunManifest -ManifestPath $manifestPath -State $state
    }

    Write-Host "ZAP run manifest: $manifestPath"
    if ($null -ne $primaryFailure) {
        [Console]::Error.WriteLine($primaryFailure)
    }

    $script:ZapExitCode = $primaryExitCode
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-ZapBaseline | Out-Host
        exit $script:ZapExitCode
    } catch {
        Write-Error "ZAP baseline setup failed before a run manifest could be finalized: $($_.Exception.Message)"
        exit 1
    }
}
