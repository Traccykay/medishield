<#
.SYNOPSIS
Runs OWASP ZAP's passive baseline scan against a disposable MediShield instance.

.DESCRIPTION
Starts the shared MySQL bootstrap, rebuilds medishield_ui_test, serves the app
locally, then runs ZAP in Docker. This is intentionally passive: it spiders and
checks responses but does not submit destructive active-scan payloads. Reports
are written under test-results\zap and any ZAP WARN/FAIL alert fails the command.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 10)]
    [int]$SpiderMinutes = 2,

    [int]$Port = 8766
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$reportDirectory = Join-Path $root 'test-results\zap'
$server = $null
$zapImages = @(
    'ghcr.io/zaproxy/zaproxy:stable',
    'zaproxy/zap-stable'
)

function Wait-MediShieldHttp {
    param([Parameter(Mandatory = $true)][string]$Url)

    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                return
            }
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    throw "The local MediShield server did not become ready at $Url."
}

function Ensure-ZapImage {
    param(
        [Parameter(Mandatory = $true)][string]$DockerPath,
        [Parameter(Mandatory = $true)][string[]]$Images
    )

    $delays = @(0, 5, 15)
    foreach ($image in $Images) {
        for ($attempt = 0; $attempt -lt $delays.Count; $attempt++) {
            if ($delays[$attempt] -gt 0) {
                Write-Host "Retrying ZAP image pull in $($delays[$attempt]) seconds..."
                Start-Sleep -Seconds $delays[$attempt]
            }

            & $DockerPath pull $image | Out-Host
            if ($LASTEXITCODE -eq 0) {
                return $image
            }
        }
        Write-Warning "Could not pull '$image'; trying the next official ZAP registry if available."
    }

    throw "Could not pull an official ZAP stable image after $($delays.Count) attempts per registry. Check internet, proxy, GHCR, and Docker Hub access, then rerun npm run test:zap."
}

try {
    & (Join-Path $PSScriptRoot 'ensure-docker-desktop.ps1')
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    $docker = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($null -eq $docker) {
        $desktopCli = @(
            (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe')
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if ($null -eq $desktopCli) {
            throw 'Docker Desktop passed readiness checks but docker.exe could not be resolved for the ZAP command.'
        }
        $dockerPath = $desktopCli
    } else {
        $dockerPath = $docker.Source
    }
    $dockerDirectory = Split-Path -Parent $dockerPath
    if (($env:Path -split ';') -notcontains $dockerDirectory) {
        # Docker credential helpers (for example docker-credential-desktop) live
        # beside docker.exe. Make them available to the image pull subprocess.
        $env:Path = "$dockerDirectory;$env:Path"
    }
    $zapImage = Ensure-ZapImage -DockerPath $dockerPath -Images $zapImages

    & (Join-Path $PSScriptRoot 'ensure-mysql.ps1')
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    & (Join-Path $PSScriptRoot 'setup-ui-test-db.ps1')
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null
    $localTarget = "http://127.0.0.1:$Port/login.php"
    $zapTarget = "http://host.docker.internal:$Port/login.php"
    # Start-Process inherits the environment at process creation. Set then restore
    # these values so this stays compatible with Windows PowerShell 5, which lacks
    # Start-Process -Environment.
    $previousDatabase = $env:MEDISHIELD_DB_NAME
    $previousMailDir = $env:MEDISHIELD_MAIL_DUMP_DIR
    $env:MEDISHIELD_DB_NAME = 'medishield_ui_test'
    $env:MEDISHIELD_MAIL_DUMP_DIR = Join-Path $root 'test-results\mail'
    try {
        $server = Start-Process -FilePath php.exe -ArgumentList '-S', "127.0.0.1:$Port", '-t', 'public', 'public/router.php' -WorkingDirectory $root -PassThru -WindowStyle Hidden
    } finally {
        $env:MEDISHIELD_DB_NAME = $previousDatabase
        $env:MEDISHIELD_MAIL_DUMP_DIR = $previousMailDir
    }
    Wait-MediShieldHttp -Url $localTarget

    & $dockerPath run --rm `
        '--add-host=host.docker.internal:host-gateway' `
        '-v' "${reportDirectory}:/zap/wrk/:rw" `
        $zapImage `
        'zap-baseline.py' '-t' $zapTarget '-m' $SpiderMinutes '-r' 'zap-baseline.html' '-J' 'zap-baseline.json' '-x' 'zap-baseline.xml' '-l' 'WARN'
    exit $LASTEXITCODE
} finally {
    if ($null -ne $server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id
    }
}
