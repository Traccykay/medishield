<#
.SYNOPSIS
Ensures Docker Desktop is installed and its engine is ready for local security tests.

.DESCRIPTION
The OWASP ZAP runner uses Docker to pin the scanner image instead of requiring a
machine-wide ZAP installation. This script finds Docker Desktop in standard
install locations, downloads/installs it through WinGet (or Chocolatey when
WinGet is unavailable), then starts it and waits for a real `docker version`
response. Re-running is safe: installation occurs only when Desktop is absent.
#>
[CmdletBinding()]
param(
    [ValidateRange(15, 180)]
    [int]$TimeoutSeconds = 90,

    [ValidateRange(30, 900)]
    [int]$InstallTimeoutSeconds = 600,

    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'

function Get-DockerDesktopExecutable {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Docker\Docker Desktop.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Get-DockerCli {
    $command = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $desktop = Get-DockerDesktopExecutable
    if ($null -eq $desktop) {
        return $null
    }

    $candidates = @(
        (Join-Path (Split-Path -Parent $desktop) 'resources\bin\docker.exe'),
        (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe')
    )
    foreach ($cli in $candidates) {
        if (Test-Path -LiteralPath $cli) {
            return $cli
        }
    }

    return $null
}

function Test-DockerEngine {
    param([Parameter(Mandatory = $true)][string]$DockerCli)

    & $DockerCli version --format '{{.Server.Version}}' 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

function Install-DockerDesktop {
    if ($SkipInstall) {
        throw 'Docker Desktop is not installed and installation was skipped. Remove -SkipInstall or install Docker Desktop, then rerun npm run test:zap.'
    }

    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    $choco = Get-Command choco.exe -ErrorAction SilentlyContinue

    if ($null -ne $winget) {
        Write-Host 'Docker Desktop is missing; installing the official WinGet package...'
        & $winget.Source install --id Docker.DockerDesktop --exact --silent --accept-package-agreements --accept-source-agreements | Out-Host
    } elseif ($null -ne $choco) {
        Write-Host 'Docker Desktop is missing; installing through Chocolatey...'
        & $choco.Source install docker-desktop --yes --no-progress | Out-Host
    } else {
        throw 'Docker Desktop is not installed and neither winget.exe nor choco.exe is available to install it. Install WinGet or Chocolatey, then rerun npm run test:zap.'
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Docker Desktop installation failed with exit code $LASTEXITCODE. Resolve the installer error, then rerun npm run test:zap."
    }

    for ($attempt = 1; $attempt -le $InstallTimeoutSeconds; $attempt++) {
        $installed = Get-DockerDesktopExecutable
        if ($null -ne $installed) {
            return $installed
        }
        Start-Sleep -Seconds 1
    }

    throw "Docker Desktop installation completed but its executable was not found within $InstallTimeoutSeconds seconds. Check the installer result, then rerun npm run test:zap."
}

$desktop = Get-DockerDesktopExecutable
if ($null -eq $desktop) {
    $desktop = Install-DockerDesktop
}

$docker = Get-DockerCli
if ($null -eq $docker) {
    throw "Docker Desktop was found at '$desktop', but docker.exe was not found. Repair the Docker Desktop installation, then rerun npm run test:zap."
}

if (Test-DockerEngine -DockerCli $docker) {
    Write-Host 'Docker Desktop engine is already ready.'
    exit 0
}

$desktopProcess = Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue
if ($null -eq $desktopProcess) {
    Start-Process -FilePath $desktop
    Write-Host 'Starting Docker Desktop...'
} else {
    Write-Host 'Docker Desktop is running; waiting for its engine...'
}

for ($attempt = 1; $attempt -le $TimeoutSeconds; $attempt++) {
    Start-Sleep -Seconds 1
    if (Test-DockerEngine -DockerCli $docker) {
        Write-Host "Docker Desktop engine is ready after $attempt second(s)."
        exit 0
    }
}

throw "Docker Desktop did not become ready within $TimeoutSeconds seconds. Open Docker Desktop, resolve its startup error, then rerun npm run test:zap."
