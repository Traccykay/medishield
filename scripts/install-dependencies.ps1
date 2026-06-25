<#
.SYNOPSIS
Installs MediShield development dependencies on Windows.

.DESCRIPTION
Run this from an elevated PowerShell prompt. The script installs XAMPP 8.1 and Composer with Chocolatey when needed, verifies PHP/MySQL locations, checks common PHP extensions, and runs composer install from the repository root.

.USAGE
powershell -ExecutionPolicy Bypass -File scripts\install-dependencies.ps1
#>

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-XamppToolPath {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Candidates,

        [Parameter(Mandatory = $true)]
        [string]$ToolName
    )

    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "$ToolName was not found. Checked: $($Candidates -join ', '). Install XAMPP 8.1 and verify the installation path."
}

function Find-XamppToolPath {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Refresh-PathFromEnvironment {
    $machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machinePath;$userPath"
}

try {
    Write-Host 'MediShield dependency installation starting...' -ForegroundColor Cyan

    if (-not (Test-Administrator)) {
        Write-Error 'This script must be run from an elevated PowerShell prompt because Chocolatey installs require Administrator privileges.'
        exit 1
    }

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $phpCandidates = @(
        'C:\xampp\php\php.exe',
        'C:\tools\xampp\php\php.exe'
    )
    $mysqlCandidates = @(
        'C:\xampp\mysql\bin\mysql.exe',
        'C:\tools\xampp\mysql\bin\mysql.exe'
    )

    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if (-not $choco -and (Test-Path -LiteralPath 'C:\ProgramData\chocolatey\bin\choco.exe')) {
        $choco = Get-Command 'C:\ProgramData\chocolatey\bin\choco.exe' -ErrorAction SilentlyContinue
    }

    if (-not $choco) {
        Write-Error "Chocolatey was not found. Install Chocolatey from https://chocolatey.org/install, then rerun: powershell -ExecutionPolicy Bypass -File scripts\install-dependencies.ps1"
        exit 1
    }

    $php = Find-XamppToolPath -Candidates $phpCandidates
    if ($php) {
        Write-Host "XAMPP PHP already found at: $php"
    }
    else {
        Write-Host 'Installing XAMPP 8.1 with Chocolatey...'
        & $choco.Source install xampp-81 -y --no-progress
        if ($LASTEXITCODE -ne 0) {
            throw "Chocolatey failed to install xampp-81 (exit code $LASTEXITCODE)."
        }
    }

    $composer = Get-Command composer -ErrorAction SilentlyContinue
    if ($composer) {
        Write-Host "Composer already found at: $($composer.Source)"
    }
    else {
        Write-Host 'Installing Composer with Chocolatey...'
        & $choco.Source install composer -y --no-progress
        if ($LASTEXITCODE -ne 0) {
            throw "Chocolatey failed to install composer (exit code $LASTEXITCODE)."
        }
        Refresh-PathFromEnvironment
        $composer = Get-Command composer -ErrorAction SilentlyContinue
        if (-not $composer) {
            throw 'Composer was installed, but the composer command is still not on PATH. Open a new elevated PowerShell prompt and rerun this script.'
        }
    }

    $php = Get-XamppToolPath -Candidates $phpCandidates -ToolName 'php.exe'
    $mysql = Get-XamppToolPath -Candidates $mysqlCandidates -ToolName 'mysql.exe'

    Write-Host "Discovered PHP:   $php" -ForegroundColor Green
    Write-Host "Discovered MySQL: $mysql" -ForegroundColor Green

    # Configure php.ini to the canonical MediShield baseline (enables every
    # required extension + timezone/memory settings). This is the single source
    # of truth for the PHP runtime config so all engineers share one environment.
    Write-Host 'Configuring php.ini (extensions, timezone, memory_limit)...'
    $configureScript = Join-Path $PSScriptRoot 'configure-php-ini.ps1'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $configureScript -PhpExe $php
    if ($LASTEXITCODE -ne 0) {
        throw "configure-php-ini.ps1 failed (exit code $LASTEXITCODE). Review the output above."
    }

    $composer = Get-Command composer -ErrorAction SilentlyContinue
    if (-not $composer) {
        Refresh-PathFromEnvironment
        $composer = Get-Command composer -ErrorAction SilentlyContinue
    }
    if (-not $composer) {
        throw 'Composer is not available on PATH after refresh.'
    }

    Write-Host "Running composer install in $repoRoot..."
    Push-Location $repoRoot
    try {
        & composer install
        if ($LASTEXITCODE -ne 0) {
            throw "composer install failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }

    Write-Host ''
    Write-Host 'NEXT STEPS' -ForegroundColor Cyan
    Write-Host '1. Start Apache and MySQL from the XAMPP Control Panel.'
    Write-Host '2. Initialize the database:'
    Write-Host '   powershell -ExecutionPolicy Bypass -File scripts\setup-db.ps1'
    Write-Host ''
    Write-Host 'Dependency installation completed successfully.' -ForegroundColor Green
}
catch {
    Write-Error "Dependency installation failed: $($_.Exception.Message)"
    exit 1
}
