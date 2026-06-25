<#
.SYNOPSIS
Installs MediShield development dependencies on Windows.

.DESCRIPTION
Run this from an elevated PowerShell prompt. The script bootstraps every prerequisite it needs using a check-then-install pattern: it installs Chocolatey if it is missing, then installs XAMPP 8.1 and Composer (via Chocolatey) when they are not already present, configures php.ini through configure-php-ini.ps1, and runs composer install from the repository root. Re-running is safe: anything already installed is detected and skipped.

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

function Get-ChocolateyCommand {
    # Resolve the choco command if Chocolatey is installed, or return $null.
    # We check PATH first, then fall back to the default install location in case
    # PATH has not been refreshed in the current process yet.
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if (-not $choco) {
        $default = 'C:\ProgramData\chocolatey\bin\choco.exe'
        if (Test-Path -LiteralPath $default) {
            $choco = Get-Command $default -ErrorAction SilentlyContinue
        }
    }
    return $choco
}

function Install-Chocolatey {
    # Bootstrap Chocolatey using the official install script. Chocolatey is the
    # package manager every other dependency (XAMPP, Composer) is installed with,
    # so it must exist before anything else. Requires Administrator (already
    # enforced by the caller). Returns the resolved choco command.
    Write-Host 'Chocolatey was not found. Installing Chocolatey...' -ForegroundColor Yellow

    $previousExecutionPolicy = Get-ExecutionPolicy -Scope Process
    try {
        # The official one-liner from https://chocolatey.org/install.
        Set-ExecutionPolicy Bypass -Scope Process -Force
        # Force TLS 1.2 (3072) so the HTTPS download succeeds on stock Windows
        # PowerShell 5.1, which still negotiates older protocols by default.
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

        $installScript = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
        Invoke-Expression $installScript
    }
    finally {
        # Restore the process execution policy we changed above.
        Set-ExecutionPolicy $previousExecutionPolicy -Scope Process -Force -ErrorAction SilentlyContinue
    }

    # choco was just added to the machine PATH; make it visible to this process.
    Refresh-PathFromEnvironment

    $choco = Get-ChocolateyCommand
    if (-not $choco) {
        throw 'Chocolatey installation completed but the choco command is still not available. Open a NEW elevated PowerShell prompt and rerun this script.'
    }

    Write-Host "Chocolatey installed at: $($choco.Source)" -ForegroundColor Green
    return $choco
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

    # Ensure Chocolatey (the package manager every other dependency relies on) is
    # present. If it is missing we install it automatically rather than failing.
    $choco = Get-ChocolateyCommand
    if ($choco) {
        Write-Host "Chocolatey already found at: $($choco.Source)"
    }
    else {
        $choco = Install-Chocolatey
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
