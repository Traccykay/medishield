<#
.SYNOPSIS
Installs the pinned browser-test dependencies when needed and runs the MediShield
Playwright suite against its disposable database.
#>
[CmdletBinding()]
param(
    [switch]$Demo
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

foreach ($command in @('node.exe', 'npm.cmd', 'php.exe', 'mysql.exe')) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command '$command' was not found on PATH. Complete the project setup first."
    }
}

function Test-MediShieldDatabase {
    & mysql.exe '--host=127.0.0.1' '--user=root' '--execute=SELECT 1;' 2>$null
    return $LASTEXITCODE -eq 0
}

function Start-MediShieldDatabase {
    if (Test-MediShieldDatabase) {
        return
    }

    $service = Get-Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Status -ne 'Running' -and (
                $_.Name -match 'mysql|mariadb' -or
                $_.DisplayName -match 'mysql|mariadb'
            )
        } |
        Select-Object -First 1

    if ($null -ne $service) {
        Start-Service -Name $service.Name -ErrorAction Stop
    }
    elseif (Test-Path 'C:\xampp\mysql_start.bat') {
        Start-Process -FilePath $env:ComSpec -ArgumentList '/c', 'C:\xampp\mysql_start.bat' -WindowStyle Hidden
    }
    else {
        throw 'MySQL/MariaDB is not running and the runner could not start it. Start MySQL in XAMPP, then run this command again.'
    }

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Seconds 1
        if (Test-MediShieldDatabase) {
            return
        }
    }

    throw 'MySQL/MariaDB did not become ready within 30 seconds. Check the XAMPP Control Panel or Windows Services.'
}

Start-MediShieldDatabase

if (-not (Test-Path (Join-Path $root 'node_modules/@playwright/test'))) {
    & npm.cmd ci
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

& npx.cmd playwright install chromium
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($Demo) {
    $env:MEDISHIELD_DEMO = '1'
}

& npm.cmd run test:ui
exit $LASTEXITCODE
