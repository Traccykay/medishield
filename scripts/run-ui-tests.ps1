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
