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

$downloadHostOverrides = @(
    'PLAYWRIGHT_DOWNLOAD_HOST',
    'PLAYWRIGHT_CHROMIUM_DOWNLOAD_HOST',
    'PLAYWRIGHT_FIREFOX_DOWNLOAD_HOST',
    'PLAYWRIGHT_WEBKIT_DOWNLOAD_HOST'
)
foreach ($name in $downloadHostOverrides) {
    $value = [Environment]::GetEnvironmentVariable($name, 'Process')
    if (-not [string]::IsNullOrWhiteSpace($value)) {
        throw "Custom Playwright download host override '$name' is not allowed."
    }
}
if ($env:NODE_TLS_REJECT_UNAUTHORIZED -eq '0') {
    throw 'NODE_TLS_REJECT_UNAUTHORIZED=0 is not allowed for dependency or browser downloads.'
}

foreach ($command in @('node.exe', 'npm.cmd', 'php.exe', 'mysql.exe')) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command '$command' was not found on PATH. Complete the project setup first."
    }
}

& npm.cmd ci --ignore-scripts --registry=https://registry.npmjs.org/ --strict-ssl=true
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$playwright = Join-Path $root 'node_modules\.bin\playwright.cmd'
if (-not (Test-Path -LiteralPath $playwright)) {
    throw "The repository-local Playwright command was not created at '$playwright'."
}

& $playwright install chromium
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& (Join-Path $PSScriptRoot 'ensure-mysql.ps1')
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($Demo) {
    $env:MEDISHIELD_DEMO = '1'
}

& $playwright test
exit $LASTEXITCODE
