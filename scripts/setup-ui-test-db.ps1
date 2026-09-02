<#
.SYNOPSIS
Creates the isolated database used by Playwright UI tests.
#>
[CmdletBinding()]
param(
    [string]$DbName = 'medishield_ui_test'
)

$AllowedDatabases = @('medishield_ui_test', 'medishield_ui_account_test')
if ($DbName -notin $AllowedDatabases) {
    throw "UI test setup may only rebuild a named disposable database: $($AllowedDatabases -join ', ')."
}

$mysql = (Get-Command mysql.exe -ErrorAction Stop).Source
& (Join-Path $PSScriptRoot 'ensure-mysql.ps1')
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
& $mysql '--host=127.0.0.1' '--user=root' "--execute=DROP DATABASE IF EXISTS ``$DbName``;"
if ($LASTEXITCODE -ne 0) {
    throw "Could not remove the disposable UI test database '$DbName'."
}

$scriptPath = Join-Path $PSScriptRoot 'setup-db.ps1'
& $scriptPath -DbName $DbName
exit $LASTEXITCODE
