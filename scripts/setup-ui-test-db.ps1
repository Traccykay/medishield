<#
.SYNOPSIS
Creates the isolated database used by Playwright UI tests.
#>
[CmdletBinding()]
param(
    [string]$DbName = 'medishield_ui_test'
)

if ($DbName -notmatch '^[A-Za-z0-9_]+$') {
    throw 'The UI test database name may contain only letters, numbers, and underscores.'
}

$mysql = (Get-Command mysql.exe -ErrorAction Stop).Source
& $mysql '--host=127.0.0.1' '--user=root' "--execute=DROP DATABASE IF EXISTS ``$DbName``;"
if ($LASTEXITCODE -ne 0) {
    throw "Could not remove the disposable UI test database '$DbName'."
}

$scriptPath = Join-Path $PSScriptRoot 'setup-db.ps1'
& $scriptPath -DbName $DbName
exit $LASTEXITCODE
