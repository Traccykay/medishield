<#
.SYNOPSIS
Creates and seeds the MediShield MySQL database.

.DESCRIPTION
Run this after XAMPP is installed and MySQL is running from the XAMPP Control Panel. The script creates the database, loads sql\schema.sql and sql\seed.sql, and creates config\config.php from config\config.sample.php when needed.

.USAGE
powershell -ExecutionPolicy Bypass -File scripts\setup-db.ps1
powershell -ExecutionPolicy Bypass -File scripts\setup-db.ps1 -DbHost 127.0.0.1 -DbUser root -DbPass '' -DbName medishield_db
#>

[CmdletBinding()]
param(
    [string]$DbHost = '127.0.0.1',
    [string]$DbUser = 'root',
    [string]$DbPass = '',
    [string]$DbName = 'medishield_db'
)

$ErrorActionPreference = 'Stop'

function Get-XamppMysqlPath {
    $candidates = @(
        'C:\xampp\mysql\bin\mysql.exe',
        'C:\tools\xampp\mysql\bin\mysql.exe',
        'C:\tools\mysql\bin\mysql.exe'
    )

    $mysqlCommand = Get-Command mysql.exe -ErrorAction SilentlyContinue
    if ($null -ne $mysqlCommand -and (Test-Path -LiteralPath $mysqlCommand.Source)) {
        return $mysqlCommand.Source
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "mysql.exe was not found. Checked: $($candidates -join ', ') and PATH. Install XAMPP 8.1 or MariaDB via Scoop first."
}

function Get-MySqlBaseArgs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$UserName,

        [AllowEmptyString()]
        [string]$Password
    )

    $args = @("--host=$HostName", "--user=$UserName")
    if ($Password -ne '') {
        $args += "--password=$Password"
    }

    return $args
}

function Invoke-MySqlCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MySqlPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    & $MySqlPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Invoke-MySqlScriptFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MySqlPath,

        [Parameter(Mandatory = $true)]
        [string[]]$BaseArguments,

        [Parameter(Mandatory = $true)]
        [string]$DatabaseName,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw "$Description file not found at '$ScriptPath'. Ensure the SQL artifacts have been created before running this script."
    }

    Get-Content -LiteralPath $ScriptPath -Raw | & $MySqlPath @BaseArguments $DatabaseName
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

try {
    Write-Host 'MediShield database setup starting...' -ForegroundColor Cyan

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $mysql = Get-XamppMysqlPath
    $baseArgs = Get-MySqlBaseArgs -HostName $DbHost -UserName $DbUser -Password $DbPass

    Write-Host "Discovered MySQL: $mysql" -ForegroundColor Green
    Write-Host "Checking MySQL connectivity at $DbHost..."
    Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @('--execute=SELECT 1;')) -Description 'MySQL connectivity check'

    $createDatabaseSql = "CREATE DATABASE IF NOT EXISTS ``$DbName`` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    Write-Host "Creating database if needed: $DbName"
    Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=$createDatabaseSql")) -Description 'Database creation'

    $schemaPath = Join-Path $repoRoot 'sql\schema.sql'
    $seedPath = Join-Path $repoRoot 'sql\seed.sql'

    Write-Host "Loading schema from $schemaPath"
    Invoke-MySqlScriptFile -MySqlPath $mysql -BaseArguments $baseArgs -DatabaseName $DbName -ScriptPath $schemaPath -Description 'Schema load'

    Write-Host "Loading seed data from $seedPath"
    Invoke-MySqlScriptFile -MySqlPath $mysql -BaseArguments $baseArgs -DatabaseName $DbName -ScriptPath $seedPath -Description 'Seed load'

    # Apply incremental migrations (idempotent) so EXISTING databases pick up new
    # columns that schema.sql's CREATE TABLE IF NOT EXISTS would otherwise skip.
    $migrationsDir = Join-Path $repoRoot 'sql\migrations'
    if (Test-Path -LiteralPath $migrationsDir) {
        $migrations = Get-ChildItem -LiteralPath $migrationsDir -Filter '*.sql' | Sort-Object Name
        foreach ($migration in $migrations) {
            Write-Host "Applying migration $($migration.Name)"
            Invoke-MySqlScriptFile -MySqlPath $mysql -BaseArguments $baseArgs -DatabaseName $DbName -ScriptPath $migration.FullName -Description "Migration $($migration.Name)"
        }
    }

    $configSamplePath = Join-Path $repoRoot 'config\config.sample.php'
    $configPath = Join-Path $repoRoot 'config\config.php'
    if (-not (Test-Path -LiteralPath $configPath)) {
        if (-not (Test-Path -LiteralPath $configSamplePath)) {
            throw "Config sample not found at '$configSamplePath'. Ensure config\config.sample.php exists before running this script."
        }

        Copy-Item -LiteralPath $configSamplePath -Destination $configPath
        Write-Host "Created config file: $configPath"
    }
    else {
        Write-Host "Config file already exists: $configPath"
    }

    Write-Host ''
    Write-Host 'Database setup completed successfully.' -ForegroundColor Green
    Write-Host 'Superadmin login:'
    Write-Host '  Email:    medishield.superadmin@gmail.com'
    Write-Host '  Password: ChangeMe!2026'
}
catch {
    Write-Error "Database setup failed: $($_.Exception.Message) If MySQL is not running, start MySQL in the XAMPP Control Panel and rerun this script."
    exit 1
}
