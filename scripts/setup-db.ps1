<#
.SYNOPSIS
Creates and seeds the MediShield MySQL database.

.DESCRIPTION
Run this after XAMPP is installed and MySQL is running from the XAMPP Control Panel. The script creates the database, loads the schema and non-credential seed data, creates a least-privilege web account, and generates config\config.php with unique cryptographic keys when needed.

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

$setupConfigFunctionsPath = Join-Path $PSScriptRoot 'setup-config.ps1'
if (-not (Test-Path -LiteralPath $setupConfigFunctionsPath)) {
    throw "Setup configuration helpers were not found at '$setupConfigFunctionsPath'."
}
. $setupConfigFunctionsPath

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

function Revoke-DatabasePrivileges {
    param(
        [Parameter(Mandatory = $true)][string]$MySqlPath,
        [Parameter(Mandatory = $true)][string[]]$BaseArguments,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$AccountName
    )

    $grantee = "'''$AccountName''@''127.0.0.1'''"
    $queries = @(
        "SELECT CONCAT('REVOKE ', GROUP_CONCAT(privilege_type ORDER BY privilege_type SEPARATOR ', '), ' ON ``$DatabaseName``.* FROM ''$AccountName''@''127.0.0.1'';') FROM information_schema.schema_privileges WHERE grantee = $grantee AND table_schema = '$DatabaseName' GROUP BY table_schema;",
        "SELECT CONCAT('REVOKE ', GROUP_CONCAT(privilege_type ORDER BY privilege_type SEPARATOR ', '), ' ON ``$DatabaseName``.``', table_name, '`` FROM ''$AccountName''@''127.0.0.1'';') FROM information_schema.table_privileges WHERE grantee = $grantee AND table_schema = '$DatabaseName' GROUP BY table_name;",
        "SELECT CONCAT('REVOKE ', privilege_type, ' (', GROUP_CONCAT(CONCAT('``', column_name, '``') ORDER BY column_name SEPARATOR ', '), ') ON ``$DatabaseName``.``', table_name, '`` FROM ''$AccountName''@''127.0.0.1'';') FROM information_schema.column_privileges WHERE grantee = $grantee AND table_schema = '$DatabaseName' GROUP BY table_name, privilege_type;"
    )

    foreach ($query in $queries) {
        $statements = & $MySqlPath @BaseArguments '--batch' '--skip-column-names' "--execute=$query"
        if ($LASTEXITCODE -ne 0) {
            throw "Could not enumerate existing grants for $AccountName."
        }
        foreach ($statement in $statements) {
            if (-not [string]::IsNullOrWhiteSpace($statement)) {
                Invoke-MySqlCommand -MySqlPath $MySqlPath -Arguments ($BaseArguments + @("--execute=$statement")) -Description "Privilege reset for $AccountName"
            }
        }
    }
}

function Invoke-PhpSetupHelper {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$SetupUser,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$SetupPassword
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw "$Description helper not found at '$ScriptPath'."
    }

    $previousSetupDatabase = [Environment]::GetEnvironmentVariable(
        'MEDISHIELD_SETUP_DB_NAME',
        'Process'
    )
    $previousSetupUser = [Environment]::GetEnvironmentVariable(
        'MEDISHIELD_SETUP_DB_USER',
        'Process'
    )
    $previousSetupPass = [Environment]::GetEnvironmentVariable(
        'MEDISHIELD_SETUP_DB_PASS',
        'Process'
    )
    try {
        $env:MEDISHIELD_SETUP_DB_NAME = $DatabaseName
        $env:MEDISHIELD_SETUP_DB_USER = $SetupUser
        $env:MEDISHIELD_SETUP_DB_PASS = $SetupPassword
        & php $ScriptPath
        $exitCode = $LASTEXITCODE
    } finally {
        if ($null -eq $previousSetupDatabase) {
            Remove-Item Env:MEDISHIELD_SETUP_DB_NAME -ErrorAction SilentlyContinue
        } else {
            $env:MEDISHIELD_SETUP_DB_NAME = $previousSetupDatabase
        }
        if ($null -eq $previousSetupUser) {
            Remove-Item Env:MEDISHIELD_SETUP_DB_USER -ErrorAction SilentlyContinue
        } else {
            $env:MEDISHIELD_SETUP_DB_USER = $previousSetupUser
        }
        if ($null -eq $previousSetupPass) {
            Remove-Item Env:MEDISHIELD_SETUP_DB_PASS -ErrorAction SilentlyContinue
        } else {
            $env:MEDISHIELD_SETUP_DB_PASS = $previousSetupPass
        }
    }

    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
}

try {
    Write-Host 'MediShield database setup starting...' -ForegroundColor Cyan

    Assert-MediShieldSetupDatabaseName -DatabaseName $DbName
    $disposableUiDatabases = @('medishield_ui_test', 'medishield_ui_account_test')
    $isDisposableUiSetup = $DbName -in $disposableUiDatabases
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
    $configSamplePath = Join-Path $repoRoot 'config\config.sample.php'
    $configPath = Join-Path $repoRoot 'config\config.php'

    if (-not (Test-Path -LiteralPath $configSamplePath)) {
        throw "Config sample not found at '$configSamplePath'. Ensure config\config.sample.php exists before running this script."
    }

    $configResult = Update-MediShieldApplicationConfig `
        -SamplePath $configSamplePath `
        -DestinationPath $configPath `
        -SelectedDatabaseName $DbName `
        -DisposableUiSetup:$isDisposableUiSetup
    foreach ($message in $configResult.Messages) {
        Write-Host $message
    }
    $appPassword = $configResult.ApplicationPassword
    $auditMaintenancePassword = $configResult.AuditMaintenancePassword
    $provisionApplicationUser = $configResult.ProvisionApplicationUser
    $provisionAuditMaintenanceUser = $configResult.ProvisionAuditMaintenanceUser

    if ($provisionApplicationUser) {
        $appUserSql = "CREATE USER IF NOT EXISTS 'medishield_app'@'127.0.0.1' IDENTIFIED BY '$appPassword'; ALTER USER 'medishield_app'@'127.0.0.1' IDENTIFIED BY '$appPassword';"
        Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=$appUserSql")) -Description 'Application database account provisioning'
    }

    if ($provisionAuditMaintenanceUser) {
        $auditMaintenanceSql = "CREATE USER IF NOT EXISTS 'medishield_audit_maintenance'@'127.0.0.1' IDENTIFIED BY '$auditMaintenancePassword'; ALTER USER 'medishield_audit_maintenance'@'127.0.0.1' IDENTIFIED BY '$auditMaintenancePassword';"
        Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=$auditMaintenanceSql")) -Description 'Audit maintenance account provisioning'
    }

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

    $auditInitializerPath = Join-Path $repoRoot 'scripts\initialize-audit-chain.php'
    Write-Host 'Initializing and verifying the keyed audit chain head'
    Invoke-PhpSetupHelper -ScriptPath $auditInitializerPath `
        -Description 'Audit-chain initialization' `
        -DatabaseName $DbName `
        -SetupUser $DbUser `
        -SetupPassword $DbPass

    # Remove legacy broad grants first, then grant exact table scopes. The web
    # account can append audit rows and advance the keyed head, but cannot edit or
    # delete forensic rows. The maintenance account can scrub one PII column only.
    $appAccountSql = "'medishield_app'@'127.0.0.1'"
    Revoke-DatabasePrivileges -MySqlPath $mysql -BaseArguments $baseArgs -DatabaseName $DbName -AccountName 'medishield_app'

    $tableQuery = "SELECT table_name FROM information_schema.tables WHERE table_schema = '$DbName' AND table_type = 'BASE TABLE' AND table_name NOT IN ('audit_logs', 'audit_chain_head') ORDER BY table_name;"
    $applicationTables = & $mysql @baseArgs '--batch' '--skip-column-names' "--execute=$tableQuery"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not enumerate application tables for least-privilege grants.'
    }
    foreach ($tableName in $applicationTables) {
        $tableGrantSql = "GRANT SELECT, INSERT, UPDATE, DELETE ON ``$DbName``.``$tableName`` TO $appAccountSql;"
        Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=$tableGrantSql")) -Description "Application DML grant for $tableName"
    }
    Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=GRANT SELECT, INSERT ON ``$DbName``.audit_logs TO $appAccountSql; GRANT SELECT, UPDATE ON ``$DbName``.audit_chain_head TO $appAccountSql;")) -Description 'Application audit grants'

    $maintenanceAccountSql = "'medishield_audit_maintenance'@'127.0.0.1'"
    Revoke-DatabasePrivileges -MySqlPath $mysql -BaseArguments $baseArgs -DatabaseName $DbName -AccountName 'medishield_audit_maintenance'
    $maintenanceGrantSql = "GRANT SELECT, UPDATE (attempted_identifier) ON ``$DbName``.audit_logs TO $maintenanceAccountSql; FLUSH PRIVILEGES;"
    Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=$maintenanceGrantSql")) -Description 'Audit maintenance privilege grant'

    # INFORMATION_SCHEMA stores GRANTEE as the literal text "'user'@'host'".
    $appGranteeLiteral = "'''medishield_app''@''127.0.0.1'''"
    $unsafeGrantQuery = "SELECT COUNT(*) FROM information_schema.schema_privileges WHERE grantee = $appGranteeLiteral AND table_schema = '$DbName';"
    $unsafeGrant = (& $mysql @baseArgs '--batch' '--skip-column-names' "--execute=$unsafeGrantQuery").Trim()
    $unsafeAuditTableGrantQuery = "SELECT COUNT(*) FROM information_schema.table_privileges WHERE grantee = $appGranteeLiteral AND table_schema = '$DbName' AND table_name = 'audit_logs' AND privilege_type IN ('UPDATE', 'DELETE');"
    $unsafeAuditTableGrant = (& $mysql @baseArgs '--batch' '--skip-column-names' "--execute=$unsafeAuditTableGrantQuery").Trim()
    if ($LASTEXITCODE -ne 0 -or $unsafeGrant -ne '0' -or $unsafeAuditTableGrant -ne '0') {
        throw 'Least-privilege verification failed: the web account can still update or delete audit rows.'
    }

    $grantVerifierPath = Join-Path $repoRoot 'scripts\verify-audit-grants.php'
    Write-Host 'Verifying exact forensic grants and empirical denials'
    Invoke-PhpSetupHelper -ScriptPath $grantVerifierPath `
        -Description 'Audit grant verification' `
        -DatabaseName $DbName `
        -SetupUser $DbUser `
        -SetupPassword $DbPass

    $vitalsMigrationPath = Join-Path $repoRoot 'scripts\migrate-vitals-encryption.php'
    Write-Host 'Encrypting legacy vitals, if any'
    Invoke-PhpSetupHelper -ScriptPath $vitalsMigrationPath `
        -Description 'Vitals encryption migration' `
        -DatabaseName $DbName `
        -SetupUser $DbUser `
        -SetupPassword $DbPass

    Write-Host ''
    Write-Host 'Database setup completed successfully.' -ForegroundColor Green
    Write-Host 'No application user credentials were seeded or printed.'
    if ($DbName -in $disposableUiDatabases) {
        Write-Host 'The CLI-guarded UI seeder will add deterministic fixtures to this allowlisted disposable database.'
    } else {
        Write-Host 'For a normal database with no administrator, explicitly provision one with:'
        Write-Host "  php scripts\provision-initial-admin.php --name=`"<full name>`" --email=`"<email>`" --confirm-database=$DbName --confirm-initial-admin"
    }
}
catch {
    Write-Error "Database setup failed: $($_.Exception.Message) If MySQL is not running, start MySQL in the XAMPP Control Panel and rerun this script."
    exit 1
}
