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

function New-SetupSecret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ([BitConverter]::ToString($bytes).Replace('-', '')).ToLowerInvariant()
}

function Write-ApplicationConfig {
    param(
        [Parameter(Mandatory = $true)][string]$SamplePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$DatabasePassword,
        [Parameter(Mandatory = $true)][string]$AuditMaintenanceDatabasePassword,
        [Parameter(Mandatory = $true)][string]$EncryptionKey,
        [Parameter(Mandatory = $true)][string]$AuditKey
    )

    $config = Get-Content -LiteralPath $SamplePath -Raw
    $config = $config.Replace("'name'    => 'medishield_db'", "'name'    => '$DatabaseName'")
    $config = $config.Replace('__DB_PASSWORD__', $DatabasePassword)
    $config = $config.Replace('__AUDIT_MAINTENANCE_DB_PASSWORD__', $AuditMaintenanceDatabasePassword)
    $config = $config.Replace('__ENCRYPTION_KEY__', $EncryptionKey)
    $config = $config.Replace('__AUDIT_HMAC_KEY__', $AuditKey)
    Set-Content -LiteralPath $DestinationPath -Value $config -NoNewline
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
    $configSamplePath = Join-Path $repoRoot 'config\config.sample.php'
    $configPath = Join-Path $repoRoot 'config\config.php'

    if (-not (Test-Path -LiteralPath $configSamplePath)) {
        throw "Config sample not found at '$configSamplePath'. Ensure config\config.sample.php exists before running this script."
    }

    $provisionApplicationUser = $false
    $provisionAuditMaintenanceUser = $false
    if (-not (Test-Path -LiteralPath $configPath)) {
        $appPassword = New-SetupSecret
        $auditMaintenancePassword = New-SetupSecret
        $encryptionKey = New-SetupSecret
        $auditKey = New-SetupSecret
        Write-ApplicationConfig -SamplePath $configSamplePath -DestinationPath $configPath -DatabaseName $DbName -DatabasePassword $appPassword -AuditMaintenanceDatabasePassword $auditMaintenancePassword -EncryptionKey $encryptionKey -AuditKey $auditKey
        Write-Host "Created generated application configuration: $configPath"
        $provisionApplicationUser = $true
        $provisionAuditMaintenanceUser = $true
    } else {
        $existingConfig = Get-Content -LiteralPath $configPath -Raw
        if ($existingConfig -match "'user'\s*=>\s*'root'") {
            $appPassword = New-SetupSecret
            Copy-Item -LiteralPath $configPath -Destination "$configPath.pre-hardening.bak"
            $existingConfig = $existingConfig -replace "'user'\s*=>\s*'root'", "'user'    => 'medishield_app'"
            $existingConfig = $existingConfig -replace "'pass'\s*=>\s*''", "'pass'    => '$appPassword'"
            Set-Content -LiteralPath $configPath -Value $existingConfig -NoNewline
            Write-Host "Migrated legacy root database credentials; backup saved beside config.php"
            $provisionApplicationUser = $true
        } else {
            Write-Host "Config file already exists: $configPath (preserving existing secrets)"
        }

        if ($existingConfig -notmatch "'audit_maintenance_db'\s*=>") {
            $auditMaintenancePassword = New-SetupSecret
            $maintenanceConfig = @"
    // Dedicated scheduled-maintenance identity. It can read audit rows and null
    // only attempted_identifier; it cannot edit chained fields or delete rows.
    'audit_maintenance_db' => [
        'host'    => '127.0.0.1',
        'port'    => 3306,
        'name'    => '$DbName',
        'user'    => 'medishield_audit_maintenance',
        'pass'    => '$auditMaintenancePassword',
        'charset' => 'utf8mb4',
    ],

"@
            $configMarker = '    // --- Cryptographic keys'
            if (-not $existingConfig.Contains($configMarker)) {
                throw "Cannot add audit-maintenance credentials to '$configPath': expected configuration marker was not found."
            }
            $existingConfig = $existingConfig.Replace($configMarker, "$maintenanceConfig$configMarker")
            Set-Content -LiteralPath $configPath -Value $existingConfig -NoNewline
            Write-Host 'Added dedicated audit-maintenance credentials to existing configuration'
            $provisionAuditMaintenanceUser = $true
        }
    }

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

    # Remove legacy broad grants first. The web account can write operational
    # tables, but audit_logs remains physically append-only to request code.
    $appAccountSql = "'medishield_app'@'127.0.0.1'"
    $resetAppPrivilegesSql = "REVOKE ALL PRIVILEGES, GRANT OPTION FROM $appAccountSql; GRANT SELECT, INSERT ON ``$DbName``.* TO $appAccountSql;"
    Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=$resetAppPrivilegesSql")) -Description 'Application privilege reset'

    $tableQuery = "SELECT table_name FROM information_schema.tables WHERE table_schema = '$DbName' AND table_type = 'BASE TABLE' AND table_name <> 'audit_logs' ORDER BY table_name;"
    $applicationTables = & $mysql @baseArgs '--batch' '--skip-column-names' "--execute=$tableQuery"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not enumerate application tables for least-privilege grants.'
    }
    foreach ($tableName in $applicationTables) {
        $tableGrantSql = "GRANT UPDATE, DELETE ON ``$DbName``.``$tableName`` TO $appAccountSql;"
        Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=$tableGrantSql")) -Description "Application DML grant for $tableName"
    }

    $maintenanceAccountSql = "'medishield_audit_maintenance'@'127.0.0.1'"
    $maintenanceGrantSql = "REVOKE ALL PRIVILEGES, GRANT OPTION FROM $maintenanceAccountSql; GRANT SELECT, UPDATE (attempted_identifier) ON ``$DbName``.audit_logs TO $maintenanceAccountSql; FLUSH PRIVILEGES;"
    Invoke-MySqlCommand -MySqlPath $mysql -Arguments ($baseArgs + @("--execute=$maintenanceGrantSql")) -Description 'Audit maintenance privilege grant'

    # INFORMATION_SCHEMA stores GRANTEE as the literal text "'user'@'host'".
    $appGranteeLiteral = "'''medishield_app''@''127.0.0.1'''"
    $unsafeGrantQuery = "SELECT COUNT(*) FROM information_schema.schema_privileges WHERE grantee = $appGranteeLiteral AND table_schema = '$DbName' AND privilege_type IN ('UPDATE', 'DELETE');"
    $unsafeGrant = (& $mysql @baseArgs '--batch' '--skip-column-names' "--execute=$unsafeGrantQuery").Trim()
    $unsafeAuditTableGrantQuery = "SELECT COUNT(*) FROM information_schema.table_privileges WHERE grantee = $appGranteeLiteral AND table_schema = '$DbName' AND table_name = 'audit_logs' AND privilege_type IN ('UPDATE', 'DELETE');"
    $unsafeAuditTableGrant = (& $mysql @baseArgs '--batch' '--skip-column-names' "--execute=$unsafeAuditTableGrantQuery").Trim()
    if ($LASTEXITCODE -ne 0 -or $unsafeGrant -ne '0' -or $unsafeAuditTableGrant -ne '0') {
        throw 'Least-privilege verification failed: the web account can still update or delete audit rows.'
    }

    $vitalsMigrationPath = Join-Path $repoRoot 'scripts\migrate-vitals-encryption.php'
    if (-not (Test-Path -LiteralPath $vitalsMigrationPath)) {
        throw "Vitals encryption migration not found at '$vitalsMigrationPath'."
    }
    Write-Host 'Encrypting legacy vitals, if any'
    $previousSetupDatabase = [Environment]::GetEnvironmentVariable('MEDISHIELD_SETUP_DB_NAME', 'Process')
    $previousSetupUser = [Environment]::GetEnvironmentVariable('MEDISHIELD_SETUP_DB_USER', 'Process')
    $previousSetupPass = [Environment]::GetEnvironmentVariable('MEDISHIELD_SETUP_DB_PASS', 'Process')
    try {
        $env:MEDISHIELD_SETUP_DB_NAME = $DbName
        $env:MEDISHIELD_SETUP_DB_USER = $DbUser
        $env:MEDISHIELD_SETUP_DB_PASS = $DbPass
        & php $vitalsMigrationPath
        $vitalsMigrationExitCode = $LASTEXITCODE
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
    if ($vitalsMigrationExitCode -ne 0) {
        throw "Vitals encryption migration failed with exit code $vitalsMigrationExitCode."
    }

    Write-Host ''
    Write-Host 'Database setup completed successfully.' -ForegroundColor Green
    Write-Host 'No application user credentials were seeded or printed.'
    $disposableUiDatabases = @('medishield_ui_test', 'medishield_ui_account_test')
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
