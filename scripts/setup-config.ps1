<#
.SYNOPSIS
Provides isolated application-config generation and upgrade helpers for setup-db.ps1.

.DESCRIPTION
Persistent web configuration and a setup command's selected database are separate
concerns. Disposable UI setup uses its selected database only at process scope;
the shared config keeps the existing normal web database name (or the sample's
normal name on first generation).
#>

function Assert-MediShieldSetupDatabaseName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabaseName
    )

    if ($DatabaseName -notmatch '\A[A-Za-z0-9_]+\z') {
        throw "Database name '$DatabaseName' contains unsupported characters."
    }
}

function New-MediShieldSetupSecret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }

    return ([BitConverter]::ToString($bytes).Replace('-', '')).ToLowerInvariant()
}

function Get-MediShieldConfigBlockMatches {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigContent,
        [Parameter(Mandatory = $true)][string]$BlockName
    )

    $escapedBlockName = [regex]::Escape($BlockName)
    $pattern = "(?ms)^[\t ]*'$escapedBlockName'\s*=>\s*\[(?<body>.*?)^[\t ]*\],\s*$"

    return [regex]::Matches($ConfigContent, $pattern)
}

function Get-MediShieldConfigBlockMatch {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigContent,
        [Parameter(Mandatory = $true)][string]$BlockName
    )

    $matches = @(Get-MediShieldConfigBlockMatches -ConfigContent $ConfigContent -BlockName $BlockName)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one '$BlockName' configuration block; found $($matches.Count)."
    }

    return $matches[0]
}

function Get-MediShieldConfigStringMatch {
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.RegularExpressions.Match]$BlockMatch,

        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    $escapedKey = [regex]::Escape($Key)
    $pattern = "(?m)^(?<prefix>[\t ]*'$escapedKey'\s*=>\s*)'(?<value>[^']*)'(?<suffix>\s*,[\t ]*)\r?$"
    $matches = [regex]::Matches($BlockMatch.Groups['body'].Value, $pattern)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one '$Key' value in the configuration block; found $($matches.Count)."
    }

    return $matches[0]
}

function Get-MediShieldConfigStringValue {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigContent,
        [Parameter(Mandatory = $true)][string]$BlockName,
        [Parameter(Mandatory = $true)][string]$Key
    )

    $block = Get-MediShieldConfigBlockMatch -ConfigContent $ConfigContent -BlockName $BlockName
    $value = Get-MediShieldConfigStringMatch -BlockMatch $block -Key $Key

    return $value.Groups['value'].Value
}

function Set-MediShieldConfigStringValue {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigContent,
        [Parameter(Mandatory = $true)][string]$BlockName,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $block = Get-MediShieldConfigBlockMatch -ConfigContent $ConfigContent -BlockName $BlockName
    $valueMatch = Get-MediShieldConfigStringMatch -BlockMatch $block -Key $Key
    $absoluteIndex = $block.Groups['body'].Index + $valueMatch.Groups['value'].Index

    return $ConfigContent.Substring(0, $absoluteIndex) +
        $Value +
        $ConfigContent.Substring($absoluteIndex + $valueMatch.Groups['value'].Length)
}

function Get-MediShieldConfiguredDatabaseName {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigContent,
        [Parameter(Mandatory = $true)][string]$BlockName
    )

    $databaseName = Get-MediShieldConfigStringValue `
        -ConfigContent $ConfigContent `
        -BlockName $BlockName `
        -Key 'name'
    Assert-MediShieldSetupDatabaseName -DatabaseName $databaseName

    return $databaseName
}

function Write-MediShieldApplicationConfig {
    param(
        [Parameter(Mandatory = $true)][string]$SamplePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$DatabasePassword,
        [Parameter(Mandatory = $true)][string]$AuditMaintenanceDatabasePassword,
        [Parameter(Mandatory = $true)][string]$EncryptionKey,
        [Parameter(Mandatory = $true)][string]$AuditKey,
        [Parameter(Mandatory = $true)][string]$AuditAnchorKey,
        [Parameter(Mandatory = $true)][string]$ThrottleKey
    )

    Assert-MediShieldSetupDatabaseName -DatabaseName $DatabaseName
    $config = Get-Content -LiteralPath $SamplePath -Raw -Encoding UTF8
    $config = Set-MediShieldConfigStringValue `
        -ConfigContent $config `
        -BlockName 'db' `
        -Key 'name' `
        -Value $DatabaseName
    $config = Set-MediShieldConfigStringValue `
        -ConfigContent $config `
        -BlockName 'audit_maintenance_db' `
        -Key 'name' `
        -Value $DatabaseName
    $config = $config.Replace('__DB_PASSWORD__', $DatabasePassword)
    $config = $config.Replace(
        '__AUDIT_MAINTENANCE_DB_PASSWORD__',
        $AuditMaintenanceDatabasePassword
    )
    $config = $config.Replace('__ENCRYPTION_KEY__', $EncryptionKey)
    $config = $config.Replace('__AUDIT_HMAC_KEY__', $AuditKey)
    $config = $config.Replace('__AUDIT_ANCHOR_HMAC_KEY__', $AuditAnchorKey)
    $config = $config.Replace('__THROTTLE_HMAC_KEY__', $ThrottleKey)
    [System.IO.File]::WriteAllText(
        $DestinationPath,
        $config,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Update-MediShieldApplicationConfig {
    param(
        [Parameter(Mandatory = $true)][string]$SamplePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$SelectedDatabaseName,
        [switch]$DisposableUiSetup
    )

    Assert-MediShieldSetupDatabaseName -DatabaseName $SelectedDatabaseName
    if (-not (Test-Path -LiteralPath $SamplePath)) {
        throw "Config sample not found at '$SamplePath'."
    }

    $messages = New-Object 'System.Collections.Generic.List[string]'
    $applicationPassword = $null
    $auditMaintenancePassword = $null
    $provisionApplicationUser = $false
    $provisionAuditMaintenanceUser = $false

    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        $sample = Get-Content -LiteralPath $SamplePath -Raw -Encoding UTF8
        $persistentDatabaseName = if ($DisposableUiSetup) {
            Get-MediShieldConfiguredDatabaseName -ConfigContent $sample -BlockName 'db'
        } else {
            $SelectedDatabaseName
        }
        $applicationPassword = New-MediShieldSetupSecret
        $auditMaintenancePassword = New-MediShieldSetupSecret
        Write-MediShieldApplicationConfig `
            -SamplePath $SamplePath `
            -DestinationPath $DestinationPath `
            -DatabaseName $persistentDatabaseName `
            -DatabasePassword $applicationPassword `
            -AuditMaintenanceDatabasePassword $auditMaintenancePassword `
            -EncryptionKey (New-MediShieldSetupSecret) `
            -AuditKey (New-MediShieldSetupSecret) `
            -AuditAnchorKey (New-MediShieldSetupSecret) `
            -ThrottleKey (New-MediShieldSetupSecret)
        [void] $messages.Add("Created generated application configuration: $DestinationPath")
        $provisionApplicationUser = $true
        $provisionAuditMaintenanceUser = $true
    } else {
        $existingConfig = Get-Content -LiteralPath $DestinationPath -Raw -Encoding UTF8
        $persistentDatabaseName = if ($DisposableUiSetup) {
            Get-MediShieldConfiguredDatabaseName `
                -ConfigContent $existingConfig `
                -BlockName 'db'
        } else {
            $SelectedDatabaseName
        }
        $configChanged = $false

        $configuredWebUser = Get-MediShieldConfigStringValue `
            -ConfigContent $existingConfig `
            -BlockName 'db' `
            -Key 'user'
        if ($configuredWebUser -eq 'root') {
            $applicationPassword = New-MediShieldSetupSecret
            Copy-Item `
                -LiteralPath $DestinationPath `
                -Destination "$DestinationPath.pre-hardening.bak"
            $existingConfig = Set-MediShieldConfigStringValue `
                -ConfigContent $existingConfig `
                -BlockName 'db' `
                -Key 'user' `
                -Value 'medishield_app'
            $existingConfig = Set-MediShieldConfigStringValue `
                -ConfigContent $existingConfig `
                -BlockName 'db' `
                -Key 'pass' `
                -Value $applicationPassword
            [void] $messages.Add(
                'Migrated legacy root database credentials; backup saved beside config.php'
            )
            $provisionApplicationUser = $true
            $configChanged = $true
        } else {
            [void] $messages.Add(
                "Config file already exists: $DestinationPath (preserving existing secrets)"
            )
        }

        $maintenanceMatches = @(
            Get-MediShieldConfigBlockMatches `
                -ConfigContent $existingConfig `
                -BlockName 'audit_maintenance_db'
        )
        if ($maintenanceMatches.Count -gt 1) {
            throw "Expected at most one 'audit_maintenance_db' configuration block; found $($maintenanceMatches.Count)."
        }

        if ($maintenanceMatches.Count -eq 0) {
            $auditMaintenancePassword = New-MediShieldSetupSecret
            $maintenanceConfig = @"
    // Dedicated scheduled-maintenance identity. It can read audit rows and null
    // only attempted_identifier; it cannot edit chained fields or delete rows.
    'audit_maintenance_db' => [
        'host'    => '127.0.0.1',
        'port'    => 3306,
        'name'    => '$persistentDatabaseName',
        'user'    => 'medishield_audit_maintenance',
        'pass'    => '$auditMaintenancePassword',
        'charset' => 'utf8mb4',
    ],

"@
            $configMarker = '    // --- Cryptographic keys'
            if (-not $existingConfig.Contains($configMarker)) {
                throw "Cannot add audit-maintenance credentials to '$DestinationPath': expected configuration marker was not found."
            }
            $existingConfig = $existingConfig.Replace(
                $configMarker,
                "$maintenanceConfig$configMarker"
            )
            [void] $messages.Add(
                'Added dedicated audit-maintenance credentials to existing configuration'
            )
            $provisionAuditMaintenanceUser = $true
            $configChanged = $true
        } elseif (-not $DisposableUiSetup) {
            $configuredMaintenanceDatabase = Get-MediShieldConfiguredDatabaseName `
                -ConfigContent $existingConfig `
                -BlockName 'audit_maintenance_db'
            if ($configuredMaintenanceDatabase -ne $SelectedDatabaseName) {
                $existingConfig = Set-MediShieldConfigStringValue `
                    -ConfigContent $existingConfig `
                    -BlockName 'audit_maintenance_db' `
                    -Key 'name' `
                    -Value $SelectedDatabaseName
                [void] $messages.Add(
                    "Aligned audit-maintenance database with normal setup target '$SelectedDatabaseName'"
                )
                $configChanged = $true
            }
        }

        if ($existingConfig -notmatch "'request_throttle_hmac_key_hex'\s*=>") {
            $auditAnchorKey = New-MediShieldSetupSecret
            $throttleKey = New-MediShieldSetupSecret
            $auditKeyLine = [regex]::Match(
                $existingConfig,
                "(?m)^(?<indent>\s*)'audit_hmac_key_hex'\s*=>\s*'[^']+',\s*$"
            )
            if (-not $auditKeyLine.Success) {
                throw "Cannot add forensic keys to '$DestinationPath': audit_hmac_key_hex was not found."
            }
            $insert = $auditKeyLine.Value + "`r`n" +
                $auditKeyLine.Groups['indent'].Value + "'audit_key_id' => 'audit-primary-2026',`r`n" +
                $auditKeyLine.Groups['indent'].Value + "'audit_anchor_hmac_key_hex' => '$auditAnchorKey',`r`n" +
                $auditKeyLine.Groups['indent'].Value + "'audit_anchor_key_id' => 'anchor-primary-2026',`r`n" +
                $auditKeyLine.Groups['indent'].Value + "'audit_anchor_path' => dirname(__DIR__) . '/var/audit-chain-anchors.jsonl',`r`n" +
                $auditKeyLine.Groups['indent'].Value + "'request_throttle_hmac_key_hex' => '$throttleKey',"
            $existingConfig = $existingConfig.Replace($auditKeyLine.Value, $insert)
            [void] $messages.Add(
                'Added separate audit-anchor and request-throttle keys to existing configuration'
            )
            $configChanged = $true
        }

        if ($configChanged) {
            [System.IO.File]::WriteAllText(
                $DestinationPath,
                $existingConfig,
                (New-Object System.Text.UTF8Encoding($false))
            )
        }
    }

    return [pscustomobject]@{
        ApplicationPassword = $applicationPassword
        AuditMaintenancePassword = $auditMaintenancePassword
        ProvisionApplicationUser = $provisionApplicationUser
        ProvisionAuditMaintenanceUser = $provisionAuditMaintenanceUser
        Messages = @($messages)
    }
}
