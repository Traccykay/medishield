<#
.SYNOPSIS
Ensures a local MySQL/MariaDB instance is accepting MediShield test connections.

.DESCRIPTION
Checks readiness before changing anything. If the server is stopped, it tries a
Windows service, XAMPP, then the installed Scoop MariaDB server. The script is
idempotent: a ready server is never restarted. It is used by all runners that
need MySQL so they fail with one actionable diagnostic instead of a later,
misleading application error.
#>
[CmdletBinding()]
param(
    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'

function Test-MediShieldDatabase {
    param([Parameter(Mandatory = $true)][string]$MySql)

    & $MySql '--host=127.0.0.1' '--user=root' '--connect-timeout=2' '--execute=SELECT 1;' 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

function Get-ScoopMariaDbServer {
    param([Parameter(Mandatory = $true)][string]$MySqlCommand)

    $shim = [System.IO.Path]::ChangeExtension($MySqlCommand, '.shim')
    if (-not (Test-Path -LiteralPath $shim)) {
        return $null
    }

    $match = [regex]::Match(
        (Get-Content -LiteralPath $shim -Raw),
        '(?m)^path\s*=\s*"(?<path>[^"]+mysql\.exe)"'
    )
    if (-not $match.Success) {
        return $null
    }

    $bin = Split-Path -Parent $match.Groups['path'].Value
    $root = Split-Path -Parent $bin
    $server = @(
        (Join-Path $bin 'mariadbd.exe'),
        (Join-Path $bin 'mysqld.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $defaults = Join-Path $root 'data\my.ini'

    if ($null -eq $server -or -not (Test-Path -LiteralPath $defaults)) {
        return $null
    }

    return [PSCustomObject]@{
        Server = $server
        DefaultsFile = $defaults
    }
}

$mysqlCommand = Get-Command mysql.exe -ErrorAction SilentlyContinue
if ($null -eq $mysqlCommand) {
    throw 'mysql.exe was not found on PATH. Run scripts\install-dependencies.ps1 or install MariaDB/XAMPP before running database-dependent tests.'
}

$mysql = $mysqlCommand.Source
if (Test-MediShieldDatabase -MySql $mysql) {
    Write-Host 'MySQL/MariaDB is already ready on 127.0.0.1:3306.'
    exit 0
}

$startMethods = [System.Collections.Generic.List[string]]::new()
$service = Get-Service -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Status -ne 'Running' -and (
            $_.Name -match 'mysql|mariadb' -or
            $_.DisplayName -match 'mysql|mariadb'
        )
    } |
    Select-Object -First 1

if ($null -ne $service) {
    try {
        Start-Service -Name $service.Name -ErrorAction Stop
        $startMethods.Add("Windows service '$($service.Name)'")
    } catch {
        $startMethods.Add("Windows service '$($service.Name)' failed: $($_.Exception.Message)")
    }
} elseif (Test-Path -LiteralPath 'C:\xampp\mysql_start.bat') {
    Start-Process -FilePath $env:ComSpec -ArgumentList '/c', 'C:\xampp\mysql_start.bat' -WindowStyle Hidden
    $startMethods.Add('XAMPP mysql_start.bat')
} else {
    $scoop = Get-ScoopMariaDbServer -MySqlCommand $mysql
    if ($null -ne $scoop) {
        Start-Process -FilePath $scoop.Server -ArgumentList "--defaults-file=$($scoop.DefaultsFile)", '--port=3306', '--bind-address=127.0.0.1' -WindowStyle Hidden
        $startMethods.Add("Scoop server '$($scoop.Server)'")
    }
}

for ($attempt = 1; $attempt -le $TimeoutSeconds; $attempt++) {
    Start-Sleep -Seconds 1
    if (Test-MediShieldDatabase -MySql $mysql) {
        Write-Host "MySQL/MariaDB is ready after $attempt second(s)."
        exit 0
    }
}

$attempted = if ($startMethods.Count -eq 0) { 'no recognised startup method' } else { $startMethods -join '; ' }
throw "MySQL/MariaDB did not become ready within $TimeoutSeconds seconds. Attempted: $attempted. Check the database logs, then rerun scripts\ensure-mysql.ps1."
