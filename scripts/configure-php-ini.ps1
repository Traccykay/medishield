<#
.SYNOPSIS
Configures a PHP installation's php.ini to match the canonical MediShield
development environment.

.DESCRIPTION
MediShield requires a specific set of PHP extensions and INI settings. Scoop's
PHP ships with NO active php.ini (every extension off), and a stock XAMPP php.ini
has several of these extensions commented out. Either way, running the app or the
PHPUnit suite fails with confusing "class not found" / "could not find driver"
errors until php.ini is fixed by hand.

This script removes that guesswork. It is the single source of truth for the PHP
runtime configuration so every engineer / agent gets an identical environment:

  * Locates the php.ini actually loaded by the target php.exe (php --ini).
  * If none is loaded (typical for Scoop), creates one from php.ini-production.
  * Ensures extension_dir points at the install's ext/ folder.
  * Enables every extension in $RequiredExtensions (idempotent: uncomments an
    existing line, or appends one if absent).
  * Sets date.timezone = UTC and memory_limit = 256M.
  * Verifies the result with `php -m` and fails if anything is still missing.

Re-running the script is safe; it never duplicates lines.

WHY THESE EXTENSIONS (keep this list in sync with any new runtime dependency):
  openssl    - AES-256-GCM crypto + secure random (src/Security/Crypto.php).
  mbstring   - multibyte-safe string handling.
  pdo_mysql  - PDO driver for MySQL/MariaDB (production database).
  mysqli     - mysql CLI/driver parity used by setup-db.ps1 checks.
  pdo_sqlite - PDO SQLite driver for the in-memory PHPUnit test database.
  sqlite3    - SQLite support used by the test suite.
  fileinfo   - MIME detection for lab-result uploads (later deliverables).
  zip        - required by Composer to extract packages. This fixes the earlier Composer error where the zip extension and unzip/7z commands were missing.

.PARAMETER PhpExe
Full path to the php.exe to configure. If omitted, the script uses the first
php.exe on PATH.

.USAGE
powershell -ExecutionPolicy Bypass -File scripts\configure-php-ini.ps1
powershell -ExecutionPolicy Bypass -File scripts\configure-php-ini.ps1 -PhpExe C:\xampp\php\php.exe
#>

param(
    [string]$PhpExe
)

$ErrorActionPreference = 'Stop'

# --- Canonical configuration -------------------------------------------------
# Keep this list in sync with every runtime dependency MediShield relies on.
$RequiredExtensions = @(
    'openssl',
    'mbstring',
    'pdo_mysql',
    'mysqli',
    'pdo_sqlite',
    'sqlite3',
    'fileinfo',
    'zip'
)
$IniSettings = [ordered]@{
    'date.timezone' = 'UTC'
    'memory_limit'  = '256M'
}

function Resolve-PhpExe {
    param([string]$Explicit)

    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) {
            throw "php.exe not found at: $Explicit"
        }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }

    $cmd = Get-Command php -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw 'php.exe was not found on PATH. Pass -PhpExe <path>, e.g. C:\xampp\php\php.exe.'
    }
    return $cmd.Source
}

function Get-LoadedIniPath {
    param([string]$Php)

    $iniLine = (& $Php --ini) | Where-Object { $_ -match 'Loaded Configuration File' }
    if ($iniLine -and $iniLine -match ':\s*"?(.+?)"?\s*$') {
        $candidate = $Matches[1].Trim()
        if ($candidate -and $candidate -ne '(none)') {
            return $candidate
        }
    }
    return $null
}

try {
    $php = Resolve-PhpExe -Explicit $PhpExe

    # The resolved php.exe may be a proxy/shim (e.g. Scoop's shims\php.exe). Ask
    # PHP itself for its real binary location so extension_dir / template lookups
    # point at the actual install (apps\php\current\ext, C:\xampp\php\ext, ...),
    # not the shim folder.
    $realBin = (& $php -n -r "echo PHP_BINARY;") 2>$null
    if ($realBin -and (Test-Path -LiteralPath $realBin)) {
        $phpDir = Split-Path -Parent $realBin
    }
    else {
        $phpDir = Split-Path -Parent $php
    }
    Write-Host "Configuring PHP at: $php" -ForegroundColor Cyan
    Write-Host "PHP home:           $phpDir"

    # 1. Find (or create) the php.ini this php.exe loads.
    $iniPath = Get-LoadedIniPath -Php $php
    if (-not $iniPath) {
        $iniPath = Join-Path $phpDir 'php.ini'
        $template = Join-Path $phpDir 'php.ini-production'
        if (-not (Test-Path -LiteralPath $template)) {
            $template = Join-Path $phpDir 'php.ini-development'
        }
        if (Test-Path -LiteralPath $template) {
            Copy-Item -LiteralPath $template -Destination $iniPath -Force
            Write-Host "Created php.ini from $(Split-Path -Leaf $template)."
        }
        else {
            New-Item -ItemType File -Path $iniPath -Force | Out-Null
            Write-Host 'Created empty php.ini (no template found).'
        }
    }
    Write-Host "Using php.ini: $iniPath"

    $lines = @(Get-Content -LiteralPath $iniPath)

    # 2. Ensure extension_dir points at this install's ext/ folder.
    $extDir = Join-Path $phpDir 'ext'
    $extDirSet = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*;?\s*extension_dir\s*=') {
            $lines[$i] = "extension_dir = `"$extDir`""
            $extDirSet = $true
            break
        }
    }
    if (-not $extDirSet) {
        $lines += "extension_dir = `"$extDir`""
    }

    # 3. Enable each required extension (uncomment existing, else append).
    foreach ($ext in $RequiredExtensions) {
        $found = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s*;?\s*extension\s*=\s*$([regex]::Escape($ext))(\.dll)?\s*$") {
                $lines[$i] = "extension=$ext"
                $found = $true
                break
            }
        }
        if (-not $found) {
            $lines += "extension=$ext"
        }
    }

    # 4. Apply scalar INI settings (replace existing, else append).
    foreach ($key in $IniSettings.Keys) {
        $value = $IniSettings[$key]
        $set = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s*;?\s*$([regex]::Escape($key))\s*=") {
                $lines[$i] = "$key = $value"
                $set = $true
                break
            }
        }
        if (-not $set) {
            $lines += "$key = $value"
        }
    }

    Set-Content -LiteralPath $iniPath -Value $lines -Encoding UTF8
    Write-Host 'php.ini updated.' -ForegroundColor Green

    # 5. Verify every required extension is now actually loaded.
    Write-Host 'Verifying loaded extensions...'
    $loaded = (& $php -m) | ForEach-Object { $_.Trim().ToLowerInvariant() }
    $missing = @()
    foreach ($ext in $RequiredExtensions) {
        if ($loaded -contains $ext.ToLowerInvariant()) {
            Write-Host "  OK: $ext"
        }
        else {
            Write-Warning "  MISSING: $ext (no $ext.dll in $extDir?)"
            $missing += $ext
        }
    }

    if ($missing.Count -gt 0) {
        throw "These extensions could not be loaded: $($missing -join ', '). Confirm the matching .dll files exist in $extDir."
    }

    Write-Host ''
    Write-Host 'PHP configuration complete. Environment matches the MediShield baseline.' -ForegroundColor Green
}
catch {
    Write-Error "PHP configuration failed: $($_.Exception.Message)"
    exit 1
}
