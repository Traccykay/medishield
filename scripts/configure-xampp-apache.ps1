<#
.SYNOPSIS
Configures and verifies a hardened XAMPP Apache site for MediShield.

.DESCRIPTION
This idempotent script makes public/ the Apache document root, enables and
asserts mod_rewrite and mod_headers, applies protocol hardening, configures the
medishield.local host without replacing XAMPP's default localhost site,
validates with httpd.exe -t and -M, restarts Apache, and probes the live HTTP
boundary. Existing Apache and hosts files are backed up and restored if
configuration validation fails.

.PARAMETER XamppRoot
Optional XAMPP installation directory. C:\xampp and C:\tools\xampp are checked
when omitted.

.PARAMETER Port
Apache listener and virtual-host port. A managed Listen directive is added
when the main configuration does not already listen on this port.

.PARAMETER SkipRestart
Apply and syntax-check configuration without restarting Apache.

.PARAMETER SkipHttpProbe
Skip HTTP behavior probes. This does not make static checks runtime proof.

.PARAMETER AllowRemoteAccess
Replace the default local-only MediShield vhost rule with Require all granted.
Use only when the surrounding network and host firewall are intentionally
configured for remote development access.
#>

[CmdletBinding()]
param(
    [string]$XamppRoot,
    [string]$HostName = 'medishield.local',
    [ValidateRange(1, 65535)]
    [int]$Port = 80,
    [switch]$SkipRestart,
    [switch]$SkipHttpProbe,
    [switch]$AllowRemoteAccess
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ApacheRunning {
    param([string]$Root)

    $pidFile = Join-Path $Root 'apache\logs\httpd.pid'
    if (-not (Test-Path -LiteralPath $pidFile)) {
        return $false
    }

    $apachePid = 0
    if (-not [int]::TryParse((Get-Content -LiteralPath $pidFile -Raw).Trim(), [ref]$apachePid)) {
        return $false
    }

    return $null -ne (Get-Process -Id $apachePid -ErrorAction SilentlyContinue)
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [string[]]$ArgumentList = @()
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 promotes redirected native stderr to ErrorRecord
        # objects. Continue keeps those records capturable even when the caller
        # uses Stop, while PowerShell 7 follows the same result contract.
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    $renderedOutput = ($output | ForEach-Object { $_.ToString() } | Out-String).Trim()
    return [pscustomobject]@{
        Output = $renderedOutput
        ExitCode = [int] $exitCode
    }
}

function Resolve-XamppRoot {
    param([string]$ExplicitRoot)

    $candidates = if ($ExplicitRoot) {
        @($ExplicitRoot)
    }
    else {
        @('C:\xampp', 'C:\tools\xampp')
    }

    foreach ($candidate in $candidates) {
        $httpd = Join-Path $candidate 'apache\bin\httpd.exe'
        $php = Join-Path $candidate 'php\php.exe'
        if ((Test-Path -LiteralPath $httpd) -and (Test-Path -LiteralPath $php)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "XAMPP was not found. Checked: $($candidates -join ', '). Install XAMPP 8.1 or pass -XamppRoot."
}

function Set-ManagedBlock {
    param(
        [string]$Content,
        [string]$Name,
        [string]$Body
    )

    $begin = "# BEGIN MEDISHIELD $Name"
    $end = "# END MEDISHIELD $Name"
    $pattern = "(?ms)^$([regex]::Escape($begin))\r?\n.*?^$([regex]::Escape($end))\r?\n?"
    $block = "$begin`r`n$Body`r`n$end`r`n"
    if ([regex]::IsMatch($Content, $pattern)) {
        return [regex]::Replace($Content, $pattern, $block, 1)
    }
    return $Content.TrimEnd() + "`r`n`r`n" + $block
}

function Remove-ManagedBlock {
    param(
        [string]$Content,
        [string]$Name
    )

    $begin = "# BEGIN MEDISHIELD $Name"
    $end = "# END MEDISHIELD $Name"
    $pattern = "(?ms)^$([regex]::Escape($begin))\r?\n.*?^$([regex]::Escape($end))\r?\n?"
    return [regex]::Replace($Content, $pattern, '', 1)
}

function Get-ApacheDocumentRoot {
    param([string]$Content)

    $match = [regex]::Match(
        $Content,
        '(?im)^\s*DocumentRoot\s+(?:"(?<quoted>[^"]+)"|(?<unquoted>\S+))\s*(?:#.*)?$'
    )
    if (-not $match.Success) {
        throw 'Apache main configuration does not define a DocumentRoot for the default localhost site.'
    }

    if ($match.Groups['quoted'].Success) {
        return $match.Groups['quoted'].Value
    }
    return $match.Groups['unquoted'].Value
}

function New-ApacheHardeningBody {
    param(
        [string]$MainContent,
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    $directives = @()
    $listenPattern = "(?im)^\s*Listen\s+(?:\S+:)?$([regex]::Escape([string] $Port))\s*(?:#.*)?$"
    if (-not [regex]::IsMatch($MainContent, $listenPattern)) {
        $directives += "Listen $Port"
    }
    $directives += @(
        'ServerTokens Prod',
        'ServerSignature Off',
        'TraceEnable Off'
    )
    return $directives -join "`r`n"
}

function New-ApacheVirtualHostsBody {
    param(
        [string]$DefaultRoot,
        [string]$PublicRoot,
        [string]$ApplicationHostName,
        [ValidateRange(1, 65535)]
        [int]$Port,
        [switch]$AllowRemoteAccess
    )

    $apacheDefaultRoot = $DefaultRoot.Replace('\', '/')
    $apachePublicRoot = $PublicRoot.Replace('\', '/')
    $accessRule = if ($AllowRemoteAccess) { 'Require all granted' } else { 'Require local' }
    return @"
<VirtualHost *:$Port>
    ServerName localhost
    DocumentRoot "$apacheDefaultRoot"
</VirtualHost>

<VirtualHost *:$Port>
    ServerName $ApplicationHostName
    DocumentRoot "$apachePublicRoot"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "no-referrer"
    Header always set Content-Security-Policy "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'"
    Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
    Header always set Cross-Origin-Embedder-Policy "require-corp"
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set Cross-Origin-Resource-Policy "same-origin"
    Header always unset X-Powered-By
    <Directory "$apachePublicRoot">
        Options -Indexes -MultiViews
        AcceptPathInfo Off
        AllowOverride All
        $accessRule
    </Directory>
    ErrorLog "logs/medishield-error.log"
    CustomLog "logs/medishield-access.log" combined
</VirtualHost>
"@
}

function Get-HttpErrorBody {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $body = [string] $ErrorRecord.ErrorDetails.Message
    $bodyInspected = -not [string]::IsNullOrEmpty($body)

    if (-not $bodyInspected) {
        $response = $ErrorRecord.Exception.Response
        if ($null -ne $response) {
            $contentProperty = $response.PSObject.Properties['Content']
            if ($null -ne $contentProperty -and $null -ne $contentProperty.Value) {
                $responseContent = $contentProperty.Value
                if ($null -ne $responseContent.PSObject.Methods['ReadAsStringAsync']) {
                    try {
                        $body = $responseContent.ReadAsStringAsync().GetAwaiter().GetResult()
                        $bodyInspected = $true
                    }
                    catch {
                        $body = ''
                        $bodyInspected = $false
                    }
                }
                else {
                    $body = [string] $responseContent
                    $bodyInspected = $true
                }
            }
            elseif ($null -ne $response.PSObject.Methods['GetResponseStream']) {
                $stream = $response.GetResponseStream()
                if ($null -ne $stream) {
                    $reader = [IO.StreamReader]::new($stream)
                    try {
                        $body = $reader.ReadToEnd()
                    }
                    finally {
                        $reader.Dispose()
                    }
                    $bodyInspected = $true
                }
            }
        }
    }

    return [pscustomobject]@{
        Body = $body
        Inspected = $bodyInspected
    }
}

function Get-HttpHeaderValues {
    param(
        $Headers,
        [string]$Name
    )

    if ($null -eq $Headers) {
        return @()
    }
    if ($null -ne $Headers.PSObject.Methods['GetValues']) {
        return @($Headers.GetValues($Name) | ForEach-Object { [string] $_ })
    }

    $value = $Headers[$Name]
    if ($null -eq $value) {
        return @()
    }
    return @($value | ForEach-Object { [string] $_ })
}

function Invoke-HttpProbe {
    param(
        [string]$Uri,
        [int[]]$ExpectedStatuses,
        [string[]]$ForbiddenContent = @(),
        [string[]]$RequiredContent = @(),
        [string]$Method = 'GET',
        [hashtable]$Headers = @{},
        [string]$ExpectedContentType,
        [switch]$RequireSecurityHeaders,
        [switch]$AllowCaching
    )

    try {
        $request = @{
            Uri = $Uri
            UseBasicParsing = $true
            MaximumRedirection = 0
            Method = $Method
            Headers = $Headers
        }
        $response = Invoke-WebRequest @request
        $status = [int] $response.StatusCode
        $body = [string] $response.Content
        $responseHeaders = $response.Headers
    }
    catch {
        if ($null -eq $_.Exception.Response) {
            throw "HTTP probe could not reach $Uri`: $($_.Exception.Message)"
        }

        $status = [int] $_.Exception.Response.StatusCode
        $errorBody = Get-HttpErrorBody -ErrorRecord $_
        if (-not $errorBody.Inspected) {
            throw "HTTP probe $Uri returned $status, but its response body could not be inspected."
        }
        $body = $errorBody.Body
        $responseHeaders = $_.Exception.Response.Headers
    }

    if ($status -notin $ExpectedStatuses) {
        throw "HTTP probe $Uri returned $status; expected $($ExpectedStatuses -join ' or ')."
    }
    foreach ($forbidden in $ForbiddenContent) {
        if ($body.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "HTTP probe $Uri exposed forbidden diagnostic content: $forbidden"
        }
    }
    foreach ($required in $RequiredContent) {
        if ($body.IndexOf($required, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "HTTP probe $Uri did not contain required content: $required"
        }
    }

    if ($ExpectedContentType) {
        $contentTypes = @(Get-HttpHeaderValues -Headers $responseHeaders -Name 'Content-Type')
        if ($contentTypes.Count -ne 1 -or $contentTypes[0] -ine $ExpectedContentType) {
            throw "HTTP probe $Uri returned Content-Type '$($contentTypes -join ', ')'; expected exactly '$ExpectedContentType'."
        }
    }

    if ($RequireSecurityHeaders) {
        $expectedHeaders = [ordered]@{
            'X-Frame-Options' = 'DENY'
            'X-Content-Type-Options' = 'nosniff'
            'Referrer-Policy' = 'no-referrer'
            'Content-Security-Policy' = "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'"
            'Permissions-Policy' = 'geolocation=(), camera=(), microphone=()'
            'Cross-Origin-Embedder-Policy' = 'require-corp'
            'Cross-Origin-Opener-Policy' = 'same-origin'
            'Cross-Origin-Resource-Policy' = 'same-origin'
        }
        foreach ($headerName in $expectedHeaders.Keys) {
            $values = @(Get-HttpHeaderValues -Headers $responseHeaders -Name $headerName)
            if ($values.Count -ne 1 -or $values[0] -cne $expectedHeaders[$headerName]) {
                throw "HTTP probe $Uri returned non-unique or unexpected $headerName`: $($values -join ', ')"
            }
        }
    }

    if ($AllowCaching) {
        $cacheValues = @(Get-HttpHeaderValues -Headers $responseHeaders -Name 'Cache-Control')
        if (($cacheValues -join ',').IndexOf('no-store', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "HTTP probe $Uri unexpectedly disabled static caching."
        }
    }

    Write-Host "  PASS $status $Method $Uri" -ForegroundColor Green
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$root = Resolve-XamppRoot -ExplicitRoot $XamppRoot
if (-not (Test-Administrator)) {
    throw 'Administrator privileges are required to update Apache configuration and the Windows hosts file.'
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$publicRoot = Join-Path $repositoryRoot 'public'
$httpd = Join-Path $root 'apache\bin\httpd.exe'
$httpdConf = Join-Path $root 'apache\conf\httpd.conf'
$vhostsConf = Join-Path $root 'apache\conf\extra\httpd-vhosts.conf'
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$phpConfigurator = Join-Path $PSScriptRoot 'configure-php-ini.ps1'
$xamppPhp = Join-Path $root 'php\php.exe'

foreach ($requiredPath in @($publicRoot, $httpdConf, $vhostsConf, $hostsFile, $phpConfigurator)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required path was not found: $requiredPath"
    }
}

Write-Host "Configuring XAMPP at: $root" -ForegroundColor Cyan
Write-Host "MediShield public root: $publicRoot"

& $phpConfigurator -PhpExe $xamppPhp
if ($LASTEXITCODE -ne 0) {
    throw 'XAMPP PHP configuration failed.'
}

$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$backups = [ordered]@{}
foreach ($path in @($httpdConf, $vhostsConf, $hostsFile)) {
    $backup = "$path.medishield.$stamp.bak"
    Copy-Item -LiteralPath $path -Destination $backup -Force
    $backups[$path] = $backup
}

$configurationWritten = $false
$apacheWasRunning = Test-ApacheRunning -Root $root
try {
    $main = Get-Content -LiteralPath $httpdConf -Raw
    $main = Remove-ManagedBlock -Content $main -Name 'HARDENING'
    $apacheDefaultRoot = Get-ApacheDocumentRoot -Content $main
    $rewriteDirective = 'LoadModule rewrite_module modules/mod_rewrite.so'
    if ($main -match '(?m)^\s*#?\s*LoadModule\s+rewrite_module\s+modules/mod_rewrite\.so\s*$') {
        $main = [regex]::Replace(
            $main,
            '(?m)^\s*#?\s*LoadModule\s+rewrite_module\s+modules/mod_rewrite\.so\s*$',
            $rewriteDirective,
            1
        )
    }
    else {
        $main = $main.TrimEnd() + "`r`n$rewriteDirective`r`n"
    }
    $headersDirective = 'LoadModule headers_module modules/mod_headers.so'
    if ($main -match '(?m)^\s*#?\s*LoadModule\s+headers_module\s+modules/mod_headers\.so\s*$') {
        $main = [regex]::Replace(
            $main,
            '(?m)^\s*#?\s*LoadModule\s+headers_module\s+modules/mod_headers\.so\s*$',
            $headersDirective,
            1
        )
    }
    else {
        $main = $main.TrimEnd() + "`r`n$headersDirective`r`n"
    }

    $vhostInclude = 'Include conf/extra/httpd-vhosts.conf'
    if ($main -match '(?m)^\s*#?\s*Include\s+conf/extra/httpd-vhosts\.conf\s*$') {
        $main = [regex]::Replace(
            $main,
            '(?m)^\s*#?\s*Include\s+conf/extra/httpd-vhosts\.conf\s*$',
            $vhostInclude,
            1
        )
    }
    else {
        $main = $main.TrimEnd() + "`r`n$vhostInclude`r`n"
    }

    $main = Set-ManagedBlock `
        -Content $main `
        -Name 'HARDENING' `
        -Body (New-ApacheHardeningBody -MainContent $main -Port $Port)
    Set-Content -LiteralPath $httpdConf -Value $main -Encoding ascii

    $virtualHosts = New-ApacheVirtualHostsBody `
        -DefaultRoot $apacheDefaultRoot `
        -PublicRoot $publicRoot `
        -ApplicationHostName $HostName `
        -Port $Port `
        -AllowRemoteAccess:$AllowRemoteAccess
    $vhosts = Get-Content -LiteralPath $vhostsConf -Raw
    $vhosts = Set-ManagedBlock -Content $vhosts -Name 'VIRTUAL HOST' -Body $virtualHosts
    Set-Content -LiteralPath $vhostsConf -Value $vhosts -Encoding ascii

    $hosts = Get-Content -LiteralPath $hostsFile -Raw
    $hostPattern = "(?im)^\s*(?!#)(\S+)\s+.*\b$([regex]::Escape($HostName))\b.*$"
    $existingHost = [regex]::Match($hosts, $hostPattern)
    if ($existingHost.Success -and $existingHost.Groups[1].Value -notin @('127.0.0.1', '::1')) {
        throw "$HostName is already mapped to $($existingHost.Groups[1].Value) in the Windows hosts file."
    }
    $managedHost = "127.0.0.1 $HostName # MediShield managed"
    if ($existingHost.Success) {
        $hosts = [regex]::Replace($hosts, $hostPattern, $managedHost, 1)
    }
    else {
        $hosts = $hosts.TrimEnd() + "`r`n$managedHost`r`n"
    }
    Set-Content -LiteralPath $hostsFile -Value $hosts -Encoding ascii
    $configurationWritten = $true

    $syntaxResult = Invoke-NativeCommand -FilePath $httpd -ArgumentList @('-t')
    if ($syntaxResult.ExitCode -ne 0) {
        throw "Apache syntax validation failed: $($syntaxResult.Output)"
    }
    Write-Host "Apache syntax validation passed: $($syntaxResult.Output)" -ForegroundColor Green

    $moduleResult = Invoke-NativeCommand -FilePath $httpd -ArgumentList @('-M')
    if ($moduleResult.ExitCode -ne 0) {
        throw "Apache module inspection failed: $($moduleResult.Output)"
    }
    foreach ($requiredModule in @('headers_module', 'rewrite_module')) {
        if ($moduleResult.Output -notmatch "(?m)^\s*$([regex]::Escape($requiredModule))\s+\(") {
            throw "Apache required module is not loaded: $requiredModule"
        }
    }
    Write-Host 'Apache required modules are loaded: headers_module, rewrite_module' -ForegroundColor Green
}
catch {
    if ($configurationWritten -or $backups.Count -gt 0) {
        foreach ($path in $backups.Keys) {
            Copy-Item -LiteralPath $backups[$path] -Destination $path -Force
        }
        Write-Warning 'Apache and hosts configuration restored from backups.'
    }
    throw
}

try {
    if (-not $SkipRestart) {
        $restartResult = Invoke-NativeCommand -FilePath $httpd -ArgumentList @('-k', 'restart')
        if ($restartResult.ExitCode -ne 0) {
            $startScript = Join-Path $root 'apache_start.bat'
            if (-not (Test-Path -LiteralPath $startScript)) {
                throw 'Apache was not running and apache_start.bat was not found.'
            }
            Start-Process -FilePath $startScript -WorkingDirectory $root -WindowStyle Hidden
        }

        $baseUri = if ($Port -eq 80) { "http://$HostName" } else { "http://$HostName`:$Port" }
        $ready = $false
        for ($attempt = 1; $attempt -le 30; $attempt++) {
            try {
                $response = Invoke-WebRequest -Uri "$baseUri/login.php" -UseBasicParsing -TimeoutSec 2
                if ([int] $response.StatusCode -eq 200) {
                    $ready = $true
                    break
                }
            }
            catch {
                Start-Sleep -Seconds 1
            }
        }
        if (-not $ready) {
            throw "Apache did not serve $baseUri/login.php within 30 seconds."
        }
    }

    if (-not $SkipHttpProbe) {
        if ($SkipRestart) {
            throw '-SkipHttpProbe must also be supplied when -SkipRestart is used.'
        }

        $baseUri = if ($Port -eq 80) { "http://$HostName" } else { "http://$HostName`:$Port" }
        $forbidden = @(
            'Stack trace',
            'SQLSTATE',
            'C:\xampp',
            $repositoryRoot,
            $repositoryRoot.Replace('\', '/'),
            'medishield_db'
        )
        Invoke-HttpProbe `
            -Uri "$baseUri/login.php" `
            -ExpectedStatuses @(200) `
            -RequiredContent @('Sign in') `
            -RequireSecurityHeaders
        Invoke-HttpProbe `
            -Uri "$baseUri/assets/css/style.css" `
            -ExpectedStatuses @(200) `
            -ExpectedContentType 'text/css; charset=utf-8' `
            -RequiredContent @('body {', 'margin: 0;') `
            -RequireSecurityHeaders `
            -AllowCaching
        foreach ($path in @(
            '/README.md',
            '/.htaccess',
            '/router.php',
            '/assets/README.md',
            '/assets/css/style.css.map',
            '/login.php.bak',
            '/manifest.json',
            '/partials/bill_charges.php',
            '/Partials/bill_charges.php',
            '/scripts/seed-ui-test-users.php',
            '/logs/app_errors.log',
            '/sql/schema.sql',
            '/src/Auth/AuthService.php',
            '/tests/README.md',
            '/config/config.php',
            '/composer.lock',
            '/.git/config'
        )) {
            Invoke-HttpProbe `
                -Uri "$baseUri$path" `
                -ExpectedStatuses @(403, 404) `
                -ForbiddenContent $forbidden `
                -RequireSecurityHeaders
        }
        Invoke-HttpProbe `
            -Uri "$baseUri/assets/css/" `
            -ExpectedStatuses @(403, 404) `
            -ForbiddenContent ($forbidden + @('Index of', 'style.css')) `
            -RequireSecurityHeaders
        Invoke-HttpProbe `
            -Uri "$baseUri/runtime-probe-missing" `
            -ExpectedStatuses @(404) `
            -ForbiddenContent $forbidden `
            -RequireSecurityHeaders
        Invoke-HttpProbe `
            -Uri "$baseUri/login.php" `
            -Method 'TRACE' `
            -ExpectedStatuses @(405) `
            -ForbiddenContent $forbidden `
            -RequireSecurityHeaders

        $loopbackBaseUri = if ($Port -eq 80) {
            'http://127.0.0.1'
        }
        else {
            "http://127.0.0.1`:$Port"
        }
        Invoke-HttpProbe `
            -Uri "$loopbackBaseUri/login.php" `
            -Headers @{ Host = 'unexpected.invalid' } `
            -ExpectedStatuses @(403, 404) `
            -ForbiddenContent ($forbidden + @('MediShield'))
    }
}
catch {
    $failure = $_
    foreach ($path in $backups.Keys) {
        Copy-Item -LiteralPath $backups[$path] -Destination $path -Force
    }

    $rollbackSyntaxResult = Invoke-NativeCommand -FilePath $httpd -ArgumentList @('-t')
    if ($rollbackSyntaxResult.ExitCode -ne 0) {
        throw "MediShield verification failed and restored Apache configuration is invalid: $($rollbackSyntaxResult.Output). Original failure: $($failure.Exception.Message)"
    }

    if ($apacheWasRunning) {
        $rollbackRestartResult = Invoke-NativeCommand -FilePath $httpd -ArgumentList @('-k', 'restart')
        if ($rollbackRestartResult.ExitCode -ne 0) {
            throw "MediShield verification failed and Apache could not restart with restored configuration. Original failure: $($failure.Exception.Message)"
        }
    }
    elseif (Test-ApacheRunning -Root $root) {
        $rollbackShutdownResult = Invoke-NativeCommand -FilePath $httpd -ArgumentList @('-k', 'shutdown')
        if ($rollbackShutdownResult.ExitCode -ne 0) {
            throw "MediShield verification failed and the Apache instance started by this script could not be stopped. Original failure: $($failure.Exception.Message)"
        }
    }

    Write-Warning 'Runtime verification failed; Apache, hosts, and process state were restored.'
    throw $failure
}

Write-Host 'XAMPP Apache hardening and verification completed.' -ForegroundColor Green
