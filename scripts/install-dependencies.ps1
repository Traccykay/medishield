<#
.SYNOPSIS
Installs workstation machine packages or project dependencies at separate privilege levels.

.DESCRIPTION
An elevated invocation may install only the exact reviewed XAMPP 8.1 package
from the approved Chocolatey community source. A standard-user invocation may
configure PHP and install the locked Composer project dependencies. Composer
plugins and scripts are disabled, every attempt is time-bounded, and no global
Composer or user environment configuration is changed.

Chocolatey is deliberately not bootstrapped. If it is absent, install it
manually using the instructions at https://chocolatey.org/install, inspect the
publisher and command, then rerun the machine-package phase.

.EXAMPLE
.\scripts\install-dependencies.ps1 -MachinePackages

.EXAMPLE
.\scripts\install-dependencies.ps1 -ProjectDependencies
#>
[CmdletBinding()]
param(
    [switch]$MachinePackages,

    [switch]$ProjectDependencies,

    [ValidateRange(60, 1800)]
    [int]$ComposerTimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
$script:ApprovedChocolateySource = 'https://community.chocolatey.org/api/v2/'
$script:XamppPackageVersion = '8.1.6'
$script:ChocolateyPath = 'C:\ProgramData\chocolatey\bin\choco.exe'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Resolve-InstallPhase {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$IsAdministrator,

        [Parameter(Mandatory = $true)]
        [bool]$MachinePackages,

        [Parameter(Mandatory = $true)]
        [bool]$ProjectDependencies
    )

    if ($MachinePackages -and $ProjectDependencies) {
        throw 'MachinePackages and ProjectDependencies cannot run in the same process.'
    }
    if ($IsAdministrator -and $ProjectDependencies) {
        throw 'Project dependency installation refuses Administrator privileges. Open a standard PowerShell window.'
    }
    if (-not $IsAdministrator -and $MachinePackages) {
        throw 'Machine package installation requires an elevated PowerShell window.'
    }

    if ($MachinePackages -or $IsAdministrator) {
        return 'MachinePackages'
    }

    return 'ProjectDependencies'
}

function Assert-ApprovedPackageSource {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Source, [UriKind]::Absolute, [ref]$uri)) {
        throw "Package source '$Source' is not an absolute URI."
    }
    if ($uri.Scheme -ne 'https' -or $Source -cne $script:ApprovedChocolateySource) {
        throw "Package source '$Source' is not the approved HTTPS Chocolatey source."
    }
}

function Get-XamppInstallation {
    $roots = @(
        'C:\xampp',
        'C:\tools\xampp'
    )

    foreach ($root in $roots) {
        $php = Join-Path $root 'php\php.exe'
        $mysql = Join-Path $root 'mysql\bin\mysql.exe'
        if ((Test-Path -LiteralPath $php) -and (Test-Path -LiteralPath $mysql)) {
            return [pscustomobject]@{
                Root = $root
                Php = $php
                MySql = $mysql
            }
        }
    }

    return $null
}

function Assert-XamppPhpVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PhpPath
    )

    $version = & $PhpPath -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;'
    if ($LASTEXITCODE -ne 0 -or ([string]$version).Trim() -ne '8.1') {
        throw "XAMPP PHP at '$PhpPath' is not the required PHP 8.1 runtime."
    }

    Write-Host "Validated XAMPP PHP $(& $PhpPath -r 'echo PHP_VERSION;')."
}

function Assert-KnownPublisherWhenSigned {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$SubjectPattern
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -eq [System.Management.Automation.SignatureStatus]::NotSigned) {
        Write-Warning "'$Path' is unsigned; provenance relies on the approved package source and its checksum."
        return
    }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode validation failed for '$Path': $($signature.Status)."
    }
    if ($signature.SignerCertificate.Subject -notmatch $SubjectPattern) {
        throw "The signer for '$Path' is not an approved publisher."
    }
}

function Install-MachinePackages {
    Assert-ApprovedPackageSource -Source $script:ApprovedChocolateySource

    if (-not (Test-Path -LiteralPath $script:ChocolateyPath)) {
        throw 'Chocolatey is missing. Automatic remote bootstrap is prohibited. Follow https://chocolatey.org/install in a separate reviewed Administrator session, then rerun this command.'
    }
    Assert-KnownPublisherWhenSigned `
        -Path $script:ChocolateyPath `
        -SubjectPattern 'Chocolatey Software'

    $xampp = Get-XamppInstallation
    if ($null -eq $xampp) {
        Write-Host "Installing exact XAMPP package xampp-81 $script:XamppPackageVersion..."
        & $script:ChocolateyPath install xampp-81 `
            --version $script:XamppPackageVersion `
            --source $script:ApprovedChocolateySource `
            --yes `
            --no-progress `
            --limit-output
        if ($LASTEXITCODE -ne 0) {
            throw "Chocolatey failed to install xampp-81 $script:XamppPackageVersion (exit code $LASTEXITCODE)."
        }
        $xampp = Get-XamppInstallation
    }

    if ($null -eq $xampp) {
        throw 'XAMPP installation completed, but approved application paths contain no complete installation.'
    }

    Assert-XamppPhpVersion -PhpPath $xampp.Php
    Assert-KnownPublisherWhenSigned -Path $xampp.Php -SubjectPattern 'Apache Friends|BitRock'
    & $xampp.MySql --version
    if ($LASTEXITCODE -ne 0) {
        throw "MySQL version validation failed for '$($xampp.MySql)'."
    }

    Write-Host 'Machine package phase complete.' -ForegroundColor Green
    Write-Host 'Open a standard PowerShell window and run:'
    Write-Host '  .\scripts\install-dependencies.ps1 -ProjectDependencies'
}

function Resolve-ProjectPhp {
    foreach ($candidate in @(
        'C:\xampp\php\php.exe',
        'C:\tools\xampp\php\php.exe',
        'C:\tools\php85\php.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command php.exe -ErrorAction SilentlyContinue
    if ($null -ne $command -and (Test-Path -LiteralPath $command.Source)) {
        return $command.Source
    }

    throw 'php.exe was not found. Complete the reviewed machine prerequisite installation first.'
}

function Resolve-ComposerPhar {
    $candidates = @(
        'C:\ProgramData\ComposerSetup\bin\composer.phar',
        (Join-Path $env:USERPROFILE 'scoop\apps\composer\current\composer.phar'),
        (Join-Path $env:APPDATA 'Composer\composer.phar')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw 'composer.phar was not found at an application path. Install Composer manually from https://getcomposer.org/download/ as a standard user, verify its installer checksum, then rerun.'
}

function ConvertTo-ProcessArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-BoundedApplication {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $argumentLine = ($ArgumentList | ForEach-Object {
        ConvertTo-ProcessArgument -Value $_
    }) -join ' '
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $argumentLine
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Process '$FilePath' could not be started."
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) {
            Stop-Process -Id $process.Id -Force
        }

        $process.WaitForExit()
        $process.Refresh()
        [Console]::Out.Write($stdout.GetAwaiter().GetResult())
        [Console]::Error.Write($stderr.GetAwaiter().GetResult())
        if ($timedOut) {
            throw "Process '$FilePath' exceeded the $TimeoutSeconds second timeout."
        }

        return [int]$process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Invoke-ProjectDependencies {
    param(
        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $root = Split-Path -Parent $PSScriptRoot
    $php = Resolve-ProjectPhp
    $composerPhar = Resolve-ComposerPhar
    $powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $configureScript = Join-Path $PSScriptRoot 'configure-php-ini.ps1'

    $configureExit = Invoke-BoundedApplication `
        -FilePath $powerShell `
        -ArgumentList @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $configureScript,
            '-PhpExe',
            $php
        ) `
        -WorkingDirectory $root `
        -TimeoutSeconds 180
    if ($configureExit -ne 0) {
        throw "PHP configuration failed with exit code $configureExit."
    }

    $versionExit = Invoke-BoundedApplication `
        -FilePath $php `
        -ArgumentList @($composerPhar, '--version', '--no-ansi') `
        -WorkingDirectory $root `
        -TimeoutSeconds 30
    if ($versionExit -ne 0) {
        throw "Composer version validation failed with exit code $versionExit."
    }

    $installArguments = @(
        $composerPhar,
        'install',
        '--no-interaction',
        '--no-progress',
        '--prefer-dist',
        '--no-plugins',
        '--no-scripts'
    )
    $installExit = Invoke-BoundedApplication `
        -FilePath $php `
        -ArgumentList $installArguments `
        -WorkingDirectory $root `
        -TimeoutSeconds $TimeoutSeconds
    if ($installExit -ne 0) {
        Write-Warning "The first locked Composer install failed with exit code $installExit. Retrying once after a bounded delay."
        Start-Sleep -Seconds 5
        $installExit = Invoke-BoundedApplication `
            -FilePath $php `
            -ArgumentList $installArguments `
            -WorkingDirectory $root `
            -TimeoutSeconds $TimeoutSeconds
    }
    if ($installExit -ne 0) {
        throw "Locked Composer installation failed twice; final exit code $installExit."
    }

    Write-Host 'Project dependency phase complete without Composer plugins or scripts.' -ForegroundColor Green
}

function Invoke-MediShieldDependencyInstall {
    $isAdministrator = Test-Administrator
    $phase = Resolve-InstallPhase `
        -IsAdministrator $isAdministrator `
        -MachinePackages $MachinePackages.IsPresent `
        -ProjectDependencies $ProjectDependencies.IsPresent

    if ($phase -eq 'MachinePackages') {
        Install-MachinePackages
        return
    }

    Invoke-ProjectDependencies -TimeoutSeconds $ComposerTimeoutSeconds
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-MediShieldDependencyInstall
        exit 0
    } catch {
        Write-Error "Dependency installation failed: $($_.Exception.Message)"
        exit 1
    }
}
