<#
.SYNOPSIS
Validates a reviewed Docker Desktop installation and waits for its engine.

.DESCRIPTION
Automatic Docker installation is intentionally unavailable because this
repository does not pin a reviewed immutable Docker Desktop installer. The
helper resolves only known application paths, validates the Authenticode
publisher where Windows exposes one, starts the installed application, and
waits for a real Docker Engine response.
#>
[CmdletBinding()]
param(
    [ValidateRange(15, 180)]
    [int]$TimeoutSeconds = 90,

    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'

function Get-DockerDesktopExecutable {
    $candidates = @(
        'C:\Program Files\Docker\Docker\Docker Desktop.exe',
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Docker\Docker Desktop.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Get-DockerCli {
    $candidates = @(
        'C:\Program Files\Docker\Docker\resources\bin\docker.exe',
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'),
        (Join-Path $env:LOCALAPPDATA 'Docker\resources\bin\docker.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Assert-DockerPublisher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DesktopPath
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $DesktopPath
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Docker Desktop Authenticode validation failed: $($signature.Status)."
    }
    if ($signature.SignerCertificate.Subject -notmatch 'Docker Inc') {
        throw "Docker Desktop at '$DesktopPath' is not signed by Docker Inc."
    }
}

function Test-DockerEngine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DockerCli
    )

    & $DockerCli version --format '{{.Server.Version}}' 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

function Invoke-DockerDesktopReadiness {
    $desktop = Get-DockerDesktopExecutable
    if ($null -eq $desktop) {
        $suffix = if ($SkipInstall) {
            'Installation was explicitly skipped.'
        } else {
            'Automatic installation is refused because no reviewed exact installer version and digest are pinned.'
        }
        throw "Docker Desktop must be preinstalled from https://docs.docker.com/desktop/setup/install/windows-install/. $suffix Verify the Docker Inc. publisher, then rerun."
    }

    Assert-DockerPublisher -DesktopPath $desktop
    $docker = Get-DockerCli
    if ($null -eq $docker) {
        throw "Docker Desktop was found at '$desktop', but docker.exe was absent from approved application paths."
    }

    if (Test-DockerEngine -DockerCli $docker) {
        Write-Host "Docker Desktop $((Get-Item -LiteralPath $desktop).VersionInfo.ProductVersion) engine is ready."
        return
    }

    Start-Process -FilePath $desktop | Out-Null
    Write-Host 'Starting the validated Docker Desktop application...'

    for ($attempt = 1; $attempt -le $TimeoutSeconds; $attempt++) {
        Start-Sleep -Seconds 1
        if (Test-DockerEngine -DockerCli $docker) {
            Write-Host "Docker Desktop engine is ready after $attempt second(s)."
            return
        }
    }

    throw "Docker Desktop did not become ready within $TimeoutSeconds seconds."
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-DockerDesktopReadiness
        exit 0
    } catch {
        Write-Error "Docker Desktop readiness failed: $($_.Exception.Message)"
        exit 1
    }
}
