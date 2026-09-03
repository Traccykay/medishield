<#
.SYNOPSIS
Reconciles and audits the exact Composer and npm lock files.

.DESCRIPTION
Runs Composer's strict manifest validation, locked advisory audit, and PHP 8.1
compatibility proof. It then performs a script-free npm clean install from the
official TLS registry before checking advisories and registry signatures.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$npmRegistry = 'https://registry.npmjs.org/'

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

try {
    if ($env:NODE_TLS_REJECT_UNAUTHORIZED -eq '0') {
        throw 'NODE_TLS_REJECT_UNAUTHORIZED=0 is not allowed for dependency audits.'
    }

    foreach ($command in @('composer', 'npm.cmd')) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Required command '$command' was not found on PATH."
        }
    }

    Push-Location $root
    try {
        Invoke-CheckedCommand -Description 'composer validate --strict' -Command {
            & composer validate --strict
        }
        Invoke-CheckedCommand -Description 'composer audit --locked' -Command {
            & composer audit --locked
        }
        Invoke-CheckedCommand -Description 'composer prohibits php 8.1 --tree' -Command {
            & composer prohibits php 8.1 --tree
        }
        Invoke-CheckedCommand -Description 'npm clean lock reconciliation' -Command {
            & npm.cmd ci --ignore-scripts --registry=$npmRegistry --strict-ssl=true
        }
        Invoke-CheckedCommand -Description 'npm locked advisory audit' -Command {
            & npm.cmd audit --package-lock-only --ignore-scripts `
                --registry=$npmRegistry --strict-ssl=true
        }
        Invoke-CheckedCommand -Description 'npm registry signature audit' -Command {
            & npm.cmd audit signatures --registry=$npmRegistry --strict-ssl=true
        }
    } finally {
        Pop-Location
    }

    Write-Host 'Locked Composer and npm dependency audits passed.' -ForegroundColor Green
} catch {
    Write-Error "Dependency audit failed: $($_.Exception.Message)"
    exit 1
}
