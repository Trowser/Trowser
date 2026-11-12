# Generates trowserkit/trowser-api-index.md from source code.
# Run from repo root: .\scripts\generate-api-index.ps1
# Check only (CI): .\scripts\generate-api-index.ps1 -Check
#
# Implementation lives in generate-api-index.core.ps1 (PowerShell 7+ syntax).

param(
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$core = Join-Path $PSScriptRoot 'generate-api-index.core.ps1'
if (-not (Test-Path $core)) {
    Write-Error "Missing $core"
}

$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $pwsh) {
    Write-Error 'API index generation requires PowerShell 7 (pwsh). Install from https://aka.ms/powershell'
}

$argList = @('-NoProfile', '-File', $core)
if ($Check) { $argList += '-Check' }
& $pwsh.Source @argList
exit $LASTEXITCODE
