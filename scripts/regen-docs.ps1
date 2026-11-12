# Regenerate everything derived from the API source after adding or renaming a REST route or MCP tool.
#   .\scripts\regen-docs.ps1          rewrite trowser-api-index.md and swagger/openapi.yaml
#   .\scripts\regen-docs.ps1 -Check   fail if either is out of date (no writes)
# Needs PowerShell 7 (pwsh) for the index and Python 3 (standard library only) for OpenAPI.
param(
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$unit = Join-Path $root 'src\Trowser.Tests\Trowser.Tests.csproj'

if ($Check) {
    Write-Host '--- API index ---' -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'generate-api-index.ps1') -Check
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host '--- OpenAPI vs index ---' -ForegroundColor Cyan
    dotnet test $unit -c Release --filter "FullyQualifiedName~OpenApiSpecTests" --logger "console;verbosity=minimal"
    exit $LASTEXITCODE
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error 'OpenAPI sync requires Python 3 on PATH (https://www.python.org/downloads/).'
}

Write-Host '--- API index ---' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'generate-api-index.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '--- OpenAPI ---' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'update-openapi-from-index.ps1')
exit $LASTEXITCODE
