# Lists REST routes and MCP tools not mentioned in regression scripts and/or ApiTests (grep heuristic).
param(
    [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path,
    [string]$OutPath = (Join-Path (Resolve-Path "$PSScriptRoot\..").Path "tests\api-coverage.md")
)

$ErrorActionPreference = 'Stop'
$index = Join-Path $RepoRoot 'trowserkit\trowser-api-index.md'
$regression = Join-Path $RepoRoot 'tests\regression'
$apiTests = Join-Path $RepoRoot 'src\Trowser.ApiTests'

$scriptBlob = (Get-ChildItem $regression -Recurse -Filter '*.csx' | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
$apiTestBlob = (Get-ChildItem $apiTests -Recurse -Filter '*.cs' | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
$combinedBlob = $scriptBlob + "`n" + $apiTestBlob

function Test-Referenced([string]$path, [string]$toolName) {
    $key = $path -replace '^/api/', '' -replace '/', '-'
    $inRegression = $scriptBlob -match [regex]::Escape($path) -or ($key -and $scriptBlob -match [regex]::Escape($key))
    $inApiTests = $apiTestBlob -match [regex]::Escape($path)
    if ($toolName) {
        $inRegression = $inRegression -or ($scriptBlob -match [regex]::Escape($toolName))
        $inApiTests = $inApiTests -or ($apiTestBlob -match [regex]::Escape($toolName))
    }
    return @{ Regression = $inRegression; ApiTests = $inApiTests }
}

$restRows = [regex]::Matches((Get-Content $index -Raw), '\| (GET|POST|PUT|DELETE|PATCH) \| `(/api/[^`]+)`')
$mcpRows = [regex]::Matches((Get-Content $index -Raw), '\| `(browser_\w+)` \|')

$apiTestsOnly = @()
$stillUntouched = @()

foreach ($m in $restRows) {
    $method = $m.Groups[1].Value
    $path = $m.Groups[2].Value
    $ref = Test-Referenced $path $null
    if (-not $ref.Regression -and -not $ref.ApiTests) {
        $stillUntouched += "| $method | ``$path`` |"
    } elseif (-not $ref.Regression -and $ref.ApiTests) {
        $apiTestsOnly += "| $method | ``$path`` |"
    }
}

$mcpApiTestsOnly = @()
$mcpStillUntouched = @()

foreach ($m in $mcpRows) {
    $tool = $m.Groups[1].Value
    $inReg = $scriptBlob -match [regex]::Escape($tool)
    $inApi = $apiTestBlob -match [regex]::Escape($tool)
    if (-not $inReg -and -not $inApi) {
        $mcpStillUntouched += "| ``$tool`` |"
    } elseif (-not $inReg -and $inApi) {
        $mcpApiTestsOnly += "| ``$tool`` |"
    }
}

$md = @"
# API coverage heuristic

Auto-generated $(Get-Date -Format o). String grep over ``tests/regression/**/*.csx`` and ``src/Trowser.ApiTests/**/*.cs`` against ``trowser-api-index.md``.

## REST — still untouched ($($stillUntouched.Count))

| Method | Path |
|--------|------|
$($stillUntouched -join "`n")

## REST — ApiTests only, not regression ($($apiTestsOnly.Count))

| Method | Path |
|--------|------|
$($apiTestsOnly -join "`n")

## MCP — still untouched ($($mcpStillUntouched.Count))

| Tool |
|------|
$($mcpStillUntouched -join "`n")

## MCP — ApiTests only, not regression ($($mcpApiTestsOnly.Count))

| Tool |
|------|
$($mcpApiTestsOnly -join "`n")
"@

Set-Content -LiteralPath $OutPath -Value $md -Encoding UTF8
Write-Host "Wrote $OutPath"
