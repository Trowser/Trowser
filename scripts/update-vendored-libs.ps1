<#
.SYNOPSIS
  Check (default) or update (-Update) vendored third-party JS libraries.

.DESCRIPTION
  Reads scripts/vendored-libs.json, queries npm for latest versions, and reports
  whether Trowser is behind. With -Update, downloads CDN artifacts / rebuilds
  esbuild bundles, refreshes license stubs, and bumps pinnedVersion.

  Intentionally NOT wired into MSBuild — axe/html-validate bumps can change
  finding oracles; run tests/regression/run-regression.ps1 after -Update.

  retire.js / jsrepository.json is excluded (refreshed on Trowser build via scripts/update-jsrepository.ps1).

.PARAMETER Update
  Fetch/rebuild libraries that are behind (or all with -Force) and bump the manifest.

.PARAMETER Force
  With -Update, refresh every library even if already at latest.

.PARAMETER Library
  Limit to one library id (e.g. axe-core, web-vitals).
#>
[CmdletBinding()]
param(
    [switch]$Update,
    [switch]$Force,
    [string]$Library
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $PSScriptRoot "vendored-libs.json"
$resourcesDir = Join-Path $repoRoot "src\Trowser\Resources"
$licensesDir = Join-Path $repoRoot "licenses"
$workDir = Join-Path $env:TEMP "trowser-vendored-libs-$(Get-Random)"

function Get-NpmLatestVersion([string]$Package) {
    $url = "https://registry.npmjs.org/$Package/latest"
    $json = Invoke-RestMethod -Uri $url -TimeoutSec 30
    return [string]$json.version
}

function Get-AxeHeaderVersion([string]$Path) {
    if (-not (Test-Path $Path)) { return $null }
    $head = Get-Content -Path $Path -TotalCount 3 -ErrorAction SilentlyContinue
    foreach ($line in $head) {
        if ($line -match 'axe v(\d+\.\d+\.\d+)') { return $Matches[1] }
    }
    return $null
}

function Compare-SemVer([string]$A, [string]$B) {
    # Returns -1 if A < B, 0 if equal, 1 if A > B. Non-semver falls back to string compare.
    try {
        $va = [version]($A -replace '[^0-9.].*$','')
        $vb = [version]($B -replace '[^0-9.].*$','')
        return $va.CompareTo($vb)
    } catch {
        return [string]::CompareOrdinal($A, $B)
    }
}

function Download-File([string]$Url, [string]$OutPath) {
    Write-Host "  Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing -TimeoutSec 120
}

function Build-EsbuildBundle([string]$Package, [string]$Version, [string]$GlobalName, [string]$OutFile) {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        throw "npm is required to rebuild $Package. Install Node.js or update manually."
    }
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    Push-Location $workDir
    try {
        if (-not (Test-Path "package.json")) {
            '{"name":"trowser-vendor-build","private":true}' | Set-Content -Path "package.json" -Encoding utf8
        }
        npm install --silent "$Package@$Version" esbuild | Out-Null
        $entry = Join-Path $workDir "node_modules\$Package"
        # Prefer package main / browser field via require.resolve through a tiny entry
        $entryJs = Join-Path $workDir "entry-$Package.js"
        @"
module.exports = require('$Package');
"@ | Set-Content -Path $entryJs -Encoding utf8
        $outPath = Join-Path $resourcesDir $OutFile
        npx --yes esbuild $entryJs --bundle --minify --format=iife --global-name=$GlobalName --outfile=$outPath
        Write-Host "  Built $OutFile via esbuild ($Package@$Version)"
    } finally {
        Pop-Location
    }
}

function Ensure-LicenseStub([string]$LicenseFile, [string]$Package, [string]$Version, [string]$Spdx) {
    $path = Join-Path $repoRoot $LicenseFile
    if (Test-Path $path) { return }
    $text = @"
$Package $Version
License: $Spdx

Full license text should be copied from the upstream package when available.
See https://www.npmjs.com/package/$Package
"@
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    Set-Content -Path $path -Value $text -Encoding utf8
    Write-Host "  Wrote license stub: $LicenseFile"
}

$manifest = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json
$libs = @($manifest.libraries)
if ($Library) {
    $libs = @($libs | Where-Object { $_.id -eq $Library })
    if ($libs.Count -eq 0) { throw "Unknown library id: $Library" }
}

Write-Host ""
Write-Host "Trowser vendored libraries"
Write-Host ("=" * 72)
$behind = @()

foreach ($lib in $libs) {
    $latest = Get-NpmLatestVersion $lib.npmPackage
    $pinned = [string]$lib.pinnedVersion
    $resourceFull = Join-Path $repoRoot ($lib.resourcePath -replace '/', '\')
    $installed = $pinned
    if ($lib.detectVersionFrom -eq "header") {
        $hdr = Get-AxeHeaderVersion $resourceFull
        if ($hdr) { $installed = $hdr }
    }
    $exists = Test-Path $resourceFull
    $cmp = Compare-SemVer $installed $latest
    $status = if (-not $exists) { "MISSING" }
              elseif ($cmp -lt 0) { "BEHIND" }
              elseif ($cmp -gt 0) { "AHEAD" }
              else { "CURRENT" }

    Write-Host ("{0,-16} pinned={1,-10} installed={2,-10} latest={3,-10} [{4}]" -f `
        $lib.id, $pinned, $installed, $latest, $status)

    if ($status -in @("BEHIND", "MISSING") -or ($Force -and $Update)) {
        $behind += [pscustomobject]@{ Lib = $lib; Latest = $latest; Status = $status }
    }
}

if (-not $Update) {
    Write-Host ""
    if ($behind.Count -eq 0) {
        Write-Host "All libraries are current."
    } else {
        Write-Host "$($behind.Count) library(ies) need attention. Re-run with -Update to refresh."
    }
    Write-Host "After updating, run: .\tests\regression\run-regression.ps1"
    exit 0
}

Write-Host ""
Write-Host "Updating..."
New-Item -ItemType Directory -Path $resourcesDir -Force | Out-Null

foreach ($item in $behind) {
    $lib = $item.Lib
    $ver = $item.Latest
    Write-Host ("-> {0} -> {1}" -f $lib.id, $ver)

    $recipe = $lib.fetchOrBuild
    $outPath = Join-Path $repoRoot ($lib.resourcePath -replace '/', '\')
    $outDir = Split-Path $outPath -Parent
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

    switch ($recipe.type) {
        "cdn" {
            $url = ($recipe.url -replace '\{version\}', $ver)
            Download-File $url $outPath
        }
        "esbuild" {
            Build-EsbuildBundle $lib.npmPackage $ver $recipe.globalName $recipe.outfile
        }
        default { throw "Unknown fetchOrBuild.type: $($recipe.type)" }
    }

    $spdx = switch -Wildcard ($lib.licenseFile) {
        "*MPL*" { "MPL-2.0" }
        "*Apache*" { "Apache-2.0" }
        "*MIT*" { "MIT" }
        default { "SEE LICENSE" }
    }
    Ensure-LicenseStub $lib.licenseFile $lib.npmPackage $ver $spdx

    # Bump pinned version in memory
    $lib.pinnedVersion = $ver
}

# Write manifest back
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $manifestPath -Encoding utf8

if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "Update complete. Review diffs, then run:"
Write-Host "  .\tests\regression\run-regression.ps1"
Write-Host "Do NOT commit without verifying accessibility / HTML validation / performance oracles."
