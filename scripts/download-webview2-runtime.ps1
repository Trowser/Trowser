#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads the WebView2 Fixed Version Runtime for bundling with Trowser.
.DESCRIPTION
    Downloads the WebView2.Runtime.X64 NuGet package (a community-maintained
    repackaging of Microsoft's Fixed Version Runtime) and extracts the runtime
    files to webview2-runtime/ in the repo root. This folder is used by
    build-zip.ps1 to create the bundled ZIP.

    Run this script before building the bundled distribution. Only needs to be
    re-run when you want to update the WebView2 version.
#>

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outputDir = Join-Path $repoRoot "webview2-runtime"
$tempDir = Join-Path $repoRoot "dist\_wv2temp"

Write-Host "=== WebView2 Fixed Version Runtime Download ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Find the latest version of WebView2.Runtime.X64 on NuGet
Write-Host "[1/3] Querying NuGet for latest WebView2.Runtime.X64..." -ForegroundColor Yellow

$packageId = "WebView2.Runtime.X64"
$indexUrl = "https://api.nuget.org/v3-flatcontainer/$($packageId.ToLower())/index.json"

try {
    $versionIndex = Invoke-RestMethod -Uri $indexUrl -UseBasicParsing
} catch {
    Write-Error "Failed to query NuGet for $packageId. Check your internet connection."
    exit 1
}

$latestVersion = $versionIndex.versions | Select-Object -Last 1
Write-Host "      Latest version: $latestVersion" -ForegroundColor Green

# Step 2: Download the .nupkg
Write-Host "[2/3] Downloading $packageId $latestVersion..." -ForegroundColor Yellow

$nupkgUrl = "https://api.nuget.org/v3-flatcontainer/$($packageId.ToLower())/$latestVersion/$($packageId.ToLower()).$latestVersion.nupkg"

if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
New-Item $tempDir -ItemType Directory -Force | Out-Null

$nupkgPath = Join-Path $tempDir "$packageId.$latestVersion.zip"
try {
    Invoke-WebRequest -Uri $nupkgUrl -OutFile $nupkgPath -UseBasicParsing
} catch {
    Write-Error "Failed to download package from $nupkgUrl"
    exit 1
}

$sizeMB = [math]::Round((Get-Item $nupkgPath).Length / 1MB, 1)
Write-Host "      Downloaded: $sizeMB MB" -ForegroundColor Green

# Step 3: Extract the runtime files
Write-Host "[3/3] Extracting runtime..." -ForegroundColor Yellow

$extractDir = Join-Path $tempDir "extracted"
Expand-Archive -Path $nupkgPath -DestinationPath $extractDir -Force

# Find the folder containing msedgewebview2.exe (the actual runtime)
$runtimeDir = $null

# Check common locations in the package
$candidates = @(
    (Join-Path $extractDir "runtimes\win-x64\native"),
    (Join-Path $extractDir "WebView2"),
    (Join-Path $extractDir "content"),
    (Join-Path $extractDir "tools")
)

foreach ($candidate in $candidates) {
    if (Test-Path $candidate) {
        $hasRuntime = Get-ChildItem $candidate -Filter "msedgewebview2.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hasRuntime) {
            $runtimeDir = $hasRuntime.DirectoryName
            break
        }
    }
}

# Fallback: search the entire extraction
if (-not $runtimeDir) {
    $found = Get-ChildItem $extractDir -Filter "msedgewebview2.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        $runtimeDir = $found.DirectoryName
    }
}

if (-not $runtimeDir) {
    Write-Error "Could not find msedgewebview2.exe in the downloaded package."
    Write-Host "Package contents:" -ForegroundColor Yellow
    Get-ChildItem $extractDir -Recurse -Directory | ForEach-Object {
        Write-Host "  $($_.FullName.Substring($extractDir.Length + 1))\"
    }
    exit 1
}

Write-Host "      Found runtime at: $($runtimeDir.Substring($extractDir.Length + 1))" -ForegroundColor Green

# Copy to output
if (Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force }
Copy-Item $runtimeDir $outputDir -Recurse

# Clean up
Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

$fileCount = (Get-ChildItem $outputDir -Recurse -File).Count
$totalSizeMB = [math]::Round(((Get-ChildItem $outputDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB), 1)

Write-Host ""
Write-Host "=== Done! ===" -ForegroundColor Green
Write-Host "Runtime extracted to: $outputDir"
Write-Host "Files: $fileCount ($totalSizeMB MB)"
Write-Host "Version: $latestVersion"
Write-Host ""
Write-Host "Next: Run build-zip.ps1 to create both distribution ZIPs." -ForegroundColor Cyan
Write-Host "The bundled ZIP will include WebView2 runtime files alongside Trowser.exe." -ForegroundColor Cyan
