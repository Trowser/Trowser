#Requires -Version 5.1
<#
.SYNOPSIS
    Builds Trowser and packages it as distributable ZIPs.
.DESCRIPTION
    1. Runs dotnet publish (Release, self-contained, single-file)
    2. Optionally signs Trowser.exe (requires -Sign and prior create-cert.ps1)
    3. Stages output + trowserkit/ into a clean folder
    4. Creates Trowser-<version>.zip (lightweight, assumes WebView2 is installed)
    5. If webview2-runtime/ exists, also creates Trowser-<version>-webview2.zip
       (includes bundled WebView2 runtime for offline use)
.PARAMETER SkipBuild
    Skip the dotnet publish step (use existing publish output).
.PARAMETER Sign
    Sign Trowser.exe with the self-signed certificate. Requires .cert/trowser.pfx
    from scripts/create-cert.ps1. Includes Trowser.cer and SMARTScreen.md for users.
.PARAMETER CertPassword
    Certificate password for signing. If omitted with -Sign, prompts interactively.
.PARAMETER Version
    Override the version label (default: read from Trowser.csproj).
.PARAMETER NoBump
    Skip auto-incrementing the patch version in the .csproj after building.
#>
param(
    [switch]$SkipBuild,
    [switch]$Sign,
    [string]$CertPassword = "",
    [string]$Version = "",
    [switch]$NoBump
)

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot
$projectDir = Join-Path $repoRoot "src\Trowser"
$csprojPath = Join-Path $projectDir "Trowser.csproj"
$publishDir = Join-Path $projectDir "bin\Release\net8.0-windows\win-x64\publish"
$distDir = Join-Path $repoRoot "dist"
$stagingRoot = Join-Path $distDir "_staging"
$stagingDir = Join-Path $stagingRoot "Trowser"
$webview2RuntimeDir = Join-Path $repoRoot "webview2-runtime"

# Read version from .csproj if not overridden
if (-not $Version) {
    $csprojXml = [xml](Get-Content $csprojPath)
    $versionNode = $csprojXml.Project.PropertyGroup.Version
    if ($versionNode) {
        $Version = $versionNode
    } else {
        Write-Error "No <Version> found in Trowser.csproj and no -Version parameter specified."
        exit 1
    }
}

Write-Host "=== Trowser Packaging ===" -ForegroundColor Cyan
Write-Host "Version: $Version"
Write-Host ""

# Step 1: Build
if (-not $SkipBuild) {
    Write-Host "[1/4] Building Trowser (dotnet publish -c Release)..." -ForegroundColor Yellow

    # Clean publish directory to prevent stale incremental builds
    if (Test-Path $publishDir) {
        Remove-Item $publishDir -Recurse -Force
    }

    dotnet publish $projectDir -c Release
    if ($LASTEXITCODE -ne 0) {
        Write-Error "dotnet publish failed with exit code $LASTEXITCODE"
        exit 1
    }
    Write-Host "      Build succeeded." -ForegroundColor Green
} else {
    Write-Host "[1/4] Skipping build (using existing publish output)." -ForegroundColor Yellow
    if (-not (Test-Path (Join-Path $publishDir "Trowser.exe"))) {
        Write-Error "No publish output found. Run without -SkipBuild first."
        exit 1
    }
}

# Step 2: Sign (optional)
if ($Sign) {
    $signScript = Join-Path $repoRoot "scripts\sign-exe.ps1"
    if (-not (Test-Path $signScript)) {
        Write-Error "Sign script not found: $signScript"
        exit 1
    }
    Write-Host "[2/4] Signing Trowser.exe..." -ForegroundColor Yellow
    $signParams = @{
        ExePath = Join-Path $publishDir "Trowser.exe"
        CertPath = Join-Path $repoRoot ".cert\trowser.pfx"
    }
    if ($CertPassword) { $signParams["Password"] = $CertPassword }
    & $signScript @signParams
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Signing failed."
        exit 1
    }
    Write-Host "      Signed successfully." -ForegroundColor Green
} else {
    Write-Host "[2/4] Skipping signing (use -Sign to enable)." -ForegroundColor Yellow
}

# Step 3: Stage files
Write-Host "[3/4] Staging files..." -ForegroundColor Yellow

if (Test-Path $stagingRoot) {
    Remove-Item $stagingRoot -Recurse -Force
}
New-Item $stagingDir -ItemType Directory -Force | Out-Null

# Copy publish output (exclude debug symbols and XML docs)
$excludeExtensions = @(".pdb", ".xml")
Get-ChildItem $publishDir -Recurse | Where-Object {
    -not $_.PSIsContainer -and $_.Extension -notin $excludeExtensions
} | ForEach-Object {
    $relativePath = $_.FullName.Substring($publishDir.Length + 1)
    $destPath = Join-Path $stagingDir $relativePath
    $destDir = Split-Path $destPath -Parent
    if (-not (Test-Path $destDir)) {
        New-Item $destDir -ItemType Directory -Force | Out-Null
    }
    Copy-Item $_.FullName $destPath
}

# Copy trowserkit/ (exclude .cursor\plans)
$trowserkitSrc = Join-Path $repoRoot "trowserkit"
$trowserkitDest = Join-Path $stagingDir "trowserkit"
Copy-Item $trowserkitSrc $trowserkitDest -Recurse
$plansDir = Join-Path $trowserkitDest ".cursor\plans"
if (Test-Path $plansDir) {
    Remove-Item $plansDir -Recurse -Force
}
$cursorRule = Join-Path $trowserkitDest "trowser.mdc"
if (Test-Path $cursorRule) {
    $rulesDir = Join-Path $trowserkitDest ".cursor\rules"
    New-Item $rulesDir -ItemType Directory -Force | Out-Null
    Move-Item $cursorRule (Join-Path $rulesDir "trowser.mdc") -Force
}

# Copy CHANGELOG.md, LICENSE, and licenses/ into staging root
Copy-Item (Join-Path $repoRoot "CHANGELOG.md") (Join-Path $stagingDir "CHANGELOG.md")
Copy-Item (Join-Path $repoRoot "LICENSE") (Join-Path $stagingDir "LICENSE")
Copy-Item (Join-Path $repoRoot "licenses") (Join-Path $stagingDir "licenses") -Recurse

# If signed, include certificate and SmartScreen instructions
if ($Sign) {
    $cerPath = Join-Path $repoRoot ".cert\trowser.cer"
    $smartscreenPath = Join-Path $repoRoot "SMARTScreen.md"
    if (Test-Path $cerPath) {
        Copy-Item $cerPath (Join-Path $stagingDir "Trowser.cer")
        Write-Host "      Included Trowser.cer for users." -ForegroundColor Green
    }
    if (Test-Path $smartscreenPath) {
        Copy-Item $smartscreenPath (Join-Path $stagingDir "SMARTScreen.md")
        Write-Host "      Included SMARTScreen.md." -ForegroundColor Green
    }
}

Write-Host "      Staged files:" -ForegroundColor Green
Get-ChildItem $stagingDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($stagingDir.Length + 1)
    $sizeMB = [math]::Round($_.Length / 1MB, 1)
    if ($sizeMB -ge 1) {
        Write-Host "        $rel ($sizeMB MB)"
    } else {
        $sizeKB = [math]::Round($_.Length / 1KB, 1)
        Write-Host "        $rel ($sizeKB KB)"
    }
}

# Step 4: Create ZIPs
Write-Host "[4/4] Creating distribution ZIPs..." -ForegroundColor Yellow

# --- ZIP 1: Lightweight (no WebView2 runtime) ---
$zipName = "Trowser-$Version.zip"
$zipPath = Join-Path $distDir $zipName

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $stagingDir -DestinationPath $zipPath -CompressionLevel Optimal

$zipSizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
Write-Host "      Created: $zipName ($zipSizeMB MB)" -ForegroundColor Green

# --- ZIP 2: With bundled WebView2 runtime ---
$hasWebView2Runtime = Test-Path $webview2RuntimeDir
if ($hasWebView2Runtime) {
    $runtimeFileCount = (Get-ChildItem $webview2RuntimeDir -Recurse -File).Count
    if ($runtimeFileCount -eq 0) {
        Write-Host "      webview2-runtime/ exists but is empty. Skipping bundled ZIP." -ForegroundColor Yellow
        $hasWebView2Runtime = $false
    }
}

if ($hasWebView2Runtime) {
    $bundledZipName = "Trowser-$Version-webview2.zip"
    $bundledZipPath = Join-Path $distDir $bundledZipName

    # Copy runtime into staging as WebView2Runtime/ subfolder
    $runtimeDest = Join-Path $stagingDir "WebView2Runtime"
    Copy-Item $webview2RuntimeDir $runtimeDest -Recurse

    $runtimeSizeMB = [math]::Round(((Get-ChildItem $runtimeDest -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB), 1)
    Write-Host "      Added WebView2Runtime/ ($runtimeSizeMB MB, $runtimeFileCount files)" -ForegroundColor Green

    if (Test-Path $bundledZipPath) { Remove-Item $bundledZipPath -Force }
    Compress-Archive -Path $stagingDir -DestinationPath $bundledZipPath -CompressionLevel Optimal

    $bundledZipSizeMB = [math]::Round((Get-Item $bundledZipPath).Length / 1MB, 1)
    Write-Host "      Created: $bundledZipName ($bundledZipSizeMB MB)" -ForegroundColor Green
} else {
    Write-Host "      No webview2-runtime/ found. Skipping bundled ZIP." -ForegroundColor Yellow
    Write-Host "      Run scripts/download-webview2-runtime.ps1 to enable." -ForegroundColor Yellow
}

# Clean up staging
Remove-Item $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Done! ===" -ForegroundColor Green
Write-Host "Output:" -ForegroundColor Cyan
Write-Host "  $zipPath ($zipSizeMB MB) -- requires WebView2 installed on user's machine"
if ($hasWebView2Runtime) {
    Write-Host "  $bundledZipPath ($bundledZipSizeMB MB) -- includes WebView2, works offline"
}
Write-Host ""
Write-Host "To distribute: share the ZIP(s). Recipients unzip and run Trowser.exe." -ForegroundColor Cyan
Write-Host "The trowserkit/ folder contains docs, examples, and the Cursor rule." -ForegroundColor Cyan
if ($Sign) {
    Write-Host ""
    Write-Host "Signed build includes Trowser.cer and SMARTScreen.md for users." -ForegroundColor Cyan
}

# Auto-increment patch version in .csproj for next build
if (-not $NoBump) {
    $parts = $Version -split '\.'
    if ($parts.Count -ge 3) {
        $parts[2] = [int]$parts[2] + 1
        $nextVersion = $parts -join '.'
        $csprojContent = Get-Content $csprojPath -Raw
        $csprojContent = $csprojContent -replace "<Version>[^<]+</Version>", "<Version>$nextVersion</Version>"
        Set-Content $csprojPath $csprojContent -NoNewline
        Write-Host ""
        Write-Host "Version bumped to $nextVersion in Trowser.csproj (for next build)." -ForegroundColor Cyan
    }
}
