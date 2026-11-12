#Requires -Version 5.1
<#
.SYNOPSIS
    Packages local source files allowed by the repo whitelist .gitignore.
.DESCRIPTION
    Creates a ZIP of every path Git would not ignore: tracked files plus untracked
    files under whitelisted trees (see .gitignore). Excludes dist/, .cursor/, build
    output, and other paths re-ignored there. Output is meant for sharing a clean
    source tree, not a built Trowser release (see build-zip.ps1).
.PARAMETER OutputPath
    Full path to the ZIP file. Default: dist/Trowser-source-gitignore.zip under the repo root.
.PARAMETER Force
    Overwrite OutputPath if it already exists.
.EXAMPLE
    .\scripts\create-zip-local-source.ps1
.EXAMPLE
    .\scripts\create-zip-local-source.ps1 -OutputPath C:\temp\trowser-src.zip -Force
#>
param(
    [string]$OutputPath = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "git is not on PATH."
}

Push-Location $repoRoot
try {
    $null = git rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Not a git repository: $repoRoot"
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $distDir = Join-Path $repoRoot "dist"
        New-Item -ItemType Directory -Force -Path $distDir | Out-Null
        $OutputPath = Join-Path $distDir "Trowser-source-gitignore.zip"
    } else {
        $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        $parent = Split-Path -Parent $OutputPath
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
    }

    if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
        Write-Error "Output already exists: $OutputPath (use -Force to overwrite)."
    }
    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Force
    }

    $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
    if (-not $tar) {
        Write-Error "tar.exe is required (included with recent Windows 10/11)."
    }

    $fileList = @(git ls-files --cached --others --exclude-standard)
    if ($fileList.Count -eq 0) {
        Write-Error "No non-ignored files found under $repoRoot."
    }

    Write-Host "Creating source ZIP ($($fileList.Count) files)..." -ForegroundColor Yellow
    $fileList | & $tar.Source -caf $OutputPath -T -

    $sizeMB = [math]::Round((Get-Item -LiteralPath $OutputPath).Length / 1MB, 2)
    Write-Host "Created: $OutputPath ($sizeMB MB)" -ForegroundColor Green
}
finally {
    Pop-Location
}
