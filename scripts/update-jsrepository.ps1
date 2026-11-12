<#
.SYNOPSIS
  Refresh Retire.js jsrepository.json before build when upstream is newer.

.DESCRIPTION
  One GitHub API call (latest commit touching repository/jsrepository.json).
  If the commit SHA matches scripts/jsrepository.upstream.json, exits immediately.
  Otherwise downloads the raw file, validates JSON, updates Resources only when
  content changed, and writes the sidecar SHA.

  Network or validation errors are logged and exit 0 so MSBuild continues.

.PARAMETER Check
  Exit 1 if upstream is ahead of the recorded SHA (for optional manual/CI use).
  Does not download.
#>
[CmdletBinding()]
param(
    [switch]$Check
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$resourcePath = Join-Path $repoRoot "src\Trowser\Resources\jsrepository.json"
$metaPath = Join-Path $PSScriptRoot "jsrepository.upstream.json"
$rawUrl = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
$commitsUrl = "https://api.github.com/repos/RetireJS/retire.js/commits?path=repository/jsrepository.json&per_page=1"

function Write-Notice([string]$Message, [string]$Color = "DarkGray") {
    Write-Host "[retire.js] $Message" -ForegroundColor $Color
}

function Exit-Ok([int]$Code = 0) {
    exit $Code
}

function Exit-Skip([string]$Reason) {
    Write-Notice $Reason
    Exit-Ok 0
}

if (-not (Test-Path -LiteralPath $resourcePath)) {
    Write-Notice "Missing $resourcePath — skipping refresh." "Yellow"
    Exit-Ok 0
}

try {
    $headers = @{
        Accept        = "application/vnd.github+json"
        "User-Agent"  = "Trowser-build"
    }
    $commits = Invoke-RestMethod -Uri $commitsUrl -Headers $headers -TimeoutSec 20
    if (-not $commits -or $commits.Count -lt 1) {
        Exit-Skip "No commit history from GitHub — skipping refresh."
    }

    $latestSha = [string]$commits[0].sha
    $latestDate = [datetime]$commits[0].commit.committer.date

    $meta = $null
    if (Test-Path -LiteralPath $metaPath) {
        $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
    }

    $recordedSha = if ($meta -and $meta.upstreamSha) { [string]$meta.upstreamSha } else { "" }

    if ($recordedSha -eq $latestSha) {
        Write-Notice "jsrepository.json is current ($($latestSha.Substring(0, 7)))."
        Exit-Ok 0
    }

    if ($Check) {
        Write-Notice "Upstream jsrepository.json is newer (local $($recordedSha.Substring(0, [Math]::Min(7, $recordedSha.Length))), remote $($latestSha.Substring(0, 7)))." "Yellow"
        Exit-Ok 1
    }

    Write-Notice "Updating jsrepository.json ($($latestSha.Substring(0, 7)), $($latestDate.ToString('yyyy-MM-dd')))..." "Cyan"
    Invoke-WebRequest -Uri $rawUrl -OutFile "$resourcePath.download" -UseBasicParsing -TimeoutSec 120 -Headers @{ "User-Agent" = "Trowser-build" }

    $bytes = [System.IO.File]::ReadAllBytes("$resourcePath.download")
    if ($bytes.Length -lt 64) {
        throw "Downloaded file is too small ($($bytes.Length) bytes)."
    }

    $null = Get-Content -LiteralPath "$resourcePath.download" -Raw -Encoding UTF8 | ConvertFrom-Json

    $newText = [System.IO.File]::ReadAllText("$resourcePath.download")
    $oldText = if (Test-Path -LiteralPath $resourcePath) {
        [System.IO.File]::ReadAllText($resourcePath)
    } else { "" }

    if ($newText -ne $oldText) {
        [System.IO.File]::WriteAllText($resourcePath, $newText, [System.Text.UTF8Encoding]::new($false))
        Write-Notice "Wrote $resourcePath" "Green"
    } else {
        Write-Notice "Content unchanged; updating upstream SHA only." "DarkGray"
    }

    Remove-Item -LiteralPath "$resourcePath.download" -Force -ErrorAction SilentlyContinue

    $metaOut = [ordered]@{
        upstreamSha  = $latestSha
        upstreamDate = $latestDate.ToString("o")
        refreshedAt  = (Get-Date).ToUniversalTime().ToString("o")
        sourceUrl    = $rawUrl
    }
    ($metaOut | ConvertTo-Json -Depth 3) + "`n" | Set-Content -LiteralPath $metaPath -Encoding utf8NoBOM -NoNewline
    Write-Notice "Recorded $metaPath" "Green"
    Exit-Ok 0
}
catch {
    Write-Notice "Refresh skipped: $($_.Exception.Message)" "Yellow"
    Remove-Item -LiteralPath "$resourcePath.download" -Force -ErrorAction SilentlyContinue
    Exit-Ok 0
}
